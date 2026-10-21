//! State transition: validation, block building, execution, queries.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use solo_abi::chain::consensus::{MAX_EVIDENCE, signing_preimage};
use solo_abi::chain::{Account, BLOCK_GAS_LIMIT, BlockHeader, CallRequest, CallResult, Evidence, Participation, Receipt, StorageQuery, call_status, query, reason};
use solo_abi::codec::Seq;
use solo_abi::types::{Address, Ahead, Block, BuildArgs, ExecuteArgs, ExecuteResult, ExecuteSummary, FinalizeArgs, Hash, QueryArgs, QueryResult, ValidateArgs, ValidateResult};
use solo_abi::{Decode, Encode};
use solo_eth::MAX_TX_GAS;

use crate::evm::{self, BASE_FEE, BlockFields, Message};
use crate::state;
use crate::tx::{self, Signed, decode_signed};

/// The checks that do not depend on the sender's account.
fn well_formed(s: &Signed) -> Result<(), u32> {
    let tx = &s.tx;
    if tx.gas_limit > MAX_TX_GAS || tx.gas_limit > BLOCK_GAS_LIMIT {
        return Err(reason::GAS_LIMIT_TOO_HIGH);
    }
    if !tx.initcode_ok() {
        return Err(reason::INITCODE_TOO_LARGE);
    }
    if tx.gas_limit < tx.min_gas_limit() {
        return Err(reason::GAS_TOO_LOW);
    }
    if tx.effective_gas_price(u128::from(BASE_FEE)).is_none() || tx.priority_fee.is_some_and(|tip| tip > tx.gas_price) {
        return Err(reason::FEE_TOO_LOW);
    }
    Ok(())
}

/// The checks against the sender's account: it may send (it has no code, or
/// only a delegation designator: EIP-3607, EIP-7702), the nonce is its next
/// one and still usable (EIP-2681), and it can pay the worst case. With
/// `well_formed` these are the checks revm makes before it runs a transaction,
/// so one that validates against a state also runs on it.
fn admissible(s: &Signed, account: &Account) -> Result<(), u32> {
    if account.code_hash != [0; 32] && !evm::is_delegation(&evm::code_of(account)) {
        return Err(reason::SENDER_NOT_EOA);
    }
    if s.tx.nonce != account.nonce || account.nonce == u64::MAX {
        return Err(reason::BAD_NONCE);
    }
    match s.tx.max_cost() {
        Some(cost) if cost <= account.balance => Ok(()),
        _ => Err(reason::INSUFFICIENT_FUNDS),
    }
}

fn check(raw: &[u8]) -> Result<Signed, u32> {
    let s = decode_signed(raw, state::chain_id())?;
    well_formed(&s)?;
    crate::governance::admit(&s)?;
    crate::staking::admit(&s)?;
    crate::modules::admit(&s)?;
    crate::outbox::admit(&s)?;
    crate::bridge::admit(&s)?;
    Ok(s)
}

/// The sender's account as it will be once the transactions a mempool holds
/// ahead of this one have run (spec 06 §5.1): `ahead.nonces` more and
/// `ahead.reserved` less. A nonce past the end of the range has no next
/// transaction; a balance below the reserve pays for nothing.
fn ahead_of(account: Account, ahead: &Ahead) -> Result<Account, u32> {
    let nonce = account.nonce.checked_add(ahead.nonces).ok_or(reason::BAD_NONCE)?;
    let balance = account.balance.checked_sub(ahead.reserved).ok_or(reason::INSUFFICIENT_FUNDS)?;
    Ok(Account { nonce, balance, ..account })
}

/// `kernel_stf_validate_tx`: the transaction validates against the sender's
/// account with what the mempool holds ahead of it already run. Only
/// admission depends on `ahead`; block building and execution check every
/// transaction against the state as it is, so a mempool that reports it
/// wrongly can delay its own transactions but never make a block invalid.
pub fn validate(args: &ValidateArgs) -> ValidateResult {
    match check(&args.tx).and_then(|s| admissible(&s, &ahead_of(state::account(&s.from), &args.ahead)?).map(|()| s)) {
        Ok(s) => {
            let price = s.tx.effective_gas_price(u128::from(BASE_FEE)).unwrap_or(0);
            ValidateResult::Valid {
                priority: u64::try_from(price - u128::from(BASE_FEE)).unwrap_or(u64::MAX),
                reserved_fee: u64::try_from(s.tx.max_cost().unwrap_or(u128::MAX)).unwrap_or(u64::MAX),
            }
        }
        Err(reason) => ValidateResult::Invalid { reason },
    }
}

/// Selects candidates that validate in sequence and fit the block gas limit.
pub fn build(args: &BuildArgs) -> Block {
    let max = usize::try_from(args.limits.max_txs).unwrap_or(usize::MAX);
    let mut accounts: BTreeMap<Address, Account> = BTreeMap::new();
    let mut selected = Vec::new();
    let mut gas = 0u64;
    for raw in &args.candidates.0 {
        if selected.len() >= max {
            break;
        }
        let Ok(s) = check(raw) else { continue };
        if gas + s.tx.gas_limit > BLOCK_GAS_LIMIT {
            continue;
        }
        let account = accounts.entry(s.from).or_insert_with(|| state::account(&s.from));
        if admissible(&s, account).is_err() {
            continue;
        }
        account.nonce += 1;
        account.balance -= s.tx.max_cost().unwrap_or(0);
        gas += s.tx.gas_limit;
        selected.push(raw.clone());
    }
    let header = BlockHeader { height: args.context.height, parent_hash: args.context.parent_hash, timestamp_ms: args.context.timestamp_ms, ..BlockHeader::default() };
    Block { header: header.to_bytes(), txs: Seq(selected), participation: Vec::new() }
}

/// Whether both messages of `evidence` are signed by the validator it names
/// in `validators`, the set of the epoch of its view.
fn verified(evidence: &Evidence, validators: &[Hash], chain_id: u64) -> bool {
    let Some(id) = validators.get(evidence.validator as usize) else { return false };
    evidence.well_formed()
        && [&evidence.first, &evidence.second].iter().all(|m| {
            let msg = state::keccak256(&signing_preimage(evidence.kind, chain_id, evidence.view, &m.hash));
            tx::recover_pubkey(&msg, &m.signature.0).is_some_and(|pubkey| state::keccak256(&pubkey) == *id)
        })
}

/// Records the equivocation evidence a block carries (spec 08 §9): at most
/// `MAX_EVIDENCE` records, each kept only if both signatures verify and the
/// offence is new, and the DKG envelopes it carries (spec 15 §6.2). Nothing
/// here can make a block invalid.
fn record_participation(participation: &[u8], height: u64) {
    let Ok(participation) = Participation::from_bytes(participation) else { return };
    let chain_id = state::chain_id();
    for evidence in participation.evidence.0.iter().take(MAX_EVIDENCE) {
        // The slashing hook: the offender's stake is cut in the same state
        // transition that records the offence, once per offence.
        if verified(evidence, &crate::staking::evidence_set(evidence.view), chain_id) && state::put_evidence(evidence) {
            crate::staking::slash(evidence);
        }
    }
    crate::staking::record_dkg(&participation.dkg.0, height);
}

fn failed(height: u64, index: u32, cumulative: u64) -> Receipt {
    Receipt { status: 0, height, index, cumulative_gas_used: cumulative, ..Receipt::default() }
}

/// Whether the transaction with this hash has run. Every transaction that runs
/// uses at least the 21 000 base gas; the failed receipt of one that could not
/// run records none.
pub fn has_run(tx_hash: &Hash) -> bool {
    state::receipt(tx_hash).is_some_and(|r| r.gas_used > 0)
}

/// Runs one transaction of `block` at `index`, after `cumulative` gas; `None`
/// if it cannot run, in which case nothing changed.
fn run_tx(raw: &[u8], chain_id: u64, block: BlockFields, index: u32, cumulative: u64) -> Option<Receipt> {
    let s = decode_signed(raw, chain_id).ok()?;
    if well_formed(&s).is_err() || cumulative + s.tx.gas_limit > BLOCK_GAS_LIMIT {
        return None;
    }
    let message = Message {
        tx_type: s.tx.tx_type,
        caller: s.from,
        to: s.tx.to,
        value: s.tx.value,
        data: s.tx.input.clone(),
        gas_limit: s.tx.gas_limit,
        gas_price: s.tx.gas_price,
        priority_fee: s.tx.priority_fee,
        nonce: Some(s.tx.nonce),
        access_list: s.tx.access_list.clone(),
    };
    let outcome = if crate::staking::is_staking(&s) {
        crate::staking::run(&s, block.number, message, block)
    } else if s.tx.to == Some(solo_abi::modules::MODULE_ADDRESS) {
        crate::modules::run(&s, block.number, message, block)
    } else {
        crate::governance::run(&s, block.number, message, block)
    };
    if outcome.status == call_status::INVALID {
        return None;
    }
    Some(Receipt {
        status: u8::from(outcome.status == call_status::SUCCESS),
        gas_used: outcome.gas_used,
        from: s.from,
        to: s.tx.to.unwrap_or([0; 20]),
        value: s.tx.value,
        height: block.number,
        index,
        cumulative_gas_used: cumulative + outcome.gas_used,
        contract: outcome.contract,
        logs: Seq(outcome.logs),
        tx_type: s.tx.tx_type,
        effective_gas_price: s.tx.effective_gas_price(u128::from(BASE_FEE)).unwrap_or(0),
    })
}

/// `kernel_stf_execute_block`: runs every transaction in order through the
/// EVM, writing a receipt for each, then the header with the state commitment.
///
/// A transaction that cannot run (it should not have been included) changes
/// nothing. It gets a failed receipt, unless a receipt is already stored under
/// its hash: then an earlier inclusion ran, or could not run either, and this
/// block leaves it out, neither listing it nor touching that receipt. So a
/// transaction that ran keeps its receipt, in the one block that lists it.
pub fn execute(args: &ExecuteArgs) -> ExecuteResult {
    let chain_id = state::chain_id();
    let template = BlockHeader::from_bytes(&args.block.header).unwrap_or_else(|_| solo_guest::trap());
    let height = template.height;
    let block = BlockFields { number: height, timestamp: template.timestamp_ms / 1000 };
    crate::precompiles::begin(crate::governance::gate_active(solo_upgrade::gate::PRECOMPILES, height));
    record_participation(&args.block.participation, height);
    crate::modules::begin_block(height, template.timestamp_ms);
    let mut receipts = Vec::new();
    let mut tx_hashes = Vec::new();
    let mut cumulative = 0u64;
    let mut receipt_hashes = Vec::new();
    for raw in &args.block.txs.0 {
        let index = receipts.len() as u32;
        let hash = state::keccak256(raw);
        let receipt = match run_tx(raw, chain_id, block, index, cumulative) {
            Some(receipt) => receipt,
            None if state::receipt(&hash).is_some() => continue,
            None => failed(height, index, cumulative),
        };
        cumulative = receipt.cumulative_gas_used;
        state::put_receipt(&hash, &receipt, raw);
        let encoded = receipt.to_bytes();
        receipt_hashes.extend_from_slice(&state::keccak256(&encoded));
        receipts.push(encoded);
        tx_hashes.push(hash);
    }
    let receipts_root = state::keccak256(&receipt_hashes);
    crate::modules::end_block(height, template.timestamp_ms);
    crate::governance::end_block(height);
    crate::staking::end_block(height);
    let state_root = state::commit();
    let header = BlockHeader {
        height,
        parent_hash: state::last_hash(),
        timestamp_ms: template.timestamp_ms,
        state_root,
        receipts_root,
        tx_hashes: Seq(tx_hashes),
        gas_used: cumulative,
    };
    let block_hash = state::keccak256(&header.to_bytes());
    state::put_block(&header, &block_hash);
    ExecuteResult {
        state_root,
        summary: ExecuteSummary { gas_used: cumulative, tx_count: receipts.len() as u32, receipts_root, logs_bloom: Vec::new() },
        receipts: Seq(receipts),
    }
}

/// `kernel_stf_finalize_block`.
pub fn finalize(args: &FinalizeArgs) {
    state::set(solo_abi::chain::keys::FINALIZED, &args.height);
}

fn found<T: Encode>(v: Option<T>) -> QueryResult {
    match v {
        Some(v) => QueryResult { status: 0, body: v.to_bytes() },
        None => QueryResult { status: 1, body: Vec::new() },
    }
}

fn bad_params() -> QueryResult {
    QueryResult { status: 2, body: Vec::new() }
}

/// Runs a call against the head state without keeping its effects. The EVM
/// sees the head block (its number and timestamp), as `eth_call` at `latest`
/// does. A message with an access list runs as an EIP-2930 transaction, the
/// only way the EVM charges and warms one.
fn call(request: CallRequest) -> CallResult {
    let height = state::height().unwrap_or(0);
    let timestamp = state::block_by_number(height).map_or(0, |h| h.timestamp_ms / 1000);
    let gas = if request.gas == 0 { MAX_TX_GAS } else { request.gas.min(MAX_TX_GAS) };
    let access_list: Vec<solo_eth::AccessItem> = request.access_list.0.into_iter().map(|item| solo_eth::AccessItem { address: item.address, keys: item.keys.0 }).collect();
    let message = Message {
        tx_type: u8::from(!access_list.is_empty()),
        caller: request.from,
        to: request.to,
        value: request.value,
        data: request.data,
        gas_limit: gas,
        gas_price: 0,
        priority_fee: None,
        nonce: None,
        access_list,
    };
    // The host serves the gates active for the next block (spec 13 §7.1).
    crate::precompiles::begin(crate::governance::gate_active(solo_upgrade::gate::PRECOMPILES, height + 1));
    let outcome = crate::native::run(message, BlockFields { number: height, timestamp }, false);
    CallResult { status: outcome.status, gas_used: outcome.gas_used, output: outcome.output }
}

/// `kernel_query`.
pub fn query(args: &QueryArgs) -> QueryResult {
    let method = core::str::from_utf8(&args.method).unwrap_or("");
    match method {
        query::CHAIN_ID => found(Some(state::chain_id())),
        query::BLOCK_NUMBER => found(Some(state::height().unwrap_or(0))),
        query::FINALIZED => found(Some(state::get::<u64>(solo_abi::chain::keys::FINALIZED).unwrap_or(0))),
        query::ACCOUNT => match Address::from_bytes(&args.params) {
            Ok(address) => found(Some(state::account(&address))),
            Err(_) => bad_params(),
        },
        query::BLOCK_BY_NUMBER => match u64::from_bytes(&args.params) {
            Ok(height) => found(state::block_by_number(height)),
            Err(_) => bad_params(),
        },
        query::BLOCK_BY_HASH => match Hash::from_bytes(&args.params) {
            Ok(hash) => found(state::block_by_hash(&hash)),
            Err(_) => bad_params(),
        },
        query::RECEIPT => match Hash::from_bytes(&args.params) {
            Ok(hash) => found(state::receipt(&hash)),
            Err(_) => bad_params(),
        },
        query::TRANSACTION => match Hash::from_bytes(&args.params) {
            Ok(hash) => found(state::transaction(&hash)),
            Err(_) => bad_params(),
        },
        query::CODE => match Address::from_bytes(&args.params) {
            Ok(address) => found(Some(evm::code(&address))),
            Err(_) => bad_params(),
        },
        query::STORAGE => match StorageQuery::from_bytes(&args.params) {
            Ok(q) => found(Some(evm::storage(&q.address, &q.slot))),
            Err(_) => bad_params(),
        },
        query::CALL => match CallRequest::from_bytes(&args.params) {
            Ok(request) => found(Some(call(request))),
            Err(_) => bad_params(),
        },
        query::EVIDENCE => match u64::from_bytes(&args.params) {
            Ok(first) => found(Some(Seq(state::evidence_from(first)))),
            Err(_) => bad_params(),
        },
        solo_abi::bridge::query::FINALITY_PROOF => match u64::from_bytes(&args.params) {
            Ok(height) => found(crate::driver::finality_proof(height)),
            Err(_) => bad_params(),
        },
        _ => crate::staking::query(method, &args.params)
            .or_else(|| crate::modules::query(method, &args.params))
            .unwrap_or_else(|| crate::governance::query(method, &args.params)),
    }
}
