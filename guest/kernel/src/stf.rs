//! State transition: validation, block building, execution, queries.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use solo_abi::chain::consensus::{MAX_EVIDENCE, signing_preimage};
use solo_abi::chain::{Account, BLOCK_GAS_LIMIT, BlockHeader, CallRequest, CallResult, Evidence, Participation, Receipt, StorageQuery, call_status, query, reason};
use solo_abi::codec::Seq;
use solo_abi::types::{Address, Block, BuildArgs, ExecuteArgs, ExecuteResult, ExecuteSummary, FinalizeArgs, Hash, QueryArgs, QueryResult, ValidateArgs, ValidateResult};
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

/// The checks against the sender's account: next nonce and enough to pay the worst case.
fn admissible(s: &Signed, account: &Account) -> Result<(), u32> {
    if s.tx.nonce != account.nonce {
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
    Ok(s)
}

/// `kernel_stf_validate_tx`.
pub fn validate(args: &ValidateArgs) -> ValidateResult {
    match check(&args.tx).and_then(|s| admissible(&s, &state::account(&s.from)).map(|()| s)) {
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

/// Whether both messages of `evidence` are signed by the validator it names.
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
/// offence is new. Nothing here can make a block invalid.
fn record_evidence(participation: &[u8]) {
    let Ok(participation) = Participation::from_bytes(participation) else { return };
    if participation.evidence.0.is_empty() {
        return;
    }
    let validators = state::validators();
    let chain_id = state::chain_id();
    for evidence in participation.evidence.0.iter().take(MAX_EVIDENCE) {
        if verified(evidence, &validators, chain_id) {
            // The slashing hook: once validators stake, the offender's stake is
            // cut here, in the same state transition that records the offence.
            state::put_evidence(evidence);
        }
    }
}

fn failed(height: u64, index: u32, cumulative: u64) -> Receipt {
    Receipt { status: 0, height, index, cumulative_gas_used: cumulative, ..Receipt::default() }
}

/// `kernel_stf_execute_block`: runs every transaction in order through the
/// EVM, writing a receipt for each, then the header with the state commitment.
/// A transaction that cannot run (it should not have been included) gets a
/// failed receipt and changes nothing.
pub fn execute(args: &ExecuteArgs) -> ExecuteResult {
    let chain_id = state::chain_id();
    let template = BlockHeader::from_bytes(&args.block.header).unwrap_or_else(|_| solo_guest::trap());
    let height = template.height;
    let block = BlockFields { number: height, timestamp: template.timestamp_ms / 1000 };
    record_evidence(&args.block.participation);
    let mut receipts = Vec::new();
    let mut tx_hashes = Vec::new();
    let mut cumulative = 0u64;
    let mut receipt_hashes = Vec::new();
    for (index, raw) in args.block.txs.0.iter().enumerate() {
        let index = index as u32;
        let hash = state::keccak256(raw);
        let receipt = match decode_signed(raw, chain_id) {
            Ok(s) if well_formed(&s).is_ok() && cumulative + s.tx.gas_limit <= BLOCK_GAS_LIMIT => {
                let price = s.tx.effective_gas_price(u128::from(BASE_FEE)).unwrap_or(0);
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
                let outcome = evm::run(message, block, true);
                if outcome.status == call_status::INVALID {
                    failed(height, index, cumulative)
                } else {
                    cumulative += outcome.gas_used;
                    Receipt {
                        status: u8::from(outcome.status == call_status::SUCCESS),
                        gas_used: outcome.gas_used,
                        from: s.from,
                        to: s.tx.to.unwrap_or([0; 20]),
                        value: s.tx.value,
                        height,
                        index,
                        cumulative_gas_used: cumulative,
                        contract: outcome.contract,
                        logs: Seq(outcome.logs),
                        tx_type: s.tx.tx_type,
                        effective_gas_price: price,
                    }
                }
            }
            _ => failed(height, index, cumulative),
        };
        state::put_receipt(&hash, &receipt, raw);
        let encoded = receipt.to_bytes();
        receipt_hashes.extend_from_slice(&state::keccak256(&encoded));
        receipts.push(encoded);
        tx_hashes.push(hash);
    }
    let receipts_root = state::keccak256(&receipt_hashes);
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
        summary: ExecuteSummary { gas_used: cumulative, tx_count: args.block.txs.0.len() as u32, receipts_root, logs_bloom: Vec::new() },
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

/// Runs a call against the latest state without keeping its effects.
fn call(request: CallRequest) -> CallResult {
    let height = state::height().unwrap_or(0);
    let timestamp = state::block_by_number(height).map_or(0, |h| h.timestamp_ms / 1000);
    let gas = if request.gas == 0 { MAX_TX_GAS } else { request.gas.min(MAX_TX_GAS) };
    let message = Message {
        tx_type: 0,
        caller: request.from,
        to: request.to,
        value: request.value,
        data: request.data,
        gas_limit: gas,
        gas_price: 0,
        priority_fee: None,
        nonce: None,
        access_list: Vec::new(),
    };
    let outcome = evm::run(message, BlockFields { number: height + 1, timestamp }, false);
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
        _ => QueryResult { status: 3, body: Vec::new() },
    }
}
