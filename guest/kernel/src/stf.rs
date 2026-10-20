//! State transition: validation, block building, execution, queries.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use solo_abi::chain::{Account, BlockHeader, Receipt, TRANSFER_GAS, query, reason};
use solo_abi::codec::Seq;
use solo_abi::types::{Address, Block, BuildArgs, ExecuteArgs, ExecuteResult, ExecuteSummary, FinalizeArgs, Hash, QueryArgs, QueryResult, ValidateArgs, ValidateResult};
use solo_abi::{Decode, Encode};

use crate::state;
use crate::tx::{Transfer, decode_transfer};

fn admissible(t: &Transfer, account: &Account) -> Result<(), u32> {
    if t.nonce != account.nonce {
        return Err(reason::BAD_NONCE);
    }
    match t.max_cost() {
        Some(cost) if cost <= account.balance => Ok(()),
        _ => Err(reason::INSUFFICIENT_FUNDS),
    }
}

/// `kernel_stf_validate_tx`.
pub fn validate(args: &ValidateArgs) -> ValidateResult {
    let chain_id = state::chain_id();
    match decode_transfer(&args.tx, chain_id).and_then(|t| admissible(&t, &state::account(&t.from)).map(|()| t)) {
        Ok(t) => ValidateResult::Valid {
            priority: u64::try_from(t.gas_price).unwrap_or(u64::MAX),
            reserved_fee: u64::try_from(t.max_cost().unwrap_or(u128::MAX)).unwrap_or(u64::MAX),
        },
        Err(reason) => ValidateResult::Invalid { reason },
    }
}

/// Selects candidates that validate in sequence against the current state.
pub fn build(args: &BuildArgs) -> Block {
    let chain_id = state::chain_id();
    let max = usize::try_from(args.limits.max_txs).unwrap_or(usize::MAX);
    let mut accounts: BTreeMap<Address, Account> = BTreeMap::new();
    let mut selected = Vec::new();
    for raw in &args.candidates.0 {
        if selected.len() >= max {
            break;
        }
        let Ok(t) = decode_transfer(raw, chain_id) else { continue };
        let account = accounts.entry(t.from).or_insert_with(|| state::account(&t.from));
        if admissible(&t, account).is_err() {
            continue;
        }
        account.nonce += 1;
        account.balance -= t.max_cost().unwrap_or(0);
        selected.push(raw.clone());
    }
    let header = BlockHeader {
        height: args.context.height,
        parent_hash: args.context.parent_hash,
        timestamp_ms: args.context.timestamp_ms,
        ..BlockHeader::default()
    };
    Block { header: header.to_bytes(), txs: Seq(selected), participation: Vec::new() }
}

fn apply(t: &Transfer) -> bool {
    let mut from = state::account(&t.from);
    if admissible(t, &from).is_err() {
        return false;
    }
    let Some(cost) = t.cost() else { return false };
    from.balance -= cost;
    from.nonce += 1;
    state::set_account(&t.from, &from);
    let mut to = if t.to == t.from { from } else { state::account(&t.to) };
    to.balance = to.balance.saturating_add(t.value);
    state::set_account(&t.to, &to);
    true
}

/// `kernel_stf_execute_block`: applies every transaction in order, writing a
/// receipt for each, then the header with the state commitment.
pub fn execute(args: &ExecuteArgs) -> ExecuteResult {
    let chain_id = state::chain_id();
    let template = BlockHeader::from_bytes(&args.block.header).unwrap_or_else(|_| solo_guest::trap());
    let height = template.height;
    let mut receipts = Vec::new();
    let mut tx_hashes = Vec::new();
    let mut gas_used = 0u64;
    let mut receipt_hashes = Vec::new();
    for (index, raw) in args.block.txs.0.iter().enumerate() {
        let hash = state::keccak256(raw);
        let receipt = match decode_transfer(raw, chain_id) {
            Ok(t) if apply(&t) => {
                gas_used += TRANSFER_GAS;
                Receipt { status: 1, gas_used: TRANSFER_GAS, from: t.from, to: t.to, value: t.value, height, index: index as u32 }
            }
            Ok(t) => Receipt { status: 0, gas_used: 0, from: t.from, to: t.to, value: t.value, height, index: index as u32 },
            Err(_) => Receipt { status: 0, height, index: index as u32, ..Receipt::default() },
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
        gas_used,
    };
    let block_hash = state::keccak256(&header.to_bytes());
    state::put_block(&header, &block_hash);
    ExecuteResult {
        state_root,
        summary: ExecuteSummary { gas_used, tx_count: args.block.txs.0.len() as u32, receipts_root, logs_bloom: Vec::new() },
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

/// `kernel_query`.
pub fn query(args: &QueryArgs) -> QueryResult {
    let method = core::str::from_utf8(&args.method).unwrap_or("");
    match method {
        query::CHAIN_ID => found(Some(state::chain_id())),
        query::BLOCK_NUMBER => found(Some(state::height().unwrap_or(0))),
        query::FINALIZED => found(Some(state::get::<u64>(solo_abi::chain::keys::FINALIZED).unwrap_or(0))),
        query::ACCOUNT => match Address::from_bytes(&args.params) {
            Ok(address) => found(Some(state::account(&address))),
            Err(_) => QueryResult { status: 2, body: Vec::new() },
        },
        query::BLOCK_BY_NUMBER => match u64::from_bytes(&args.params) {
            Ok(height) => found(state::block_by_number(height)),
            Err(_) => QueryResult { status: 2, body: Vec::new() },
        },
        query::BLOCK_BY_HASH => match Hash::from_bytes(&args.params) {
            Ok(hash) => found(state::block_by_hash(&hash)),
            Err(_) => QueryResult { status: 2, body: Vec::new() },
        },
        query::RECEIPT => match Hash::from_bytes(&args.params) {
            Ok(hash) => found(state::receipt(&hash)),
            Err(_) => QueryResult { status: 2, body: Vec::new() },
        },
        query::TRANSACTION => match Hash::from_bytes(&args.params) {
            Ok(hash) => found(state::transaction(&hash)),
            Err(_) => QueryResult { status: 2, body: Vec::new() },
        },
        _ => QueryResult { status: 3, body: Vec::new() },
    }
}
