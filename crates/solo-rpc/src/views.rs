//! The JSON shapes of transactions, receipts, logs and blocks, as geth
//! returns them. Pure functions of what the node stores.

use serde_json::{Value, json};
use solo_abi::chain::{BASE_FEE, BLOCK_GAS_LIMIT, BlockHeader, Log, Receipt};
use solo_eth::Tx;
use solo_host::hash::keccak256;

use crate::hex::{data, quantity, quantity_be};

/// Where a mined transaction sits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Position {
    /// Hash of the block.
    pub block_hash: [u8; 32],
    /// Height of the block.
    pub height: u64,
    /// Index within the block.
    pub index: u32,
}

/// Decodes a stored transaction. A block can carry bytes that do not decode
/// (the kernel gives them a failed receipt); those show as an empty legacy
/// transaction so block views stay total.
#[must_use]
pub fn decode_or_blank(raw: &[u8]) -> Tx {
    solo_eth::decode(raw).unwrap_or(Tx {
        tx_type: 0,
        chain_id: None,
        nonce: 0,
        gas_price: 0,
        priority_fee: None,
        gas_limit: 0,
        to: None,
        value: 0,
        input: Vec::new(),
        access_list: Vec::new(),
        v: 0,
        r: [0; 32],
        s: [0; 32],
        signing_payload: Vec::new(),
    })
}

fn address_or_null(address: Option<[u8; 20]>) -> Value {
    address.map_or(Value::Null, |a| json!(data(&a)))
}

/// A transaction. `mined` is its position and the price it paid; a pending
/// transaction has null block fields and, for a dynamic-fee transaction, its
/// maximum fee as the gas price, as in geth.
#[must_use]
pub fn transaction(
    hash: &[u8; 32],
    tx: &Tx,
    from: &[u8; 20],
    mined: Option<(&Position, u128)>,
) -> Value {
    let mut view = json!({
        "hash": data(hash),
        "type": quantity(u128::from(tx.tx_type)),
        "nonce": quantity(u128::from(tx.nonce)),
        "from": data(from),
        "to": address_or_null(tx.to),
        "value": quantity(tx.value),
        "gas": quantity(u128::from(tx.gas_limit)),
        "gasPrice": quantity(tx.gas_price),
        "input": data(&tx.input),
        "v": quantity(u128::from(tx.v)),
        "r": quantity_be(&tx.r),
        "s": quantity_be(&tx.s),
        "blockHash": Value::Null,
        "blockNumber": Value::Null,
        "transactionIndex": Value::Null,
    });
    if let Some(chain_id) = tx.chain_id {
        view["chainId"] = json!(quantity(u128::from(chain_id)));
    }
    if tx.tx_type != 0 {
        view["yParity"] = json!(quantity(u128::from(tx.v)));
        view["accessList"] = tx
            .access_list
            .iter()
            .map(|item| {
                json!({
                    "address": data(&item.address),
                    "storageKeys": item.keys.iter().map(|k| data(k)).collect::<Vec<_>>(),
                })
            })
            .collect();
    }
    if let Some(tip) = tx.priority_fee {
        view["maxFeePerGas"] = json!(quantity(tx.gas_price));
        view["maxPriorityFeePerGas"] = json!(quantity(tip));
    }
    if let Some((position, price)) = mined {
        view["blockHash"] = json!(data(&position.block_hash));
        view["blockNumber"] = json!(quantity(u128::from(position.height)));
        view["transactionIndex"] = json!(quantity(u128::from(position.index)));
        view["gasPrice"] = json!(quantity(price));
    }
    view
}

/// The logs bloom of `logs`.
#[must_use]
pub fn bloom(logs: &[&Log]) -> [u8; 256] {
    let entries: Vec<(&[u8; 20], &[[u8; 32]])> = logs
        .iter()
        .map(|log| (&log.address, log.topics.0.as_slice()))
        .collect();
    solo_eth::logs_bloom(&entries, keccak256)
}

/// A log emitted by the transaction `tx_hash` at `position`; `log_index` counts
/// across the whole block.
#[must_use]
pub fn log(log: &Log, tx_hash: &[u8; 32], position: &Position, log_index: u64) -> Value {
    json!({
        "address": data(&log.address),
        "topics": log.topics.0.iter().map(|t| data(t)).collect::<Vec<_>>(),
        "data": data(&log.data),
        "blockHash": data(&position.block_hash),
        "blockNumber": quantity(u128::from(position.height)),
        "transactionHash": data(tx_hash),
        "transactionIndex": quantity(u128::from(position.index)),
        "logIndex": quantity(u128::from(log_index)),
        "removed": false,
    })
}

/// A receipt. `to` is the transaction's recipient (`None` for a creation);
/// `first_log` is the block-wide index of its first log.
#[must_use]
pub fn receipt(
    hash: &[u8; 32],
    receipt: &Receipt,
    to: Option<[u8; 20]>,
    block_hash: &[u8; 32],
    first_log: u64,
) -> Value {
    let position = Position {
        block_hash: *block_hash,
        height: receipt.height,
        index: receipt.index,
    };
    let logs: Vec<&Log> = receipt.logs.0.iter().collect();
    json!({
        "transactionHash": data(hash),
        "transactionIndex": quantity(u128::from(receipt.index)),
        "blockHash": data(block_hash),
        "blockNumber": quantity(u128::from(receipt.height)),
        "from": data(&receipt.from),
        "to": address_or_null(to),
        "status": quantity(u128::from(receipt.status)),
        "gasUsed": quantity(u128::from(receipt.gas_used)),
        "cumulativeGasUsed": quantity(u128::from(receipt.cumulative_gas_used)),
        "effectiveGasPrice": quantity(receipt.effective_gas_price),
        "contractAddress": address_or_null(receipt.contract),
        "logs": logs
            .iter()
            .zip(first_log..)
            .map(|(l, index)| log(l, hash, &position, index))
            .collect::<Vec<_>>(),
        "logsBloom": data(&bloom(&logs)),
        "type": quantity(u128::from(receipt.tx_type)),
    })
}

/// Solo's transactions commitment: `keccak256` of the concatenated
/// transaction hashes, as the kernel's receipts root is of the receipt
/// hashes. Not a Merkle-Patricia root; nothing in Solo verifies one.
#[must_use]
pub fn transactions_root(tx_hashes: &[[u8; 32]]) -> [u8; 32] {
    keccak256(&tx_hashes.concat())
}

/// A block. `transactions` are hashes or full transaction views; `size` is
/// the bytes of the stored header and transactions.
#[must_use]
pub fn block(
    header: &BlockHeader,
    hash: &[u8; 32],
    transactions: &[Value],
    logs_bloom: &[u8; 256],
    size: usize,
) -> Value {
    json!({
        "number": quantity(u128::from(header.height)),
        "hash": data(hash),
        "parentHash": data(&header.parent_hash),
        "timestamp": quantity(u128::from(header.timestamp_ms / 1000)),
        "transactions": transactions,
        "transactionsRoot": data(&transactions_root(&header.tx_hashes.0)),
        "stateRoot": data(&header.state_root),
        "receiptsRoot": data(&header.receipts_root),
        "gasUsed": quantity(u128::from(header.gas_used)),
        "gasLimit": quantity(u128::from(BLOCK_GAS_LIMIT)),
        "baseFeePerGas": quantity(u128::from(BASE_FEE)),
        "logsBloom": data(logs_bloom),
        "miner": data(&[0u8; 20]),
        "difficulty": "0x0",
        "totalDifficulty": "0x0",
        "nonce": "0x0000000000000000",
        "mixHash": data(&[0u8; 32]),
        "sha3Uncles": data(&keccak256(&[0xc0])),
        "extraData": "0x",
        "size": quantity(size as u128),
        "uncles": [],
    })
}
