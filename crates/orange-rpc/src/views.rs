//! The JSON shapes of transactions, receipts, logs and blocks, as geth
//! returns them. Pure functions of what the node stores.

use orange_abi::chain::{BlockHeader, Log, Receipt};
use orange_eth::Tx;
use orange_eth::header::Header;
use orange_host::hash::keccak256;
use orange_rlp::{encode_bytes, encode_list, encode_uint};
use serde_json::{Value, json};

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
    orange_eth::decode(raw).unwrap_or(Tx {
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
        authorization_list: Vec::new(),
        v: 0,
        r: [0; 32],
        s: [0; 32],
        signing_payload: Vec::new(),
    })
}

/// The address a creation by `sender` at `nonce` deploys to:
/// `keccak256(rlp([sender, nonce]))[12..]`.
#[must_use]
pub fn created_address(sender: &[u8; 20], nonce: u64) -> [u8; 20] {
    let mut body = Vec::new();
    encode_bytes(sender, &mut body);
    encode_uint(u128::from(nonce), &mut body);
    let mut list = Vec::new();
    encode_list(&body, &mut list);
    let mut address = [0u8; 20];
    address.copy_from_slice(&keccak256(&list)[12..]);
    address
}

/// Where a mined transaction went: its recipient, `None` for a creation,
/// and for a creation the address it deploys to. geth derives that address
/// from the sender and nonce whatever the outcome, so a creation that
/// reverted still names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Destination {
    /// Recipient.
    pub to: Option<[u8; 20]>,
    /// Created contract.
    pub contract: Option<[u8; 20]>,
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
    if tx.tx_type == orange_eth::SET_CODE_TX_TYPE {
        view["authorizationList"] = tx
            .authorization_list
            .iter()
            .map(|auth| {
                json!({
                    "chainId": quantity_be(&auth.chain_id),
                    "address": data(&auth.address),
                    "nonce": quantity(u128::from(auth.nonce)),
                    "yParity": quantity(u128::from(auth.y_parity)),
                    "r": quantity_be(&auth.r),
                    "s": quantity_be(&auth.s),
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
    orange_eth::logs_bloom(&entries, keccak256)
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

/// A receipt. `destination` is where the transaction went; `first_log` is
/// the block-wide index of its first log.
#[must_use]
pub fn receipt(
    hash: &[u8; 32],
    receipt: &Receipt,
    destination: Destination,
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
        "to": address_or_null(destination.to),
        "status": quantity(u128::from(receipt.status)),
        "gasUsed": quantity(u128::from(receipt.gas_used)),
        "cumulativeGasUsed": quantity(u128::from(receipt.cumulative_gas_used)),
        "effectiveGasPrice": quantity(receipt.effective_gas_price),
        "contractAddress": address_or_null(destination.contract),
        "logs": logs
            .iter()
            .zip(first_log..)
            .map(|(l, index)| log(l, hash, &position, index))
            .collect::<Vec<_>>(),
        "logsBloom": data(&bloom(&logs)),
        "type": quantity(u128::from(receipt.tx_type)),
    })
}

/// A block: the fields of its Ethereum header (spec 20 §3), whose hash
/// `hash` is, and `transactions` as hashes or full transaction views; `size`
/// is the length of the block's RLP encoding ([`block_size`]).
#[must_use]
pub fn block(header: &BlockHeader, hash: &[u8; 32], transactions: &[Value], size: usize) -> Value {
    let h = Header::of(header);
    json!({
        "number": quantity(u128::from(h.number)),
        "hash": data(hash),
        "parentHash": data(&h.parent_hash),
        "sha3Uncles": data(&h.ommers_hash),
        "miner": data(&h.beneficiary),
        "stateRoot": data(&h.state_root),
        "transactionsRoot": data(&h.transactions_root),
        "receiptsRoot": data(&h.receipts_root),
        "logsBloom": data(&h.logs_bloom),
        "difficulty": quantity(h.difficulty),
        "gasLimit": quantity(u128::from(h.gas_limit)),
        "gasUsed": quantity(u128::from(h.gas_used)),
        "timestamp": quantity(u128::from(h.timestamp)),
        "extraData": data(&h.extra_data),
        "mixHash": data(&h.mix_hash),
        "nonce": data(&h.nonce),
        "baseFeePerGas": quantity(u128::from(h.base_fee_per_gas)),
        "withdrawalsRoot": data(&h.withdrawals_root),
        "blobGasUsed": quantity(u128::from(h.blob_gas_used)),
        "excessBlobGas": quantity(u128::from(h.excess_blob_gas)),
        "parentBeaconBlockRoot": data(&h.parent_beacon_block_root),
        "requestsHash": data(&h.requests_hash),
        "totalDifficulty": "0x0",
        "size": quantity(size as u128),
        "transactions": transactions,
        "uncles": [],
        "withdrawals": [],
    })
}

/// A block's header as `newHeads` announces it (spec 20 §8.7.3): the
/// fields of [`block`] without the block's body and size.
#[must_use]
pub fn head(header: &BlockHeader, hash: &[u8; 32]) -> Value {
    let mut view = block(header, hash, &[], 0);
    let body = ["transactions", "uncles", "withdrawals", "size"];
    view.as_object_mut()
        .into_iter()
        .for_each(|fields| fields.retain(|name, _| !body.contains(&name.as_str())));
    view
}

/// The length of a block's RLP encoding, `[header, transactions, ommers,
/// withdrawals]`, where a typed transaction is the string of its bytes and
/// a legacy one its list (EIP-2718).
#[must_use]
pub fn block_size(header: &BlockHeader, raws: &[Vec<u8>]) -> usize {
    let mut txs = Vec::new();
    for raw in raws {
        match raw.first() {
            Some(t) if *t < 0x80 => encode_bytes(raw, &mut txs),
            _ => txs.extend_from_slice(raw),
        }
    }
    let mut body = Header::of(header).rlp();
    encode_list(&txs, &mut body);
    encode_list(&[], &mut body);
    encode_list(&[], &mut body);
    let mut out = Vec::new();
    encode_list(&body, &mut out);
    out.len()
}
