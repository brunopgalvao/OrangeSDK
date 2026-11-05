//! geth's `txpool` namespace over the node's mempool (spec 14 §7):
//! `txpool_status` counts and `txpool_content` lists, pending and queued.

use std::collections::BTreeMap;

use orange_host::hash::keccak256;
use orange_node::{Mempool, PoolTx};
use serde_json::{Map, Value, json};

use crate::RpcError;
use crate::hex::{data, quantity};
use crate::methods::{encoded_len, too_large};
use crate::views::{self, decode_or_blank};

/// An address in EIP-55 mixed-case hex, the form geth keys `txpool_content`
/// by.
#[must_use]
pub fn checksum(address: &[u8; 20]) -> String {
    let lower = data(address);
    let digest = keccak256(&lower.as_bytes()[2..]);
    let mut out = String::from("0x");
    for (i, c) in lower[2..].chars().enumerate() {
        let nibble = (digest[i / 2] >> (4 * (1 - i % 2))) & 0xF;
        out.push(if nibble >= 8 {
            c.to_ascii_uppercase()
        } else {
            c
        });
    }
    out
}

/// `txpool_status`: how many transactions are pending and queued.
#[must_use]
pub fn status(pool: &Mempool) -> Value {
    let (pending, queued) = pool.status();
    json!({
        "pending": quantity(pending as u128),
        "queued": quantity(queued as u128),
    })
}

/// `txpool_content`: every transaction, pending or queued, by sender and
/// then by nonce as a decimal string, in the shape `eth_getTransactionByHash`
/// gives a pending transaction.
///
/// # Errors
/// geth's `response too large` once the transactions' views pass
/// `max_bytes` of JSON (spec 20 §8.6): a full pool is several times what
/// one answer should hold.
pub fn content(pool: &Mempool, max_bytes: usize) -> Result<Value, RpcError> {
    let mut pending: BTreeMap<String, Map<String, Value>> = BTreeMap::new();
    let mut queued: BTreeMap<String, Map<String, Value>> = BTreeMap::new();
    let mut spent = 0;
    for tx in pool.iter() {
        let view = view(tx);
        spent += encoded_len(&view);
        if spent > max_bytes {
            return Err(too_large());
        }
        let side = if pool.is_pending(tx) {
            &mut pending
        } else {
            &mut queued
        };
        side.entry(checksum(&tx.sender))
            .or_default()
            .insert(tx.nonce.to_string(), view);
    }
    Ok(json!({ "pending": pending, "queued": queued }))
}

fn view(tx: &PoolTx) -> Value {
    views::transaction(&tx.hash, &decode_or_blank(&tx.raw), &tx.sender, None)
}
