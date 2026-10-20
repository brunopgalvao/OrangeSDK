//! The mempool through JSON-RPC (spec 14): consecutive sends from one
//! account before a block, the `pending` transaction count, geth's pool
//! errors, and the `txpool` namespace.

mod common;

use common::{ETHER, SLOT_MS, Wallet, err, node, ok};
use serde_json::{Value, json};
use solo_host::hash::keccak256;
use solo_node::PoolLimits;
use solo_rpc::Rpc;
use solo_rpc::methods::data;
use solo_rpc::txpool::checksum;

fn count(rpc: &mut Rpc, address: &[u8; 20], tag: &str) -> Value {
    ok(rpc, "eth_getTransactionCount", json!([data(address), tag]))
}

fn send(rpc: &mut Rpc, raw: &[u8]) -> Value {
    ok(rpc, "eth_sendRawTransaction", json!([data(raw)]))
}

#[test]
fn checksums_follow_eip_55() {
    for address in [
        "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
        "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
        "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
        "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
    ] {
        let bytes = solo_rpc::methods::parse_address(&address.to_lowercase()).unwrap();
        assert_eq!(checksum(&bytes), address);
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn consecutive_sends_land_in_one_block() {
    let alice = Wallet::new(1);
    let bob = Wallet::new(2);
    let mut rpc = Rpc::new(node(&alice));
    assert_eq!(
        ok(&mut rpc, "txpool_status", json!([])),
        json!({"pending": "0x0", "queued": "0x0"})
    );
    // What a wallet does twice in a row: ask the pending count, sign, send.
    let mut hashes = Vec::new();
    for expected in ["0x0", "0x1"] {
        let nonce = count(&mut rpc, &alice.address, "pending");
        assert_eq!(nonce, json!(expected));
        let n = u64::from_str_radix(&expected[2..], 16).unwrap();
        let raw = alice.transfer(n, bob.address, ETHER, 21_000);
        assert_eq!(send(&mut rpc, &raw), json!(data(&keccak256(&raw))));
        hashes.push(keccak256(&raw));
    }
    assert_eq!(count(&mut rpc, &alice.address, "latest"), json!("0x0"));
    assert_eq!(count(&mut rpc, &alice.address, "pending"), json!("0x2"));
    assert_eq!(count(&mut rpc, &bob.address, "pending"), json!("0x0"));
    // A gapped nonce waits, queued.
    let gapped = alice.transfer(5, bob.address, ETHER, 21_000);
    send(&mut rpc, &gapped);
    assert_eq!(
        ok(&mut rpc, "txpool_status", json!([])),
        json!({"pending": "0x2", "queued": "0x1"})
    );
    assert_eq!(count(&mut rpc, &alice.address, "pending"), json!("0x2"));
    let content = ok(&mut rpc, "txpool_content", json!([]));
    let key = checksum(&alice.address);
    let pending = &content["pending"][&key];
    assert_eq!(pending.as_object().unwrap().len(), 2);
    assert_eq!(pending["1"]["hash"], json!(data(&hashes[1])));
    assert_eq!(pending["0"]["from"], json!(data(&alice.address)));
    assert_eq!(pending["0"]["blockHash"], Value::Null);
    assert_eq!(
        content["queued"][&key]["5"]["hash"],
        json!(data(&keccak256(&gapped)))
    );
    let pending_tx = ok(
        &mut rpc,
        "eth_getTransactionByHash",
        json!([data(&hashes[0])]),
    );
    assert_eq!(pending_tx["from"], json!(data(&alice.address)));
    // The same nonce at the same price is no replacement.
    let (code, message) = err(
        &mut rpc,
        "eth_sendRawTransaction",
        json!([data(&alice.transfer(0, bob.address, 2 * ETHER, 21_000))]),
    );
    assert_eq!(
        (code, message.as_str()),
        (-32000, "replacement transaction underpriced")
    );
    // One slot: both land, in order.
    rpc.node_mut().tick(1_000 + SLOT_MS).unwrap();
    for (index, hash) in hashes.iter().enumerate() {
        let receipt = ok(&mut rpc, "eth_getTransactionReceipt", json!([data(hash)]));
        assert_eq!(receipt["blockNumber"], json!("0x1"));
        assert_eq!(receipt["transactionIndex"], json!(format!("{index:#x}")));
        assert_eq!(receipt["status"], json!("0x1"));
    }
    assert_eq!(count(&mut rpc, &alice.address, "latest"), json!("0x2"));
    assert_eq!(count(&mut rpc, &alice.address, "pending"), json!("0x2"));
    assert_eq!(
        ok(&mut rpc, "txpool_status", json!([])),
        json!({"pending": "0x0", "queued": "0x1"})
    );
}

#[test]
fn a_full_pool_says_so() {
    let alice = Wallet::new(1);
    let bob = Wallet::new(2);
    let mut rpc = Rpc::new(node(&alice));
    rpc.node_mut().set_mempool_limits(PoolLimits {
        max_txs: 1,
        ..PoolLimits::default()
    });
    send(&mut rpc, &alice.transfer(0, bob.address, ETHER, 21_000));
    let (code, message) = err(
        &mut rpc,
        "eth_sendRawTransaction",
        json!([data(&alice.transfer(1, bob.address, ETHER, 21_000))]),
    );
    assert_eq!((code, message.as_str()), (-32000, "txpool is full"));
}
