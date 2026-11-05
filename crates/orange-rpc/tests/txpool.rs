//! The mempool through JSON-RPC (spec 14): consecutive sends from one
//! account before a block, the `pending` transaction count, geth's pool
//! errors, and the `txpool` namespace.

mod common;

use common::{ETHER, SLOT_MS, Wallet, err, node, ok};
use orange_host::hash::keccak256;
use orange_node::PoolLimits;
use orange_rpc::Rpc;
use orange_rpc::methods::data;
use orange_rpc::txpool::checksum;
use serde_json::{Value, json};

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
        let bytes = orange_rpc::methods::parse_address(&address.to_lowercase()).unwrap();
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

/// `txpool_content` and a batch's answers stop at 25 MB of JSON, as geth's
/// batches do (spec 20 §8.6). Before, a pool of large transactions was
/// answered whole, and a batch of 1 000 `txpool_content` built a thousand
/// copies of it.
#[test]
fn large_answers_are_refused() {
    assert_eq!(orange_rpc::methods::MAX_RESPONSE_BYTES, 25_000_000);
    let (alice, bob) = (Wallet::new(1), Wallet::new(2));
    let mut rpc = Rpc::new(common::node_funding(&[&alice, &bob]));
    assert_eq!(rpc.max_response_bytes, 25_000_000);
    // 110 transactions of 120 000 bytes of calldata: over 26 MB as JSON,
    // from two senders, each within the pool's gas per sender (spec 14 §4).
    let input = vec![0; 120_000];
    for wallet in [&alice, &bob] {
        for nonce in 0..55 {
            let raw = wallet.legacy(&common::Fields {
                nonce,
                to: Some([7; 20]),
                value: 0,
                gas_limit: 1_300_000,
                data: &input,
            });
            send(&mut rpc, &raw);
        }
    }
    let too_large = (-32003, "response too large".to_owned());
    assert_eq!(err(&mut rpc, "txpool_content", json!([])), too_large);
    // Under a larger limit it is answered, and a batch stops after the
    // answer that passes the limit.
    rpc.max_response_bytes = 30_000_000;
    let content = ok(&mut rpc, "txpool_content", json!([]));
    for wallet in [&alice, &bob] {
        let key = checksum(&wallet.address);
        assert_eq!(content["pending"][&key].as_object().unwrap().len(), 55);
    }
    rpc.max_response_bytes = 1_000;
    let r = rpc.handle_body(
        r#"[{"id":1,"method":"eth_chainId"},{"id":2,"method":"txpool_content"},{"id":3,"method":"eth_chainId"},{"method":"eth_chainId"}]"#,
    );
    assert_eq!(r[0]["result"], json!("0x539"));
    assert_eq!(r[1]["error"]["code"], json!(-32003), "past its own limit");
    assert_eq!(r[2]["result"], json!("0x539"), "errors are small");
    rpc.max_response_bytes = 30;
    let r = rpc.handle_body(
        r#"[{"id":1,"method":"eth_chainId"},{"id":2,"method":"eth_chainId"},{"method":"eth_chainId"}]"#,
    );
    assert_eq!(
        r[0]["result"],
        json!("0x539"),
        "the answer that passes is kept"
    );
    let refused = json!({ "code": -32003, "message": "response too large" });
    assert_eq!(r[1], json!({ "jsonrpc": "2.0", "id": 2, "error": refused }));
    assert_eq!(r[2]["id"], Value::Null);
    assert_eq!(r[2]["error"], refused);
}
