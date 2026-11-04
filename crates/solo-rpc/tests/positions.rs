//! The execution API's smaller methods that standard clients call (spec 20
//! §8.2): transactions by block and index, transaction and uncle counts,
//! `web3_sha3`, `net_listening`, `net_peerCount`, `eth_blobBaseFee`, and the
//! answer to a subscription over HTTP (§8.1).

mod common;

use common::{SLOT_MS, Wallet, err, node, ok};
use serde_json::json;
use solo_host::hash::keccak256;
use solo_rpc::Rpc;
use solo_rpc::methods::data;

#[test]
#[allow(clippy::too_many_lines)]
fn transactions_by_block_and_index() {
    let alice = Wallet::new(1);
    let mut rpc = Rpc::new(node(&alice));
    let bob = [2; 20];
    let first = ok(
        &mut rpc,
        "eth_sendRawTransaction",
        json!([data(&alice.transfer(0, bob, 1, 21_000))]),
    );
    let second = ok(
        &mut rpc,
        "eth_sendRawTransaction",
        json!([data(&alice.transfer(1, bob, 1, 21_000))]),
    );
    rpc.node_mut().tick(1_000 + SLOT_MS).unwrap();
    let block = ok(&mut rpc, "eth_getBlockByNumber", json!(["0x1", false]));
    assert_eq!(block["transactions"], json!([first, second]));
    let hash = block["hash"].clone();

    for (method, block) in [
        ("eth_getBlockTransactionCountByNumber", json!("0x1")),
        ("eth_getBlockTransactionCountByNumber", json!("latest")),
        ("eth_getBlockTransactionCountByHash", hash.clone()),
    ] {
        assert_eq!(ok(&mut rpc, method, json!([block])), "0x2", "{method}");
    }
    assert_eq!(
        ok(
            &mut rpc,
            "eth_getBlockTransactionCountByNumber",
            json!(["earliest"])
        ),
        "0x0",
        "the genesis block has none"
    );
    assert_eq!(
        ok(
            &mut rpc,
            "eth_getBlockTransactionCountByNumber",
            json!(["0x9"])
        ),
        json!(null)
    );
    assert_eq!(
        ok(
            &mut rpc,
            "eth_getBlockTransactionCountByHash",
            json!([data(&[7; 32])])
        ),
        json!(null)
    );

    let by_hash = ok(&mut rpc, "eth_getTransactionByHash", json!([second]));
    assert_eq!(by_hash["transactionIndex"], "0x1");
    assert_eq!(
        ok(
            &mut rpc,
            "eth_getTransactionByBlockNumberAndIndex",
            json!(["0x1", "0x1"])
        ),
        by_hash
    );
    assert_eq!(
        ok(
            &mut rpc,
            "eth_getTransactionByBlockHashAndIndex",
            json!([hash, "0x1"])
        ),
        by_hash
    );
    assert_eq!(
        ok(
            &mut rpc,
            "eth_getTransactionByBlockNumberAndIndex",
            json!(["0x1", "0x0"])
        )["hash"],
        first
    );
    for params in [
        json!(["0x1", "0x2"]),
        json!(["0x9", "0x0"]),
        json!(["0x1", "0xffffffffffffffff"]),
    ] {
        assert_eq!(
            ok(&mut rpc, "eth_getTransactionByBlockNumberAndIndex", params),
            json!(null)
        );
    }
    assert_eq!(
        err(
            &mut rpc,
            "eth_getTransactionByBlockNumberAndIndex",
            json!(["0x1"])
        )
        .0,
        -32602
    );
    assert_eq!(
        err(
            &mut rpc,
            "eth_getTransactionByBlockHashAndIndex",
            json!(["0x01", "0x0"])
        )
        .0,
        -32602
    );

    // A post-merge block has no uncles.
    assert_eq!(
        ok(&mut rpc, "eth_getUncleCountByBlockNumber", json!(["0x1"])),
        "0x0"
    );
    assert_eq!(
        ok(&mut rpc, "eth_getUncleCountByBlockHash", json!([hash])),
        "0x0"
    );
    assert_eq!(
        ok(&mut rpc, "eth_getUncleCountByBlockNumber", json!(["0x9"])),
        json!(null)
    );
    for method in [
        "eth_getUncleByBlockNumberAndIndex",
        "eth_getUncleByBlockHashAndIndex",
    ] {
        assert_eq!(ok(&mut rpc, method, json!(["0x1", "0x0"])), json!(null));
    }
    assert_eq!(
        err(&mut rpc, "eth_getUncleCountByBlockNumber", json!([])).0,
        -32602
    );
}

#[test]
fn small_methods_answer_as_geth() {
    let alice = Wallet::new(1);
    let mut rpc = Rpc::new(node(&alice));
    assert_eq!(
        ok(&mut rpc, "web3_sha3", json!(["0x68656c6c6f"])),
        data(&keccak256(b"hello"))
    );
    assert_eq!(err(&mut rpc, "web3_sha3", json!(["hello"])).0, -32602);
    assert_eq!(ok(&mut rpc, "net_listening", json!([])), true);
    assert_eq!(
        ok(&mut rpc, "net_peerCount", json!([])),
        "0x0",
        "no transport"
    );
    assert_eq!(ok(&mut rpc, "eth_blobBaseFee", json!([])), "0x1");
    for method in ["eth_subscribe", "eth_unsubscribe"] {
        assert_eq!(
            err(&mut rpc, method, json!(["newHeads"])),
            (-32601, "notifications not supported".into()),
            "{method}"
        );
    }
}
