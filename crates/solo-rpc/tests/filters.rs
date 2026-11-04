//! The polled filters of spec 20 §8.1: `eth_newFilter`, `eth_newBlockFilter`,
//! `eth_newPendingTransactionFilter`, `eth_getFilterChanges`,
//! `eth_getFilterLogs` and `eth_uninstallFilter`, the methods ethers'
//! `contract.on` and viem's `watchContractEvent` and `createBlockFilter`
//! poll over HTTP.

mod common;

use std::time::Duration;

use common::{Fields, SLOT_MS, Wallet, calldata, counter_initcode, created_address, err, node, ok};
use serde_json::{Value, json};
use solo_host::hash::keccak256;
use solo_rpc::Rpc;
use solo_rpc::filters::{FILTER_TIMEOUT, MAX_FILTERS};
use solo_rpc::methods::data;

fn mine(rpc: &mut Rpc) {
    let height = rpc.node_mut().block_number().unwrap();
    rpc.node_mut().tick(1_000 + (height + 1) * SLOT_MS).unwrap();
}

fn send(rpc: &mut Rpc, raw: &[u8]) -> String {
    ok(rpc, "eth_sendRawTransaction", json!([data(raw)]))
        .as_str()
        .unwrap()
        .to_owned()
}

/// `increment(delta)` on the counter from `alice` at `nonce`.
fn increment(alice: &Wallet, counter: [u8; 20], nonce: u64, delta: u64) -> Vec<u8> {
    let input = calldata("increment(uint256)", &[delta]);
    alice.legacy(&Fields {
        nonce,
        to: Some(counter),
        value: 0,
        gas_limit: 100_000,
        data: &input,
    })
}

/// A node with the counter deployed in block 1.
fn deployed(alice: &Wallet) -> (Rpc, [u8; 20]) {
    let mut rpc = Rpc::new(node(alice));
    let initcode = counter_initcode(5);
    send(
        &mut rpc,
        &alice.legacy(&Fields {
            nonce: 0,
            to: None,
            value: 0,
            gas_limit: 1_000_000,
            data: &initcode,
        }),
    );
    mine(&mut rpc);
    (rpc, created_address(&alice.address, 0))
}

fn changes(rpc: &mut Rpc, id: &Value) -> Value {
    ok(rpc, "eth_getFilterChanges", json!([id]))
}

fn block_hash(rpc: &mut Rpc, height: u64) -> Value {
    ok(
        rpc,
        "eth_getBlockByNumber",
        json!([format!("{height:#x}"), false]),
    )["hash"]
        .clone()
}

#[test]
fn defaults_follow_geth() {
    assert_eq!(FILTER_TIMEOUT, Duration::from_mins(5));
    assert_eq!(MAX_FILTERS, 1024);
    let alice = Wallet::new(1);
    let rpc = Rpc::new(node(&alice));
    assert_eq!(rpc.filter_timeout, FILTER_TIMEOUT);
    assert_eq!(rpc.max_filters, MAX_FILTERS);
}

#[test]
fn log_filters_report_new_logs_once() {
    let alice = Wallet::new(1);
    let (mut rpc, counter) = deployed(&alice);
    let c = data(&counter);
    let incremented = data(&keccak256(b"Incremented(address,uint256,uint256)"));

    let all = ok(&mut rpc, "eth_newFilter", json!([{ "address": c }]));
    let from_one = ok(
        &mut rpc,
        "eth_newFilter",
        json!([{ "address": c, "fromBlock": "0x1", "topics": [incremented] }]),
    );
    let other = ok(
        &mut rpc,
        "eth_newFilter",
        json!([{ "address": data(&[9; 20]) }]),
    );
    let id = all.as_str().unwrap();
    assert_eq!(id.len(), 34, "16 bytes, as geth's ids");
    assert_ne!(all, from_one);
    assert_eq!(
        changes(&mut rpc, &all),
        json!([]),
        "the deployment came before"
    );

    send(&mut rpc, &increment(&alice, counter, 1, 2));
    assert_eq!(changes(&mut rpc, &all), json!([]), "not mined yet");
    mine(&mut rpc);
    send(&mut rpc, &increment(&alice, counter, 2, 3));
    mine(&mut rpc);
    let logs = ok(&mut rpc, "eth_getLogs", json!([{ "fromBlock": "0x2" }]));
    assert_eq!(logs.as_array().unwrap().len(), 2);
    assert_eq!(changes(&mut rpc, &all), logs);
    assert_eq!(
        changes(&mut rpc, &all),
        json!([]),
        "each log is reported once"
    );
    assert_eq!(changes(&mut rpc, &from_one), logs);
    assert_eq!(changes(&mut rpc, &other), json!([]));

    // `eth_getFilterLogs` answers the whole range, as `eth_getLogs` would.
    assert_eq!(ok(&mut rpc, "eth_getFilterLogs", json!([from_one])), logs);
    assert_eq!(
        ok(&mut rpc, "eth_getFilterLogs", json!([all])),
        json!([logs[1]]),
        "no range is the latest block"
    );
}

#[test]
fn log_filters_keep_their_block_bounds() {
    let alice = Wallet::new(1);
    let (mut rpc, counter) = deployed(&alice);
    let c = data(&counter);
    // Bounded to blocks that come and go before the next poll, to blocks
    // not made yet, and to the past.
    let to_two = ok(
        &mut rpc,
        "eth_newFilter",
        json!([{ "address": c, "fromBlock": "earliest", "toBlock": "0x2" }]),
    );
    let from_three = ok(
        &mut rpc,
        "eth_newFilter",
        json!([{ "address": c, "fromBlock": "0x3", "toBlock": "pending" }]),
    );
    let past = ok(
        &mut rpc,
        "eth_newFilter",
        json!([{ "fromBlock": "0x1", "toBlock": "0x1" }]),
    );
    for nonce in 1..=3 {
        send(&mut rpc, &increment(&alice, counter, nonce, 1));
        mine(&mut rpc);
    }
    let in_block = |rpc: &mut Rpc, height: u64| {
        ok(
            rpc,
            "eth_getLogs",
            json!([{ "fromBlock": format!("{height:#x}"), "toBlock": format!("{height:#x}") }]),
        )
    };
    assert_eq!(changes(&mut rpc, &to_two), in_block(&mut rpc, 2));
    let three_on = ok(&mut rpc, "eth_getLogs", json!([{ "fromBlock": "0x3" }]));
    assert_eq!(changes(&mut rpc, &from_three), three_on);
    assert_eq!(changes(&mut rpc, &past), json!([]));

    // A filter on one block by hash has nothing new to report; its logs
    // are `eth_getFilterLogs`'.
    let hash = block_hash(&mut rpc, 2);
    let by_hash = ok(&mut rpc, "eth_newFilter", json!([{ "blockHash": hash }]));
    send(&mut rpc, &increment(&alice, counter, 4, 1));
    mine(&mut rpc);
    assert_eq!(changes(&mut rpc, &by_hash), json!([]));
    assert_eq!(
        ok(&mut rpc, "eth_getFilterLogs", json!([by_hash])),
        in_block(&mut rpc, 2)
    );

    assert_eq!(
        err(
            &mut rpc,
            "eth_newFilter",
            json!([{ "fromBlock": "0x5", "toBlock": "0x2" }])
        ),
        (-32602, "invalid block range".into())
    );
    assert_eq!(
        err(&mut rpc, "eth_newFilter", json!([{ "fromBlock": "0xzz" }])).0,
        -32602
    );
    assert_eq!(
        err(&mut rpc, "eth_newFilter", json!([{ "toBlock": "2" }])).0,
        -32602
    );
    assert_eq!(err(&mut rpc, "eth_newFilter", json!([])).0, -32602);
}

#[test]
fn block_filters_report_each_new_block() {
    let alice = Wallet::new(1);
    let mut rpc = Rpc::new(node(&alice));
    let blocks = ok(&mut rpc, "eth_newBlockFilter", json!([]));
    assert_eq!(changes(&mut rpc, &blocks), json!([]));
    mine(&mut rpc);
    mine(&mut rpc);
    let (one, two) = (block_hash(&mut rpc, 1), block_hash(&mut rpc, 2));
    assert_eq!(changes(&mut rpc, &blocks), json!([one, two]));
    assert_eq!(changes(&mut rpc, &blocks), json!([]));

    // A poll reports at most the log range; the next one the rest.
    rpc.max_log_range = 1;
    mine(&mut rpc);
    mine(&mut rpc);
    let (three, four) = (block_hash(&mut rpc, 3), block_hash(&mut rpc, 4));
    assert_eq!(changes(&mut rpc, &blocks), json!([three]));
    assert_eq!(changes(&mut rpc, &blocks), json!([four]));
    assert_eq!(changes(&mut rpc, &blocks), json!([]));
    rpc.max_log_range = 0;
    mine(&mut rpc);
    let five = block_hash(&mut rpc, 5);
    assert_eq!(changes(&mut rpc, &blocks), json!([five]));

    assert_eq!(
        err(&mut rpc, "eth_getFilterLogs", json!([blocks])),
        (-32000, "filter not found".into()),
        "only a log filter has logs"
    );
}

#[test]
fn pending_filters_report_each_transaction_once() {
    let alice = Wallet::new(1);
    let mut rpc = Rpc::new(node(&alice));
    let pending = ok(&mut rpc, "eth_newPendingTransactionFilter", json!([]));
    assert_eq!(changes(&mut rpc, &pending), json!([]));
    let bob = [2; 20];
    let first = send(&mut rpc, &alice.transfer(0, bob, 1, 21_000));
    assert_eq!(changes(&mut rpc, &pending), json!([first]), "from the pool");
    mine(&mut rpc);
    assert_eq!(
        changes(&mut rpc, &pending),
        json!([]),
        "mined, seen already"
    );
    // One that is mined before the next poll is still reported, from its
    // block.
    let second = send(&mut rpc, &alice.transfer(1, bob, 1, 21_000));
    mine(&mut rpc);
    let third = send(&mut rpc, &alice.transfer(2, bob, 1, 21_000));
    assert_eq!(changes(&mut rpc, &pending), json!([second, third]));
    assert_eq!(changes(&mut rpc, &pending), json!([]));
}

#[test]
fn filters_are_removed_expire_and_are_bounded() {
    let alice = Wallet::new(1);
    let mut rpc = Rpc::new(node(&alice));
    let blocks = ok(&mut rpc, "eth_newBlockFilter", json!([]));
    assert_eq!(ok(&mut rpc, "eth_uninstallFilter", json!([blocks])), true);
    assert_eq!(ok(&mut rpc, "eth_uninstallFilter", json!([blocks])), false);
    let not_found = (-32000, "filter not found".to_owned());
    assert_eq!(
        err(&mut rpc, "eth_getFilterChanges", json!([blocks])),
        not_found
    );
    assert_eq!(
        err(&mut rpc, "eth_getFilterLogs", json!([blocks])),
        not_found
    );
    for method in [
        "eth_getFilterChanges",
        "eth_getFilterLogs",
        "eth_uninstallFilter",
    ] {
        assert_eq!(err(&mut rpc, method, json!([])).0, -32602, "{method}");
    }

    rpc.max_filters = 1;
    let kept = ok(&mut rpc, "eth_newPendingTransactionFilter", json!([]));
    assert_eq!(
        err(&mut rpc, "eth_newBlockFilter", json!([])),
        (-32000, "too many filters installed, the limit is 1".into())
    );
    // A filter not polled within the timeout is gone, and makes room.
    rpc.filter_timeout = Duration::ZERO;
    assert_eq!(
        err(&mut rpc, "eth_getFilterChanges", json!([kept])),
        not_found
    );
    rpc.filter_timeout = FILTER_TIMEOUT;
    let log_filter = ok(&mut rpc, "eth_newFilter", json!([{}]));
    // Polling keeps a filter alive: changes and logs both count.
    assert_eq!(changes(&mut rpc, &log_filter), json!([]));
    assert_eq!(
        ok(&mut rpc, "eth_getFilterLogs", json!([log_filter])),
        json!([])
    );
    assert_eq!(
        ok(&mut rpc, "eth_uninstallFilter", json!([log_filter])),
        true
    );
}
