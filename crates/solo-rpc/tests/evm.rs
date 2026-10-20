//! JSON-RPC over the EVM: the test contract (`solo-node/tests/fixtures/Counter.sol`)
//! deployed and exercised through the node with every transaction type,
//! `eth_call`, gas estimation, code and storage, receipts and logs, log
//! filters, fee history, and the errors of each.

mod common;

use common::{
    COUNTER_RUNTIME, ETHER, Fields, GAS_PRICE, SLOT_MS, Wallet, call, calldata, calldata_string,
    counter_initcode, created_address, err, hex, node_funding, ok, selector, word,
};
use serde_json::{Value, json};
use solo_abi::Encode;
use solo_abi::chain::{BlockHeader, CallResult, call_status};
use solo_abi::codec::Seq;
use solo_abi::types::{Block, Effect};
use solo_host::hash::keccak256;
use solo_rpc::Rpc;
use solo_rpc::call::{call_error, revert_reason};
use solo_rpc::methods::{data, parse_quantity, quantity};

const GWEI: u128 = 1_000_000_000;

/// Produces the next block.
fn mine(rpc: &mut Rpc) {
    let height = rpc.node_mut().block_number().unwrap();
    rpc.node_mut().tick(1_000 + (height + 1) * SLOT_MS).unwrap();
}

/// Sends a raw transaction and returns its hash.
fn send(rpc: &mut Rpc, raw: &[u8]) -> String {
    let hash = ok(rpc, "eth_sendRawTransaction", json!([data(raw)]));
    assert_eq!(hash, data(&keccak256(raw)));
    hash.as_str().unwrap().to_owned()
}

/// Deploys Counter(`start`) from `wallet` at `nonce` in a block of its own.
fn deploy(rpc: &mut Rpc, wallet: &Wallet, nonce: u64, start: u64) -> [u8; 20] {
    let initcode = counter_initcode(start);
    let creation = Fields {
        nonce,
        to: None,
        value: 0,
        gas_limit: 1_000_000,
        data: &initcode,
    };
    let hash = send(rpc, &wallet.legacy(&creation));
    mine(rpc);
    let receipt = ok(rpc, "eth_getTransactionReceipt", json!([hash]));
    assert_eq!(receipt["status"], "0x1");
    created_address(&wallet.address, nonce)
}

/// A call object to the contract.
fn to(contract: &[u8; 20], input: &[u8]) -> Value {
    json!({ "to": data(contract), "input": data(input) })
}

/// An address as an indexed topic.
fn topic(address: &[u8; 20]) -> String {
    let mut out = [0u8; 32];
    out[12..].copy_from_slice(address);
    data(&out)
}

fn quantity_of(v: &Value) -> u64 {
    parse_quantity(v.as_str().unwrap()).unwrap()
}

#[test]
#[allow(clippy::too_many_lines)]
fn deploy_code_storage_and_calls() {
    let alice = Wallet::new(1);
    let bob = Wallet::new(2);
    let mut rpc = Rpc::new(node_funding(&[&alice, &bob]));
    let initcode = counter_initcode(5);
    let creation = Fields {
        nonce: 0,
        to: None,
        value: 0,
        gas_limit: 1_000_000,
        data: &initcode,
    };
    let hash = send(&mut rpc, &alice.legacy(&creation));
    mine(&mut rpc);
    let counter = created_address(&alice.address, 0);
    let receipt = ok(&mut rpc, "eth_getTransactionReceipt", json!([hash]));
    assert_eq!(receipt["status"], "0x1");
    assert_eq!(receipt["contractAddress"], data(&counter));
    assert_eq!(receipt["to"], Value::Null);
    assert_eq!(receipt["logs"], json!([]));
    let tx = ok(&mut rpc, "eth_getTransactionByHash", json!([hash]));
    assert_eq!(tx["to"], Value::Null);
    assert_eq!(tx["input"], data(&initcode));
    let block_hash = receipt["blockHash"].as_str().unwrap().to_owned();

    // Code and storage, with every form of block parameter.
    let runtime = data(&hex(COUNTER_RUNTIME));
    let c = data(&counter);
    assert_eq!(ok(&mut rpc, "eth_getCode", json!([c, "latest"])), runtime);
    assert_eq!(ok(&mut rpc, "eth_getCode", json!([c])), runtime);
    assert_eq!(ok(&mut rpc, "eth_getCode", json!([c, null])), runtime);
    assert_eq!(
        err(&mut rpc, "eth_getCode", json!([c, "earliest"])),
        (
            -32000,
            "historical state not available: block 0, the node keeps the state of block 1 only"
                .into()
        )
    );
    assert_eq!(ok(&mut rpc, "eth_getCode", json!([c, "0x1"])), runtime);
    assert_eq!(ok(&mut rpc, "eth_getCode", json!([c, "safe"])), runtime);
    assert_eq!(
        ok(
            &mut rpc,
            "eth_getCode",
            json!([c, { "blockHash": block_hash }])
        ),
        runtime
    );
    assert_eq!(
        ok(
            &mut rpc,
            "eth_getCode",
            json!([c, { "blockNumber": "0x1" }])
        ),
        runtime
    );
    assert_eq!(ok(&mut rpc, "eth_getCode", json!([c, {}])), runtime);
    assert_eq!(ok(&mut rpc, "eth_getCode", json!([c, block_hash])), runtime);
    assert_eq!(
        err(&mut rpc, "eth_getCode", json!([c, data(&[9; 32])])).1,
        "header for hash not found"
    );
    assert_eq!(
        ok(&mut rpc, "eth_getCode", json!([data(&alice.address)])),
        "0x"
    );
    assert_eq!(
        err(&mut rpc, "eth_getCode", json!([c, "0x2"])),
        (-32000, "header not found".into())
    );
    assert_eq!(
        err(
            &mut rpc,
            "eth_getCode",
            json!([c, { "blockHash": data(&[9; 32]) }])
        ),
        (-32000, "header for hash not found".into())
    );
    assert_eq!(
        err(&mut rpc, "eth_getCode", json!([c, 1])).0,
        -32602,
        "a bare number is not a block parameter"
    );
    assert_eq!(
        err(&mut rpc, "eth_getCode", json!([c, { "blockHash": 1 }])).0,
        -32602
    );
    assert_eq!(
        ok(&mut rpc, "eth_getStorageAt", json!([c, "0x0", "latest"])),
        data(&word(5))
    );
    let owner = ok(&mut rpc, "eth_getStorageAt", json!([c, data(&word(1))]));
    assert_eq!(owner, topic(&alice.address));
    assert_eq!(
        ok(&mut rpc, "eth_getStorageAt", json!([c, "0x02"])),
        data(&[0; 32])
    );
    assert_eq!(
        err(&mut rpc, "eth_getStorageAt", json!([c, "0x0", "0x7"])).1,
        "header not found"
    );

    // eth_call: return data, and each way a message fails.
    let count = calldata("count()", &[]);
    assert_eq!(
        ok(
            &mut rpc,
            "eth_call",
            json!([to(&counter, &count), "latest"])
        ),
        data(&word(5))
    );
    let same = json!({ "to": c, "data": data(&count), "input": data(&count) });
    assert_eq!(ok(&mut rpc, "eth_call", json!([same])), data(&word(5)));
    let legacy_field = json!({ "to": c, "data": data(&count), "gasPrice": "0x1" });
    assert_eq!(
        ok(&mut rpc, "eth_call", json!([legacy_field])),
        data(&word(5))
    );
    let fail = calldata_string("fail(string)", "nope");
    let (code, message, revert) =
        call(&mut rpc, "eth_call", json!([to(&counter, &fail)])).unwrap_err();
    assert_eq!((code, message.as_str()), (3, "execution reverted: nope"));
    let mut expected = selector("Error(string)");
    expected.extend_from_slice(&calldata_string("x()", "nope")[4..]);
    assert_eq!(revert, data(&expected));
    let divide = calldata("divide(uint256,uint256)", &[1, 0]);
    let (code, message, _) =
        call(&mut rpc, "eth_call", json!([to(&counter, &divide)])).unwrap_err();
    assert_eq!(
        (code, message.as_str()),
        (3, "execution reverted: division or modulo by zero")
    );
    assert_eq!(
        ok(
            &mut rpc,
            "eth_call",
            json!([to(&counter, &calldata("divide(uint256,uint256)", &[9, 3]))])
        ),
        data(&word(3))
    );
    // A custom error: no reason, the data carries it.
    let guarded =
        json!({ "from": data(&bob.address), "to": c, "input": data(&selector("guarded()")) });
    let (code, message, revert) = call(&mut rpc, "eth_call", json!([guarded])).unwrap_err();
    assert_eq!((code, message.as_str()), (3, "execution reverted"));
    let mut not_owner = selector("NotOwner(address)");
    not_owner.extend_from_slice(&hex(&topic(&bob.address)[2..]));
    assert_eq!(revert, data(&not_owner));
    let owner_call =
        json!({ "from": data(&alice.address), "to": c, "input": data(&selector("guarded()")) });
    assert_eq!(
        ok(&mut rpc, "eth_call", json!([owner_call])),
        topic(&alice.address)
    );
    let (code, message, revert) = call(
        &mut rpc,
        "eth_call",
        json!([to(&counter, &selector("halt()"))]),
    )
    .unwrap_err();
    assert_eq!(code, -32000);
    assert!(message.starts_with("execution halted"), "{message}");
    assert_eq!(revert, Value::Null);
    // A contract can be the sender of a call, as in geth's `eth_call`: EIP-3607
    // applies to transactions only.
    let from_contract = json!({ "from": c, "to": data(&bob.address) });
    assert_eq!(ok(&mut rpc, "eth_call", json!([from_contract])), "0x");
    // A sender that cannot pay the value the call carries is refused, not run.
    let poor = Wallet::new(9);
    let unfunded = json!({ "from": data(&poor.address), "to": data(&bob.address), "value": "0x1" });
    assert_eq!(
        err(&mut rpc, "eth_call", json!([unfunded])),
        (
            -32000,
            format!(
                "insufficient funds for gas * price + value: address {} have 0 want 1",
                data(&poor.address)
            )
        )
    );
    let low = json!({ "to": c, "input": data(&count), "gas": "0x5208" });
    assert_eq!(
        err(&mut rpc, "eth_call", json!([low])),
        (
            -32000,
            "intrinsic gas too low: gas 21000, minimum needed 21160".into()
        )
    );
    let rich = json!({ "from": data(&bob.address), "to": c, "value": quantity(1_000 * ETHER) });
    let (code, message) = err(&mut rpc, "eth_call", json!([rich]));
    assert_eq!(code, -32000);
    assert_eq!(
        message,
        format!(
            "insufficient funds for gas * price + value: address {} have {} want {}",
            data(&bob.address),
            100 * ETHER,
            1_000 * ETHER
        )
    );
    let huge = json!({ "input": data(&vec![0u8; 49_153]) });
    assert_eq!(
        err(&mut rpc, "eth_call", json!([huge])).1,
        "max initcode size exceeded: code size 49153, limit 49152"
    );
    // Value the sender can pay, to an account without code.
    let pay = json!({ "from": data(&alice.address), "to": data(&bob.address), "value": "0x1" });
    assert_eq!(ok(&mut rpc, "eth_call", json!([pay])), "0x");
    // A creation runs the initcode and returns the code it would deploy.
    let create = json!({ "from": data(&alice.address), "input": data(&initcode) });
    assert_eq!(ok(&mut rpc, "eth_call", json!([create])), runtime);
    // Parameter errors.
    let differ = json!({ "to": c, "data": "0x01", "input": "0x02" });
    let bad: [Value; 6] = [
        json!([]),
        json!(["0x"]),
        json!([differ]),
        json!([{ "to": c, "gas": 5 }]),
        json!([{ "to": "0x12" }]),
        json!([{ "to": c }, "0xzz"]),
    ];
    for params in bad {
        assert_eq!(
            err(&mut rpc, "eth_call", params.clone()).0,
            -32602,
            "{params}"
        );
    }
    assert_eq!(err(&mut rpc, "eth_estimateGas", json!([])).0, -32602);
    assert_eq!(
        err(&mut rpc, "eth_estimateGas", json!([{}, "0x9"])).1,
        "header not found"
    );

    // A creation that reverts (PUSH1 0 PUSH1 0 REVERT) still names the
    // address it would have deployed to, as geth's receipts do.
    let reverting = Fields {
        nonce: 0,
        to: None,
        value: 0,
        gas_limit: 100_000,
        data: &hex("60006000fd"),
    };
    let hash = send(&mut rpc, &bob.legacy(&reverting));
    mine(&mut rpc);
    let receipt = ok(&mut rpc, "eth_getTransactionReceipt", json!([hash]));
    assert_eq!(receipt["status"], "0x0");
    assert_eq!(receipt["to"], Value::Null);
    assert_eq!(
        receipt["contractAddress"],
        data(&created_address(&bob.address, 0))
    );
    assert_eq!(
        ok(&mut rpc, "eth_getBlockReceipts", json!(["latest"])),
        json!([receipt])
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn state_at_the_head_only() {
    let alice = Wallet::new(1);
    let mut rpc = Rpc::new(node_funding(&[&alice]));
    let counter = deploy(&mut rpc, &alice, 0, 5);
    let first = ok(&mut rpc, "eth_getBlockByNumber", json!(["0x1"]))["hash"].clone();
    mine(&mut rpc);
    let head = ok(&mut rpc, "eth_getBlockByNumber", json!(["latest"]));
    let head_hash = head["hash"].clone();
    let a = data(&alice.address);
    let c = data(&counter);
    let count = to(&counter, &calldata("count()", &[]));
    // Every state method answers for every name of the head, and refuses
    // older blocks instead of answering from the head's state.
    let methods = [
        ("eth_getBalance", json!([a])),
        ("eth_getTransactionCount", json!([a])),
        ("eth_getCode", json!([c])),
        ("eth_getStorageAt", json!([c, "0x0"])),
        ("eth_call", json!([count])),
        ("eth_estimateGas", json!([count])),
    ];
    let heads = [
        json!("latest"),
        json!("pending"),
        json!("safe"),
        json!("finalized"),
        json!("0x2"),
        head_hash.clone(),
        json!({ "blockHash": head_hash }),
        json!({ "blockNumber": "0x2" }),
        json!({}),
    ];
    let older = [
        json!("0x1"),
        first.clone(),
        json!({ "blockHash": first }),
        json!({ "blockNumber": "0x1" }),
    ];
    let historical = |height: u64| {
        (
            -32000,
            format!(
                "historical state not available: block {height}, the node keeps the state of block 2 only"
            ),
        )
    };
    for (method, params) in methods {
        let at = |block: &Value| {
            let mut list = params.as_array().unwrap().clone();
            list.push(block.clone());
            Value::Array(list)
        };
        let answer = ok(&mut rpc, method, params.clone());
        for block in &heads {
            assert_eq!(ok(&mut rpc, method, at(block)), answer, "{method} {block}");
        }
        for block in &older {
            assert_eq!(
                err(&mut rpc, method, at(block)),
                historical(1),
                "{method} {block}"
            );
        }
        assert_eq!(err(&mut rpc, method, at(&json!("earliest"))), historical(0));
        assert_eq!(
            err(&mut rpc, method, at(&json!("0x3"))),
            (-32000, "header not found".into())
        );
    }
    // A call runs in the head block, as geth's `latest`: NUMBER and
    // TIMESTAMP (each followed by PUSH1 0 MSTORE PUSH1 32 PUSH1 0 RETURN)
    // describe the same block.
    let number = json!({ "input": "0x4360005260206000f3" });
    assert_eq!(ok(&mut rpc, "eth_call", json!([number])), data(&word(2)));
    let timestamp = json!({ "input": "0x4260005260206000f3" });
    assert_eq!(
        ok(&mut rpc, "eth_call", json!([timestamp])),
        data(&word(quantity_of(&head["timestamp"])))
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn access_lists_in_calls_and_estimates() {
    let alice = Wallet::new(1);
    let bob = Wallet::new(2);
    let mut rpc = Rpc::new(node_funding(&[&alice, &bob]));
    let counter = deploy(&mut rpc, &alice, 0, 5);
    let a = data(&alice.address);
    let b = data(&bob.address);
    let c = data(&counter);
    let other = [0xde; 20];
    let access = [(other, vec![word(1)])];
    let list = json!([{ "address": data(&other), "storageKeys": [data(&word(1))] }]);

    // An entry the message never touches costs its intrinsic gas, 2400 for
    // the account and 1900 for the key, and the estimate includes it.
    let pay = json!({ "from": b, "to": a, "value": "0x1", "type": "0x1", "accessList": list });
    assert_eq!(
        ok(&mut rpc, "eth_estimateGas", json!([pay])),
        quantity(21_000 + 2_400 + 1_900)
    );
    let inc = calldata("increment(uint256)", &[2]);
    let plain = quantity_of(&ok(
        &mut rpc,
        "eth_estimateGas",
        json!([{ "from": a, "to": c, "input": data(&inc) }]),
    ));
    let listed = json!({ "from": a, "to": c, "input": data(&inc), "accessList": list });
    let estimate = quantity_of(&ok(&mut rpc, "eth_estimateGas", json!([listed])));
    assert_eq!(estimate, plain + 2_400 + 1_900);
    // Transactions sent with those lists and estimates succeed, using
    // exactly the estimate.
    let transfer = bob.access_list_tx(
        &Fields {
            nonce: 0,
            to: Some(alice.address),
            value: 1,
            gas_limit: 25_300,
            data: &[],
        },
        &access,
    );
    let increment = alice.access_list_tx(
        &Fields {
            nonce: 1,
            to: Some(counter),
            value: 0,
            gas_limit: estimate,
            data: &inc,
        },
        &access,
    );
    let hashes = [send(&mut rpc, &transfer), send(&mut rpc, &increment)];
    mine(&mut rpc);
    for (hash, used) in hashes.iter().zip([25_300, estimate]) {
        let receipt = ok(&mut rpc, "eth_getTransactionReceipt", json!([hash]));
        assert_eq!(receipt["status"], "0x1", "{hash}");
        assert_eq!(quantity_of(&receipt["gasUsed"]), used, "{hash}");
    }

    // A listed slot the message reads is warm: the first read costs 100
    // instead of 2100.
    let warm = json!([{ "address": c, "storageKeys": [data(&word(0))] }]);
    let warmed = json!({ "from": a, "to": c, "input": data(&inc), "accessList": warm });
    assert_eq!(
        quantity_of(&ok(&mut rpc, "eth_estimateGas", json!([warmed]))),
        plain + 2_400 + 1_900 - 2_000
    );
    // eth_call checks the list's intrinsic gas too.
    let low = json!({ "from": a, "to": b, "gas": "0x5208", "accessList": list });
    assert_eq!(
        err(&mut rpc, "eth_call", json!([low])),
        (
            -32000,
            "intrinsic gas too low: gas 21000, minimum needed 25300".into()
        )
    );
    let none = json!({ "from": a, "to": b, "accessList": null });
    assert_eq!(ok(&mut rpc, "eth_call", json!([none])), "0x");
    let empty = json!({ "from": a, "to": b, "accessList": [] });
    assert_eq!(ok(&mut rpc, "eth_estimateGas", json!([empty])), "0x5208");
    // Lists that do not parse.
    let bad = [
        json!(5),
        json!("x"),
        json!([5]),
        json!([{ "address": a }]),
        json!([{ "storageKeys": [] }]),
        json!([{ "address": "0x12", "storageKeys": [] }]),
        json!([{ "address": a, "storageKeys": ["0x12"] }]),
        json!([{ "address": a, "storageKeys": [5] }]),
        json!([{ "address": 5, "storageKeys": [] }]),
    ];
    for list in bad {
        let object = json!({ "to": b, "accessList": list });
        assert_eq!(
            err(&mut rpc, "eth_call", json!([object])).0,
            -32602,
            "{list}"
        );
    }
}

#[test]
fn revert_reasons() {
    let error = |text: &str| {
        let mut out = selector("Error(string)");
        out.extend_from_slice(&calldata_string("x()", text)[4..]);
        out
    };
    let panic = |code: [u8; 32]| [selector("Panic(uint256)"), code.to_vec()].concat();
    assert_eq!(revert_reason(&error("no")), Some("no".into()));
    assert_eq!(revert_reason(&error("")), Some(String::new()));
    let codes = [
        (0x00, "generic panic"),
        (0x01, "assert(false)"),
        (0x11, "arithmetic underflow or overflow"),
        (0x12, "division or modulo by zero"),
        (0x21, "enum overflow"),
        (0x22, "invalid encoded storage byte array accessed"),
        (
            0x31,
            "out-of-bounds array access; popping on an empty array",
        ),
        (0x32, "out-of-bounds access of an array or bytesN"),
        (0x41, "out of memory"),
        (0x51, "uninitialized function"),
    ];
    for (code, text) in codes {
        assert_eq!(revert_reason(&panic(word(code))), Some(text.into()));
    }
    assert_eq!(
        revert_reason(&panic(word(0x99))),
        Some("unknown panic code: 0x99".into())
    );
    let mut big = [0u8; 32];
    big[0] = 1;
    big[31] = 1;
    assert_eq!(
        revert_reason(&panic(big)),
        Some(format!("unknown panic code: 0x1{}01", "0".repeat(60)))
    );
    // Too short, unknown selector, truncated or malformed payloads.
    assert_eq!(revert_reason(&[]), None);
    // What the kernel refuses to run at all, after the checks the RPC makes
    // itself, is a server error without data.
    let refused = call_error(&CallResult {
        status: call_status::INVALID,
        gas_used: 0,
        output: Vec::new(),
    });
    assert_eq!(
        (refused.code, refused.message.as_str(), refused.data),
        (
            -32000,
            "message cannot run: it fails the kernel's validation",
            None
        )
    );
    assert_eq!(revert_reason(&[0x08, 0xc3, 0x79]), None);
    assert_eq!(revert_reason(&selector("NotOwner(address)")), None);
    assert_eq!(revert_reason(&panic(word(1))[..20]), None);
    let mut truncated = error("hello");
    truncated.truncate(4 + 64 + 2);
    assert_eq!(revert_reason(&truncated), None);
    assert_eq!(revert_reason(&selector("Error(string)")), None);
    let mut far = selector("Error(string)");
    far.extend_from_slice(&[0xff; 32]);
    assert_eq!(revert_reason(&far), None, "offset beyond any length");
    let mut wrap = selector("Error(string)");
    wrap.extend_from_slice(&word(u64::MAX));
    assert_eq!(revert_reason(&wrap), None, "offset overflows");
    let mut long = selector("Error(string)");
    long.extend_from_slice(&word(32));
    long.extend_from_slice(&word(u64::MAX));
    assert_eq!(revert_reason(&long), None, "length overflows");
    let mut no_length = selector("Error(string)");
    no_length.extend_from_slice(&word(32));
    assert_eq!(revert_reason(&no_length), None);
    let mut invalid = error("ab");
    invalid[4 + 64] = 0xff;
    assert_eq!(revert_reason(&invalid), None, "not UTF-8");
}

/// The logs bloom of logs given as (address, topics).
fn bloom_of(logs: &[([u8; 20], Vec<[u8; 32]>)]) -> String {
    let entries: Vec<(&[u8; 20], &[[u8; 32]])> =
        logs.iter().map(|(a, t)| (a, t.as_slice())).collect();
    data(&solo_eth::logs_bloom(&entries, keccak256))
}

fn topics_of(log: &Value) -> Vec<[u8; 32]> {
    log["topics"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| hex(&t.as_str().unwrap()[2..]).try_into().unwrap())
        .collect()
}

#[test]
#[allow(clippy::too_many_lines)]
fn every_transaction_type_with_receipts_and_logs() {
    let alice = Wallet::new(1);
    let bob = Wallet::new(2);
    let carol = Wallet::new(3);
    let mut rpc = Rpc::new(node_funding(&[&alice, &bob, &carol]));
    let counter = deploy(&mut rpc, &alice, 0, 5);
    let c = data(&counter);
    let incremented = keccak256(b"Incremented(address,uint256,uint256)");
    let noted = keccak256(b"Noted(string)");

    // Block 2: a legacy, a dynamic-fee and an access-list transaction, each
    // emitting one log.
    let inc2 = calldata("increment(uint256)", &[2]);
    let estimate = quantity_of(&ok(
        &mut rpc,
        "eth_estimateGas",
        json!([{ "from": data(&alice.address), "to": c, "input": data(&inc2) }]),
    ));
    let legacy = alice.legacy(&Fields {
        nonce: 1,
        to: Some(counter),
        value: 0,
        gas_limit: estimate,
        data: &inc2,
    });
    let inc3 = calldata("increment(uint256)", &[3]);
    let dynamic = bob.dynamic(
        &Fields {
            nonce: 0,
            to: Some(counter),
            value: 0,
            gas_limit: 100_000,
            data: &inc3,
        },
        3 * GWEI,
        2 * GWEI,
        &[],
    );
    let note = calldata_string("note(string)", "hello");
    let typed1 = carol.access_list_tx(
        &Fields {
            nonce: 0,
            to: Some(counter),
            value: 0,
            gas_limit: 100_000,
            data: &note,
        },
        &[(counter, vec![word(0)])],
    );
    let h_legacy = send(&mut rpc, &legacy);
    let h_dynamic = send(&mut rpc, &dynamic);
    let h_typed1 = send(&mut rpc, &typed1);
    // Pending, a dynamic-fee transaction shows its maximum fee as its price.
    let pending = ok(&mut rpc, "eth_getTransactionByHash", json!([h_dynamic]));
    assert_eq!(pending["gasPrice"], quantity(3 * GWEI));
    assert_eq!(pending["from"], data(&bob.address));
    assert_eq!(pending["blockNumber"], Value::Null);
    mine(&mut rpc);
    assert_eq!(
        ok(
            &mut rpc,
            "eth_call",
            json!([to(&counter, &calldata("count()", &[]))])
        ),
        data(&word(10))
    );

    // Receipts: the higher tip goes first; log indexes run across the block.
    let r_dynamic = ok(&mut rpc, "eth_getTransactionReceipt", json!([h_dynamic]));
    let r_legacy = ok(&mut rpc, "eth_getTransactionReceipt", json!([h_legacy]));
    let r_typed1 = ok(&mut rpc, "eth_getTransactionReceipt", json!([h_typed1]));
    let block_hash = r_dynamic["blockHash"].as_str().unwrap().to_owned();
    for (index, (receipt, tx_type, price)) in [
        (&r_dynamic, "0x2", 2 * GWEI),
        (&r_legacy, "0x0", GAS_PRICE),
        (&r_typed1, "0x1", GAS_PRICE),
    ]
    .into_iter()
    .enumerate()
    {
        assert_eq!(receipt["status"], "0x1");
        assert_eq!(receipt["type"], tx_type);
        assert_eq!(receipt["effectiveGasPrice"], quantity(price));
        assert_eq!(receipt["transactionIndex"], quantity(index as u128));
        assert_eq!(receipt["blockNumber"], "0x2");
        assert_eq!(receipt["blockHash"], block_hash);
        assert_eq!(receipt["to"], c);
        assert_eq!(receipt["contractAddress"], Value::Null);
        let logs = receipt["logs"].as_array().unwrap();
        assert_eq!(logs.len(), 1);
        let log = &logs[0];
        assert_eq!(log["address"], c);
        assert_eq!(log["logIndex"], quantity(index as u128));
        assert_eq!(log["transactionIndex"], quantity(index as u128));
        assert_eq!(log["transactionHash"], receipt["transactionHash"]);
        assert_eq!(log["blockHash"], block_hash);
        assert_eq!(log["blockNumber"], "0x2");
        assert_eq!(log["removed"], false);
        assert_eq!(receipt["logsBloom"], bloom_of(&[(counter, topics_of(log))]));
    }
    assert_eq!(r_legacy["from"], data(&alice.address));
    assert_eq!(
        quantity_of(&r_legacy["gasUsed"]),
        estimate,
        "the estimate is exact"
    );
    assert_eq!(
        quantity_of(&r_legacy["cumulativeGasUsed"]),
        quantity_of(&r_dynamic["gasUsed"]) + estimate
    );
    assert_eq!(
        quantity_of(&r_typed1["cumulativeGasUsed"]),
        quantity_of(&r_legacy["cumulativeGasUsed"]) + quantity_of(&r_typed1["gasUsed"])
    );
    let d = &r_dynamic["logs"][0];
    assert_eq!(
        d["topics"],
        json!([data(&incremented), topic(&bob.address), data(&word(8))])
    );
    assert_eq!(d["data"], data(&word(3)));
    let l = &r_legacy["logs"][0];
    assert_eq!(
        l["topics"],
        json!([data(&incremented), topic(&alice.address), data(&word(10))])
    );
    let n = &r_typed1["logs"][0];
    assert_eq!(n["topics"], json!([data(&noted)]));
    assert_eq!(n["data"], data(&calldata_string("x()", "hello")[4..]));
    let receipts = json!([r_dynamic, r_legacy, r_typed1]);
    assert_eq!(
        ok(&mut rpc, "eth_getBlockReceipts", json!(["0x2"])),
        receipts
    );

    // Transactions of each type.
    let t_dynamic = ok(&mut rpc, "eth_getTransactionByHash", json!([h_dynamic]));
    assert_eq!(t_dynamic["type"], "0x2");
    assert_eq!(t_dynamic["chainId"], "0x539");
    assert_eq!(t_dynamic["maxFeePerGas"], quantity(3 * GWEI));
    assert_eq!(t_dynamic["maxPriorityFeePerGas"], quantity(2 * GWEI));
    assert_eq!(t_dynamic["gasPrice"], quantity(2 * GWEI), "the price paid");
    assert_eq!(t_dynamic["accessList"], json!([]));
    assert_eq!(t_dynamic["yParity"], t_dynamic["v"]);
    assert!(t_dynamic["v"] == "0x0" || t_dynamic["v"] == "0x1");
    assert_eq!(t_dynamic["to"], c);
    assert_eq!(t_dynamic["input"], data(&inc3));
    assert_eq!(t_dynamic["gas"], quantity(100_000));
    assert_eq!(t_dynamic["transactionIndex"], "0x0");
    let t_typed1 = ok(&mut rpc, "eth_getTransactionByHash", json!([h_typed1]));
    assert_eq!(t_typed1["type"], "0x1");
    assert_eq!(
        t_typed1["accessList"],
        json!([{ "address": c, "storageKeys": [data(&word(0))] }])
    );
    assert_eq!(t_typed1["gasPrice"], quantity(GAS_PRICE));
    assert_eq!(t_typed1["yParity"], t_typed1["v"]);
    assert!(t_typed1.get("maxFeePerGas").is_none());
    let t_legacy = ok(&mut rpc, "eth_getTransactionByHash", json!([h_legacy]));
    let block = ok(&mut rpc, "eth_getBlockByNumber", json!(["0x2", true]));
    assert_eq!(
        block["transactions"],
        json!([t_dynamic, t_legacy, t_typed1])
    );
    assert_eq!(
        block["logsBloom"],
        bloom_of(&[
            (counter, topics_of(d)),
            (counter, topics_of(l)),
            (counter, topics_of(n)),
        ])
    );
    assert_eq!(
        quantity_of(&block["gasUsed"]),
        quantity_of(&r_typed1["cumulativeGasUsed"])
    );

    // Log filters.
    let all = json!([d, l, n]);
    let logs = |rpc: &mut Rpc, filter: Value| ok(rpc, "eth_getLogs", json!([filter]));
    assert_eq!(logs(&mut rpc, json!({ "fromBlock": "0x1" })), all);
    assert_eq!(
        logs(
            &mut rpc,
            json!({ "fromBlock": "earliest", "toBlock": "latest" })
        ),
        all
    );
    assert_eq!(logs(&mut rpc, json!({ "address": c })), all);
    assert_eq!(
        logs(&mut rpc, json!({ "address": [data(&[1; 20]), c] })),
        all
    );
    assert_eq!(
        logs(&mut rpc, json!({ "address": data(&[1; 20]) })),
        json!([])
    );
    assert_eq!(logs(&mut rpc, json!({ "blockHash": block_hash })), all);
    assert_eq!(
        logs(&mut rpc, json!({ "fromBlock": "0x1", "toBlock": "0x1" })),
        json!([])
    );
    assert_eq!(
        logs(&mut rpc, json!({ "topics": [data(&incremented)] })),
        json!([d, l])
    );
    assert_eq!(
        logs(&mut rpc, json!({ "topics": [null, topic(&bob.address)] })),
        json!([d])
    );
    assert_eq!(
        logs(
            &mut rpc,
            json!({ "topics": [[data(&incremented), data(&noted)]] })
        ),
        all
    );
    assert_eq!(
        logs(&mut rpc, json!({ "topics": [[data(&noted), null]] })),
        all,
        "a null alternative matches anything"
    );
    assert_eq!(
        logs(&mut rpc, json!({ "topics": [[]] })),
        all,
        "so does an empty list, as in geth"
    );
    assert_eq!(
        logs(&mut rpc, json!({ "topics": [[], [topic(&bob.address)]] })),
        json!([d])
    );
    assert_eq!(
        logs(
            &mut rpc,
            json!({ "topics": [data(&incremented), null, [data(&word(8)), data(&word(9))]] })
        ),
        json!([d])
    );
    assert_eq!(
        logs(&mut rpc, json!({ "topics": [data(&noted), null] })),
        json!([]),
        "more positions than the log has topics"
    );
    assert_eq!(
        logs(
            &mut rpc,
            json!({ "address": null, "topics": null, "fromBlock": null })
        ),
        all
    );

    // Fee history over the three blocks, with the tips paid.
    let history = ok(
        &mut rpc,
        "eth_feeHistory",
        json!(["0x3", "latest", [25, 75]]),
    );
    assert_eq!(history["oldestBlock"], "0x0");
    assert_eq!(
        history["baseFeePerGas"],
        json!(["0x0", "0x0", "0x0", "0x0"])
    );
    assert_eq!(
        history["baseFeePerBlobGas"],
        json!(["0x0", "0x0", "0x0", "0x0"])
    );
    assert_eq!(history["blobGasUsedRatio"], json!([0.0, 0.0, 0.0]));
    let ratios = history["gasUsedRatio"].as_array().unwrap();
    assert_eq!(ratios[0], 0.0);
    #[allow(clippy::cast_precision_loss)]
    let ratio = quantity_of(&block["gasUsed"]) as f64 / 30_000_000.0;
    assert_eq!(ratios[2], ratio);
    let one = quantity(GWEI);
    assert_eq!(
        history["reward"],
        json!([["0x0", "0x0"], [one, one], [one, quantity(2 * GWEI)]])
    );
}

#[test]
fn gas_estimation() {
    let alice = Wallet::new(1);
    let bob = Wallet::new(2);
    let mut rpc = Rpc::new(node_funding(&[&alice, &bob]));
    let counter = deploy(&mut rpc, &alice, 0, 5);
    let c = data(&counter);
    let a = data(&alice.address);
    let estimate = |rpc: &mut Rpc, object: Value| ok(rpc, "eth_estimateGas", json!([object]));
    // A transfer to an account without code needs the intrinsic gas; so does an empty creation.
    let pay = json!({ "from": a, "to": data(&bob.address), "value": "0x1" });
    assert_eq!(estimate(&mut rpc, pay), "0x5208");
    assert_eq!(estimate(&mut rpc, json!({})), quantity(53_000));
    // The requested gas caps the search.
    let read = calldata("count()", &[]);
    let used = estimate(&mut rpc, to(&counter, &read));
    let capped = json!({ "to": c, "input": data(&read), "gas": quantity_of(&used).to_string() });
    assert_eq!(err(&mut rpc, "eth_estimateGas", json!([capped])).0, -32602);
    let capped = json!({ "to": c, "input": data(&read), "gas": "0x7530" });
    assert_eq!(estimate(&mut rpc, capped), used);
    let exact = json!({ "to": c, "input": data(&read), "gas": used });
    assert_eq!(estimate(&mut rpc, exact), used, "exactly enough");
    // Failures.
    let fail = calldata_string("fail(string)", "nope");
    let (code, message, revert) =
        call(&mut rpc, "eth_estimateGas", json!([to(&counter, &fail)])).unwrap_err();
    assert_eq!((code, message.as_str()), (3, "execution reverted: nope"));
    assert!(revert.as_str().unwrap().starts_with("0x08c379a0"));
    let halt = selector("halt()");
    assert_eq!(
        err(&mut rpc, "eth_estimateGas", json!([to(&counter, &halt)])),
        (-32000, "gas required exceeds allowance (16777216)".into())
    );
    let halt_capped = json!({ "to": c, "input": data(&halt), "gas": "0x9c40" });
    assert_eq!(
        err(&mut rpc, "eth_estimateGas", json!([halt_capped])).1,
        "gas required exceeds allowance (40000)"
    );
    let low = json!({ "to": c, "input": data(&read), "gas": "0x5208" });
    assert!(
        err(&mut rpc, "eth_estimateGas", json!([low]))
            .1
            .starts_with("intrinsic gas too low")
    );
    let above_cap = json!({ "to": c, "input": data(&read), "gas": quantity(1 << 30) });
    assert_eq!(estimate(&mut rpc, above_cap), used);

    // Refunds: clearing slots needs more gas than it ends up using, so the
    // search runs past the first guesses.
    let fill = calldata("fill(uint256)", &[8]);
    send(
        &mut rpc,
        &alice.legacy(&Fields {
            nonce: 1,
            to: Some(counter),
            value: 0,
            gas_limit: 400_000,
            data: &fill,
        }),
    );
    mine(&mut rpc);
    assert_eq!(
        ok(&mut rpc, "eth_getStorageAt", json!([c, "0x9"])),
        data(&word(8))
    );
    let clear = calldata("clear(uint256)", &[8]);
    let needed = quantity_of(&estimate(
        &mut rpc,
        json!({ "from": a, "to": c, "input": data(&clear) }),
    ));
    let with = |gas: u64| json!({ "from": a, "to": c, "input": data(&clear), "gas": quantity(u128::from(gas)) });
    assert_eq!(ok(&mut rpc, "eth_call", json!([with(needed)])), "0x");
    assert!(
        err(&mut rpc, "eth_call", json!([with(needed * 985 / 1000)]))
            .1
            .starts_with("execution halted"),
        "within 1.5% of the least gas that works"
    );
    let hash = send(
        &mut rpc,
        &alice.legacy(&Fields {
            nonce: 2,
            to: Some(counter),
            value: 0,
            gas_limit: needed,
            data: &clear,
        }),
    );
    mine(&mut rpc);
    let receipt = ok(&mut rpc, "eth_getTransactionReceipt", json!([hash]));
    assert_eq!(receipt["status"], "0x1");
    assert!(quantity_of(&receipt["gasUsed"]) < needed, "refunded");
    assert_eq!(
        ok(&mut rpc, "eth_getStorageAt", json!([c, "0x9"])),
        data(&[0; 32])
    );
}

#[test]
fn undecodable_transactions_show_as_blank() {
    let alice = Wallet::new(1);
    let mut rpc = Rpc::new(node_funding(&[&alice]));
    // A block carrying bytes that are no transaction, as a faulty leader could propose.
    let header = BlockHeader {
        height: 1,
        timestamp_ms: 1_200,
        ..BlockHeader::default()
    };
    let block = Block {
        header: header.to_bytes(),
        txs: Seq(vec![b"garbage".to_vec()]),
        participation: vec![],
    };
    rpc.node_mut()
        .apply_effect(Effect::ExecuteBlock { block })
        .unwrap();
    let hash = data(&keccak256(b"garbage"));
    let receipt = ok(&mut rpc, "eth_getTransactionReceipt", json!([hash]));
    assert_eq!(receipt["status"], "0x0");
    assert_eq!(receipt["to"], Value::Null);
    assert_eq!(receipt["contractAddress"], Value::Null, "not a creation");
    assert_eq!(receipt["gasUsed"], "0x0");
    let tx = ok(&mut rpc, "eth_getTransactionByHash", json!([hash]));
    assert_eq!(tx["type"], "0x0");
    assert_eq!(tx["to"], Value::Null);
    assert_eq!(tx["input"], "0x");
    assert_eq!(
        (&tx["v"], &tx["r"], &tx["s"]),
        (&json!("0x0"), &json!("0x0"), &json!("0x0"))
    );
    assert_eq!(tx["blockNumber"], "0x1");
    assert!(tx.get("chainId").is_none());
    let block = ok(&mut rpc, "eth_getBlockByNumber", json!(["0x1", true]));
    assert_eq!(block["transactions"], json!([tx]));
}

#[test]
fn log_filter_errors_and_range_limit() {
    let alice = Wallet::new(1);
    let mut rpc = Rpc::new(node_funding(&[&alice]));
    let counter = deploy(&mut rpc, &alice, 0, 5);
    let inc = calldata("increment(uint256)", &[1]);
    send(
        &mut rpc,
        &alice.legacy(&Fields {
            nonce: 1,
            to: Some(counter),
            value: 0,
            gas_limit: 100_000,
            data: &inc,
        }),
    );
    mine(&mut rpc);
    let latest = ok(&mut rpc, "eth_getBlockByNumber", json!(["latest"]));
    let block_hash = latest["hash"].clone();
    let bad: [Value; 13] = [
        json!([]),
        json!([{ "blockHash": block_hash, "fromBlock": "0x1" }]),
        json!([{ "blockHash": block_hash, "toBlock": "0x1" }]),
        json!([{ "blockHash": "0x12" }]),
        json!([{ "fromBlock": 1 }]),
        json!([{ "fromBlock": "0x2", "toBlock": "0x1" }]),
        json!([{ "fromBlock": "0xzz" }]),
        json!([{ "topics": "x" }]),
        json!([{ "topics": [1] }]),
        json!([{ "topics": [[1]] }]),
        json!([{ "topics": [null, null, null, null, null] }]),
        json!([{ "address": [5] }]),
        json!([{ "address": "0x12" }]),
    ];
    for params in bad {
        assert_eq!(
            err(&mut rpc, "eth_getLogs", params.clone()).0,
            -32602,
            "{params}"
        );
    }
    assert_eq!(
        err(
            &mut rpc,
            "eth_getLogs",
            json!([{ "topics": [null, null, null, null, null] }])
        )
        .1,
        "exceed max topics"
    );
    assert_eq!(
        err(
            &mut rpc,
            "eth_getLogs",
            json!([{ "blockHash": data(&[9; 32]) }])
        ),
        (-32000, "unknown block".into())
    );
    // The range limit counts blocks within the chain.
    rpc.max_log_range = 1;
    assert_eq!(
        err(&mut rpc, "eth_getLogs", json!([{ "fromBlock": "0x1" }])),
        (
            -32005,
            "block range too large: 2 blocks, the limit is 1".into()
        )
    );
    assert_eq!(
        ok(
            &mut rpc,
            "eth_getLogs",
            json!([{ "fromBlock": "0x2", "toBlock": "0x99" }])
        )
        .as_array()
        .unwrap()
        .len(),
        1
    );
    assert_eq!(
        ok(
            &mut rpc,
            "eth_getLogs",
            json!([{ "fromBlock": "0x5", "toBlock": "0x9" }])
        ),
        json!([]),
        "beyond the head"
    );
    assert_eq!(
        ok(
            &mut rpc,
            "eth_getLogs",
            json!([{ "fromBlock": "earliest", "toBlock": "earliest" }])
        ),
        json!([]),
        "the genesis has no logs"
    );
}

#[test]
fn fee_history_parameters() {
    let alice = Wallet::new(1);
    let mut rpc = Rpc::new(node_funding(&[&alice]));
    mine(&mut rpc);
    mine(&mut rpc);
    let two = ok(&mut rpc, "eth_feeHistory", json!(["0x2", "latest"]));
    assert_eq!(
        two,
        json!({
            "oldestBlock": "0x1",
            "baseFeePerGas": ["0x0", "0x0", "0x0"],
            "gasUsedRatio": [0.0, 0.0],
            "baseFeePerBlobGas": ["0x0", "0x0", "0x0"],
            "blobGasUsedRatio": [0.0, 0.0],
        })
    );
    assert_eq!(
        ok(&mut rpc, "eth_feeHistory", json!(["2", "latest", []])),
        two
    );
    assert_eq!(ok(&mut rpc, "eth_feeHistory", json!([2, "0x2", null])), two);
    let clamped = ok(&mut rpc, "eth_feeHistory", json!(["0x10", "0x1", [50]]));
    assert_eq!(clamped["oldestBlock"], "0x0");
    assert_eq!(clamped["reward"], json!([["0x0"], ["0x0"]]));
    assert_eq!(
        ok(&mut rpc, "eth_feeHistory", json!(["0x0", "latest"])),
        json!({ "oldestBlock": "0x0", "baseFeePerGas": [], "gasUsedRatio": [] })
    );
    assert_eq!(
        err(&mut rpc, "eth_feeHistory", json!(["0x5", "0x9"])),
        (
            -32000,
            "request beyond head block: requested 9, head 2".into()
        )
    );
    let bad: [Value; 11] = [
        json!([]),
        json!(["abc", "latest"]),
        json!([true, "latest"]),
        json!([1.5, "latest"]),
        json!(["0x1"]),
        json!(["0x1", "latest", [50, 25]]),
        json!(["0x1", "latest", [50, 50]]),
        json!(["0x1", "latest", [101]]),
        json!(["0x1", "latest", [-1]]),
        json!(["0x1", "latest", ["x"]]),
        json!(["0x1", "latest", 5]),
    ];
    for params in bad {
        assert_eq!(
            err(&mut rpc, "eth_feeHistory", params.clone()).0,
            -32602,
            "{params}"
        );
    }
}
