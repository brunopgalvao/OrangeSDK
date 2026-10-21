//! Ethereum JSON-RPC over the reference kernel: the request envelope, value
//! transfers, blocks and receipts, rejection reasons, parameter errors and
//! kernel failures. Contracts are in `evm.rs`.

mod common;

use std::cell::Cell;
use std::rc::Rc;

use common::{CHAIN_ID, ETHER, Fields, GAS_PRICE, SLOT_MS, Wallet, call, err, err_code, node, ok};
use serde_json::{Value, json};
use solo_abi::chain::reason;
use solo_host::hash::keccak256;
use solo_rlp::{encode_bytes, encode_list, encode_uint};
use solo_rpc::methods::{
    data, parse_address, parse_big, parse_hash, parse_hex, parse_quantity, parse_word, quantity,
    quantity_be, reason_text, sender,
};
use solo_rpc::{Rpc, RpcError};

fn rpc(alice: &Wallet) -> Rpc {
    Rpc::new(node(alice))
}

#[test]
fn encodings() {
    // The README's example genesis funds the account of the all-ones private key.
    assert_eq!(
        data(&Wallet::new(1).address),
        "0x1a642f0e3c3af545e7acbd38b07251b3990914f1"
    );
    assert_eq!(quantity(0), "0x0");
    assert_eq!(quantity(255), "0xff");
    assert_eq!(quantity_be(&[0, 0, 1, 0xab]), "0x1ab");
    assert_eq!(quantity_be(&[0; 32]), "0x0");
    assert_eq!(quantity_be(&[]), "0x0");
    assert_eq!(data(&[]), "0x");
    assert_eq!(data(&[0, 1, 0xab]), "0x0001ab");
    assert_eq!(parse_hex("0x0001ab").unwrap(), vec![0, 1, 0xab]);
    assert_eq!(parse_hex("0x").unwrap(), Vec::<u8>::new());
    assert_eq!(parse_hex("01").unwrap_err().code, -32602);
    assert_eq!(parse_hex("0x1").unwrap_err().message, "odd-length hex");
    assert_eq!(parse_hex("0xzz").unwrap_err().message, "bad hex digit");
    assert_eq!(parse_hex("0xé").unwrap_err().message, "bad hex digit");
    assert_eq!(parse_hex("0xaé0").unwrap_err().message, "bad hex digit");
    assert_eq!(parse_quantity("0x10").unwrap(), 16);
    assert_eq!(parse_quantity("10").unwrap_err().code, -32602);
    assert_eq!(parse_quantity("0xg").unwrap_err().message, "bad quantity");
    assert_eq!(
        parse_quantity("0x10000000000000000").unwrap_err().message,
        "bad quantity"
    );
    assert_eq!(parse_big("0x10000000000000000").unwrap(), 1 << 64);
    assert_eq!(parse_big("1").unwrap_err().code, -32602);
    assert_eq!(parse_address(&data(&[7; 20])).unwrap(), [7; 20]);
    assert_eq!(
        parse_address("0x01").unwrap_err().message,
        "expected 20 bytes"
    );
    assert_eq!(parse_hash(&data(&[7; 32])).unwrap(), [7; 32]);
    assert_eq!(parse_hash("0x").unwrap_err().message, "expected 32 bytes");
    // Storage slots: a quantity or data of at most 32 bytes, left-padded.
    let mut one = [0u8; 32];
    one[31] = 1;
    assert_eq!(parse_word("0x1").unwrap(), one);
    assert_eq!(parse_word("0x01").unwrap(), one);
    assert_eq!(parse_word(&data(&one)).unwrap(), one);
    assert_eq!(parse_word("0x").unwrap(), [0; 32]);
    assert_eq!(parse_word("1").unwrap_err().code, -32602);
    assert_eq!(parse_word("0xzz").unwrap_err().message, "bad hex digit");
    assert!(
        parse_word(&format!("0x{}", "0".repeat(65)))
            .unwrap_err()
            .message
            .contains("too long")
    );
    let texts = [
        (reason::MALFORMED, "malformed transaction"),
        (reason::BAD_SIGNATURE, "invalid sender"),
        (reason::WRONG_CHAIN, "invalid chain id for signer"),
        (reason::BAD_NONCE, "invalid nonce"),
        (
            reason::INSUFFICIENT_FUNDS,
            "insufficient funds for gas * price + value",
        ),
        (reason::GAS_TOO_LOW, "intrinsic gas too low"),
        (reason::UNSUPPORTED, "transaction type not supported"),
        (reason::GAS_LIMIT_TOO_HIGH, "transaction gas limit too high"),
        (reason::INITCODE_TOO_LARGE, "max initcode size exceeded"),
        (reason::SENDER_NOT_EOA, "sender not an eoa"),
        (
            reason::SYSTEM_ACTION,
            "not a valid system action (upgrade or module install)",
        ),
        (reason::STAKING_ACTION, "not a valid staking action"),
        (reason::OUTBOX_MESSAGE, "not a valid outbox message"),
        (reason::BRIDGE_CALL, "not a valid bridge call"),
        (
            reason::BRIDGE_UPDATE,
            "light client update does not advance the light client",
        ),
        (reason::MESSAGE_DELIVERED, "message already delivered"),
        (reason::INBOX_PAUSED, "inbox paused"),
        (99, "rejected"),
    ];
    for (code, text) in texts {
        assert_eq!(reason_text(code), text);
    }
    assert!(reason_text(reason::FEE_TOO_LOW).contains("max fee per gas less than block base fee"));
    let e: RpcError = solo_node::NodeError::Decode("x").into();
    assert_eq!((e.code, e.data), (-32603, None));
    let e: RpcError = solo_node::SubmitError::Rejected(reason::BAD_NONCE).into();
    assert_eq!((e.code, e.message.as_str()), (-32000, "invalid nonce"));
    let e: RpcError = solo_node::SubmitError::Node(solo_node::NodeError::Decode("x")).into();
    assert_eq!(e.code, -32603);
    assert_eq!(e.clone(), e);
    // Senders: recovered from any decodable, well-signed transaction.
    let alice = Wallet::new(1);
    assert_eq!(
        sender(&alice.transfer(0, [2; 20], 1, 21_000)),
        Some(alice.address)
    );
    assert_eq!(sender(b"garbage"), None);
}

#[test]
fn static_and_info_methods() {
    let alice = Wallet::new(1);
    let mut rpc = rpc(&alice);
    assert_eq!(ok(&mut rpc, "eth_chainId", json!([])), "0x539");
    assert_eq!(ok(&mut rpc, "net_version", json!([])), "1337");
    assert_eq!(ok(&mut rpc, "web3_clientVersion", json!([])), "solo/0.0.1");
    assert_eq!(ok(&mut rpc, "eth_blockNumber", json!([])), "0x0");
    // The base fee is zero: the suggested price is the suggested tip.
    assert_eq!(ok(&mut rpc, "eth_gasPrice", json!([])), quantity(GAS_PRICE));
    assert_eq!(
        ok(&mut rpc, "eth_maxPriorityFeePerGas", json!([])),
        quantity(GAS_PRICE)
    );
    assert_eq!(ok(&mut rpc, "eth_syncing", json!([])), json!(false));
    assert!(!rpc.stopped);
    assert_eq!(ok(&mut rpc, "solo_stop", json!([])), json!(true));
    assert!(rpc.stopped);
    assert_eq!(ok(&mut rpc, "eth_accounts", json!([])), json!([]));
    assert!(rpc.node().mempool().is_empty());
    assert_eq!(
        ok(
            &mut rpc,
            "eth_getCode",
            json!([data(&alice.address), "latest"])
        ),
        "0x"
    );
    assert_eq!(err_code(&mut rpc, "eth_mining", json!([])), -32601);
    rpc.gas_price = 5;
    assert_eq!(ok(&mut rpc, "eth_gasPrice", json!([])), "0x5");
}

#[test]
fn accounts_and_parameter_errors() {
    let alice = Wallet::new(1);
    let mut rpc = rpc(&alice);
    assert_eq!(
        ok(
            &mut rpc,
            "eth_getBalance",
            json!([data(&alice.address), "latest"])
        ),
        quantity(100 * ETHER)
    );
    assert_eq!(
        ok(&mut rpc, "eth_getBalance", json!([data(&[9; 20])])),
        "0x0"
    );
    assert_eq!(
        ok(
            &mut rpc,
            "eth_getTransactionCount",
            json!([data(&alice.address), "pending"])
        ),
        "0x0"
    );
    let bad: [(&str, Value); 13] = [
        ("eth_getBalance", json!([])),
        ("eth_getBalance", json!([5])),
        ("eth_getBalance", json!([data(&[1; 19])])),
        ("eth_getBalance", json!(["abc"])),
        ("eth_getTransactionReceipt", json!([data(&[1; 31])])),
        ("eth_getBlockByNumber", json!(["0xzz"])),
        ("eth_getBlockByNumber", json!(["12"])),
        ("eth_sendRawTransaction", json!(["0x0"])),
        ("eth_getStorageAt", json!([data(&[1; 20])])),
        ("eth_getStorageAt", json!([data(&[1; 20]), "slot"])),
        ("eth_getBlockReceipts", json!([])),
        (
            "eth_getBlockReceipts",
            json!([format!("0x{}", "z".repeat(64))]),
        ),
        ("eth_getBlockReceipts", json!(["0xzz"])),
    ];
    for (method, params) in bad {
        assert_eq!(
            err_code(&mut rpc, method, params.clone()),
            -32602,
            "{method} {params}"
        );
    }
}

#[test]
fn request_envelope() {
    let alice = Wallet::new(1);
    let mut rpc = rpc(&alice);
    // Missing method.
    let r = rpc.handle(&json!({ "id": "a" }));
    assert_eq!(r["error"]["code"], -32600);
    assert_eq!(r["id"], "a");
    assert!(r["error"].get("data").is_none());
    // No id, params not an array: treated as none.
    let r = rpc.handle(&json!({ "method": "eth_blockNumber", "params": {} }));
    assert_eq!(r["result"], "0x0");
    assert_eq!(r["id"], Value::Null);
    // Batch.
    let r = rpc.handle_body(r#"[{"id":1,"method":"eth_chainId"},{"id":2,"method":"nope"}]"#);
    assert_eq!(r[0]["result"], "0x539");
    assert_eq!(r[1]["error"]["code"], -32601);
    // Single and parse error.
    let r = rpc.handle_body(r#"{"id":3,"method":"eth_syncing"}"#);
    assert_eq!(r["result"], false);
    let r = rpc.handle_body("{not json");
    assert_eq!(r["error"]["code"], -32700);
    assert_eq!(r["id"], Value::Null);
}

#[test]
#[allow(clippy::too_many_lines)]
fn transactions_blocks_and_receipts() {
    let alice = Wallet::new(1);
    let bob = Wallet::new(2);
    let mut rpc = rpc(&alice);
    let raw = alice.transfer(0, bob.address, 5 * ETHER, 21_000);
    let hash = keccak256(&raw);
    let hash_hex = data(&hash);
    assert_eq!(
        ok(&mut rpc, "eth_sendRawTransaction", json!([data(&raw)])),
        hash_hex
    );
    assert_eq!(
        ok(&mut rpc, "eth_getTransactionReceipt", json!([hash_hex])),
        Value::Null
    );
    // A pending transaction has no block yet.
    let pending = ok(&mut rpc, "eth_getTransactionByHash", json!([hash_hex]));
    assert_eq!(pending["hash"], hash_hex);
    assert_eq!(pending["from"], data(&alice.address));
    assert_eq!(pending["blockHash"], Value::Null);
    assert_eq!(pending["blockNumber"], Value::Null);
    assert_eq!(pending["transactionIndex"], Value::Null);
    assert_eq!(pending["gasPrice"], quantity(GAS_PRICE));
    assert_eq!(
        ok(
            &mut rpc,
            "eth_getTransactionByHash",
            json!([data(&[3; 32])])
        ),
        Value::Null
    );
    assert_eq!(
        ok(&mut rpc, "eth_getBlockByNumber", json!(["0x1"])),
        Value::Null
    );
    assert_eq!(
        ok(&mut rpc, "eth_getBlockByHash", json!([data(&[7; 32])])),
        Value::Null
    );
    // The genesis block is synthetic: an empty header whose hash is zero.
    let genesis = ok(&mut rpc, "eth_getBlockByNumber", json!(["earliest", true]));
    assert_eq!(genesis["number"], "0x0");
    assert_eq!(genesis["hash"], data(&[0; 32]));
    assert_eq!(genesis["transactions"], json!([]));
    assert_eq!(genesis["baseFeePerGas"], "0x0");
    assert_eq!(genesis["gasLimit"], quantity(30_000_000));
    assert_eq!(genesis["logsBloom"], data(&[0; 256]));
    assert_eq!(
        genesis["sha3Uncles"],
        "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347"
    );
    // Empty Merkle-Patricia tries (spec 20 §3.1).
    let empty_trie = "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421";
    assert_eq!(genesis["transactionsRoot"], empty_trie);
    assert_eq!(genesis["receiptsRoot"], empty_trie);
    assert_eq!(
        ok(&mut rpc, "eth_getBlockByNumber", json!(["latest"])),
        genesis
    );

    rpc.node_mut().tick(1_000 + SLOT_MS).unwrap();
    assert_eq!(ok(&mut rpc, "eth_blockNumber", json!([])), "0x1");
    let receipt = ok(&mut rpc, "eth_getTransactionReceipt", json!([hash_hex]));
    assert_eq!(receipt["status"], "0x1");
    assert_eq!(receipt["type"], "0x0");
    assert_eq!(receipt["blockNumber"], "0x1");
    assert_eq!(receipt["transactionIndex"], "0x0");
    assert_eq!(receipt["from"], data(&alice.address));
    assert_eq!(receipt["to"], data(&bob.address));
    assert_eq!(receipt["gasUsed"], "0x5208");
    assert_eq!(receipt["cumulativeGasUsed"], "0x5208");
    assert_eq!(receipt["effectiveGasPrice"], quantity(GAS_PRICE));
    assert_eq!(receipt["contractAddress"], Value::Null);
    assert_eq!(receipt["logs"], json!([]));
    assert_eq!(receipt["logsBloom"], data(&[0; 256]));
    let block_hash = receipt["blockHash"].as_str().unwrap().to_owned();
    assert_ne!(block_hash, data(&[0; 32]));

    let tx = ok(&mut rpc, "eth_getTransactionByHash", json!([hash_hex]));
    assert_eq!(tx["hash"], hash_hex);
    assert_eq!(tx["type"], "0x0");
    assert_eq!(tx["nonce"], "0x0");
    assert_eq!(tx["from"], data(&alice.address));
    assert_eq!(tx["to"], data(&bob.address));
    assert_eq!(tx["value"], quantity(5 * ETHER));
    assert_eq!(tx["gas"], "0x5208");
    assert_eq!(tx["gasPrice"], quantity(GAS_PRICE));
    assert_eq!(tx["chainId"], "0x539");
    assert_eq!(tx["blockHash"], block_hash);
    assert_eq!(tx["blockNumber"], "0x1");
    assert_eq!(tx["transactionIndex"], "0x0");
    assert_eq!(tx["input"], "0x");
    assert!(tx.get("accessList").is_none());
    assert!(tx.get("yParity").is_none());
    assert!(tx.get("maxFeePerGas").is_none());
    let v = parse_quantity(tx["v"].as_str().unwrap()).unwrap();
    assert!(v == CHAIN_ID * 2 + 35 || v == CHAIN_ID * 2 + 36);
    assert!(tx["r"].as_str().unwrap().len() > 50);

    let by_number = ok(&mut rpc, "eth_getBlockByNumber", json!(["0x1", false]));
    assert_eq!(by_number["hash"], block_hash);
    assert_eq!(by_number["number"], "0x1");
    assert_eq!(by_number["parentHash"], data(&[0; 32]));
    assert_eq!(by_number["transactions"], json!([hash_hex]));
    // The Merkle-Patricia root of the one raw transaction (spec 20 §3.2).
    let root = alloy_trie::root::ordered_trie_root_encoded(&[raw.clone()]);
    assert_eq!(by_number["transactionsRoot"], data(&root.0));
    assert_eq!(by_number["gasUsed"], "0x5208");
    assert_eq!(by_number["logsBloom"], data(&[0; 256]));
    assert_eq!(
        by_number["timestamp"],
        quantity(u128::from((1_000 + SLOT_MS) / 1000))
    );
    let size = parse_quantity(by_number["size"].as_str().unwrap()).unwrap();
    assert!(size > raw.len() as u64, "header and transaction bytes");
    let full = ok(&mut rpc, "eth_getBlockByHash", json!([block_hash, true]));
    assert_eq!(full["transactions"][0], tx);
    assert_eq!(full["size"], by_number["size"]);
    assert_eq!(
        ok(&mut rpc, "eth_getBlockByNumber", json!(["latest", true])),
        full
    );
    assert_eq!(
        ok(&mut rpc, "eth_getBlockByNumber", json!(["finalized"])),
        by_number
    );
    assert_eq!(
        ok(&mut rpc, "eth_getBlockByNumber", json!(["safe"])),
        by_number
    );
    assert_eq!(
        ok(&mut rpc, "eth_getBlockByNumber", json!(["pending"])),
        by_number
    );
    assert_eq!(
        ok(&mut rpc, "eth_getBlockByNumber", json!(["0x2"])),
        Value::Null
    );
    // Block receipts by tag, number or hash.
    let receipts = ok(&mut rpc, "eth_getBlockReceipts", json!(["latest"]));
    assert_eq!(receipts, json!([receipt]));
    assert_eq!(
        ok(&mut rpc, "eth_getBlockReceipts", json!([block_hash])),
        receipts
    );
    assert_eq!(
        ok(&mut rpc, "eth_getBlockReceipts", json!(["0x0"])),
        json!([])
    );
    assert_eq!(
        ok(&mut rpc, "eth_getBlockReceipts", json!(["0x9"])),
        Value::Null
    );
    assert_eq!(
        ok(&mut rpc, "eth_getBlockReceipts", json!([data(&[7; 32])])),
        Value::Null
    );
    assert_eq!(
        ok(&mut rpc, "eth_getBalance", json!([data(&bob.address)])),
        quantity(5 * ETHER)
    );
    assert_eq!(
        ok(
            &mut rpc,
            "eth_getTransactionCount",
            json!([data(&alice.address)])
        ),
        "0x1"
    );
}

/// A legacy transaction with `v` of 5: neither 27/28 nor EIP-155.
fn bad_v() -> Vec<u8> {
    let mut fields = Vec::new();
    for _ in 0..6 {
        encode_uint(0, &mut fields);
    }
    encode_uint(5, &mut fields);
    encode_bytes(&[1; 32], &mut fields);
    encode_bytes(&[1; 32], &mut fields);
    let mut list = Vec::new();
    encode_list(&fields, &mut list);
    list
}

#[test]
fn rejections_carry_reasons() {
    let alice = Wallet::new(1);
    let bob = Wallet::new(2);
    let poor = Wallet::new(3);
    let mut rpc = rpc(&alice);
    let huge_initcode = vec![0u8; 49_153];
    let creation = Fields {
        nonce: 0,
        to: None,
        value: 0,
        gas_limit: 1_000_000,
        data: &huge_initcode,
    };
    let to_bob = Fields {
        nonce: 0,
        to: Some(bob.address),
        value: 1,
        gas_limit: 21_000,
        data: &[],
    };
    let a = data(&alice.address);
    let cases: [(Vec<u8>, String); 12] = [
        (
            alice.transfer(u64::MAX, bob.address, ETHER, 21_000),
            format!("nonce has max value: address {a}, nonce: {}", u64::MAX),
        ),
        (
            poor.transfer(0, bob.address, ETHER, 21_000),
            "insufficient funds for gas * price + value".into(),
        ),
        (
            alice.transfer(0, bob.address, ETHER, 20_999),
            "intrinsic gas too low: gas 20999, minimum needed 21000".into(),
        ),
        // Calldata is executed now, so 21 000 gas no longer covers a transfer that carries it.
        (
            alice.transfer_on(0, bob.address, ETHER, 21_000, CHAIN_ID, &[1]),
            "intrinsic gas too low: gas 21000, minimum needed 21040".into(),
        ),
        (
            alice.transfer_on(0, bob.address, ETHER, 21_000, CHAIN_ID + 1, &[]),
            "invalid chain id for signer".into(),
        ),
        (
            alice.transfer(0, bob.address, 1, 1 << 25),
            "transaction gas limit too high (cap: 16777216, tx: 33554432)".into(),
        ),
        (
            alice.legacy(&creation),
            "max initcode size exceeded: code size 49153, limit 49152".into(),
        ),
        (
            alice.dynamic(&to_bob, GAS_PRICE, GAS_PRICE + 1, &[]),
            reason_text(reason::FEE_TOO_LOW).into(),
        ),
        // A blob transaction (type 3) is not executed, and a first byte below 0x80
        // such as 'g' names a typed envelope of no type the kernel executes.
        (vec![0x03, 0xC0], "transaction type not supported".into()),
        (b"garbage".to_vec(), "transaction type not supported".into()),
        // A legacy transaction that is an empty RLP list.
        (vec![0xC0], "malformed transaction".into()),
        (bad_v(), "invalid sender".into()),
    ];
    for (raw, text) in cases {
        let (code, message) = err(&mut rpc, "eth_sendRawTransaction", json!([data(&raw)]));
        assert_eq!((code, message.as_str()), (-32000, text.as_str()));
    }
    // A nonce already used.
    let first = alice.transfer(0, bob.address, ETHER, 21_000);
    ok(&mut rpc, "eth_sendRawTransaction", json!([data(&first)]));
    rpc.node_mut().tick(1_000 + SLOT_MS).unwrap();
    let again = alice.transfer(0, bob.address, 2 * ETHER, 21_000);
    let (_, message) = err(&mut rpc, "eth_sendRawTransaction", json!([data(&again)]));
    assert_eq!(
        message,
        format!("nonce too low: address {a}, tx: 0 state: 1")
    );
}

#[test]
fn kernel_failures_are_internal_errors() {
    let alice = Wallet::new(1);
    let bob = Wallet::new(2);
    let mut rpc = rpc(&alice);
    let raw = alice.transfer(0, bob.address, ETHER, 21_000);
    let hash_hex = data(&keccak256(&raw));
    ok(&mut rpc, "eth_sendRawTransaction", json!([data(&raw)]));
    rpc.node_mut().tick(1_000 + SLOT_MS).unwrap();
    let a = data(&alice.address);
    // Starve every kernel call of gas: each method surfaces the failure as -32603.
    rpc.node_mut().kernel_gas = 0;
    let methods: [(&str, Value); 19] = [
        ("eth_chainId", json!([])),
        ("net_version", json!([])),
        ("eth_blockNumber", json!([])),
        ("eth_getBalance", json!([a])),
        ("eth_getTransactionCount", json!([a])),
        (
            "eth_sendRawTransaction",
            json!([data(&alice.transfer(1, bob.address, 1, 21_000))]),
        ),
        ("eth_getTransactionReceipt", json!([hash_hex])),
        ("eth_getTransactionByHash", json!([hash_hex])),
        ("eth_getBlockByNumber", json!(["latest"])),
        ("eth_getBlockByNumber", json!(["finalized"])),
        ("eth_getBlockByNumber", json!(["0x1"])),
        ("eth_getBlockByHash", json!([data(&[1; 32])])),
        ("eth_getBlockReceipts", json!([data(&[1; 32])])),
        ("eth_getBlockReceipts", json!(["0x1"])),
        ("eth_getCode", json!([a])),
        ("eth_getStorageAt", json!([a, "0x0"])),
        ("eth_call", json!([{ "to": a, "value": "0x1" }])),
        ("eth_getLogs", json!([{}])),
        ("eth_feeHistory", json!(["0x1", "latest"])),
    ];
    for (method, params) in methods {
        let (code, message, _) = call(&mut rpc, method, params).expect_err(method);
        assert_eq!(code, -32603, "{method}");
        assert!(message.contains("ended with"), "{method}: {message}");
    }
    // A starved message runs out of the query budget, like a long one; a
    // kernel the executor refuses to start is an internal error there too.
    let to_alice = json!([{ "to": a }]);
    for method in ["eth_call", "eth_estimateGas"] {
        assert_eq!(
            err(&mut rpc, method, to_alice.clone()),
            (
                -32000,
                "execution aborted: the message ran past the node's query budget".into()
            )
        );
    }
    rpc.node_mut().kernel_gas = -1;
    for method in ["eth_call", "eth_estimateGas"] {
        let (code, message, _) = call(&mut rpc, method, to_alice.clone()).expect_err(method);
        assert_eq!(code, -32603, "{method}");
        assert!(message.contains("ended with"), "{method}: {message}");
    }
}

#[test]
fn long_requests_are_bounded_and_let_the_node_run() {
    let alice = Wallet::new(1);
    let bob = Wallet::new(2);
    let mut rpc = rpc(&alice);
    // The node produces a block each time it gets the thread back.
    let turns = Rc::new(Cell::new(0u64));
    let counter = Rc::clone(&turns);
    rpc.set_background(Box::new(move |node| {
        counter.set(counter.get() + 1);
        node.tick(1_000 + counter.get() * SLOT_MS).unwrap();
    }));
    rpc.run_background();
    assert_eq!(rpc.node().executed.len(), 1);

    // Between batch entries, so the second request sees the next block.
    let r = rpc.handle_body(
        r#"[{"id":1,"method":"eth_blockNumber"},{"id":2,"method":"eth_blockNumber"}]"#,
    );
    assert_eq!(
        (&r[0]["result"], &r[1]["result"]),
        (&json!("0x2"), &json!("0x3"))
    );
    // Between the blocks of log and fee-history scans, and between the runs
    // of a gas estimate (a transfer takes one run after the first).
    let before = turns.get();
    ok(
        &mut rpc,
        "eth_getLogs",
        json!([{ "fromBlock": "0x1", "toBlock": "0x2" }]),
    );
    assert_eq!(turns.get(), before + 2);
    ok(&mut rpc, "eth_feeHistory", json!(["0x3", "0x3"]));
    assert_eq!(turns.get(), before + 5);
    let pay = json!({ "from": data(&alice.address), "to": data(&bob.address), "value": "0x1" });
    assert_eq!(ok(&mut rpc, "eth_estimateGas", json!([pay])), "0x5208");
    assert_eq!(turns.get(), before + 6);

    // A batch past the limit is refused whole, under the id of its first
    // call, as geth refuses it, and runs nothing.
    rpc.max_batch = 1;
    let r = rpc.handle_body(r#"[{"method":"eth_chainId"},{"id":5,"method":"eth_chainId"}]"#);
    assert_eq!(
        r,
        json!([{ "jsonrpc": "2.0", "id": 5, "error": { "code": -32600, "message": "batch too large" } }])
    );
    let r = rpc.handle_body(r#"[{"method":"eth_chainId"},{"method":"eth_chainId"}]"#);
    assert_eq!(r[0]["id"], Value::Null);
    assert_eq!(turns.get(), before + 6);
    rpc.max_batch = solo_rpc::methods::MAX_BATCH;

    // Each kernel query runs within the node's budget: a message that loops
    // until its gas runs out (JUMPDEST PUSH1 0 JUMP) is aborted at it.
    rpc.node_mut().query_gas = 2_000_000;
    let looping = json!({ "input": "0x5b600056" });
    let aborted = (
        -32000,
        "execution aborted: the message ran past the node's query budget".to_owned(),
    );
    assert_eq!(err(&mut rpc, "eth_call", json!([looping])), aborted);
    assert_eq!(err(&mut rpc, "eth_estimateGas", json!([looping])), aborted);
    let pay = json!({ "from": data(&alice.address), "to": data(&bob.address), "value": "0x1" });
    assert_eq!(
        ok(&mut rpc, "eth_call", json!([pay])),
        "0x",
        "ordinary calls fit"
    );
}
