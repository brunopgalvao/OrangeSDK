//! Ethereum JSON-RPC over the reference kernel: every method, every error class.

mod common;

use common::{CHAIN_ID, ETHER, GAS_PRICE, SLOT_MS, Wallet, node};
use serde_json::{Value, json};
use solo_abi::chain::reason;
use solo_host::hash::keccak256;
use solo_rpc::methods::{
    Legacy, data, legacy_fields, parse_hex, parse_quantity, quantity, reason_text,
};
use solo_rpc::{Rpc, RpcError};

fn rpc(alice: &Wallet) -> Rpc {
    Rpc::new(node(alice))
}

#[allow(clippy::needless_pass_by_value)]
fn call(rpc: &mut Rpc, method: &str, params: Value) -> Result<Value, (i64, String)> {
    let response =
        rpc.handle(&json!({ "jsonrpc": "2.0", "id": 7, "method": method, "params": params }));
    assert_eq!(response["jsonrpc"], "2.0");
    assert_eq!(response["id"], 7);
    if let Some(err) = response.get("error") {
        Err((
            err["code"].as_i64().unwrap(),
            err["message"].as_str().unwrap().to_owned(),
        ))
    } else {
        Ok(response["result"].clone())
    }
}

fn ok(rpc: &mut Rpc, method: &str, params: Value) -> Value {
    call(rpc, method, params).unwrap_or_else(|e| panic!("{method}: {e:?}"))
}

fn err_code(rpc: &mut Rpc, method: &str, params: Value) -> i64 {
    call(rpc, method, params).expect_err(method).0
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
    assert_eq!(reason_text(reason::MALFORMED), "malformed transaction");
    assert_eq!(reason_text(reason::BAD_SIGNATURE), "invalid signature");
    assert_eq!(reason_text(reason::WRONG_CHAIN), "wrong chain id");
    assert_eq!(
        reason_text(reason::BAD_NONCE),
        "nonce too low, too high or at its maximum"
    );
    assert_eq!(
        reason_text(reason::INSUFFICIENT_FUNDS),
        "insufficient funds for value and gas"
    );
    assert_eq!(reason_text(reason::GAS_TOO_LOW), "intrinsic gas too low");
    assert_eq!(
        reason_text(reason::UNSUPPORTED),
        "transaction type not supported"
    );
    assert_eq!(
        reason_text(reason::FEE_TOO_LOW),
        "max fee per gas below the base fee or the priority fee"
    );
    assert_eq!(
        reason_text(reason::GAS_LIMIT_TOO_HIGH),
        "gas limit above the transaction or block cap"
    );
    assert_eq!(
        reason_text(reason::INITCODE_TOO_LARGE),
        "max initcode size exceeded"
    );
    assert_eq!(reason_text(reason::SENDER_NOT_EOA), "sender not an eoa");
    assert_eq!(reason_text(99), "rejected");
    assert_eq!(legacy_fields(b"garbage"), Legacy::default());
    assert_eq!(legacy_fields(&[0xC0]), Legacy::default());
    let e: RpcError = solo_node::NodeError::Decode("x").into();
    assert_eq!(e.code, -32603);
    let e: RpcError = solo_node::SubmitError::Rejected(reason::BAD_NONCE).into();
    assert_eq!(e.code, -32000);
    let e: RpcError = solo_node::SubmitError::Node(solo_node::NodeError::Decode("x")).into();
    assert_eq!(e.code, -32603);
    assert_eq!(e.clone(), e);
}

#[test]
fn static_and_info_methods() {
    let alice = Wallet::new(1);
    let mut rpc = rpc(&alice);
    assert_eq!(ok(&mut rpc, "eth_chainId", json!([])), "0x539");
    assert_eq!(ok(&mut rpc, "net_version", json!([])), "1337");
    assert_eq!(ok(&mut rpc, "web3_clientVersion", json!([])), "solo/0.0.1");
    assert_eq!(ok(&mut rpc, "eth_blockNumber", json!([])), "0x0");
    assert_eq!(ok(&mut rpc, "eth_gasPrice", json!([])), quantity(GAS_PRICE));
    assert_eq!(
        ok(&mut rpc, "eth_maxPriorityFeePerGas", json!([])),
        quantity(GAS_PRICE)
    );
    assert_eq!(ok(&mut rpc, "eth_estimateGas", json!([{}])), "0x5208");
    assert_eq!(ok(&mut rpc, "eth_syncing", json!([])), json!(false));
    assert!(!rpc.stopped);
    assert_eq!(ok(&mut rpc, "solo_stop", json!([])), json!(true));
    assert!(rpc.stopped);
    assert_eq!(ok(&mut rpc, "eth_accounts", json!([])), json!([]));
    assert_eq!(
        ok(
            &mut rpc,
            "eth_getCode",
            json!([data(&alice.address), "latest"])
        ),
        "0x"
    );
    let history = ok(&mut rpc, "eth_feeHistory", json!(["0x1", "latest", []]));
    assert_eq!(history["oldestBlock"], "0x0");
    assert_eq!(history["baseFeePerGas"][0], quantity(GAS_PRICE));
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
    assert_eq!(err_code(&mut rpc, "eth_getBalance", json!([])), -32602);
    assert_eq!(err_code(&mut rpc, "eth_getBalance", json!([5])), -32602);
    assert_eq!(
        err_code(&mut rpc, "eth_getBalance", json!([data(&[1; 19])])),
        -32602
    );
    assert_eq!(err_code(&mut rpc, "eth_getBalance", json!(["abc"])), -32602);
    assert_eq!(
        err_code(
            &mut rpc,
            "eth_getTransactionReceipt",
            json!([data(&[1; 31])])
        ),
        -32602
    );
    assert_eq!(
        err_code(&mut rpc, "eth_getBlockByNumber", json!(["0xzz"])),
        -32602
    );
    assert_eq!(
        err_code(&mut rpc, "eth_getBlockByNumber", json!(["12"])),
        -32602
    );
    assert_eq!(
        err_code(&mut rpc, "eth_sendRawTransaction", json!(["0x0"])),
        -32602
    );
}

#[test]
fn request_envelope() {
    let alice = Wallet::new(1);
    let mut rpc = rpc(&alice);
    // Missing method.
    let r = rpc.handle(&json!({ "id": "a" }));
    assert_eq!(r["error"]["code"], -32600);
    assert_eq!(r["id"], "a");
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
    assert_eq!(
        ok(&mut rpc, "eth_getTransactionByHash", json!([hash_hex])),
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
    // Genesis block is synthetic.
    let genesis = ok(&mut rpc, "eth_getBlockByNumber", json!(["earliest", true]));
    assert_eq!(genesis["number"], "0x0");
    assert_eq!(genesis["transactions"], json!([]));
    assert_eq!(
        ok(&mut rpc, "eth_getBlockByNumber", json!(["latest"])),
        genesis
    );

    rpc.node_mut().tick(1_000 + SLOT_MS).unwrap();
    assert_eq!(ok(&mut rpc, "eth_blockNumber", json!([])), "0x1");
    let receipt = ok(&mut rpc, "eth_getTransactionReceipt", json!([hash_hex]));
    assert_eq!(receipt["status"], "0x1");
    assert_eq!(receipt["blockNumber"], "0x1");
    assert_eq!(receipt["transactionIndex"], "0x0");
    assert_eq!(receipt["from"], data(&alice.address));
    assert_eq!(receipt["to"], data(&bob.address));
    assert_eq!(receipt["gasUsed"], "0x5208");
    assert_eq!(receipt["effectiveGasPrice"], quantity(GAS_PRICE));
    assert_eq!(receipt["contractAddress"], Value::Null);
    let block_hash = receipt["blockHash"].as_str().unwrap().to_owned();
    assert_ne!(block_hash, data(&[0; 32]));

    let tx = ok(&mut rpc, "eth_getTransactionByHash", json!([hash_hex]));
    assert_eq!(tx["hash"], hash_hex);
    assert_eq!(tx["nonce"], "0x0");
    assert_eq!(tx["value"], quantity(5 * ETHER));
    assert_eq!(tx["gas"], "0x5208");
    assert_eq!(tx["gasPrice"], quantity(GAS_PRICE));
    assert_eq!(tx["blockHash"], block_hash);
    assert_eq!(tx["input"], "0x");
    let v = parse_quantity(tx["v"].as_str().unwrap()).unwrap();
    assert!(v == CHAIN_ID * 2 + 35 || v == CHAIN_ID * 2 + 36);
    assert_eq!(tx["r"].as_str().unwrap().len(), 66);

    let by_number = ok(&mut rpc, "eth_getBlockByNumber", json!(["0x1", false]));
    assert_eq!(by_number["hash"], block_hash);
    assert_eq!(by_number["number"], "0x1");
    assert_eq!(by_number["parentHash"], data(&[0; 32]));
    assert_eq!(by_number["transactions"], json!([hash_hex]));
    assert_eq!(by_number["gasUsed"], "0x5208");
    assert_eq!(
        by_number["timestamp"],
        quantity(u128::from((1_000 + SLOT_MS) / 1000))
    );
    let full = ok(&mut rpc, "eth_getBlockByHash", json!([block_hash, true]));
    assert_eq!(full["transactions"][0], tx);
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
        ok(&mut rpc, "eth_getBlockByNumber", json!(["0x2"])),
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
    assert_eq!(
        ok(&mut rpc, "eth_feeHistory", json!([]))["oldestBlock"],
        "0x1"
    );
}

#[test]
fn rejections_carry_reasons() {
    let alice = Wallet::new(1);
    let bob = Wallet::new(2);
    let poor = Wallet::new(3);
    let mut rpc = rpc(&alice);
    let cases: [(Vec<u8>, &str); 8] = [
        (alice.transfer(1, bob.address, ETHER, 21_000), "nonce"),
        (
            poor.transfer(0, bob.address, ETHER, 21_000),
            "insufficient funds",
        ),
        (
            alice.transfer(0, bob.address, ETHER, 20_999),
            "intrinsic gas",
        ),
        (
            alice.transfer_on(0, bob.address, ETHER, 21_000, CHAIN_ID + 1, &[]),
            "wrong chain",
        ),
        // Calldata is executed now, so 21 000 gas no longer covers a transfer that carries it.
        (
            alice.transfer_on(0, bob.address, ETHER, 21_000, CHAIN_ID, &[1]),
            "intrinsic gas",
        ),
        // A blob transaction (type 3) is not executed, and a first byte below 0x80
        // such as 'g' names a typed envelope of no type the kernel executes.
        (vec![0x03, 0xC0], "transaction type not supported"),
        (b"garbage".to_vec(), "transaction type not supported"),
        // A legacy transaction that is an empty RLP list.
        (vec![0xC0], "malformed"),
    ];
    for (raw, text) in cases {
        let (code, message) =
            call(&mut rpc, "eth_sendRawTransaction", json!([data(&raw)])).unwrap_err();
        assert_eq!(code, -32000);
        assert!(message.contains(text), "{text}: {message}");
    }
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
    // Starve every kernel call of gas: each method surfaces the failure as -32603.
    rpc.node_mut().kernel_gas = 0;
    let methods: [(&str, Value); 12] = [
        ("eth_chainId", json!([])),
        ("net_version", json!([])),
        ("eth_blockNumber", json!([])),
        ("eth_getBalance", json!([data(&alice.address)])),
        ("eth_getTransactionCount", json!([data(&alice.address)])),
        (
            "eth_sendRawTransaction",
            json!([data(&alice.transfer(1, bob.address, 1, 21_000))]),
        ),
        ("eth_getTransactionReceipt", json!([hash_hex])),
        ("eth_getTransactionByHash", json!([hash_hex])),
        ("eth_getBlockByNumber", json!(["latest"])),
        ("eth_getBlockByNumber", json!(["0x1"])),
        ("eth_getBlockByHash", json!([data(&[1; 32])])),
        ("eth_feeHistory", json!([])),
    ];
    for (method, params) in methods {
        let (code, message) = call(&mut rpc, method, params).expect_err(method);
        assert_eq!(code, -32603, "{method}");
        assert!(message.contains("ended with"), "{method}: {message}");
    }
}
