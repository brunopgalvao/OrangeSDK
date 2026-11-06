//! Tracing (spec 20 §9): `debug_traceTransaction`, `debug_traceBlockByNumber`,
//! `debug_traceBlockByHash` and `debug_traceCall` with `callTracer`,
//! `prestateTracer` and `noopTracer`, against reference output.
//!
//! The reference traces in `tests/fixtures/trace` are what a reference node
//! (anvil 1.7.1, Osaka, chain id 1337, whose tracers are revm-inspectors'
//! geth-compatible ones) answered on 2026-11-07 for the same signed
//! transactions from the same key and nonces, so the same addresses: the
//! hand-assembled contracts below, deployed and called in the order of
//! [`scenario`]. Where geth itself (go-ethereum 1.17, `eth/tracers/native`)
//! differs from that node, the test applies geth's rule to the reference
//! before comparing, and says so: the top frame's `gas` is the
//! transaction's gas limit (geth's `OnTxStart`), `onlyTopCall` counts no
//! frames in a log's `position`, a prestate names `codeHash` beside code,
//! and leaves out accounts that were empty before (`includeEmpty`). The
//! sender's and the beneficiary's balances depend on each chain's fees and
//! are checked against this chain's own `eth_getBalance`.

mod common;

use common::{Fields, SLOT_MS, Wallet, err, hex, node_funding, ok};
use orange_abi::chain::{BlockHeader, Proposal};
use orange_abi::codec::Seq;
use orange_abi::trace::{CallFrame, TxTrace, frame_error, kind};
use orange_abi::types::{Block, Effect};
use orange_abi::{Decode, Encode};
use orange_host::hash::keccak256;
use orange_rpc::Rpc;
use orange_rpc::methods::{data, quantity};
use orange_rpc::trace::{call_json, error_text, tracer_of};
use serde_json::{Value, json};

/// The child: `LOG1(0xaa…, 1)`, returns the word 42.
const CHILD: &str = "60016000527faaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa60206000a1602a60005260206000f3";
/// Reverts with `Error("nope")`.
const REVERTER: &str = "7f08c379a000000000000000000000000000000000000000000000000000000000600052602060045260046024527f6e6f70650000000000000000000000000000000000000000000000000000000060445260646000fd";
/// The designated invalid opcode.
const INVALID: &str = "fe";
/// `(child, reverter, invalid)`: `LOG0`; `CALL` child; `LOG0`; `CALL`
/// reverter; `STATICCALL` the identity precompile; `DELEGATECALL` child;
/// `CALL` invalid with 1 000 gas.
const PARENT: &str = "60006000a0602060006000600060006000355af15060006000a0600060006000600060006020355af150600060006004600060045afa5060006000600060006000355af450600060006000600060006040356103e8f15000";
/// `CREATE` with 1 wei and `CREATE2` (salt 7) of `CALLER SELFDESTRUCT`.
const FACTORY: &str = "6133ff6000526002601e6001f05060076002601e6000f55000";
/// Creation code of the store: its constructor sets slot 1 to 5; it adds 1
/// to slot 0 and clears slot 1.
const STORE_INIT: &str = "6005600155600f8060106000396000f3600054600101600055600060015500";
/// 130 `STATICCALL`s of the identity precompile with 100 000 bytes each:
/// 13 MB of frame inputs, past what a trace records.
const FLOOD: &str = "60825b60006000620186a0600060045afa50600190038060025700";

/// Creation code that deploys `runtime`.
fn deploy_code(runtime: &str) -> Vec<u8> {
    let code = hex(runtime);
    let mut out = vec![
        0x60,
        u8::try_from(code.len()).unwrap(),
        0x80,
        0x60,
        0x0b,
        0x60,
        0x00,
        0x39,
        0x60,
        0x00,
        0xf3,
    ];
    out.extend(code);
    out
}

/// An RPC that serves the `debug` namespace, as `orange dev` and
/// `orange node --rpc-debug` do.
fn debug_rpc(node: orange_node::Node) -> Rpc {
    let mut rpc = Rpc::new(node);
    rpc.debug_allowed = true;
    rpc
}

fn wallet() -> Wallet {
    Wallet::new(0x11)
}

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

fn tx(
    w: &Wallet,
    nonce: u64,
    to: Option<[u8; 20]>,
    value: u128,
    gas_limit: u64,
    input: &[u8],
) -> Vec<u8> {
    w.legacy(&Fields {
        nonce,
        to,
        value,
        gas_limit,
        data: input,
    })
}

fn word(address: &[u8; 20]) -> [u8; 32] {
    let mut out = [0; 32];
    out[12..].copy_from_slice(address);
    out
}

/// The contracts' addresses: child, reverter, invalid, parent, factory, store.
struct Contracts {
    child: [u8; 20],
    reverter: [u8; 20],
    invalid: [u8; 20],
    parent: [u8; 20],
    factory: [u8; 20],
    store: [u8; 20],
}

impl Contracts {
    fn parent_input(&self) -> Vec<u8> {
        [word(&self.child), word(&self.reverter), word(&self.invalid)].concat()
    }
}

/// The reference transactions, nonce by nonce, each in a block of its own
/// but for nonces 9 and 10, which share one: deployments (0 to 4), a
/// transfer (5), the parent's calls (6), a revert (7), the factory (8), the
/// child then the parent (9, 10), the store's deployment and call (11, 12).
/// The hashes, by nonce.
fn scenario(rpc: &mut Rpc) -> (Vec<String>, Contracts) {
    let w = wallet();
    let at = |n| common::created_address(&w.address, n);
    let c = Contracts {
        child: at(0),
        reverter: at(1),
        invalid: at(2),
        parent: at(3),
        factory: at(4),
        store: at(11),
    };
    let mut hashes = Vec::new();
    let one = |rpc: &mut Rpc, hashes: &mut Vec<String>, raw: Vec<u8>| {
        hashes.push(send(rpc, &raw));
        mine(rpc);
    };
    for (n, code) in [CHILD, REVERTER, INVALID, PARENT, FACTORY]
        .iter()
        .enumerate()
    {
        one(
            rpc,
            &mut hashes,
            tx(&w, n as u64, None, 0, 200_000, &deploy_code(code)),
        );
    }
    one(rpc, &mut hashes, tx(&w, 5, Some(dead()), 1, 21_000, &[]));
    one(
        rpc,
        &mut hashes,
        tx(&w, 6, Some(c.parent), 0, 300_000, &c.parent_input()),
    );
    one(
        rpc,
        &mut hashes,
        tx(&w, 7, Some(c.reverter), 0, 100_000, &[]),
    );
    one(
        rpc,
        &mut hashes,
        tx(&w, 8, Some(c.factory), 1, 300_000, &[]),
    );
    let first = send(rpc, &tx(&w, 9, Some(c.child), 0, 100_000, &[]));
    let second = send(
        rpc,
        &tx(&w, 10, Some(c.parent), 0, 300_000, &c.parent_input()),
    );
    mine(rpc);
    hashes.extend([first, second]);
    one(
        rpc,
        &mut hashes,
        tx(&w, 11, None, 0, 200_000, &hex(STORE_INIT)),
    );
    one(rpc, &mut hashes, tx(&w, 12, Some(c.store), 0, 100_000, &[]));
    for hash in &hashes {
        let receipt = ok(rpc, "eth_getTransactionReceipt", json!([hash]));
        assert!(!receipt.is_null(), "{hash} mined");
    }
    (hashes, c)
}

fn dead() -> [u8; 20] {
    let mut out = [0; 20];
    out[18..].copy_from_slice(&[0xde, 0xad]);
    out
}

fn fixture(name: &str) -> Value {
    let path = format!(
        "{}/tests/fixtures/trace/{name}.json",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

/// The reference `callTracer` result under geth's rule for the top frame's
/// `gas`: the transaction's gas limit.
fn geth_call(name: &str, gas_limit: u64) -> Value {
    let mut v = fixture(name);
    v["gas"] = json!(quantity(u128::from(gas_limit)));
    v
}

fn call_tracer(with_log: bool) -> Value {
    json!({"tracer": "callTracer", "tracerConfig": {"withLog": with_log}})
}

/// A reference prestate account under geth's rules: `codeHash` beside its
/// code; `None` for an account that was empty, which geth leaves out.
fn geth_account(mut account: Value, pre: bool) -> Option<Value> {
    if let Some(code) = account
        .get("code")
        .and_then(Value::as_str)
        .map(str::to_owned)
    {
        account["codeHash"] = json!(data(&keccak256(&hex(&code[2..]))));
    }
    (!pre || account != json!({"balance": "0x0"})).then_some(account)
}

fn geth_accounts(map: &Value, pre: bool, skip: &[String]) -> Value {
    let mut out = serde_json::Map::new();
    for (address, account) in map.as_object().unwrap() {
        if skip.contains(address) {
            continue;
        }
        if let Some(account) = geth_account(account.clone(), pre) {
            out.insert(address.clone(), account);
        }
    }
    Value::Object(out)
}

/// `map` without `skip`.
fn without(map: &Value, skip: &[String]) -> Value {
    let mut out = map.as_object().unwrap().clone();
    for key in skip {
        out.remove(key);
    }
    Value::Object(out)
}

fn balance(rpc: &mut Rpc, address: &[u8; 20], height: u64) -> u128 {
    let v = ok(
        rpc,
        "eth_getBalance",
        json!([data(address), quantity(u128::from(height))]),
    );
    u128::from_str_radix(&v.as_str().unwrap()[2..], 16).unwrap()
}

/// The sender's and the beneficiary's prestate entries, from this chain's
/// balances after `height`.
fn fee_accounts(rpc: &mut Rpc, height: u64, nonce: u64) -> (Value, Option<Value>) {
    let w = wallet().address;
    let mut sender = json!({"balance": quantity(balance(rpc, &w, height))});
    if nonce != 0 {
        sender["nonce"] = json!(nonce);
    }
    let coinbase = balance(rpc, &[0; 20], height);
    (
        sender,
        (coinbase != 0).then(|| json!({"balance": quantity(coinbase)})),
    )
}

fn height_of(rpc: &mut Rpc, hash: &str) -> u64 {
    let receipt = ok(rpc, "eth_getTransactionReceipt", json!([hash]));
    u64::from_str_radix(&receipt["blockNumber"].as_str().unwrap()[2..], 16).unwrap()
}

#[test]
#[allow(clippy::too_many_lines)]
fn traces_match_the_reference() {
    let w = wallet();
    let mut rpc = debug_rpc(node_funding(&[&w]));
    let (hashes, contracts) = scenario(&mut rpc);
    let gas_limits = [
        200_000, 200_000, 200_000, 200_000, 200_000, 21_000, 300_000, 100_000, 300_000,
    ];
    // callTracer, with and without logs, for every kind of frame: a
    // creation, a plain transfer, nested calls with logs, a revert with a
    // reason, a precompile, a delegate call, an invalid opcode, CREATE,
    // CREATE2 and SELFDESTRUCT.
    for n in [0, 5, 6, 7, 8] {
        let traced = ok(
            &mut rpc,
            "debug_traceTransaction",
            json!([hashes[n], call_tracer(true)]),
        );
        assert_eq!(
            traced,
            geth_call(&format!("call{n}"), gas_limits[n]),
            "callTracer of {n}"
        );
    }
    let traced = ok(
        &mut rpc,
        "debug_traceTransaction",
        json!([hashes[12], call_tracer(true)]),
    );
    assert_eq!(traced, geth_call("call12", 100_000));
    let traced = ok(
        &mut rpc,
        "debug_traceTransaction",
        json!([hashes[6], call_tracer(false)]),
    );
    assert_eq!(traced, geth_call("calllite6", 300_000));
    let traced = ok(
        &mut rpc,
        "debug_traceTransaction",
        json!([hashes[6], {"tracer": "callTracer", "tracerConfig": {"onlyTopCall": true, "withLog": true}}]),
    );
    // geth counts only the frames it records in a log's position: none.
    let mut top = geth_call("top6", 300_000);
    top["logs"][1]["position"] = json!("0x0");
    assert_eq!(traced, top);
    // A block of two: the second transaction's logs are numbered after the
    // first's, as its receipt numbers them.
    let height = height_of(&mut rpc, &hashes[10]);
    let block = ok(
        &mut rpc,
        "debug_traceBlockByNumber",
        json!([quantity(u128::from(height)), call_tracer(true)]),
    );
    let mut second = geth_call("call6", 300_000);
    for log in 0..2 {
        let index = &mut second["logs"][log]["index"];
        *index = json!(if log == 0 { "0x1" } else { "0x3" });
    }
    second["calls"][0]["logs"][0]["index"] = json!("0x2");
    second["calls"][3]["logs"][0]["index"] = json!("0x4");
    assert_eq!(block[1], json!({"txHash": hashes[10], "result": second}));
    assert_eq!(block[0]["txHash"], json!(hashes[9]));
    assert_eq!(block[0]["result"]["logs"][0]["index"], "0x0");
    let hash = ok(
        &mut rpc,
        "eth_getBlockByNumber",
        json!([quantity(u128::from(height)), false]),
    )["hash"]
        .clone();
    assert_eq!(
        ok(
            &mut rpc,
            "debug_traceBlockByHash",
            json!([hash, call_tracer(true)])
        ),
        block
    );
    // The same call as a call, at the head: gas is the call's.
    let call = json!({"from": data(&w.address), "to": data(&contracts.parent), "input": data(&contracts.parent_input()), "gas": "0x493e0"});
    let traced = ok(
        &mut rpc,
        "debug_traceCall",
        json!([call, "latest", call_tracer(true)]),
    );
    assert_eq!(traced, geth_call("call6", 300_000));
    // prestateTracer, and its diffMode.
    let skip = [data(&w.address), data(&[0; 20])];
    for (n, nonce) in [(0, 0), (5, 5), (6, 6), (8, 8), (12, 12)] {
        let height = height_of(&mut rpc, &hashes[n]);
        let pre = ok(
            &mut rpc,
            "debug_traceTransaction",
            json!([hashes[n], {"tracer": "prestateTracer"}]),
        );
        assert_eq!(
            without(&pre, &skip),
            geth_accounts(&fixture(&format!("pre{n}")), true, &skip),
            "prestate of {n}"
        );
        let (sender, coinbase) = fee_accounts(&mut rpc, height - 1, nonce);
        assert_eq!(pre[&skip[0]], sender);
        assert_eq!(pre.get(&skip[1]), coinbase.as_ref());
        let diff = ok(
            &mut rpc,
            "debug_traceTransaction",
            json!([hashes[n], {"tracer": "prestateTracer", "tracerConfig": {"diffMode": true}}]),
        );
        let reference = fixture(&format!("diff{n}"));
        assert_eq!(
            without(&diff["pre"], &skip),
            geth_accounts(&reference["pre"], true, &skip),
            "pre of {n}"
        );
        assert_eq!(
            without(&diff["post"], &skip),
            geth_accounts(&reference["post"], false, &skip),
            "post of {n}"
        );
        let (after, _) = fee_accounts(&mut rpc, height, nonce + 1);
        assert_eq!(diff["pre"][&skip[0]], sender);
        assert_eq!(diff["post"][&skip[0]], after);
    }
    // The options: no code, no storage, the empty accounts kept.
    let options = |rpc: &mut Rpc, config: Value| {
        ok(
            rpc,
            "debug_traceTransaction",
            json!([hashes[12], {"tracer": "prestateTracer", "tracerConfig": config}]),
        )
    };
    let store = data(&contracts.store);
    let bare = options(
        &mut rpc,
        json!({"disableCode": true, "disableStorage": true}),
    );
    assert_eq!(
        bare[&store],
        json!({"balance": "0x0", "codeHash": data(&keccak256(&hex("600054600101600055600060015500"))), "nonce": 1})
    );
    let diff = options(&mut rpc, json!({"diffMode": true, "disableStorage": true}));
    assert!(
        diff["post"].get(&store).is_none(),
        "only its storage changed"
    );
    let precompile = data(&{
        let mut a = [0; 20];
        a[19] = 4;
        a
    });
    let all = ok(
        &mut rpc,
        "debug_traceTransaction",
        json!([hashes[6], {"tracer": "prestateTracer", "tracerConfig": {"includeEmpty": true}}]),
    );
    assert_eq!(all[&precompile], json!({"balance": "0x0"}));
    let all = ok(
        &mut rpc,
        "debug_traceTransaction",
        json!([hashes[6], {"tracer": "prestateTracer", "tracerConfig": {"diffMode": true, "includeEmpty": true}}]),
    );
    assert!(all["pre"].get(&precompile).is_none(), "unchanged");
    // A created contract that was empty before is in post only, unless
    // includeEmpty keeps its empty pre.
    let created = data(&contracts.child);
    let diff = ok(
        &mut rpc,
        "debug_traceTransaction",
        json!([hashes[0], {"tracer": "prestateTracer", "tracerConfig": {"diffMode": true, "includeEmpty": true}}]),
    );
    assert_eq!(diff["pre"][&created], json!({"balance": "0x0"}));
    assert_eq!(
        diff["post"][&created]["codeHash"],
        json!(data(&keccak256(&hex(CHILD))))
    );
    let diff = ok(
        &mut rpc,
        "debug_traceTransaction",
        json!([hashes[0], {"tracer": "prestateTracer", "tracerConfig": {"diffMode": true, "disableCode": true}}]),
    );
    assert_eq!(
        diff["post"][&created],
        json!({"codeHash": data(&keccak256(&hex(CHILD))), "nonce": 1})
    );
    // The factory's children, created and destroyed in the transaction,
    // are in neither, and with includeEmpty in pre alone.
    let diff = ok(
        &mut rpc,
        "debug_traceTransaction",
        json!([hashes[8], {"tracer": "prestateTracer", "tracerConfig": {"diffMode": true, "includeEmpty": true}}]),
    );
    let child = data(&common::created_address(&contracts.factory, 1));
    assert_eq!(diff["pre"][&child], json!({"balance": "0x0"}));
    assert!(diff["post"].get(&child).is_none());
    // noopTracer.
    assert_eq!(
        ok(
            &mut rpc,
            "debug_traceTransaction",
            json!([hashes[6], {"tracer": "noopTracer"}])
        ),
        json!({})
    );
    let diff = ok(
        &mut rpc,
        "debug_traceCall",
        json!([call, "latest", {"tracer": "prestateTracer", "tracerConfig": {"diffMode": true}}]),
    );
    assert!(
        diff["pre"].get(data(&contracts.parent)).is_none(),
        "the parent changes nothing"
    );
    // The genesis block records nothing.
    assert_eq!(
        ok(
            &mut rpc,
            "debug_traceBlockByNumber",
            json!(["0x0", call_tracer(false)])
        ),
        json!([])
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn tracer_objects_and_errors() {
    let w = wallet();
    let mut rpc = debug_rpc(node_funding(&[&w]));
    let hash = send(&mut rpc, &tx(&w, 0, Some(dead()), 1, 21_000, &[]));
    mine(&mut rpc);
    let trace =
        |rpc: &mut Rpc, config: Value| err(rpc, "debug_traceTransaction", json!([hash, config]));
    assert_eq!(
        err(&mut rpc, "debug_traceTransaction", json!([hash])),
        (-32000, "opcode-level tracing (the struct logger) is not supported: ask for callTracer or prestateTracer".into())
    );
    assert_eq!(trace(&mut rpc, json!({})).0, -32000);
    for (config, message) in [
        (json!("callTracer"), "tracer config must be an object"),
        (json!({"tracer": 1}), "tracer must be a string"),
        (
            json!({"tracer": "callTracer", "tracerConfig": 1}),
            "tracerConfig must be an object",
        ),
        (
            json!({"tracer": "callTracer", "tracerConfig": {"withLog": "yes"}}),
            "withLog must be a boolean",
        ),
        (
            json!({"tracer": "4byteTracer"}),
            "tracer not supported: 4byteTracer (this node runs callTracer, prestateTracer and noopTracer)",
        ),
        (
            json!({"tracer": "callTracer", "stateOverrides": {}}),
            "stateOverrides are not supported",
        ),
    ] {
        assert_eq!(trace(&mut rpc, config), (-32602, message.to_owned()));
    }
    // Options are read as geth reads them; null is false, and timeouts do nothing.
    let config = json!({"tracer": "callTracer", "timeout": "5s", "tracerConfig": {"onlyTopCall": null}, "stateOverrides": null});
    assert_eq!(
        ok(&mut rpc, "debug_traceTransaction", json!([hash, config]))["gasUsed"],
        "0x5208"
    );
    assert_eq!(tracer_of(Some(&Value::Null)).unwrap_err().code, -32000);
    assert_eq!(
        err(
            &mut rpc,
            "debug_traceTransaction",
            json!([data(&[7; 32]), call_tracer(false)])
        ),
        (-32000, "transaction not found".into())
    );
    assert_eq!(
        err(
            &mut rpc,
            "debug_traceBlockByNumber",
            json!(["0x99", call_tracer(false)])
        ),
        (-32000, "block not found".into())
    );
    assert_eq!(
        err(
            &mut rpc,
            "debug_traceBlockByHash",
            json!([data(&[7; 32]), call_tracer(false)])
        ),
        (-32000, "header for hash not found".into())
    );
    // debug_traceCall takes eth_call's checks and block parameter.
    let call = json!({"from": data(&w.address), "to": data(&dead()), "gas": "0x1"});
    assert_eq!(
        err(
            &mut rpc,
            "debug_traceCall",
            json!([call, "latest", call_tracer(false)])
        ),
        (
            -32000,
            "intrinsic gas too low: gas 1, minimum needed 21000".into()
        )
    );
    assert_eq!(
        err(
            &mut rpc,
            "debug_traceCall",
            json!([{"to": data(&dead())}, "0x99", call_tracer(false)])
        ),
        (-32000, "header not found".into())
    );
    // The trace budget and the response budget.
    rpc.node_mut().trace_gas = 10_000;
    let aborted = (
        -32000,
        "execution aborted: the trace ran past the node's trace budget (--trace-gas)".to_owned(),
    );
    assert_eq!(trace(&mut rpc, call_tracer(false)), aborted);
    assert_eq!(
        err(
            &mut rpc,
            "debug_traceCall",
            json!([{"to": data(&dead())}, "latest", call_tracer(false)])
        ),
        aborted
    );
    rpc.node_mut().trace_gas = orange_node::TRACE_GAS;
    rpc.max_response_bytes = 10;
    assert_eq!(
        trace(&mut rpc, call_tracer(false)),
        (-32003, "response too large".into())
    );
    rpc.max_response_bytes = orange_rpc::methods::MAX_RESPONSE_BYTES;
    // A trace past what the kernel records is too large, a transaction's
    // and a call's alike.
    let flood = common::created_address(&w.address, 1);
    send(&mut rpc, &tx(&w, 1, None, 0, 200_000, &deploy_code(FLOOD)));
    mine(&mut rpc);
    let hash = send(&mut rpc, &tx(&w, 2, Some(flood), 0, 5_000_000, &[]));
    mine(&mut rpc);
    assert_eq!(
        ok(&mut rpc, "eth_getTransactionReceipt", json!([hash]))["status"],
        "0x1"
    );
    assert_eq!(
        err(
            &mut rpc,
            "debug_traceTransaction",
            json!([hash, call_tracer(false)])
        ),
        (-32003, "response too large".into())
    );
    let height = height_of(&mut rpc, &hash);
    assert_eq!(
        err(
            &mut rpc,
            "debug_traceBlockByNumber",
            json!([quantity(u128::from(height)), call_tracer(false)])
        )
        .0,
        -32003
    );
    assert_eq!(
        err(
            &mut rpc,
            "debug_traceCall",
            json!([{"to": data(&flood), "gas": "0x4c4b40"}, "latest", call_tracer(false)])
        ),
        (-32003, "response too large".into())
    );
    let lite = json!({"tracer": "callTracer", "tracerConfig": {"onlyTopCall": true}});
    assert_eq!(
        ok(&mut rpc, "debug_traceTransaction", json!([hash, lite]))["type"],
        "CALL"
    );
}

/// Off unless asked for (spec 20 §8.5): every `debug_*` method is then
/// unknown, as in geth without `--http.api debug`.
#[test]
fn the_debug_namespace_is_served_only_when_asked_for() {
    let mut rpc = Rpc::new(node_funding(&[]));
    for method in [
        "debug_traceTransaction",
        "debug_traceBlockByNumber",
        "debug_traceBlockByHash",
        "debug_traceCall",
        "debug_getRawBlock",
    ] {
        assert_eq!(
            err(&mut rpc, method, json!([])),
            (
                -32601,
                format!(
                    "method not found: {method} (this node serves the debug namespace only when started with --rpc-debug)"
                )
            )
        );
    }
    rpc.debug_allowed = true;
    assert_eq!(
        ok(
            &mut rpc,
            "debug_traceBlockByNumber",
            json!(["0x0", call_tracer(false)])
        ),
        json!([])
    );
    assert_eq!(
        err(&mut rpc, "debug_getRawBlock", json!([])).1,
        "method not found: debug_getRawBlock"
    );
}

#[test]
fn a_block_whose_parent_state_is_gone_is_not_traced() {
    let w = wallet();
    let config = orange_node::NodeConfig {
        now_ms: 1_000,
        key: Some(common::node_key()),
        state_history: 2,
        ..orange_node::NodeConfig::default()
    };
    let node =
        orange_node::Node::open(&common::kernel_module(), &common::genesis(&w), config).unwrap();
    let mut rpc = debug_rpc(node);
    rpc.node_mut().start(None).unwrap();
    let hash = send(&mut rpc, &tx(&w, 0, Some(dead()), 1, 21_000, &[]));
    mine(&mut rpc);
    for _ in 0..3 {
        mine(&mut rpc);
    }
    let (code, message) = err(
        &mut rpc,
        "debug_traceTransaction",
        json!([hash, call_tracer(false)]),
    );
    assert_eq!(code, -32000);
    assert!(message.starts_with("missing trie node "), "{message}");
    assert!(
        message.contains("state of block 0 is not available"),
        "{message}"
    );
}

/// Traces from a node reopened over its chain store with driver tables
/// changed: a body that is gone, a body that differs from what the block
/// executed, and a block that records a transaction that could not run.
#[test]
#[allow(clippy::too_many_lines)]
fn traces_are_checked_against_the_block() {
    let dir = orange_scratch::Scratch::new("rpc-trace", "store");
    let w = wallet();
    let config = |persisted| orange_node::NodeConfig {
        now_ms: 1_000,
        key: Some(common::node_key()),
        persisted,
        store: orange_node::StoreConfig::Disk(dir.to_path_buf()),
        ..orange_node::NodeConfig::default()
    };
    let genesis = common::genesis(&w);
    let mut node = orange_node::Node::open(
        &common::kernel_module(),
        &genesis,
        config(std::collections::BTreeMap::default()),
    )
    .unwrap();
    node.start(None).unwrap();
    let mut rpc = debug_rpc(node);
    let first = send(&mut rpc, &tx(&w, 0, Some(dead()), 1, 21_000, &[]));
    mine(&mut rpc);
    let second = send(&mut rpc, &tx(&w, 1, Some(dead()), 1, 21_000, &[]));
    mine(&mut rpc);
    assert_eq!(rpc.node_mut().block_number().unwrap(), 2);
    // A block that records bytes that are no transaction, executed outside
    // consensus, and its body as the driver would have kept it.
    let block3 = BlockHeader {
        height: 3,
        timestamp_ms: 9_000,
        ..BlockHeader::default()
    };
    rpc.node_mut()
        .apply_effect(Effect::ExecuteBlock {
            block: Block {
                header: block3.to_bytes(),
                txs: Seq(vec![b"garbage".to_vec()]),
                participation: vec![],
            },
        })
        .unwrap();
    let mut tables = rpc.node().persisted();
    drop(rpc);
    let at = |prefix: &[u8], h: u64| [prefix, &h.to_le_bytes()[..]].concat();
    let proposal_of = |tables: &std::collections::BTreeMap<Vec<u8>, Vec<u8>>, h: u64| {
        let hash = tables[&at(b"final/", h)].clone();
        Proposal::from_bytes(&tables[&[b"prop/".as_slice(), &hash].concat()]).unwrap()
    };
    let put = |tables: &mut std::collections::BTreeMap<Vec<u8>, Vec<u8>>, p: &Proposal| {
        let bytes = p.to_bytes();
        let hash = keccak256(&bytes);
        tables.insert([b"prop/".as_slice(), &hash].concat(), bytes);
        tables.insert(at(b"final/", p.height), hash.to_vec());
        tables.insert(at(b"cert/", p.height), vec![0]);
    };
    // Block 2's body with another transaction of the sender's nonce ahead
    // of its own, which then cannot run.
    let mut two = proposal_of(&tables, 2);
    two.txs
        .0
        .insert(0, tx(&w, 1, Some([9; 20]), 2, 21_000, &[]));
    put(&mut tables, &two);
    put(
        &mut tables,
        &Proposal {
            height: 3,
            timestamp_ms: 9_000,
            txs: Seq(vec![b"garbage".to_vec()]),
            ..Proposal::default()
        },
    );
    tables.remove(&at(b"final/", 1));
    let node = orange_node::Node::open(&common::kernel_module(), &genesis, config(tables)).unwrap();
    let mut rpc = debug_rpc(node);
    assert_eq!(
        err(
            &mut rpc,
            "debug_traceTransaction",
            json!([first, call_tracer(false)])
        ),
        (
            -32000,
            "the body of block 1 is no longer kept by this node, which cannot trace it".into()
        )
    );
    assert_eq!(
        err(
            &mut rpc,
            "debug_traceTransaction",
            json!([second, call_tracer(false)])
        ),
        (
            -32000,
            format!(
                "trace diverged from block 2: transaction {second} used 0 gas with status 0, its receipt records 21000 with status 1"
            )
        )
    );
    assert_eq!(
        err(
            &mut rpc,
            "debug_traceBlockByNumber",
            json!(["0x2", call_tracer(false)])
        ),
        (
            -32000,
            "trace diverged from block 2: it executed other transactions than the block records"
                .into()
        )
    );
    let garbage = data(&keccak256(b"garbage"));
    assert_eq!(
        ok(
            &mut rpc,
            "debug_traceBlockByNumber",
            json!(["0x3", call_tracer(false)])
        ),
        json!([{"txHash": garbage, "error": "transaction could not run: it fails the kernel's validation"}])
    );
    assert_eq!(
        err(
            &mut rpc,
            "debug_traceTransaction",
            json!([garbage, call_tracer(false)])
        ),
        (
            -32000,
            "transaction could not run: it fails the kernel's validation".into()
        )
    );
}

#[test]
fn frames_as_geth_writes_them() {
    let frame = |error: u8, op: u8| CallFrame {
        error,
        op,
        stack: 1,
        bound: 2,
        ..CallFrame::default()
    };
    let texts: Vec<String> = [
        (frame_error::NONE, 0),
        (frame_error::REVERTED, 0),
        (frame_error::OUT_OF_GAS, 0),
        (frame_error::DEPTH, 0),
        (frame_error::INSUFFICIENT_BALANCE, 0),
        (frame_error::COLLISION, 0),
        (frame_error::INVALID_JUMP, 0),
        (frame_error::INVALID_OPCODE, 0xFE),
        (frame_error::INVALID_OPCODE, 0xEF),
        (frame_error::STACK_UNDERFLOW, 0),
        (frame_error::STACK_OVERFLOW, 0),
        (frame_error::WRITE_PROTECTION, 0),
        (frame_error::RETURN_DATA_OUT_OF_BOUNDS, 0),
        (frame_error::NONCE_OVERFLOW, 0),
        (frame_error::CODE_SIZE, 0),
        (frame_error::INVALID_CODE, 0),
        (frame_error::INITCODE_SIZE, 0),
        (frame_error::GAS_OVERFLOW, 0),
        (frame_error::PRECOMPILE, 0),
    ]
    .iter()
    .map(|(e, op)| error_text(&frame(*e, *op)))
    .collect();
    assert_eq!(
        texts,
        [
            "",
            "execution reverted",
            "out of gas",
            "max call depth exceeded",
            "insufficient balance for transfer",
            "contract address collision",
            "invalid jump destination",
            "invalid opcode: INVALID",
            "invalid opcode: opcode 0xef not defined",
            "stack underflow (1 <=> 2)",
            "stack limit reached 1 (2)",
            "write protection",
            "return data out of bounds",
            "nonce uint64 overflow",
            "max code size exceeded",
            "invalid code: must not begin with 0xef",
            "max initcode size exceeded",
            "gas uint64 overflow",
            "precompile failed",
        ]
    );
    // Every kind's name, a frame without a recipient, and a trace without
    // frames.
    let kinds = [
        kind::CREATE,
        kind::CREATE2,
        kind::CALLCODE,
        kind::DELEGATECALL,
        kind::STATICCALL,
        kind::SELFDESTRUCT,
        kind::CALL,
    ];
    let frames: Vec<CallFrame> = kinds
        .iter()
        .enumerate()
        .map(|(i, k)| CallFrame {
            kind: *k,
            depth: u32::from(i > 0),
            ..CallFrame::default()
        })
        .collect();
    let trace = TxTrace {
        frames: Seq(frames),
        ..TxTrace::default()
    };
    let out = call_json(&trace);
    assert_eq!(out["type"], "CREATE");
    assert!(out.get("to").is_none() && out.get("value").is_none());
    let names: Vec<&str> = out["calls"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["type"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        [
            "CREATE2",
            "CALLCODE",
            "DELEGATECALL",
            "STATICCALL",
            "SELFDESTRUCT",
            "CALL"
        ]
    );
    assert_eq!(call_json(&TxTrace::default()), json!({}));
}
