//! The `orange dev` command: argument errors, genesis parsing, and a live node
//! that answers JSON-RPC and exits after the requested number of blocks.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};

use orange_abi::Decode;
use orange_abi::chain::GenesisParams;
use orange_cli::{USAGE, arg, load_kernel, parse_genesis, run, run_until, snapshot};

const KERNEL: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../orange-node/tests/fixtures/kernel.elf"
);
const HELLO: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../orange-recompile/tests/fixtures/hello.elf"
);

/// A kernel gas budget that lets the driver start (80 228) but not produce a block
/// (276 548) with the pinned kernel fixture, bisected on 2026-10-24 in-process (the
/// dev key, this genesis, slots of 60 ms, in a debug host build) on the kernel with
/// the block log and snapshot record of spec 22, the fee market of spec 23 with its
/// bounds and the payout that leaves jailed validators out (spec 23 §2, spec 15
/// §10.2), the stake-weighted threshold shares of spec 15 §6.8, the genesis block of
/// spec 20 §3.4, delegator votes and governed calls (spec 13 §9.3, §9.5), and the
/// running tallies, the system receipt and the genesis time of codex ADR 0045
/// (spec 13 §9.3, spec 20 §3.4, §3.5). Before that last change the figures were
/// 79 399 and 275 029, which the earlier fixture still gives by the same bisection.
/// The new kernel takes 80 169 and 275 782 on this genesis without a genesis time
/// (bisected with `--data-dir`, where `orange dev` takes the file as written): 770
/// and 753 more, its rebuilt code (the parameters' decoding with their optional
/// last field, which every step runs, and the read of the sweep list at the end of
/// every block). The remaining 55 are the genesis time `orange dev` without a data
/// directory now gives this genesis: eight more bytes of parameters to decode. The
/// block figure depends on how the test host is built (a release build gave 275 036
/// where a debug build gave 275 029). Rebuilding the fixture may move both numbers:
/// the kernel with bounded RLP nesting (spec 20 §2.1) and the vote for a held
/// proposal (spec 08 §5) moved the block from 275 837 to 276 003 (the only
/// validator leads every view and skips the new check: the rebuilt code), and left
/// the start at 80 224; the kernel with tip fetching (spec 08 §5a, codex ADR 0049)
/// moved them to 80 228 and 276 548 (the only validator never fetches, and a
/// proposal on its own tip leaves the new check at once: the rebuilt code); the
/// kernel whose DKG phases end on completion or at a deadline, with the tip sent
/// to a leader behind it (codex ADR 0048), gave 80 224 and 276 009 on its own, and
/// merged with tip fetching gives 80 228 and 276 548 again (this chain has no
/// staking and one validator, so none of the new code runs).
const STARVED_GAS: &str = "100000";

const GENESIS: &str = r#"{"chainId": 1337, "slotMs": 60, "maxTxs": 4,
  "alloc": {"0x1111111111111111111111111111111111111111": "1000000000000000000", "0x2222222222222222222222222222222222222222": 5,
    "0x3333333333333333333333333333333333333333": {"balance": "0x10", "nonce": "0x1", "code": "0x602a60005260206000f3",
      "storage": {"0x00": "0x2a", "0x0000000000000000000000000000000000000000000000000000000000000001": "0x0102"}}}}"#;

/// A path for `name`, removed when the test ends.
fn scratch(name: &str) -> String {
    let path = orange_scratch::Scratch::new("cli", name).keep();
    path.to_str().unwrap().to_owned()
}

fn args(list: &[&str]) -> Vec<String> {
    std::iter::once("orange")
        .chain(list.iter().copied())
        .map(str::to_owned)
        .collect()
}

fn dev_args(genesis: &str, extra: &[&str]) -> Vec<String> {
    let mut list = vec![
        "dev",
        "--kernel",
        KERNEL,
        "--genesis",
        genesis,
        "--rpc",
        "127.0.0.1:0",
    ];
    list.extend_from_slice(extra);
    args(&list)
}

fn genesis_file(name: &str, text: &str) -> String {
    let path = scratch(name);
    std::fs::write(&path, text).unwrap();
    path
}

#[test]
fn genesis_parsing() {
    let g = parse_genesis(GENESIS).unwrap();
    assert_eq!(g.chain_id, 1337);
    let params = GenesisParams::from_bytes(&g.params).unwrap();
    assert_eq!((params.slot_ms, params.max_txs), (60, 4));
    assert_eq!(params.allocations.0.len(), 3);
    assert_eq!(params.allocations.0[0].balance, 1_000_000_000_000_000_000);
    assert_eq!(params.allocations.0[1].balance, 5);
    // The genesis time, in Unix seconds as geth writes it; none without one.
    assert_eq!(params.genesis_time, 0);
    for (text, seconds) in [
        (r#"{"chainId": 1, "timestamp": 1792800000}"#, 1_792_800_000),
        (r#"{"chainId": 1, "timestamp": "0x10"}"#, 16),
        (r#"{"chainId": 1, "timestamp": "17"}"#, 17),
    ] {
        let p = GenesisParams::from_bytes(&parse_genesis(text).unwrap().params).unwrap();
        assert_eq!(p.genesis_time, seconds, "{text}");
    }
    for text in [
        r#"{"chainId": 1, "timestamp": -1}"#,
        r#"{"chainId": 1, "timestamp": "soon"}"#,
        r#"{"chainId": 1, "timestamp": "0x10000000000000000"}"#,
        r#"{"chainId": 1, "timestamp": true}"#,
    ] {
        assert_eq!(
            parse_genesis(text).unwrap_err(),
            "genesis: timestamp must be Unix seconds, a number or a decimal or 0x hex string",
            "{text}"
        );
    }
    // Without validators the dev key is the single validator; with them, the given ids.
    let set = <orange_abi::chain::ValidatorSet as Decode>::from_bytes(&g.validators).unwrap();
    assert_eq!(set.validators.0.len(), 1);
    assert_eq!(
        set.validators.0[0].id,
        orange_node::validator_id(&orange_cli::dev_key())
    );
    let explicit = parse_genesis(
        r#"{"chainId": 1, "validators": ["0x0101010101010101010101010101010101010101010101010101010101010101", "0x0202020202020202020202020202020202020202020202020202020202020202"]}"#,
    )
    .unwrap();
    let set =
        <orange_abi::chain::ValidatorSet as Decode>::from_bytes(&explicit.validators).unwrap();
    assert_eq!(set.validators.0.len(), 2);
    assert_eq!(set.validators.0[1].id, [2; 32]);
    let defaults = parse_genesis(r#"{"chainId": 1}"#).unwrap();
    let params = GenesisParams::from_bytes(&defaults.params).unwrap();
    assert_eq!((params.slot_ms, params.max_txs), (400, 64));
    assert!(params.allocations.0.is_empty());
    let cases = [
        ("{", "not valid JSON"),
        ("{}", "chainId missing"),
        (r#"{"chainId": 1, "alloc": {"11": 1}}"#, "0x hex"),
        (r#"{"chainId": 1, "alloc": {"0x11": 1}}"#, "20 bytes"),
        (
            r#"{"chainId": 1, "alloc": {"0x1111111111111111111111111111111111111111": "x"}}"#,
            "decimal or 0x hex",
        ),
        (
            r#"{"chainId": 1, "alloc": {"0x1111111111111111111111111111111111111111": "0xzz"}}"#,
            "decimal or 0x hex",
        ),
        (
            r#"{"chainId": 1, "alloc": {"0x1111111111111111111111111111111111111111": -1}}"#,
            "non-negative",
        ),
        (
            r#"{"chainId": 1, "alloc": {"0x1111111111111111111111111111111111111111": true}}"#,
            "string or number",
        ),
        (
            r#"{"chainId": 1, "maxTxs": 5000000000}"#,
            "maxTxs too large",
        ),
        (r#"{"chainId": 1, "validators": [5]}"#, "must be strings"),
        (r#"{"chainId": 1, "validators": ["zz"]}"#, "0x hex"),
        (r#"{"chainId": 1, "validators": ["0x01"]}"#, "32 bytes"),
        (r#"{"chainId": 1, "validators": {}}"#, "must be an array"),
    ];
    for (text, expected) in cases {
        let message = parse_genesis(text).unwrap_err();
        assert!(message.contains(expected), "{text}: {message}");
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn genesis_accounts() {
    let g = parse_genesis(GENESIS).unwrap();
    let params = GenesisParams::from_bytes(&g.params).unwrap();
    // A geth-style account predeploys a contract: code, nonce and storage words left-padded.
    let predeploy = &params.allocations.0[2];
    assert_eq!(predeploy.address, [0x33; 20]);
    assert_eq!((predeploy.balance, predeploy.nonce), (16, 1));
    assert_eq!(
        predeploy.code,
        vec![0x60, 0x2a, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3]
    );
    let mut one = [0u8; 32];
    one[31] = 1;
    let mut value = [0u8; 32];
    value[30..].copy_from_slice(&[1, 2]);
    let slots: Vec<([u8; 32], [u8; 32])> = predeploy
        .storage
        .0
        .iter()
        .map(|s| (s.key, s.value))
        .collect();
    let mut answer = [0u8; 32];
    answer[31] = 0x2a;
    assert_eq!(slots, vec![([0; 32], answer), (one, value)]);
    // Every field of an account is optional; numbers may be decimal or hex, strings or not.
    let minimal = parse_genesis(
        r#"{"chainId": 1, "alloc": {
          "0x1111111111111111111111111111111111111111": {},
          "0x2222222222222222222222222222222222222222": {"balance": 7, "nonce": 3},
          "0x3333333333333333333333333333333333333333": {"balance": "12", "nonce": "9"},
          "0x4444444444444444444444444444444444444444": {"storage": {"0x01": "0x00"}},
          "0x5555555555555555555555555555555555555555": {"nonce": 1, "storage": {"0x01": "0x02"}}}}"#,
    )
    .unwrap();
    let accounts = GenesisParams::from_bytes(&minimal.params)
        .unwrap()
        .allocations
        .0;
    let fields: Vec<(u128, u64, usize, usize)> = accounts
        .iter()
        .map(|a| (a.balance, a.nonce, a.code.len(), a.storage.0.len()))
        .collect();
    assert_eq!(
        fields,
        vec![
            (0, 0, 0, 0),
            (7, 3, 0, 0),
            (12, 9, 0, 0),
            (0, 0, 0, 1),
            (0, 1, 0, 1)
        ]
    );
    let cases = [
        (
            r#"{"chainId": 1, "alloc": {"0x1111111111111111111111111111111111111111": {"balance": true}}}"#,
            "string or number",
        ),
        (
            r#"{"chainId": 1, "alloc": {"0x1111111111111111111111111111111111111111": {"nonce": -1}}}"#,
            "nonce must be a non-negative integer",
        ),
        (
            r#"{"chainId": 1, "alloc": {"0x1111111111111111111111111111111111111111": {"nonce": "0x10000000000000000"}}}"#,
            "nonce must be a decimal or 0x hex string",
        ),
        (
            r#"{"chainId": 1, "alloc": {"0x1111111111111111111111111111111111111111": {"nonce": "one"}}}"#,
            "nonce must be a decimal or 0x hex string",
        ),
        (
            r#"{"chainId": 1, "alloc": {"0x1111111111111111111111111111111111111111": {"nonce": []}}}"#,
            "nonce must be a string or number",
        ),
        (
            r#"{"chainId": 1, "alloc": {"0x1111111111111111111111111111111111111111": {"code": 5}}}"#,
            "code must be 0x hex",
        ),
        (
            r#"{"chainId": 1, "alloc": {"0x1111111111111111111111111111111111111111": {"code": "6000"}}}"#,
            "code must be 0x hex",
        ),
        (
            r#"{"chainId": 1, "alloc": {"0x1111111111111111111111111111111111111111": {"storage": []}}}"#,
            "storage must be an object",
        ),
        (
            r#"{"chainId": 1, "alloc": {"0x1111111111111111111111111111111111111111": {"storage": {"0x1": "0x01"}}}}"#,
            "storage keys and values",
        ),
        (
            r#"{"chainId": 1, "alloc": {"0x1111111111111111111111111111111111111111": {"storage": {"0x01": 1}}}}"#,
            "storage keys and values",
        ),
        (
            r#"{"chainId": 1, "alloc": {"0x1111111111111111111111111111111111111111": {"storage": {"0x01": "0x000000000000000000000000000000000000000000000000000000000000000001"}}}}"#,
            "storage keys and values",
        ),
        // Storage on an account with neither code nor nonce, where a CREATE could land.
        (
            r#"{"chainId": 1, "alloc": {"0x1111111111111111111111111111111111111111": {"storage": {"0x01": "0x02"}}}}"#,
            "an account with storage needs code or a non-zero nonce",
        ),
    ];
    for (text, expected) in cases {
        let message = parse_genesis(text).unwrap_err();
        assert!(message.contains(expected), "{text}: {message}");
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn argument_and_file_errors() {
    assert_eq!(run(&args(&[])).unwrap_err(), USAGE);
    assert_eq!(run(&args(&["start"])).unwrap_err(), USAGE);
    assert_eq!(run(&args(&["dev"])).unwrap_err(), "--kernel is required");
    assert_eq!(arg(&args(&["dev", "--kernel"]), "--kernel"), None);
    assert!(
        run(&args(&["dev", "--kernel", "/nonexistent/k.elf"]))
            .unwrap_err()
            .starts_with("/nonexistent/k.elf: ")
    );
    let garbage = scratch("garbage.elf");
    std::fs::write(&garbage, b"not an elf").unwrap();
    assert!(
        load_kernel(&garbage)
            .unwrap_err()
            .contains("cannot parse ELF")
    );
    let noexport = scratch("noexport.elf");
    let mut bytes = std::fs::read(HELLO).unwrap();
    for i in 0..bytes.len() - 19 {
        if &bytes[i..i + 19] == b"orange_export_main\0" {
            bytes[i] = b'x';
        }
    }
    std::fs::write(&noexport, &bytes).unwrap();
    assert!(
        load_kernel(&noexport)
            .unwrap_err()
            .contains("no orange_export_* symbol")
    );
    let module = load_kernel(KERNEL).unwrap();
    let precompiled = scratch("kernel.orange");
    std::fs::write(&precompiled, &module).unwrap();
    assert_eq!(load_kernel(&precompiled).unwrap(), module);
    assert_eq!(
        run(&args(&["dev", "--kernel", KERNEL])).unwrap_err(),
        "--genesis is required"
    );
    assert!(
        run(&args(&[
            "dev",
            "--kernel",
            KERNEL,
            "--genesis",
            "/nonexistent/g.json"
        ]))
        .unwrap_err()
        .starts_with("/nonexistent/g.json: ")
    );
    let bad = genesis_file("bad.json", "{}");
    assert_eq!(
        run(&args(&["dev", "--kernel", KERNEL, "--genesis", &bad])).unwrap_err(),
        "genesis: chainId missing"
    );
    let good = genesis_file("good.json", GENESIS);
    assert_eq!(
        run(&dev_args(&good, &["--blocks", "x"])).unwrap_err(),
        "--blocks must be a number"
    );
    assert_eq!(
        run(&dev_args(&good, &["--kernel-gas", "x"])).unwrap_err(),
        "--kernel-gas must be a number"
    );
    assert_eq!(
        run(&dev_args(&good, &["--query-gas", "-1"])).unwrap_err(),
        "--query-gas must be a number"
    );
    assert_eq!(
        run(&dev_args(&good, &["--state-history", "x"])).unwrap_err(),
        "--state-history must be a number"
    );
    assert_eq!(
        run(&dev_args(&good, &["--state-history", "0"])).unwrap_err(),
        "--state-history must be at least 1"
    );
    assert_eq!(
        run(&dev_args(&good, &["--archive", "--state-history", "8"])).unwrap_err(),
        "--archive and --state-history exclude each other"
    );
    // A guest without the kernel entrypoints fails to boot.
    let message = run(&dev_args(&good, &[])
        .iter()
        .map(|a| {
            if a == KERNEL {
                HELLO.to_owned()
            } else {
                a.clone()
            }
        })
        .collect::<Vec<_>>())
    .unwrap_err();
    assert!(message.contains("kernel"), "{message}");
    // Too little gas for even the driver start is a boot error.
    let message = run(&dev_args(&good, &["--kernel-gas", "1"])).unwrap_err();
    assert!(message.contains("OutOfGas"), "{message}");
    // An address that cannot be bound.
    let message = run(&args(&[
        "dev",
        "--kernel",
        KERNEL,
        "--genesis",
        &good,
        "--rpc",
        "nope",
    ]))
    .unwrap_err();
    assert!(message.starts_with("nope: "), "{message}");
}

#[test]
fn in_process_node_stops_on_blocks_and_on_request() {
    let good = genesis_file("inproc.json", GENESIS);
    // Produces one block, then the block limit ends the loop.
    run(&dev_args(
        &good,
        &["--blocks", "1", "--query-gas", "100000000"],
    ))
    .unwrap();
    // A genesis that names its time keeps it, in memory too.
    let dated = genesis_file(
        "inproc-dated.json",
        &GENESIS.replacen('{', r#"{"timestamp": 1792800000,"#, 1),
    );
    run(&dev_args(&dated, &["--blocks", "1"])).unwrap();
    // The node keeps the state history the flags ask for: its own window,
    // every block as an archive node, or the default.
    for (flags, expected) in [
        (&["--state-history", "8"][..], 8),
        (&["--archive"][..], orange_node::ARCHIVE),
        (&[][..], orange_node::STATE_HISTORY),
    ] {
        let mut kept = None;
        run_until(&dev_args(&good, flags), |rpc| {
            kept = Some(rpc.node().state_history);
            false
        })
        .unwrap();
        assert_eq!(kept, Some(expected), "{flags:?}");
    }
    // A starved kernel fails every slot; the caller's condition ends the loop after enough ticks.
    let mut iterations = 0;
    run_until(
        &dev_args(&good, &["--blocks", "1", "--kernel-gas", STARVED_GAS]),
        |rpc| {
            iterations += 1;
            assert!(rpc.node().executed.is_empty());
            iterations < 40
        },
    )
    .unwrap();
}

struct Live {
    child: std::process::Child,
    addr: String,
    stderr: BufReader<std::process::ChildStderr>,
}

impl Drop for Live {
    /// A failed assertion must not leave a node running.
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn start(extra: &[&str]) -> Live {
    // Tests run at once in one process: each node gets a genesis file of its
    // own, which another test's cleanup cannot remove under it.
    static STARTED: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = STARTED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let good = genesis_file(&format!("live-{n}.json"), GENESIS);
    let mut child = Command::new(env!("CARGO_BIN_EXE_orange"))
        .args([
            "dev",
            "--kernel",
            KERNEL,
            "--genesis",
            &good,
            "--rpc",
            "127.0.0.1:0",
        ])
        .args(extra)
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stderr = BufReader::new(child.stderr.take().unwrap());
    let mut line = String::new();
    stderr.read_line(&mut line).unwrap();
    assert!(line.contains("chain id 1337"), "{line}");
    let addr = line.rsplit("http://").next().unwrap().trim().to_owned();
    Live {
        child,
        addr,
        stderr,
    }
}

fn post(addr: &str, body: &str) -> String {
    let mut stream = TcpStream::connect(addr).unwrap();
    write!(
        stream,
        "POST / HTTP/1.1\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    let mut out = String::new();
    stream.read_to_string(&mut out).unwrap();
    out.rsplit("\r\n\r\n").next().unwrap().to_owned()
}

#[test]
fn live_node_serves_rpc_and_stops_after_blocks() {
    let mut live = start(&["--blocks", "2"]);
    let reply = post(
        &live.addr,
        r#"{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}"#,
    );
    assert!(reply.contains(r#""result":"0x539""#), "{reply}");
    let reply = post(
        &live.addr,
        r#"{"jsonrpc":"2.0","id":2,"method":"eth_getBalance","params":["0x2222222222222222222222222222222222222222","latest"]}"#,
    );
    assert!(reply.contains(r#""result":"0x5""#), "{reply}");
    let status = live.child.wait().unwrap();
    assert!(status.success(), "{status}");
    let rest: Vec<String> = (&mut live.stderr).lines().map(Result::unwrap).collect();
    assert!(rest.iter().any(|l| l.starts_with("block 1 0x")), "{rest:?}");
    assert!(rest.iter().any(|l| l.starts_with("block 2 0x")), "{rest:?}");
}

#[test]
fn live_node_applies_geth_style_accounts() {
    // No block limit: the node runs until asked to stop, so no request races its exit.
    let mut live = start(&["--rpc-stop"]);
    let reply = post(
        &live.addr,
        r#"{"jsonrpc":"2.0","id":1,"method":"eth_getTransactionCount","params":["0x3333333333333333333333333333333333333333","latest"]}"#,
    );
    assert!(reply.contains(r#""result":"0x1""#), "{reply}");
    let reply = post(
        &live.addr,
        r#"{"jsonrpc":"2.0","id":2,"method":"eth_getBalance","params":["0x3333333333333333333333333333333333333333","latest"]}"#,
    );
    assert!(reply.contains(r#""result":"0x10""#), "{reply}");
    // A development chain serves tracing (spec 20 §8.5, §9).
    let reply = post(
        &live.addr,
        r#"{"jsonrpc":"2.0","id":4,"method":"debug_traceBlockByNumber","params":["0x0",{"tracer":"callTracer"}]}"#,
    );
    assert!(reply.contains(r#""result":[]"#), "{reply}");
    let reply = post(
        &live.addr,
        r#"{"jsonrpc":"2.0","id":3,"method":"orange_stop"}"#,
    );
    assert!(reply.contains(r#""result":true"#), "{reply}");
    assert!(live.child.wait().unwrap().success());
}

/// Without `--rpc-stop` the node serves no `orange_stop`, and it answers a
/// browser page only from an origin `--rpc-cors` names (spec 20 §8.5):
/// before, any page its operator opened could stop it.
#[test]
fn a_dev_node_serves_browsers_and_orange_stop_only_when_told_to() {
    let mut live = start(&["--rpc-cors", "http://wallet.example"]);
    let stop = r#"{"jsonrpc":"2.0","id":1,"method":"orange_stop"}"#;
    let refused = post(&live.addr, stop);
    assert!(
        refused.contains("-32601") && refused.contains("--rpc-stop"),
        "{refused}"
    );
    let from = |origin: &str| {
        let mut stream = TcpStream::connect(&live.addr).unwrap();
        let body = r#"{"jsonrpc":"2.0","id":2,"method":"eth_chainId","params":[]}"#;
        write!(
            stream,
            "POST / HTTP/1.1\r\nOrigin: {origin}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .unwrap();
        let mut out = String::new();
        stream.read_to_string(&mut out).unwrap();
        out
    };
    let page = from("http://evil.example");
    assert!(page.starts_with("HTTP/1.1 403"), "{page}");
    let wallet = from("http://wallet.example");
    assert!(
        wallet.contains("Access-Control-Allow-Origin: http://wallet.example\r\n")
            && wallet.ends_with(r#""result":"0x539"}"#),
        "{wallet}"
    );
    live.child.kill().unwrap();
    live.child.wait().unwrap();
}

#[test]
fn starved_kernel_reports_node_errors_and_stops_on_request() {
    let mut dev = start(&["--blocks", "1", "--kernel-gas", STARVED_GAS, "--rpc-stop"]);
    // The first slot runs out of gas; the node reports it and keeps serving queries.
    let mut first = String::new();
    dev.stderr.read_line(&mut first).unwrap();
    assert!(first.starts_with("node error:"), "{first}");
    assert!(first.contains("OutOfGas"), "{first}");
    let reply = post(
        &dev.addr,
        r#"{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}"#,
    );
    assert!(reply.contains(r#""result":"0x0""#), "{reply}");
    let reply = post(
        &dev.addr,
        r#"{"jsonrpc":"2.0","id":2,"method":"orange_stop"}"#,
    );
    assert!(reply.contains(r#""result":true"#), "{reply}");
    assert!(dev.child.wait().unwrap().success());
}

#[test]
fn usage_exit_code() {
    let out = Command::new(env!("CARGO_BIN_EXE_orange")).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).starts_with("usage:"));
}

#[test]
fn keys() {
    let hex = "0101010101010101010101010101010101010101010101010101010101010101";
    let key = orange_cli::parse_key(hex).unwrap();
    assert_eq!(
        orange_cli::parse_key(&format!("0x{hex}"))
            .unwrap()
            .to_bytes(),
        key.to_bytes()
    );
    let text = orange_cli::describe_key(&key);
    // The all-ones key is the README's funded account.
    assert!(
        text.contains("\naddress   0x1a642f0e3c3af545e7acbd38b07251b3990914f1\n"),
        "{text}"
    );
    assert!(text.starts_with("validator 0x"));
    // The DKG encryption key to list under staking.keys: 48 bytes of hex.
    let dkg = text.rsplit("dkg       ").next().unwrap();
    assert_eq!(dkg.len(), 2 + 96, "{text}");
    assert_eq!(
        dkg,
        orange_rpc::methods::data(&orange_node::keystore::encryption_key(&key))
    );
    run(&args(&["key", hex])).unwrap();
    assert!(run(&args(&["key"])).unwrap_err().contains("64 hex"));
    assert!(run(&args(&["key", "xyz"])).unwrap_err().contains("64 hex"));
    assert!(
        run(&args(&["key", &"00".repeat(32)]))
            .unwrap_err()
            .contains("not a valid")
    );
    assert_eq!(
        orange_cli::args_all(&args(&["--peer", "a", "x", "--peer", "b"]), "--peer"),
        vec!["a".to_owned(), "b".to_owned()]
    );
}

fn free_ports(n: usize) -> Vec<String> {
    let listeners: Vec<std::net::TcpListener> = (0..n)
        .map(|_| std::net::TcpListener::bind("127.0.0.1:0").unwrap())
        .collect();
    listeners
        .iter()
        .map(|l| l.local_addr().unwrap().to_string())
        .collect()
}

#[test]
fn node_command_runs_a_multi_validator_chain() {
    let seeds: Vec<String> = (1..=4u8)
        .map(|i| format!("{:02x}", 0x50 + i).repeat(32))
        .collect();
    let ids: Vec<String> = seeds
        .iter()
        .map(|s| {
            orange_rpc::methods::data(&orange_node::validator_id(
                &orange_cli::parse_key(s).unwrap(),
            ))
        })
        .collect();
    let genesis = genesis_file(
        "multi.json",
        &format!(
            r#"{{"chainId": 1337, "slotMs": 400, "maxTxs": 4, "alloc": {{}}, "validators": ["{}"]}}"#,
            ids.join("\", \"")
        ),
    );
    let ports = free_ports(5);
    // Recompile once for all five nodes: five debug recompiles at once would start the
    // validators minutes apart on a loaded machine.
    let kernel = scratch("multi-kernel.orange");
    std::fs::write(&kernel, load_kernel(KERNEL).unwrap()).unwrap();
    // Every node runs until all five have three blocks, so none strands the others by leaving.
    let counts: std::sync::Arc<Vec<std::sync::atomic::AtomicUsize>> = std::sync::Arc::new(
        (0..5)
            .map(|_| std::sync::atomic::AtomicUsize::new(0))
            .collect(),
    );
    // `127.0.0.1:<port>` as `localhost:<port>`, which the system resolves.
    let by_name = |addr: &str| addr.replace("127.0.0.1", "localhost");
    let mut threads = Vec::new();
    for i in 0..5 {
        let mut list: Vec<String> = vec![
            "node".into(),
            "--kernel".into(),
            kernel.clone(),
            "--genesis".into(),
            genesis.clone(),
            "--listen".into(),
            ports[i].clone(),
            "--rpc".into(),
            "127.0.0.1:0".into(),
        ];
        if i < 4 {
            let data = scratch(&format!("multi-data-{i}"));
            let _ = std::fs::remove_dir_all(&data);
            list.extend(["--key".into(), seeds[i].clone(), "--data-dir".into(), data]);
            // Validators find each other by peer exchange from the first one's
            // address, which the last one has by name (spec 09 §5a.5).
            if i > 0 {
                let boot = if i == 3 {
                    by_name(&ports[0])
                } else {
                    ports[0].clone()
                };
                list.extend(["--bootstrap".into(), boot]);
            }
            if i == 1 {
                list.extend(["--max-peers".into(), "16".into()]);
                list.extend(["--outbound-peers".into(), "4".into()]);
                list.extend(["--advertise".into(), ports[1].clone()]);
            }
        } else {
            list.extend(["--peer".into(), by_name(&ports[0])]);
        }
        let argv = args(&list.iter().map(String::as_str).collect::<Vec<_>>());
        let counts = std::sync::Arc::clone(&counts);
        threads.push(std::thread::spawn(move || {
            use std::sync::atomic::Ordering::SeqCst;
            // Generous: an instrumented build under a parallel test load is slow. The
            // assertion below fails the test if the deadline is what ended the loop.
            let deadline = std::time::Instant::now() + std::time::Duration::from_mins(3);
            run_until(&argv, |rpc| {
                counts[i].store(rpc.node().executed.len(), SeqCst);
                let all = counts.iter().all(|c| c.load(SeqCst) >= 3);
                !all && std::time::Instant::now() < deadline
            })
            .unwrap();
        }));
    }
    for t in threads {
        t.join().unwrap();
    }
    let blocks: Vec<usize> = counts
        .iter()
        .map(|c| c.load(std::sync::atomic::Ordering::SeqCst))
        .collect();
    assert!(blocks.iter().all(|b| *b >= 3), "{blocks:?}");
}

/// Options a command would ignore are refused before anything opens:
/// `orange dev` has no transport and one key, and a trust key without a
/// snapshot to verify trusts nothing.
#[test]
fn options_a_command_would_ignore_are_refused() {
    let dev = |extra: &[&str]| {
        let mut list = vec!["dev", "--kernel", KERNEL, "--genesis", "unread.json"];
        list.extend_from_slice(extra);
        run(&args(&list)).unwrap_err()
    };
    assert_eq!(
        dev(&["--data-dir", "d", "--sync-from-peers"]),
        "orange dev does not take --sync-from-peers: it runs no peer-to-peer transport; use orange node"
    );
    for flag in [
        "--serve-snapshots",
        "--peer",
        "--listen",
        "--bootstrap",
        "--max-peers",
        "--outbound-peers",
        "--advertise",
        "--no-discovery",
    ] {
        assert!(
            dev(&[flag]).contains("runs no peer-to-peer transport"),
            "{flag}"
        );
    }
    assert_eq!(
        dev(&["--key-file", "k"]),
        "orange dev does not take --key-file: it always signs with the development key; use orange node"
    );
    assert!(dev(&["--key", "k"]).contains("development key"));
    let node = run(&args(&[
        "node",
        "--kernel",
        KERNEL,
        "--genesis",
        "unread.json",
        "--trust-key",
        "0x00",
    ]));
    assert_eq!(
        node.unwrap_err(),
        "--trust-key verifies a snapshot: give it with --snapshot or --sync-from-peers"
    );
}

#[test]
fn node_command_errors() {
    let good = genesis_file("node-errors.json", GENESIS);
    let base = [
        "node",
        "--kernel",
        KERNEL,
        "--genesis",
        &good,
        "--rpc",
        "127.0.0.1:0",
    ];
    let with = |extra: &[&str]| {
        let mut list = base.to_vec();
        list.extend_from_slice(extra);
        run(&args(&list))
    };
    assert!(
        with(&["--peer", "nowhere"])
            .unwrap_err()
            .contains("expected ip:port")
    );
    // Peer exchange's options are checked, and refused beside --no-discovery.
    assert_eq!(
        with(&["--bootstrap", "nowhere"]).unwrap_err(),
        "--bootstrap nowhere: expected ip:port or host:port"
    );
    assert_eq!(
        with(&["--max-peers", "0"]).unwrap_err(),
        "--max-peers must be at least 1"
    );
    assert!(with(&["--outbound-peers", "x"]).is_err());
    assert_eq!(
        with(&["--advertise", "0.0.0.0:1"]).unwrap_err(),
        "--advertise 0.0.0.0:1: expected an ip:port peers can dial"
    );
    assert_eq!(
        with(&["--no-discovery", "--bootstrap", "127.0.0.1:1"]).unwrap_err(),
        "--bootstrap configures peer exchange, which --no-discovery turns off"
    );
    assert!(with(&["--key", "zz"]).unwrap_err().contains("64 hex"));
    assert!(
        with(&["--listen", "nope"])
            .unwrap_err()
            .starts_with("nope: ")
    );
    // A validator keeps its driver state on disk, or does not run; a data
    // directory that cannot be made is named.
    assert!(
        with(&["--key", &"51".repeat(32)])
            .unwrap_err()
            .contains("--data-dir is required for a validator")
    );
    let file = genesis_file("not-a-directory", "x");
    assert!(
        with(&["--data-dir", &file])
            .unwrap_err()
            .starts_with(&format!("{file}: "))
    );
    // An observer with the default listen address stops on request like any
    // node; with a data directory it keeps its driver state there. Without
    // peer exchange it only dials what it is told to, and still accepts no
    // more than --max-peers.
    let mut iterations = 0;
    let data = scratch("observer-data");
    let mut list = base.to_vec();
    list.extend(["--data-dir", &data, "--no-discovery", "--max-peers", "4"]);
    run_until(&args(&list), |_| {
        iterations += 1;
        iterations < 5
    })
    .unwrap();
    assert!(std::path::Path::new(&data).join("driver.state").exists());
}

/// A dev chain whose feature-gate epochs of four blocks are its snapshot
/// epochs (spec 22 §6).
const EPOCHS: &str = r#"{"chainId": 1337, "slotMs": 60, "maxTxs": 4, "epochBlocks": 4,
  "alloc": {"0x1111111111111111111111111111111111111111": "1000000000000000000"}}"#;

/// The height a node's chain store holds and the snapshot record's, read
/// once the node in the data directory `dir` has started.
fn opened(genesis: &str, dir: &str, extra: &[&str]) -> u64 {
    let mut height = 0;
    let mut list = vec!["--data-dir", dir];
    list.extend_from_slice(extra);
    run_until(&dev_args(genesis, &list), |rpc| {
        height = rpc.node().chain_store().unwrap().head();
        false
    })
    .unwrap();
    height
}

#[test]
#[allow(clippy::too_many_lines)]
fn snapshots_export_verify_import_and_start_a_node() {
    let genesis = genesis_file("snap.json", EPOCHS);
    let staking = genesis_file(
        "snap-staking.json",
        &EPOCHS.replace("\"epochBlocks\": 4", "\"staking\": {\"epochBlocks\": 4}"),
    );
    let source = scratch("snap-source");
    // A dev chain on disk, long enough for several epochs' records.
    run(&dev_args(
        &genesis,
        &["--blocks", "16", "--data-dir", &source],
    ))
    .unwrap();
    let file = scratch("snap.snap");
    let snap = |list: &[&str]| {
        let mut full = vec!["snapshot"];
        full.extend_from_slice(list);
        snapshot::run(&args(&full))
    };
    let out = snap(&["export", "--data-dir", &source, "--out", &file]).unwrap();
    assert!(out.starts_with("snapshot of chain 1337 at epoch "), "{out}");
    assert!(
        out.ends_with(&format!("vote certificate written to {file}")),
        "{out}"
    );
    let first = scratch("snap-0.snap");
    let out = snap(&[
        "export",
        "--data-dir",
        &source,
        "--out",
        &first,
        "--epoch",
        "0",
    ])
    .unwrap();
    assert!(out.contains("at epoch 0: block 4,"), "{out}");
    // It verifies against the genesis set of a chain without staking.
    let out = snap(&["verify", "--snapshot", &file, "--genesis", &genesis]).unwrap();
    assert!(out.ends_with(" verifies"), "{out}");
    // Under a trusted group key a vote certificate is not enough; a chain
    // with staking needs one; a key must be one.
    let key = format!("0x{}", "00".repeat(96));
    let err = snap(&[
        "verify",
        "--snapshot",
        &file,
        "--genesis",
        &genesis,
        "--trust-key",
        &key,
    ])
    .unwrap_err();
    assert!(
        err.contains("a vote certificate needs the genesis validator set"),
        "{err}"
    );
    let err = snap(&["verify", "--snapshot", &file, "--genesis", &staking]).unwrap_err();
    assert_eq!(
        err,
        "a chain with staking needs --trust-key: its genesis set is not its set for good"
    );
    let err = snap(&[
        "verify",
        "--snapshot",
        &file,
        "--genesis",
        &genesis,
        "--trust-key",
        "0x12",
    ])
    .unwrap_err();
    assert_eq!(
        err,
        "--trust-key must be 96 bytes of 0x hex, or <key set id>:<them>"
    );
    // A key set is named by its id and group key (spec 22 §7.5), on a chain
    // with a threshold key; its horizon is the chain's unbonding period, and
    // a file carries no handoffs, so the key set must certify it itself.
    let verify_under = |genesis: &str, trust: &str| {
        snap(&[
            "verify",
            "--snapshot",
            &file,
            "--genesis",
            genesis,
            "--trust-key",
            trust,
        ])
        .unwrap_err()
    };
    assert_eq!(
        verify_under(&genesis, &format!("x:{key}")),
        "--trust-key: x is not a key set id"
    );
    assert_eq!(
        verify_under(&genesis, &format!("3:{key}")),
        "--trust-key names a key set, and this chain has no threshold key"
    );
    assert_eq!(
        verify_under(&staking, &format!("3:{key}")),
        "--trust-key names a key set, and this chain has no threshold key"
    );
    let threshold = genesis_file(
        "snap-threshold.json",
        &EPOCHS.replace(
            "\"epochBlocks\": 4",
            "\"staking\": {\"epochBlocks\": 4, \"dkgPhaseBlocks\": 1, \"unbondingEpochs\": 4, \"maxKeyAge\": 2}",
        ),
    );
    let err = verify_under(&threshold, &format!("3:{key}"));
    assert!(
        err.contains("a vote certificate needs the genesis validator set"),
        "{err}"
    );
    assert_eq!(
        verify_under(&threshold, "3:0x12"),
        "--trust-key must be 96 bytes of 0x hex, or <key set id>:<them>"
    );
    // Arguments and files that are missing or wrong.
    assert_eq!(snap(&[]).unwrap_err(), USAGE);
    assert_eq!(
        snap(&["export", "--out", &file]).unwrap_err(),
        "--data-dir is required"
    );
    assert_eq!(
        snap(&["export", "--data-dir", &source]).unwrap_err(),
        "--out is required"
    );
    let not_dir = genesis_file("snap-not-a-dir", "x");
    let err = snap(&["export", "--data-dir", &not_dir, "--out", &file]).unwrap_err();
    assert!(err.ends_with("(is the node still running?)"), "{err}");
    let locked = scratch("snap-driver-refuses");
    std::fs::create_dir_all(std::path::Path::new(&locked).join("persist.log")).unwrap();
    let err = snap(&["export", "--data-dir", &locked, "--out", &file]).unwrap_err();
    assert!(err.starts_with(&format!("{locked}: ")), "{err}");
    let empty = scratch("snap-empty");
    let err = snap(&["export", "--data-dir", &empty, "--out", &file]).unwrap_err();
    assert!(err.contains("the store holds no chain"), "{err}");
    let err = snap(&["export", "--data-dir", &source, "--out", &empty]).unwrap_err();
    assert!(
        err.starts_with(&format!("{empty}: snapshot file: ")),
        "{err}"
    );
    assert_eq!(
        snap(&["verify", "--snapshot", &file]).unwrap_err(),
        "--genesis is required"
    );
    assert_eq!(
        snap(&["verify", "--genesis", &genesis]).unwrap_err(),
        "--snapshot is required"
    );
    let missing = scratch("snap-missing");
    let err = snap(&["verify", "--snapshot", &file, "--genesis", &missing]).unwrap_err();
    assert!(err.starts_with(&format!("{missing}: ")), "{err}");
    let err = snap(&["verify", "--snapshot", &missing, "--genesis", &genesis]).unwrap_err();
    assert!(
        err.starts_with(&format!("{missing}: snapshot file: ")),
        "{err}"
    );
    // Imported into an empty directory, once.
    let target = scratch("snap-target");
    let import = |dir: &str, extra: &[&str]| {
        let mut list = vec!["import", "--snapshot", &file, "--genesis", &genesis];
        list.extend_from_slice(extra);
        if !dir.is_empty() {
            list.extend(["--data-dir", dir]);
        }
        snap(&list)
    };
    assert_eq!(import(&target, &[]).unwrap_err(), "--kernel is required");
    assert_eq!(
        import("", &["--kernel", KERNEL]).unwrap_err(),
        "--data-dir is required"
    );
    assert!(import(&not_dir, &["--kernel", KERNEL]).is_err());
    let out = import(&target, &["--kernel", KERNEL]).unwrap();
    assert!(out.ends_with(&format!("imported into {target}")), "{out}");
    let err = import(&target, &["--kernel", KERNEL]).unwrap_err();
    assert!(err.contains("already holds chain state at height"), "{err}");
    // A node started over it resumes at the snapshot's height (a validator
    // alone proposes and executes the next block in the step that starts
    // it) and goes on.
    let height = orange_store::Snapshot::open(std::path::Path::new(&file))
        .unwrap()
        .header
        .height;
    assert!(height >= 8 && height.is_multiple_of(4), "{height}");
    let resumed = opened(&genesis, &target, &[]);
    assert!((height..=height + 1).contains(&resumed), "{resumed}");
    run(&dev_args(
        &genesis,
        &["--data-dir", &target, "--blocks", "2"],
    ))
    .unwrap();
    assert!(opened(&genesis, &target, &[]) >= resumed + 2);
    // `--snapshot` does both in one go, wants a data directory, verifies
    // first, and leaves a directory that holds a chain as it is.
    let joined = scratch("snap-joined");
    let started = opened(&genesis, &joined, &["--snapshot", &file]);
    assert!((height..=height + 1).contains(&started), "{started}");
    let err = run(&dev_args(&genesis, &["--snapshot", &file])).unwrap_err();
    assert_eq!(
        err,
        "--snapshot needs --data-dir, where the snapshot is loaded"
    );
    let err = run(&dev_args(
        &genesis,
        &["--data-dir", &empty, "--snapshot", &missing],
    ))
    .unwrap_err();
    assert!(
        err.starts_with(&format!("{missing}: snapshot file: ")),
        "{err}"
    );
    let err = run(&dev_args(
        &staking,
        &["--data-dir", &empty, "--snapshot", &file],
    ))
    .unwrap_err();
    assert!(err.contains("needs --trust-key"), "{err}");
    let kept = opened(&genesis, &source, &["--snapshot", &first]);
    assert!(kept >= 16, "{kept}");
    // A node that keeps its state in memory has nowhere to load it.
    let mut memory = orange_node::Node::open(
        &load_kernel(KERNEL).unwrap(),
        &parse_genesis(EPOCHS).unwrap(),
        orange_node::NodeConfig::default(),
    )
    .unwrap();
    let loaded = orange_store::Snapshot::open(std::path::Path::new(&file)).unwrap();
    assert_eq!(
        snapshot::import_into(&mut memory, &loaded).unwrap_err(),
        "a snapshot loads into a chain store on disk"
    );
    // A threshold certificate is named as one.
    let mut threshold = orange_store::Snapshot::open(std::path::Path::new(&file)).unwrap();
    threshold.header.certificate = vec![2; 97];
    assert!(snapshot::describe(&threshold).ends_with(", threshold certificate"));
}

#[test]
#[allow(clippy::too_many_lines)]
fn a_node_fetches_its_state_from_a_peer_that_serves_snapshots() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::SeqCst};

    use orange_node::statesync::{Offer, SyncEvent};
    let seed = "61".repeat(32);
    let id = orange_rpc::methods::data(&orange_node::validator_id(
        &orange_cli::parse_key(&seed).unwrap(),
    ));
    let text = format!(
        r#"{{"chainId": 1337, "slotMs": 250, "maxTxs": 4, "epochBlocks": 4, "validators": ["{id}"],
  "alloc": {{"0x1111111111111111111111111111111111111111": "1000000000000000000"}}}}"#
    );
    // Slots long enough that the joiner's catch-up request (spec 08 §7a)
    // is answered within a view on a loaded machine.
    let genesis = genesis_file("sync.json", &text);
    // The same validator and chain id over another allocation: another
    // genesis block, which a sync must refuse.
    let other = genesis_file(
        "sync-other.json",
        &text.replace("1000000000000000000", "1000000000000000001"),
    );
    let staking = genesis_file(
        "sync-staking.json",
        &text.replace("\"epochBlocks\": 4", "\"staking\": {\"epochBlocks\": 4}"),
    );
    let kernel = scratch("sync-kernel.orange");
    std::fs::write(&kernel, load_kernel(KERNEL).unwrap()).unwrap();
    let ports = free_ports(4);
    let node_args = |genesis: &str, listen: &str, extra: &[&str]| {
        let mut list = vec![
            "node",
            "--kernel",
            &kernel,
            "--genesis",
            genesis,
            "--listen",
            listen,
            "--rpc",
            "127.0.0.1:0",
        ];
        list.extend_from_slice(extra);
        args(&list)
    };
    // Arguments that cannot work are refused before anything runs.
    let nowhere = node_args(&genesis, &ports[3], &["--sync-from-peers"]);
    assert_eq!(
        run(&nowhere).unwrap_err(),
        "--sync-from-peers needs --data-dir, where the snapshots are kept"
    );
    let unserved = node_args(&genesis, &ports[3], &["--serve-snapshots"]);
    assert_eq!(
        run(&unserved).unwrap_err(),
        "--serve-snapshots needs --data-dir, where the snapshots are kept"
    );
    let both_dir = scratch("sync-both");
    let both = node_args(
        &genesis,
        &ports[3],
        &[
            "--data-dir",
            &both_dir,
            "--sync-from-peers",
            "--snapshot",
            "x",
        ],
    );
    assert!(run(&both).unwrap_err().contains("give one"));
    let staked_dir = scratch("sync-staking");
    let staked = node_args(
        &staking,
        &ports[3],
        &["--data-dir", &staked_dir, "--sync-from-peers"],
    );
    assert!(run(&staked).unwrap_err().contains("needs --trust-key"));
    let blocked = scratch("sync-blocked");
    std::fs::create_dir_all(&blocked).unwrap();
    std::fs::write(std::path::Path::new(&blocked).join("statesync"), b"a file").unwrap();
    let blocked_args = node_args(
        &genesis,
        &ports[3],
        &["--data-dir", &blocked, "--sync-from-peers"],
    );
    assert!(run(&blocked_args).unwrap_err().contains("statesync"));
    // A validator serving snapshots, until the joiners are done.
    let served = scratch("sync-served");
    let finished = Arc::new(AtomicBool::new(false));
    let serving = {
        let argv = node_args(
            &genesis,
            &ports[0],
            &["--key", &seed, "--data-dir", &served, "--serve-snapshots"],
        );
        let finished = Arc::clone(&finished);
        std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + std::time::Duration::from_mins(3);
            run_until(&argv, |_| {
                !finished.load(SeqCst) && std::time::Instant::now() < deadline
            })
            .unwrap();
        })
    };
    // An observer joins from it: it fetches the snapshot, imports it, and
    // follows the chain from there.
    let joined = scratch("sync-joined");
    let oldest = Arc::new(AtomicU64::new(0));
    let observed = Arc::clone(&oldest);
    let joining = node_args(
        &genesis,
        &ports[1],
        &[
            "--data-dir",
            &joined,
            "--sync-from-peers",
            "--peer",
            &ports[0],
        ],
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_mins(2);
    let mut executed = 0;
    run_until(&joining, |rpc| {
        observed.store(rpc.node().oldest_state(), SeqCst);
        executed = rpc.node().executed.len();
        executed < 2 && std::time::Instant::now() < deadline
    })
    .unwrap();
    let height = oldest.load(SeqCst);
    assert!(height >= 4 && height.is_multiple_of(4), "{height}");
    assert!(executed >= 2, "{executed}");
    assert!(!std::path::Path::new(&joined).join("statesync").exists());
    // Started again, the directory keeps its chain.
    let again = node_args(
        &genesis,
        &ports[1],
        &[
            "--data-dir",
            &joined,
            "--sync-from-peers",
            "--peer",
            &ports[0],
        ],
    );
    let mut resumed = 0;
    run_until(&again, |rpc| {
        resumed = rpc.node().chain_store().unwrap().head();
        false
    })
    .unwrap();
    assert!(resumed >= height, "{resumed}");
    // A node of another genesis refuses what the peer serves.
    let elsewhere = scratch("sync-elsewhere");
    let refused = node_args(
        &other,
        &ports[2],
        &[
            "--data-dir",
            &elsewhere,
            "--sync-from-peers",
            "--peer",
            &ports[0],
        ],
    );
    let err = run(&refused).unwrap_err();
    assert!(err.contains("another genesis block"), "{err}");
    finished.store(true, SeqCst);
    serving.join().unwrap();
    // What the operator reads of each event.
    let offer = Offer {
        epoch: 2,
        height: 8,
        state_root: [0; 32],
        entries: 9,
    };
    assert_eq!(
        snapshot::describe_event(&SyncEvent::Target(offer)),
        "fetching epoch 2 (block 8, 9 entries)"
    );
    assert_eq!(
        snapshot::describe_event(&SyncEvent::Resumed { slices: 3 }),
        "3 slices verified by an earlier run kept"
    );
    assert!(
        snapshot::describe_event(&SyncEvent::Banned {
            peer: [1; 32],
            why: "lies"
        })
        .ends_with("no longer asked: lies")
    );
    assert!(
        snapshot::describe_event(&SyncEvent::SetAside {
            peer: [1; 32],
            epoch: 4
        })
        .starts_with("epoch 4 set aside: its certificate from peer 0x0101")
    );
    assert_eq!(
        snapshot::describe_event(&SyncEvent::PastHorizon {
            epoch: 9,
            horizon: 6
        }),
        "epoch 9 offered, past the trusted key set's horizon (epoch 6): not fetched; trust a newer key set to fetch it"
    );
    assert_eq!(
        snapshot::describe_event(&SyncEvent::Followed {
            handoffs: 3,
            key_set: 7
        }),
        "3 handoffs verified, reaching key set 7"
    );
}
