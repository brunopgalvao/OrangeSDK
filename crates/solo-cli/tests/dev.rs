//! The `solo dev` command: argument errors, genesis parsing, and a live node
//! that answers JSON-RPC and exits after the requested number of blocks.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};

use solo_abi::Decode;
use solo_abi::chain::GenesisParams;
use solo_cli::{USAGE, arg, load_kernel, parse_genesis, run, run_until};

const KERNEL: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../solo-node/tests/fixtures/kernel.elf"
);
const HELLO: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../solo-recompile/tests/fixtures/hello.elf"
);

/// A kernel gas budget that lets the driver start (about 69k) but not produce a block
/// (about 261k) with the pinned kernel fixture; rebuilding the fixture may move both numbers.
const STARVED_GAS: &str = "80000";

const GENESIS: &str = r#"{"chainId": 1337, "slotMs": 60, "maxTxs": 4,
  "alloc": {"0x1111111111111111111111111111111111111111": "1000000000000000000", "0x2222222222222222222222222222222222222222": 5,
    "0x3333333333333333333333333333333333333333": {"balance": "0x10", "nonce": "0x1", "code": "0x602a60005260206000f3",
      "storage": {"0x00": "0x2a", "0x0000000000000000000000000000000000000000000000000000000000000001": "0x0102"}}}}"#;

fn scratch(name: &str) -> String {
    let dir = std::env::temp_dir().join(format!("solo-cli-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir.join(name).to_str().unwrap().to_owned()
}

fn args(list: &[&str]) -> Vec<String> {
    std::iter::once("solo")
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
    // Without validators the dev key is the single validator; with them, the given ids.
    let set = <solo_abi::chain::ValidatorSet as Decode>::from_bytes(&g.validators).unwrap();
    assert_eq!(set.validators.0.len(), 1);
    assert_eq!(
        set.validators.0[0].id,
        solo_node::validator_id(&solo_cli::dev_key())
    );
    let explicit = parse_genesis(
        r#"{"chainId": 1, "validators": ["0x0101010101010101010101010101010101010101010101010101010101010101", "0x0202020202020202020202020202020202020202020202020202020202020202"]}"#,
    )
    .unwrap();
    let set = <solo_abi::chain::ValidatorSet as Decode>::from_bytes(&explicit.validators).unwrap();
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
    for i in 0..bytes.len() - 17 {
        if &bytes[i..i + 17] == b"solo_export_main\0" {
            bytes[i] = b'x';
        }
    }
    std::fs::write(&noexport, &bytes).unwrap();
    assert!(
        load_kernel(&noexport)
            .unwrap_err()
            .contains("no solo_export_* symbol")
    );
    let module = load_kernel(KERNEL).unwrap();
    let precompiled = scratch("kernel.solo");
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
    let good = genesis_file("live.json", GENESIS);
    let mut child = Command::new(env!("CARGO_BIN_EXE_solo"))
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
    let mut live = start(&[]);
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
    let reply = post(
        &live.addr,
        r#"{"jsonrpc":"2.0","id":3,"method":"solo_stop"}"#,
    );
    assert!(reply.contains(r#""result":true"#), "{reply}");
    assert!(live.child.wait().unwrap().success());
}

#[test]
fn starved_kernel_reports_node_errors_and_stops_on_request() {
    let mut dev = start(&["--blocks", "1", "--kernel-gas", STARVED_GAS]);
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
        r#"{"jsonrpc":"2.0","id":2,"method":"solo_stop"}"#,
    );
    assert!(reply.contains(r#""result":true"#), "{reply}");
    assert!(dev.child.wait().unwrap().success());
}

#[test]
fn usage_exit_code() {
    let out = Command::new(env!("CARGO_BIN_EXE_solo")).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).starts_with("usage:"));
}

#[test]
fn keys() {
    let hex = "0101010101010101010101010101010101010101010101010101010101010101";
    let key = solo_cli::parse_key(hex).unwrap();
    assert_eq!(
        solo_cli::parse_key(&format!("0x{hex}")).unwrap().to_bytes(),
        key.to_bytes()
    );
    let text = solo_cli::describe_key(&key);
    // The all-ones key is the README's funded account.
    assert!(
        text.ends_with("address   0x1a642f0e3c3af545e7acbd38b07251b3990914f1"),
        "{text}"
    );
    assert!(text.starts_with("validator 0x"));
    run(&args(&["key", hex])).unwrap();
    assert!(run(&args(&["key"])).unwrap_err().contains("64 hex"));
    assert!(run(&args(&["key", "xyz"])).unwrap_err().contains("64 hex"));
    assert!(
        run(&args(&["key", &"00".repeat(32)]))
            .unwrap_err()
            .contains("not a valid")
    );
    assert_eq!(
        solo_cli::args_all(&args(&["--peer", "a", "x", "--peer", "b"]), "--peer"),
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
            solo_rpc::methods::data(&solo_node::validator_id(&solo_cli::parse_key(s).unwrap()))
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
    let kernel = scratch("multi-kernel.solo");
    std::fs::write(&kernel, load_kernel(KERNEL).unwrap()).unwrap();
    // Every node runs until all five have three blocks, so none strands the others by leaving.
    let counts: std::sync::Arc<Vec<std::sync::atomic::AtomicUsize>> = std::sync::Arc::new(
        (0..5)
            .map(|_| std::sync::atomic::AtomicUsize::new(0))
            .collect(),
    );
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
            list.extend(["--key".into(), seeds[i].clone()]);
            for port in &ports[..i] {
                list.extend(["--peer".into(), port.clone()]);
            }
        } else {
            list.extend(["--peer".into(), ports[0].clone()]);
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
    assert!(with(&["--key", "zz"]).unwrap_err().contains("64 hex"));
    assert!(
        with(&["--listen", "nope"])
            .unwrap_err()
            .starts_with("nope: ")
    );
    // An observer with the default listen address stops on request like any node.
    let mut iterations = 0;
    run_until(&args(&base), |_| {
        iterations += 1;
        iterations < 5
    })
    .unwrap();
}
