//! `solo devnet` and `solo upgrade` on real processes: a devnet is
//! initialized, run, watched, stopped and restarted; a kernel upgrade is
//! staged and proposed over JSON-RPC and every mistake is named; and the
//! rehearsal script runs end to end against four validators. The compose
//! stack's rehearsal runs only with `SOLO_DOCKER` set
//! (`tools/compose-rehearsal.sh` says so otherwise).

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};

use solo_abi::Decode;
use solo_abi::chain::GenesisParams;
use solo_cli::client;
use solo_cli::devnet::{Conditions, Devnet, FUNDED, MANIFEST};
use solo_cli::{USAGE, parse_genesis, parse_key, run};
use solo_rpc::methods::data;

const SOLO: &str = env!("CARGO_BIN_EXE_solo");
const KERNEL: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../solo-node/tests/fixtures/kernel.elf"
);
const KERNEL_V2: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../solo-node/tests/fixtures/kernel_v2.elf"
);
const REHEARSAL: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tools/rehearse-upgrade.sh"
);
const COMPOSE_REHEARSAL: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tools/compose-rehearsal.sh"
);
/// A seed that makes a devnet's keys reproducible.
const SEED: &str = "0x5eed5eed5eed5eed5eed5eed5eed5eed5eed5eed5eed5eed5eed5eed5eed5eed";
/// A key that is not the governance account.
const STRANGER: &str = "0x1111111111111111111111111111111111111111111111111111111111111111";
/// Doctor limits a healthy node meets on an instrumented build under load.
const TOLERANT: [&str; 6] = [
    "--max-call-ms",
    "600000",
    "--max-head-age",
    "600",
    "--min-peers",
    "0",
];

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("solo-devnet-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir.join(name)
}

fn solo(args: &[&str]) -> Output {
    Command::new(SOLO).args(args).output().unwrap()
}

/// Runs `solo` with `args`, expecting success; its standard output.
fn ok(args: &[&str]) -> String {
    let out = solo(args);
    assert!(
        out.status.success(),
        "{args:?} failed: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

/// Runs `solo` with `args`, expecting the usage exit code; its standard error.
fn err(args: &[&str]) -> String {
    let out = solo(args);
    assert_eq!(
        out.status.code(),
        Some(2),
        "{args:?}: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    String::from_utf8(out.stderr).unwrap()
}

fn str_of(path: &Path) -> &str {
    path.to_str().unwrap()
}

/// Initializes a devnet of `validators` on free ports with short epochs.
fn init(dir: &Path, validators: &str, extra: &[&str]) -> String {
    let mut args = vec![
        "devnet",
        "init",
        "--dir",
        str_of(dir),
        "--kernel",
        KERNEL,
        "--validators",
        validators,
        "--p2p-port",
        "0",
        "--rpc-port",
        "0",
        "--epoch-blocks",
        "12",
        "--dkg-phase-blocks",
        "3",
    ];
    args.extend_from_slice(extra);
    ok(&args)
}

fn genesis_params(devnet: &Devnet) -> GenesisParams {
    let text = std::fs::read_to_string(devnet.genesis()).unwrap();
    GenesisParams::from_bytes(&parse_genesis(&text).unwrap().params).unwrap()
}

#[test]
#[allow(clippy::too_many_lines)]
fn init_writes_a_reproducible_devnet_and_names_mistakes() {
    let dir = scratch("init");
    let report = init(&dir, "2", &["--seed", SEED, "--governance-key", STRANGER]);
    assert!(report.contains("2 validators"), "{report}");
    let devnet = Devnet::load(&dir).unwrap();
    assert_eq!((devnet.nodes.len(), devnet.chain_id), (2, 1337));
    assert!(devnet.nodes[0].peers.is_empty());
    assert_eq!(devnet.nodes[1].peers, vec![devnet.nodes[0].listen.clone()]);
    assert_ne!(devnet.nodes[0].rpc, devnet.nodes[1].rpc);
    assert!(std::fs::read(devnet.kernel()).unwrap().starts_with(b"SOLO"));
    let params = genesis_params(&devnet);
    assert_eq!(
        (params.staking.epoch_blocks, params.staking.dkg_phase_blocks),
        (12, 3)
    );
    assert_eq!(params.staking.keys.0.len(), 2);
    assert_eq!(
        (params.upgrades.epoch_blocks, params.upgrades.min_delay),
        (12, 2)
    );
    assert_eq!(
        params.upgrades.governance,
        client::address(&parse_key(STRANGER).unwrap())
    );
    assert_eq!(params.allocations.0[0].address, {
        let mut a = [0u8; 20];
        a.copy_from_slice(&solo_rpc::methods::parse_hex(FUNDED).unwrap());
        a
    });
    // The key files are the governance account and the validators.
    let governance = std::fs::read_to_string(devnet.governance_key()).unwrap();
    assert_eq!(governance, STRANGER[2..]);
    let key0 =
        parse_key(&std::fs::read_to_string(devnet.node_dir(0).join("key")).unwrap()).unwrap();
    assert_eq!(
        data(&solo_node::validator_id(&key0)),
        devnet.nodes[0].validator
    );
    // The same seed gives the same validators; without one each devnet differs.
    let twin = scratch("init-twin");
    init(&twin, "2", &["--seed", SEED]);
    let twin = Devnet::load(&twin).unwrap();
    assert_eq!(twin.nodes[0].validator, devnet.nodes[0].validator);
    let other = scratch("init-other");
    init(&other, "2", &[]);
    assert_ne!(
        Devnet::load(&other).unwrap().nodes[0].validator,
        devnet.nodes[0].validator
    );
    // A second init leaves an initialized directory alone, unless forced.
    assert!(init(&dir, "3", &[]).contains("already initialized"));
    assert_eq!(Devnet::load(&dir).unwrap().nodes.len(), 2);
    init(&dir, "3", &["--force"]);
    assert_eq!(Devnet::load(&dir).unwrap().nodes.len(), 3);
    // Fixed ports count up from the bases (nothing is bound yet); no epochs
    // means no staking.
    let plain = scratch("init-plain");
    ok(&[
        "devnet",
        "init",
        "--dir",
        str_of(&plain),
        "--kernel",
        KERNEL,
        "--validators",
        "2",
        "--epoch-blocks",
        "0",
        "--p2p-port",
        "40301",
        "--rpc-port",
        "40545",
        "--host",
        "127.0.0.1",
    ]);
    let plain = Devnet::load(&plain).unwrap();
    assert_eq!(plain.nodes[1].listen, "127.0.0.1:40302");
    assert_eq!(plain.nodes[1].rpc, "127.0.0.1:40546");
    let params = genesis_params(&plain);
    assert_eq!(
        (params.staking.epoch_blocks, params.upgrades.epoch_blocks),
        (0, 0)
    );
    // Every mistake is named.
    let fresh = scratch("init-fresh");
    let fresh = str_of(&fresh);
    let cases: Vec<(Vec<&str>, &str)> = vec![
        (vec!["devnet", "init"], "--dir is required"),
        (
            vec!["devnet", "init", "--dir", fresh],
            "--kernel is required",
        ),
        (
            vec![
                "devnet",
                "init",
                "--dir",
                fresh,
                "--kernel",
                KERNEL,
                "--validators",
                "0",
            ],
            "--validators must be 1 to 256",
        ),
        (
            vec![
                "devnet",
                "init",
                "--dir",
                fresh,
                "--kernel",
                KERNEL,
                "--validators",
                "257",
            ],
            "--validators must be 1 to 256",
        ),
        (
            vec![
                "devnet", "init", "--dir", fresh, "--kernel", KERNEL, "--seed", "zz",
            ],
            "64 hex",
        ),
        (
            vec![
                "devnet",
                "init",
                "--dir",
                fresh,
                "--kernel",
                KERNEL,
                "--governance-key",
                "zz",
            ],
            "64 hex",
        ),
        (
            vec![
                "devnet",
                "init",
                "--dir",
                fresh,
                "--kernel",
                KERNEL,
                "--p2p-port",
                "65535",
                "--validators",
                "2",
            ],
            "above 65535",
        ),
        (
            vec![
                "devnet",
                "init",
                "--dir",
                fresh,
                "--kernel",
                KERNEL,
                "--host",
                "203.0.113.1",
                "--p2p-port",
                "0",
            ],
            "cannot pick a free port",
        ),
        (
            vec![
                "devnet",
                "init",
                "--dir",
                fresh,
                "--kernel",
                KERNEL,
                "--epoch-blocks",
                "x",
            ],
            "--epoch-blocks must be a number",
        ),
        (
            vec![
                "devnet",
                "init",
                "--dir",
                fresh,
                "--kernel",
                "/nonexistent/k.elf",
            ],
            "/nonexistent/k.elf: ",
        ),
        (vec!["devnet", "bogus"], "usage:"),
        (vec!["devnet"], "usage:"),
    ];
    for (args, message) in cases {
        let text = err(&args);
        assert!(text.contains(message), "{args:?}: {text}");
    }
    // A directory that cannot be made, and a file that cannot be written.
    let file = scratch("init-file");
    std::fs::write(&file, "x").unwrap();
    let under = file.join("devnet");
    let text = err(&[
        "devnet",
        "init",
        "--dir",
        str_of(&under),
        "--kernel",
        KERNEL,
    ]);
    assert!(text.contains(str_of(&under)), "{text}");
    let blocked = scratch("init-blocked");
    std::fs::create_dir_all(blocked.join("kernel.solo")).unwrap();
    let text = err(&[
        "devnet",
        "init",
        "--dir",
        str_of(&blocked),
        "--kernel",
        KERNEL,
    ]);
    assert!(text.contains("kernel.solo"), "{text}");
}

/// A server on a free port answering each connection with `reply` once per
/// entry, in order; `GET /status` gets the status document instead when
/// `status` is set.
fn fake_node(replies: Vec<&'static str>, status: Option<&'static str>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    std::thread::spawn(move || {
        let mut replies = replies.into_iter();
        loop {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let mut line = String::new();
            let _ = BufReader::new(stream.try_clone().unwrap()).read_line(&mut line);
            let reply = match status {
                Some(status) if line.starts_with("GET /status") => status,
                _ => match replies.next() {
                    Some(reply) => reply,
                    None => return,
                },
            };
            let _ = stream.write_all(reply.as_bytes());
        }
    });
    addr
}

fn http(body: &str) -> &'static str {
    Box::leak(
        format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .into_boxed_str(),
    )
}

#[test]
fn the_client_names_every_bad_answer() {
    assert_eq!(client::host_port("http://127.0.0.1:1/"), "127.0.0.1:1");
    let json = serde_json::json!([]);
    assert!(
        client::call("nope", "eth_chainId", &json)
            .unwrap_err()
            .contains("not a host:port address")
    );
    assert!(
        client::call("127.0.0.1:1", "eth_chainId", &json)
            .unwrap_err()
            .contains("refused")
    );
    let answers = fake_node(
        vec![
            "garbage",
            "HTTP/1.1 500 Oops\r\n\r\nbody",
            http("not json"),
            http(r#"{"jsonrpc":"2.0","id":1,"error":{"code":1,"message":"nope"}}"#),
            http(r#"{"jsonrpc":"2.0","id":1,"error":{}}"#),
            http(r#"{"jsonrpc":"2.0","id":1}"#),
            http(r#"{"jsonrpc":"2.0","id":1,"result":"0x10"}"#),
        ],
        None,
    );
    let call = || client::call(&answers, "eth_chainId", &json);
    assert!(call().unwrap_err().contains("malformed HTTP response"));
    assert!(call().unwrap_err().contains("500 Oops: body"));
    assert!(call().unwrap_err().contains("not a JSON-RPC response"));
    assert!(call().unwrap_err().ends_with("eth_chainId: nope"));
    assert!(call().unwrap_err().ends_with("eth_chainId: error"));
    assert_eq!(call().unwrap(), serde_json::Value::Null);
    assert_eq!(client::quantity(&call().unwrap()).unwrap(), 16);
    assert!(
        client::quantity(&serde_json::json!(5))
            .unwrap_err()
            .contains("expected a quantity")
    );
    assert!(client::status("127.0.0.1:1").is_err());
}

#[test]
#[allow(clippy::too_many_lines)]
fn manifest_and_argument_errors() {
    let dir = scratch("errors");
    std::fs::create_dir_all(&dir).unwrap();
    let d = str_of(&dir);
    assert!(Devnet::load(&dir).unwrap_err().contains(MANIFEST));
    let manifest = dir.join(MANIFEST);
    std::fs::write(&manifest, "{").unwrap();
    assert!(Devnet::load(&dir).unwrap_err().contains("not valid JSON"));
    std::fs::write(&manifest, "{}").unwrap();
    assert!(Devnet::load(&dir).unwrap_err().contains("nodes missing"));
    std::fs::write(&manifest, r#"{"nodes": [{}]}"#).unwrap();
    assert!(
        Devnet::load(&dir)
            .unwrap_err()
            .contains("validator missing")
    );
    // Nothing listens on port 1.
    std::fs::write(
        &manifest,
        r#"{"chainId": 7, "nodes": [{"validator": "0x01", "listen": "127.0.0.1:1", "rpc": "127.0.0.1:1"}]}"#,
    )
    .unwrap();
    let devnet = Devnet::load(&dir).unwrap();
    assert_eq!((devnet.chain_id, devnet.nodes[0].peers.len()), (7, 0));
    assert!(devnet.node(1).unwrap_err().contains("no node 1"));
    let cases: Vec<(Vec<&str>, &str)> = vec![
        (vec!["devnet", "up"], "--dir is required"),
        (vec!["devnet", "stop", "--dir", d], "--node <i> is required"),
        (vec!["devnet", "status"], "--dir is required"),
        (
            vec!["devnet", "wait", "--dir", d],
            "give at least one condition",
        ),
        (
            vec!["devnet", "wait", "--dir", d, "--kernel-hash", "0x01"],
            "--kernel-hash must be 32 bytes",
        ),
        (
            vec!["devnet", "wait", "--dir", d, "--active-gates", "99"],
            "not a gate index",
        ),
        (
            vec!["devnet", "wait", "--dir", d, "--nodes", "7", "--head", "1"],
            "--nodes: no node 7",
        ),
        (
            vec![
                "devnet",
                "wait",
                "--dir",
                d,
                "--head",
                "1",
                "--timeout",
                "0",
            ],
            "timeout waiting for head >= 1",
        ),
        (
            vec![
                "devnet",
                "wait",
                "--dir",
                d,
                "--head",
                "1",
                "--timeout",
                "0",
            ],
            "node 0: unreachable",
        ),
        (
            vec!["devnet", "node", "--dir", d],
            "--index <i> is required",
        ),
        (
            vec!["devnet", "node", "--dir", d, "--index", "5"],
            "no node 5",
        ),
        (
            vec!["devnet", "up", "--dir", "/nonexistent"],
            "/nonexistent/devnet.json",
        ),
    ];
    for (args, message) in cases {
        let text = err(&args);
        assert!(text.contains(message), "{args:?}: {text}");
    }
    // A node that is down is reported, not an error; stopping it is nothing.
    assert!(ok(&["devnet", "status", "--dir", d]).contains("node 0  down"));
    assert!(ok(&["devnet", "status", "--dir", d, "--json"]).contains("\"up\": false"));
    let two = ok(&[
        "devnet",
        "status",
        "--rpc",
        "127.0.0.1:1,127.0.0.1:2",
        "--nodes",
        "1",
    ]);
    assert!(
        two.contains("node 1  down") && !two.contains("node 0"),
        "{two}"
    );
    assert!(ok(&["devnet", "stop", "--dir", d, "--node", "0"]).contains("node 0 is not running"));
    assert!(ok(&["devnet", "down", "--dir", d]).contains("node 0 is not running"));
    // Starting needs the solo binary, and a node directory for the log.
    let out = Command::new(SOLO)
        .args(["devnet", "start", "--dir", d, "--node", "0"])
        .env("SOLO_BIN", "/nonexistent/solo")
        .output()
        .unwrap();
    let text = String::from_utf8(out.stderr).unwrap();
    assert!(text.contains("node-0/log"), "{text}");
    std::fs::create_dir_all(dir.join("node-0")).unwrap();
    let out = Command::new(SOLO)
        .args(["devnet", "start", "--dir", d, "--node", "0"])
        .env("SOLO_BIN", "/nonexistent/solo")
        .output()
        .unwrap();
    let text = String::from_utf8(out.stderr).unwrap();
    assert!(text.contains("cannot start node 0"), "{text}");
    // A node that dies at once (no kernel in this directory) fails `up`.
    let text = err(&["devnet", "up", "--dir", d]);
    assert!(text.contains("node 0 exited with exit status: 2"), "{text}");
    let log = std::fs::read_to_string(dir.join("node-0/log")).unwrap();
    assert!(log.contains("kernel.solo"), "{log}");
    // Conditions against a node that answers /status but no JSON-RPC.
    let status = http(
        r#"{"version":"0","chainId":7,"head":5,"headAgeSeconds":0.1,"finalized":4,"p2p":true,"peers":1,"mempool":0,"uptimeSeconds":1,"validator":null,"upgradeAlert":null,"missingGates":[],"kernelVersion":1,"kernelHash":"0x0000000000000000000000000000000000000000000000000000000000000000","activeGates":[],"pendingUpgrade":null}"#,
    );
    let fake = fake_node(vec!["HTTP/1.1 500 No\r\n\r\n"; 8], Some(status));
    let conditions = Conditions::parse(
        &[
            "solo",
            "devnet",
            "wait",
            "--signalled",
            "0",
            "--certified",
            "1",
        ]
        .map(str::to_owned),
    )
    .unwrap();
    assert_eq!(conditions.certified, Some((1, 0)));
    let unmet = conditions.unmet(&fake, 4);
    assert_eq!(unmet.len(), 2, "{unmet:?}");
    assert!(unmet[0].contains("500 No"), "{unmet:?}");
    assert!(
        unmet[1].contains("0 threshold certificates above 0"),
        "{unmet:?}"
    );
    assert_eq!(
        conditions.to_string(),
        "gates 0 signalled by every validator, 1 threshold certificates above 0"
    );
    let all = Conditions::parse(
        &[
            "solo",
            "devnet",
            "wait",
            "--head",
            "1",
            "--finalized",
            "1",
            "--peers",
            "1",
            "--kernel-version",
            "1",
            "--kernel-hash",
            &format!("0x{}", "00".repeat(32)),
            "--active-gates",
            "",
            "--locked-in",
            "1",
            "--caught-up",
        ]
        .map(str::to_owned),
    )
    .unwrap();
    assert_eq!(
        all.to_string(),
        format!(
            "head >= 1, finalized >= 1, peers >= 1, kernel version >= 1, kernel hash 0x{}, gates  active, gates 1 locked in, caught up",
            "00".repeat(32)
        )
    );
    // Met by the fake's status but for the lock-in, which it cannot answer.
    let unmet = all.unmet(&fake, 4);
    assert_eq!(unmet.len(), 1, "{unmet:?}");
    assert!(all.unmet("127.0.0.1:1", 0)[0].contains("unreachable"));
}

/// A running `solo devnet up`, taken down when dropped.
struct Up {
    dir: PathBuf,
    child: Option<Child>,
}

impl Up {
    fn start(dir: &Path) -> Up {
        let child = Command::new(SOLO)
            .args(["devnet", "up", "--dir"])
            .arg(dir)
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        Up {
            dir: dir.to_path_buf(),
            child: Some(child),
        }
    }

    /// Stops every node and returns whether `up` exited cleanly.
    fn finish(mut self) -> bool {
        ok(&["devnet", "down", "--dir", str_of(&self.dir)]);
        self.child.take().unwrap().wait().unwrap().success()
    }
}

impl Drop for Up {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = solo(&["devnet", "down", "--dir", str_of(&self.dir)]);
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn a_single_validator_devnet_runs_restarts_and_upgrades() {
    let dir = scratch("single");
    init(&dir, "1", &["--upgrade-delay", "1"]);
    let d = str_of(&dir);
    let devnet = Devnet::load(&dir).unwrap();
    let rpc = devnet.nodes[0].rpc.clone();
    let governance = devnet.governance_key();
    let governance = str_of(&governance);
    // `up --blocks` ends on its own once the node has the blocks.
    let text = ok(&["devnet", "up", "--dir", d, "--blocks", "2"]);
    assert!(text.contains("every node stopped"), "{text}");
    let log = std::fs::read_to_string(devnet.node_dir(0).join("log")).unwrap();
    assert!(log.contains("block 2 0x"), "{log}");
    assert!(ok(&["devnet", "status", "--dir", d]).contains("node 0  down"));
    // Started again, alone and from nothing, it runs; a second start is refused.
    assert!(ok(&["devnet", "start", "--dir", d, "--node", "0"]).contains("node 0 started"));
    assert!(err(&["devnet", "start", "--dir", d, "--node", "0"]).contains("already running"));
    // Conditions not met yet: no peers, no signal recorded, no gate, no certificate.
    let text = err(&[
        "devnet",
        "wait",
        "--dir",
        d,
        "--peers",
        "1",
        "--signalled",
        "0,1,2",
        "--locked-in",
        "0",
        "--active-gates",
        "2",
        "--certified",
        "1",
        "--above",
        "1000000",
        "--finalized",
        "1000000",
        "--timeout",
        "0",
    ]);
    for missing in [
        "peers 0 < 1",
        "have not signalled",
        "locked in",
        "active gates",
        "0 threshold certificates above 1000000",
        "finalized",
    ] {
        assert!(text.contains(missing), "{missing}: {text}");
    }
    let text = ok(&[
        "devnet",
        "wait",
        "--dir",
        d,
        "--head",
        "3",
        "--finalized",
        "1",
        "--timeout",
        "120",
    ]);
    assert!(text.starts_with("ok after"), "{text}");
    let text = ok(&["devnet", "status", "--dir", d]);
    assert!(
        text.contains("node 0  up") && text.contains("kernel v1"),
        "{text}"
    );
    let text = ok(&["devnet", "status", "--dir", d, "--json"]);
    assert!(text.contains("\"kernelVersion\": 1"), "{text}");
    let mut doctor = vec!["doctor", "--rpc", &rpc];
    doctor.extend(TOLERANT);
    assert!(ok(&doctor).contains("healthy"));
    // `solo upgrade`: every mistake is named before anything is sent.
    let cases: Vec<(Vec<&str>, &str)> = vec![
        (
            vec!["upgrade", "--rpc", &rpc, "--kernel", KERNEL_V2],
            "--key or --key-file is required",
        ),
        (
            vec!["upgrade", "--rpc", &rpc, "--key", STRANGER],
            "--kernel is required",
        ),
        (
            vec![
                "upgrade",
                "--rpc",
                &rpc,
                "--kernel",
                KERNEL_V2,
                "--key",
                STRANGER,
                "--key-file",
                governance,
            ],
            "--key and --key-file exclude each other",
        ),
        (
            vec![
                "upgrade",
                "--rpc",
                &rpc,
                "--kernel",
                KERNEL_V2,
                "--key-file",
                "/nonexistent/key",
            ],
            "/nonexistent/key: ",
        ),
        (
            vec![
                "upgrade",
                "--rpc",
                &rpc,
                "--kernel",
                KERNEL_V2,
                "--key",
                STRANGER,
                "--required-gates",
                "x",
            ],
            "not a gate index",
        ),
        (
            vec![
                "upgrade",
                "--rpc",
                "127.0.0.1:1",
                "--kernel",
                KERNEL_V2,
                "--key",
                STRANGER,
            ],
            "solo_upgradeStatus",
        ),
        (
            vec![
                "upgrade", "--rpc", &rpc, "--kernel", KERNEL_V2, "--key", STRANGER,
            ],
            "the governance account is",
        ),
        // No waiting at all: the chunks are sent, no receipt is asked for.
        (
            vec![
                "upgrade",
                "--rpc",
                &rpc,
                "--kernel",
                KERNEL_V2,
                "--key-file",
                governance,
                "--timeout",
                "0",
            ],
            "chunk 0: no receipt",
        ),
    ];
    for (args, message) in cases {
        let text = err(&args);
        assert!(text.contains(message), "{args:?}: {text}");
    }
    // The upgrade itself, then a second proposal while it is pending.
    let upgrade = [
        "upgrade",
        "--rpc",
        &rpc,
        "--kernel",
        KERNEL_V2,
        "--key-file",
        governance,
        "--delay",
        "3",
        "--required-gates",
        "",
    ];
    let report = ok(&upgrade);
    assert!(report.contains("code hash  0x"), "{report}");
    assert!(report.contains("chunks ("), "{report}");
    let activation: u64 = report
        .lines()
        .find_map(|l| l.strip_prefix("activation "))
        .unwrap()
        .parse()
        .unwrap();
    assert!(err(&upgrade).contains("already pending"));
    let text = ok(&["devnet", "status", "--dir", d, "--json"]);
    assert!(
        text.contains(&format!("\"pendingUpgrade\": {activation}")),
        "{text}"
    );
    let text = ok(&[
        "devnet",
        "wait",
        "--dir",
        d,
        "--kernel-version",
        "2",
        "--timeout",
        "300",
    ]);
    assert!(text.contains("kernel version >= 2"), "{text}");
    // Alone, this validator holds the one share of the threshold key: its
    // finalized blocks carry threshold certificates.
    ok(&[
        "devnet",
        "wait",
        "--dir",
        d,
        "--certified",
        "1",
        "--timeout",
        "300",
    ]);
    // The running kernel's code is frozen: staging it again reverts.
    assert!(err(&upgrade).contains("chunk 0 reverted"));
    assert!(ok(&["devnet", "stop", "--dir", d, "--node", "0"]).contains("node 0 stopped"));
    // The node command runs in-process too, with any `solo node` option after it.
    let args: Vec<String> = [
        "solo", "devnet", "node", "--dir", d, "--index", "0", "--blocks", "1",
    ]
    .map(str::to_owned)
    .to_vec();
    run(&args).unwrap();
    assert_eq!(run(&args[..3]).unwrap_err(), "--dir is required");
    assert!(
        run(&[
            "solo", "devnet", "node", "--dir", d, "--index", "0", "--rpc", "nope"
        ]
        .map(str::to_owned))
        .unwrap_err()
        .starts_with("nope: ")
    );
    assert_eq!(
        run(&["solo", "devnet", "x"].map(str::to_owned)).unwrap_err(),
        USAGE
    );
}

#[test]
fn the_rehearsal_passes_on_a_four_validator_devnet() {
    let dir = scratch("rehearsal");
    init(&dir, "4", &[]);
    let up = Up::start(&dir);
    let out = Command::new(REHEARSAL)
        .arg(&dir)
        .arg(KERNEL_V2)
        .env("SOLO", SOLO)
        .env("REHEARSE_TIMEOUT", "900")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stdout}\n{stderr}");
    assert!(
        stdout.contains("rehearsal: 9 passed, 0 failed"),
        "{stdout}\n{stderr}"
    );
    for phase in [
        "PASS network up",
        "PASS kernel switch",
        "PASS gate signalling",
        "PASS gate lock-in",
        "PASS gate activation",
        "PASS liveness",
        "PASS catch-up: node 3",
        "PASS threshold share",
        "PASS catch-up: node 2",
    ] {
        assert!(stdout.contains(phase), "{phase}: {stdout}");
    }
    assert!(up.finish());
    // Every node's log shows the switch and no error.
    for i in 0..4 {
        let log = std::fs::read_to_string(dir.join(format!("node-{i}/log"))).unwrap();
        assert!(!log.contains("node error"), "node {i}: {log}");
    }
}

#[test]
fn the_compose_stack_rehearses_an_upgrade_when_docker_is_asked_for() {
    // Needs docker: SOLO_DOCKER=1 runs it; the script says when it is skipped.
    let out = Command::new(COMPOSE_REHEARSAL)
        .env("SOLO", SOLO)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stdout}\n{stderr}");
    assert!(
        stdout.contains("rehearsal: 9 passed, 0 failed") || stdout.contains("skipped"),
        "{stdout}"
    );
}
