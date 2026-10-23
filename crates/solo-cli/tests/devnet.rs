//! `solo devnet` and `solo upgrade` on real processes: a devnet is
//! initialized, run, watched, stopped and restarted with its driver state;
//! a kernel upgrade is staged and proposed over JSON-RPC, a proposal that
//! lands too late for its activation height is sent again, and every
//! mistake is named; `up` leaves nothing of its own behind and `stop` reaches a
//! node that does not answer; and the rehearsal script runs end to end
//! against four validators. The compose stack's rehearsal runs only with
//! `SOLO_DOCKER` set (`tools/compose-rehearsal.sh` says so otherwise).

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::Duration;

use solo_abi::Decode;
use solo_abi::chain::GenesisParams;
use solo_cli::client;
use solo_cli::devnet::{Conditions, Devnet, FUNDED, LIFELINE, MANIFEST};
use solo_cli::upgrade::PROPOSE_GAS;
use solo_cli::{USAGE, parse_genesis, parse_key, run};
use solo_rpc::methods::data;
use solo_scratch::Scratch;
use solo_upgrade::Action;

const SOLO: &str = env!("CARGO_BIN_EXE_solo");
const KERNEL: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../solo-node/tests/fixtures/kernel.elf"
);
const KERNEL_V2: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../solo-node/tests/fixtures/kernel_v2.elf"
);
/// A module that recompiles like a kernel but is not one.
const COUNTER: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../solo-node/tests/fixtures/counter.elf"
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
const ETHER: u128 = 1_000_000_000_000_000_000;
/// Doctor limits a healthy node meets on an instrumented build under load.
const TOLERANT: [&str; 6] = [
    "--max-call-ms",
    "600000",
    "--max-head-age",
    "600",
    "--min-peers",
    "0",
];

/// A path for `name`, removed when the guard drops: bound first in a test,
/// it drops after the guards that stop the test's nodes.
fn scratch(name: &str) -> Scratch {
    Scratch::new("devnet", name)
}

/// A command whose nodes, however it starts them, stop when this test
/// process ends, even when it is killed: their lifeline is this process.
fn command(program: &str) -> Command {
    let mut command = Command::new(program);
    command.env(LIFELINE, std::process::id().to_string());
    command
}

fn solo(args: &[&str]) -> Output {
    command(SOLO).args(args).output().unwrap()
}

/// Kills its process when dropped.
struct Kills(Child);

impl Drop for Kills {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Stops every node of a devnet when dropped, whatever stopped the test:
/// a failed assertion must not leave the nodes it started running.
struct Stops(PathBuf);

impl Drop for Stops {
    fn drop(&mut self) {
        if let Ok(devnet) = Devnet::load(&self.0) {
            for i in 0..devnet.nodes.len() {
                let _ = solo(&[
                    "devnet",
                    "stop",
                    "--dir",
                    str_of(&self.0),
                    "--node",
                    &i.to_string(),
                ]);
            }
        }
    }
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
    // The genesis time is when `init` ran, unless `--genesis-time` names one.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!((now - 600..=now).contains(&params.genesis_time));
    assert_eq!(params.staking.keys.0.len(), 2);
    assert_eq!(
        (params.upgrades.epoch_blocks, params.upgrades.min_delay),
        (12, 2)
    );
    assert_eq!(
        params.upgrades.governance,
        client::address(&parse_key(STRANGER).unwrap())
    );
    // The README's account, every validator and the governance key are funded;
    // the fee market runs at the production defaults (spec 23 §2.1).
    let funded = |address: [u8; 20]| {
        params
            .allocations
            .0
            .iter()
            .find(|a| a.address == address)
            .map(|a| a.balance)
    };
    let readme = {
        let mut a = [0u8; 20];
        a.copy_from_slice(&solo_rpc::methods::parse_hex(FUNDED).unwrap());
        a
    };
    assert_eq!(funded(readme), Some(1_000_000 * ETHER));
    assert_eq!(
        funded(client::address(&parse_key(STRANGER).unwrap())),
        Some(1_000 * ETHER)
    );
    assert_eq!(params.allocations.0.len(), 4);
    assert_eq!(params.fees, solo_abi::fees::FeeParams::production());
    assert!(
        report.contains("base fee floor 1000000000 wei, burned"),
        "{report}"
    );
    // The key files are the governance account and the validators.
    let governance = std::fs::read_to_string(devnet.governance_key()).unwrap();
    assert_eq!(governance, STRANGER[2..]);
    let key0 =
        parse_key(&std::fs::read_to_string(devnet.node_dir(0).join("key")).unwrap()).unwrap();
    assert_eq!(
        data(&solo_node::validator_id(&key0)),
        devnet.nodes[0].validator
    );
    // Key files are the owner's alone.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for path in [devnet.governance_key(), devnet.node_dir(0).join("key")] {
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "{}", path.display());
        }
    }
    // The same seed gives the same validators; without one each devnet differs.
    let twin = scratch("init-twin");
    init(
        &twin,
        "2",
        &["--seed", SEED, "--genesis-time", "1792800000"],
    );
    let twin = Devnet::load(&twin).unwrap();
    assert_eq!(twin.nodes[0].validator, devnet.nodes[0].validator);
    assert_eq!(genesis_params(&twin).genesis_time, 1_792_800_000);
    let other = scratch("init-other");
    init(&other, "2", &[]);
    assert_ne!(
        Devnet::load(&other).unwrap().nodes[0].validator,
        devnet.nodes[0].validator
    );
    // A second init leaves an initialized directory alone, unless forced;
    // forced, it starts the node directories over (an old chain's driver
    // state must not resume on a new chain) and keys stay the owner's alone.
    assert!(init(&dir, "3", &[]).contains("already initialized"));
    assert_eq!(Devnet::load(&dir).unwrap().nodes.len(), 2);
    std::fs::write(devnet.node_dir(0).join("driver.state"), "old").unwrap();
    init(&dir, "3", &["--force"]);
    assert_eq!(Devnet::load(&dir).unwrap().nodes.len(), 3);
    assert!(!devnet.node_dir(0).join("driver.state").exists());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(devnet.governance_key())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
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
        // What the kernel would trap on at `kernel_init` is refused by name.
        (
            vec![
                "devnet",
                "init",
                "--dir",
                fresh,
                "--kernel",
                KERNEL,
                "--epoch-blocks",
                "10",
                "--dkg-phase-blocks",
                "5",
            ],
            "four DKG phases must fit an epoch",
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
    let taken = scratch("init-taken");
    std::fs::create_dir_all(&taken).unwrap();
    std::fs::write(taken.join("node-0"), "x").unwrap();
    let text = err(&[
        "devnet",
        "init",
        "--dir",
        str_of(&taken),
        "--kernel",
        KERNEL,
    ]);
    assert!(text.contains("node-0"), "{text}");
    // A key file that cannot be created is named: something sits where
    // governance.key goes.
    let held = scratch("init-held");
    std::fs::create_dir_all(held.join("governance.key")).unwrap();
    let text = err(&["devnet", "init", "--dir", str_of(&held), "--kernel", KERNEL]);
    assert!(text.contains("governance.key"), "{text}");
    // What `kernel_init` refuses beyond what the genesis checks foresee is
    // still caught at init, by running it once: a module that is no kernel.
    let text = err(&[
        "devnet",
        "init",
        "--dir",
        str_of(&scratch("init-no-kernel")),
        "--kernel",
        COUNTER,
    ]);
    assert!(text.contains("the kernel refuses this genesis"), "{text}");
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
            // Read the whole request before answering: closing a socket
            // with unread input sends a reset, which can reach the client
            // before the reply does.
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            let _ = reader.read_line(&mut line);
            let mut length = 0;
            let mut header = String::new();
            while reader.read_line(&mut header).is_ok_and(|n| n > 2) {
                if let Some(value) = header.to_ascii_lowercase().strip_prefix("content-length:") {
                    length = value.trim().parse().unwrap_or(0);
                }
                header.clear();
            }
            let _ = reader.take(length).read_to_end(&mut Vec::new());
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
fn a_proposal_that_lands_too_late_is_sent_again_with_more_slack() {
    let key = parse_key(STRANGER).unwrap();
    let result = |v: String| http(&format!(r#"{{"jsonrpc":"2.0","id":1,"result":{v}}}"#));
    let quantity = |n: u64| result(format!(r#""{n:#x}""#));
    let receipt = |ok: bool, block: u64| {
        result(format!(
            r#"{{"status":"{:#x}","blockNumber":"{block:#x}"}}"#,
            u8::from(ok)
        ))
    };
    let hash = result(r#""0xabc""#.to_owned());
    // What the node answers before the first proposal's receipt: the status
    // naming this key as governance with an upgradeDelay of 2, the chain id,
    // the gas price, the nonce, the one chunk's hash and its receipt in
    // block 5, the head (5) and the proposal's hash; that proposal names
    // activation height 5 + 2 + 2 = 9.
    let status = result(format!(
        r#"{{"pending":null,"params":{{"governance":"{}","minDelay":2}}}}"#,
        data(&client::address(&key))
    ));
    let preamble = [
        status,
        quantity(1337),
        quantity(1_000_000_000),
        quantity(0),
        hash,
        receipt(true, 5),
        quantity(5),
        hash,
    ];
    let submit = |rest: &[&'static str]| {
        let node = fake_node([&preamble[..], rest].concat(), None);
        solo_cli::upgrade::submit(&node, &key, b"a kernel", None, 0, Duration::from_secs(30))
    };
    // Landing in block 9, the proposal reverts: the kernel wants at least
    // two blocks between it and its activation height. The next one, from
    // head 9 with twice the slack, names 9 + 2 + 4 = 15 and lands in block 10.
    let report = submit(&[receipt(false, 9), quantity(9), hash, receipt(true, 10)]).unwrap();
    assert!(report.starts_with("code hash  0x"), "{report}");
    assert!(
        report.ends_with(
            "staged     1 chunks (8 bytes) in blocks 5..5\n\
             resent     1 time: a proposal landed too late for its activation height\n\
             proposed   block 10\n\
             activation 15"
        ),
        "{report}"
    );
    // Twice late: 15 from head 9 lands in block 14, then 14 + 2 + 8 = 24
    // from head 14 lands in block 15.
    let report = submit(&[
        receipt(false, 9),
        quantity(9),
        hash,
        receipt(false, 14),
        quantity(14),
        hash,
        receipt(true, 15),
    ])
    .unwrap();
    assert!(
        report.ends_with(
            "resent     2 times: a proposal landed too late for its activation height\n\
             proposed   block 15\n\
             activation 24"
        ),
        "{report}"
    );
    // A proposal that reverts in time (block 6, three blocks before 9)
    // reverted for another reason: the command stops there.
    let message = submit(&[receipt(false, 6)]).unwrap_err();
    assert!(message.starts_with("proposal reverted: "), "{message}");
    assert!(message.contains(r#""blockNumber":"0x6""#), "{message}");
    // Four proposals in a row landing too late (9, 15, 24 and 41 landing in
    // blocks 9, 14, 23 and 40) exhaust the resends.
    let message = submit(&[
        receipt(false, 9),
        quantity(9),
        hash,
        receipt(false, 14),
        quantity(14),
        hash,
        receipt(false, 23),
        quantity(23),
        hash,
        receipt(false, 40),
    ])
    .unwrap_err();
    assert!(
        message.starts_with("4 proposals landed too late for their activation height; the last: "),
        "{message}"
    );
    assert!(message.contains(r#""blockNumber":"0x28""#), "{message}");
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
    let out = command(SOLO)
        .args(["devnet", "start", "--dir", d, "--node", "0"])
        .env("SOLO_BIN", "/nonexistent/solo")
        .output()
        .unwrap();
    let text = String::from_utf8(out.stderr).unwrap();
    assert!(text.contains("node-0/log"), "{text}");
    std::fs::create_dir_all(dir.join("node-0")).unwrap();
    let out = command(SOLO)
        .args(["devnet", "start", "--dir", d, "--node", "0"])
        .env("SOLO_BIN", "/nonexistent/solo")
        .output()
        .unwrap();
    let text = String::from_utf8(out.stderr).unwrap();
    assert!(text.contains("cannot start node 0"), "{text}");
    // `up` fails when a node cannot start, and when one dies at once (no
    // kernel in this directory).
    let out = command(SOLO)
        .args(["devnet", "up", "--dir", d])
        .env("SOLO_BIN", "/nonexistent/solo")
        .output()
        .unwrap();
    let text = String::from_utf8(out.stderr).unwrap();
    assert!(text.contains("cannot start node 0"), "{text}");
    let text = err(&["devnet", "up", "--dir", d]);
    assert!(text.contains("node 0 exited with exit status: 2"), "{text}");
    let log = std::fs::read_to_string(dir.join("node-0/log")).unwrap();
    assert!(log.contains("kernel.solo"), "{log}");
    // Conditions against a node that answers /status but no JSON-RPC.
    let status = http(
        r#"{"version":"0","chainId":7,"head":5,"headAgeSeconds":0.1,"finalized":4,"p2p":true,"peers":1,"mempool":0,"uptimeSeconds":1,"validator":null,"upgradeAlert":null,"missingGates":[],"kernelVersion":1,"kernelHash":"0x0000000000000000000000000000000000000000000000000000000000000000","activeGates":[],"pendingUpgrade":null}"#,
    );
    // Its JSON-RPC answers one upgrade status and four finality proofs with
    // 500, then upgrade statuses with nothing signalled or locked in.
    let unsignalled = http(
        r#"{"jsonrpc":"2.0","id":1,"result":{"validators":[{"id":"0x01","weight":1,"signal":null}],"gates":{"nextEpoch":0,"lockedIn":[],"records":[]}}}"#,
    );
    let mut replies = vec!["HTTP/1.1 500 No\r\n\r\n"; 5];
    replies.extend([unsignalled; 3]);
    let fake = fake_node(replies, Some(status));
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
    let gates = Conditions::parse(
        &[
            "solo",
            "devnet",
            "wait",
            "--signalled",
            "0",
            "--locked-in",
            "0",
        ]
        .map(str::to_owned),
    )
    .unwrap();
    assert_eq!(
        gates.unmet(&fake, 4),
        vec![
            "1 validators have not signalled".to_owned(),
            "locked in []".to_owned()
        ]
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
    // Met by the fake's status but for the lock-in; and, with the furthest
    // node far ahead, it has not caught up either.
    let unmet = all.unmet(&fake, 4);
    assert_eq!(unmet, vec!["locked in []".to_owned()]);
    let unmet = all.unmet(&fake, 100);
    assert_eq!(unmet.len(), 2, "{unmet:?}");
    assert!(unmet[0].contains("finalized 4 behind 100"), "{unmet:?}");
    assert!(all.unmet("127.0.0.1:1", 0)[0].contains("unreachable"));
    // `--no-equivocations` reads the driver's counter from the metrics: a
    // node that recorded some, then one whose metrics do not parse.
    let equivocated = fake_node(
        vec![
            http(
                "solo_emitted_counter_total{origin=\"driver\",name=\"equivocations\"} 2\nsolo_emitted_counter_total{origin=\"driver\",name=\"blocks\"} 9\n",
            ),
            http("solo_emitted_counter_total{ 1\n"),
        ],
        Some(status),
    );
    let none =
        Conditions::parse(&["solo", "devnet", "wait", "--no-equivocations"].map(str::to_owned))
            .unwrap();
    assert_eq!(none.to_string(), "no equivocations");
    assert_eq!(
        none.unmet(&equivocated, 0),
        vec!["2 equivocations recorded".to_owned()]
    );
    let unmet = none.unmet(&equivocated, 0);
    assert!(unmet[0].contains("/metrics: line 1"), "{unmet:?}");
    // `--caught-up` measures against the furthest of every node, not of
    // the selected ones: node 0 alone is still 100 blocks behind node 1.
    let behind = fake_node(vec![], Some(status));
    let ahead = fake_node(
        vec![],
        Some(http(
            r#"{"version":"0","chainId":7,"head":100,"headAgeSeconds":0.1,"finalized":100,"p2p":true,"peers":1,"mempool":0,"uptimeSeconds":1,"validator":null,"upgradeAlert":null,"missingGates":[],"kernelVersion":1,"kernelHash":"0x0000000000000000000000000000000000000000000000000000000000000000","activeGates":[],"pendingUpgrade":null}"#,
        )),
    );
    let rpcs = format!("{behind},{ahead}");
    let text = err(&[
        "devnet",
        "wait",
        "--rpc",
        &rpcs,
        "--nodes",
        "0",
        "--caught-up",
        "--timeout",
        "0",
    ]);
    assert!(text.contains("node 0: finalized 4 behind 100"), "{text}");
    let text = ok(&[
        "devnet",
        "wait",
        "--rpc",
        &rpcs,
        "--nodes",
        "1",
        "--caught-up",
        "--timeout",
        "0",
    ]);
    assert!(
        text.contains("ok after") && text.contains("caught up"),
        "{text}"
    );
}

#[test]
fn up_stops_only_what_it_started_and_stop_falls_back_on_the_pid_file() {
    let dir = scratch("orphans");
    init(&dir, "2", &[]);
    let _stops = Stops(dir.to_path_buf());
    let d = str_of(&dir);
    let devnet = Devnet::load(&dir).unwrap();
    // Node 1 runs already: `up` refuses, kills the node 0 it had started
    // and leaves node 1, which is not its own, running.
    assert!(ok(&["devnet", "start", "--dir", d, "--node", "1"]).contains("node 1 started"));
    let text = err(&["devnet", "up", "--dir", d]);
    assert!(text.contains("node 1 is already running"), "{text}");
    assert!(!dir.join("node-0/pid").exists());
    let status = ok(&["devnet", "status", "--dir", d]);
    assert!(
        status.contains("node 0  down") && status.contains("node 1  up"),
        "{status}"
    );
    // A pid file naming a process that is not this devnet's node is left
    // alone, as is garbage, or the pid of a process that is gone.
    let mut sleeper = Command::new("sleep").arg("600").spawn().unwrap();
    let pid = dir.join("node-0/pid");
    std::fs::write(&pid, sleeper.id().to_string()).unwrap();
    assert!(ok(&["devnet", "stop", "--dir", d, "--node", "0"]).contains("node 0 is not running"));
    assert!(sleeper.try_wait().unwrap().is_none());
    sleeper.kill().unwrap();
    sleeper.wait().unwrap();
    std::fs::write(&pid, "x").unwrap();
    assert!(ok(&["devnet", "stop", "--dir", d, "--node", "0"]).contains("node 0 is not running"));
    std::fs::write(&pid, sleeper.id().to_string()).unwrap();
    assert!(ok(&["devnet", "stop", "--dir", d, "--node", "0"]).contains("node 0 is not running"));
    // A node whose RPC does not answer is stopped through its pid: node 1,
    // reached through a copy of the manifest that points its RPC nowhere.
    let wedged = scratch("orphans-wedged");
    std::fs::create_dir_all(wedged.join("node-1")).unwrap();
    let manifest = std::fs::read_to_string(dir.join(MANIFEST))
        .unwrap()
        .replace(&devnet.nodes[1].rpc, "127.0.0.1:1");
    std::fs::write(wedged.join(MANIFEST), manifest).unwrap();
    std::fs::copy(dir.join("node-1/pid"), wedged.join("node-1/pid")).unwrap();
    let text = ok(&["devnet", "stop", "--dir", str_of(&wedged), "--node", "1"]);
    assert!(
        text.contains("node 1 stopped (pid") && text.contains("signalled)"),
        "{text}"
    );
    assert!(!wedged.join("node-1/pid").exists());
    assert!(ok(&["devnet", "status", "--dir", d]).contains("node 1  down"));
}

#[test]
fn nodes_stop_when_their_lifeline_goes() {
    let dir = scratch("lifeline");
    init(&dir, "1", &[]);
    let _stops = Stops(dir.to_path_buf());
    let devnet = Devnet::load(&dir).unwrap();
    let rpc = devnet.nodes[0].rpc.clone();
    // `up` runs with a lifeline of its own, a process this test ends.
    let mut line = Kills(Command::new("sleep").arg("600").spawn().unwrap());
    let up = Command::new(SOLO)
        .args(["devnet", "up", "--dir", str_of(&dir)])
        .env(LIFELINE, line.0.id().to_string())
        .stdin(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    client::poll_until(Duration::from_mins(2), "node 0 up", &mut || {
        client::status(&rpc).is_ok()
    })
    .unwrap();
    let pid: u32 = std::fs::read_to_string(dir.join("node-0/pid"))
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    // Once the lifeline goes, `up` fails, and its node, whose lifeline is
    // `up`, follows it down.
    line.0.kill().unwrap();
    line.0.wait().unwrap();
    let out = up.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    let text = String::from_utf8_lossy(&out.stderr);
    assert!(text.contains("up stopped by its lifeline"), "{text}");
    let mut gone = || {
        !Command::new("ps")
            .args(["-p", &pid.to_string()])
            .output()
            .unwrap()
            .status
            .success()
    };
    client::poll_until(Duration::from_mins(1), "node 0 gone", &mut gone).unwrap();
    let log = std::fs::read_to_string(dir.join("node-0/log")).unwrap();
    assert!(log.contains("is gone; stopping"), "{log}");
}

/// Sends `action` from the governance key and returns its receipt.
fn send_action(rpc: &str, key: &k256::ecdsa::SigningKey, action: &Action) -> serde_json::Value {
    let ask = |method: &str, params: serde_json::Value| {
        client::quantity(&client::call(rpc, method, &params).unwrap()).unwrap()
    };
    let chain_id = ask("eth_chainId", serde_json::json!([]));
    let gas_price = u128::from(ask("eth_gasPrice", serde_json::json!([])));
    let nonce = ask(
        "eth_getTransactionCount",
        serde_json::json!([data(&client::address(key)), "pending"]),
    );
    let raw = solo_cli::upgrade::action_tx(key, chain_id, nonce, gas_price, PROPOSE_GAS, action);
    let hash = client::call(
        rpc,
        "eth_sendRawTransaction",
        &serde_json::json!([data(&raw)]),
    )
    .unwrap();
    let deadline = std::time::Instant::now() + Duration::from_mins(2);
    client::wait_receipt(rpc, hash.as_str().unwrap(), "action", deadline).unwrap()
}

/// A running `solo devnet up`, taken down when dropped.
struct Up {
    dir: PathBuf,
    child: Option<Child>,
}

impl Up {
    fn start(dir: &Path) -> Up {
        let child = command(SOLO)
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
    let _stops = Stops(dir.to_path_buf());
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
    assert!(log.contains("new, from view 1"), "{log}");
    let ran = last_block(&log);
    assert!(ran >= 2, "{log}");
    assert!(ok(&["devnet", "status", "--dir", d]).contains("node 0  down"));
    assert!(devnet.node_dir(0).join("driver.state").exists());
    // Started again, alone, it resumes the view its driver state records
    // and the chain state its store holds, executes nothing again and runs
    // on; a second start is refused.
    assert!(ok(&["devnet", "start", "--dir", d, "--node", "0"]).contains("node 0 started"));
    assert!(err(&["devnet", "start", "--dir", d, "--node", "0"]).contains("already running"));
    let log = std::fs::read_to_string(devnet.node_dir(0).join("log")).unwrap();
    assert!(log.contains("resumed in view "), "{log}");
    assert_eq!(replayed(&log), 0, "{log}");
    assert!(opened_at(&log) >= ran, "{log}");
    // Conditions not met yet: no peers, no gate, no certificate, not that high.
    let text = err(&[
        "devnet",
        "wait",
        "--dir",
        d,
        "--peers",
        "1",
        "--active-gates",
        "2",
        "--certified",
        "1",
        "--above",
        "1000000",
        "--head",
        "1000000",
        "--finalized",
        "1000000",
        "--timeout",
        "0",
    ]);
    for missing in [
        "peers 0 < 1",
        "active gates",
        "0 threshold certificates above 1000000",
        "head",
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
        "--no-equivocations",
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
    // The upgrade itself, then a second proposal while it is pending. The
    // first activation height is out of reach, so the second command, a
    // process of its own, and the status after it find the upgrade pending
    // however loaded the machine (with a short delay the chain sometimes
    // switched first, and the second command staged into the new kernel).
    let upgrade = [
        "upgrade",
        "--rpc",
        &rpc,
        "--kernel",
        KERNEL_V2,
        "--key-file",
        governance,
        "--delay",
        "1000000",
        "--required-gates",
        "",
    ];
    let report = ok(&upgrade);
    assert!(report.contains("code hash  0x"), "{report}");
    assert!(report.contains("chunks ("), "{report}");
    let field = |name: &str| {
        report
            .lines()
            .find_map(|l| l.strip_prefix(name))
            .unwrap()
            .trim()
            .to_owned()
    };
    let activation: u64 = field("activation ").parse().unwrap();
    let digits = field("code hash ");
    let code_hash: [u8; 32] =
        std::array::from_fn(|i| u8::from_str_radix(&digits[2 + 2 * i..4 + 2 * i], 16).unwrap());
    let again = err(&upgrade);
    assert!(again.contains("already pending"), "{again}");
    let text = ok(&["devnet", "status", "--dir", d, "--json"]);
    assert!(
        text.contains(&format!("\"pendingUpgrade\": {activation}")),
        "{text}"
    );
    // Governance cancels it and proposes the code it staged again, a few
    // blocks ahead (spec 13 §3: staged chunks stay).
    let key = parse_key(
        std::fs::read_to_string(devnet.governance_key())
            .unwrap()
            .trim(),
    )
    .unwrap();
    let receipt = send_action(&rpc, &key, &Action::Cancel { code_hash });
    assert_eq!(receipt["status"], "0x1", "{receipt}");
    let head =
        client::quantity(&client::call(&rpc, "eth_blockNumber", &serde_json::json!([])).unwrap())
            .unwrap();
    let propose = Action::Propose {
        code_hash,
        activation_height: head + 20,
        required_gates: 0,
    };
    let receipt = send_action(&rpc, &key, &propose);
    assert_eq!(receipt["status"], "0x1", "{receipt}");
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
    // Alone, this validator holds every share of the threshold key (four, of
    // which three sign): its finalized blocks carry threshold certificates.
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
    let _stops = Stops(dir.to_path_buf());
    let up = Up::start(&dir);
    let out = command(REHEARSAL)
        .arg(dir.path())
        .arg(KERNEL_V2)
        .env("SOLO", SOLO)
        .env("REHEARSE_TIMEOUT", "900")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stdout}\n{stderr}");
    assert!(
        stdout.contains("rehearsal: 10 passed, 0 failed"),
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
        "PASS no equivocation",
    ] {
        assert!(stdout.contains(phase), "{phase}: {stdout}");
    }
    assert!(up.finish());
    // Every node's log shows the kernel switch and no error; the two that
    // restarted resumed the driver state and the chain state they had left
    // on disk, at or past the last block they had logged before they
    // stopped, and executed nothing again (the log holds both runs).
    for i in 0..4 {
        let log = std::fs::read_to_string(dir.join(format!("node-{i}/log"))).unwrap();
        assert!(!log.contains("node error"), "node {i}: {log}");
        assert!(
            log.contains("kernel switch after block ") && log.contains(": version 1 to 2 (0x"),
            "node {i}: {log}"
        );
        assert_eq!(log.contains("resumed in view "), i >= 2, "node {i}: {log}");
        if i >= 2 {
            let (before, _) = log.split_once("resumed in view ").unwrap();
            let ran = last_block(before);
            assert!(ran > 0, "node {i}: {log}");
            assert_eq!(replayed(&log), 0, "node {i}: {log}");
            assert!(opened_at(&log) >= ran, "node {i}: {log}");
        }
    }
}

/// The height of the last `block <n> 0x…` line a node logged in `log`.
fn last_block(log: &str) -> u64 {
    log.lines()
        .filter_map(|line| line.strip_prefix("block "))
        .filter_map(|rest| rest.split(' ').next()?.parse().ok())
        .next_back()
        .unwrap_or(0)
}

/// How many blocks the node says it re-executed from its tables on resume.
fn replayed(log: &str) -> u64 {
    let (_, rest) = log.split_once("resumed in view ").unwrap();
    let (_, count) = rest.split_once(", ").unwrap();
    count.split(' ').next().unwrap().parse().unwrap()
}

/// The height the node says its chain store held when it last opened.
fn opened_at(log: &str) -> u64 {
    let (_, rest) = log.rsplit_once("chain state in ").unwrap();
    let (_, height) = rest.split_once(": height ").unwrap();
    height.split(',').next().unwrap().parse().unwrap()
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
