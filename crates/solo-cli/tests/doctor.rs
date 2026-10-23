//! `solo doctor` against in-process nodes serving JSON-RPC, and against
//! servers that answer badly.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use solo_cli::doctor::{get, parse_status};
use solo_cli::{dev_key, load_kernel, parse_genesis, run};

const KERNEL: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../solo-node/tests/fixtures/kernel.elf"
);

const GENESIS: &str = r#"{"chainId": 1337, "slotMs": 60, "maxTxs": 4, "alloc": {}}"#;

/// Gas that lets the driver start (80 224) but not produce a block (275 837); see
/// `dev.rs`, whose budget this is. It was 80 000 until the driver start passed it
/// on 2026-10-24.
const STARVED_GAS: i64 = 100_000;

/// Limits a healthy node meets even on an instrumented build under heavy load.
const TOLERANT: [&str; 4] = ["--max-call-ms", "600000", "--max-head-age", "600"];

/// A dev node serving JSON-RPC on its own thread until dropped.
struct Served {
    addr: String,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Drop for Served {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
    }
}

fn serve(kernel_gas: i64) -> Served {
    let (tx, rx) = std::sync::mpsc::channel();
    let stop = Arc::new(AtomicBool::new(false));
    let stopping = Arc::clone(&stop);
    let thread = std::thread::spawn(move || {
        let epoch = 1_000_000;
        let start = Instant::now();
        let mut node = solo_node::Node::open(
            &load_kernel(KERNEL).unwrap(),
            &parse_genesis(GENESIS).unwrap(),
            solo_node::NodeConfig {
                now_ms: epoch,
                key: Some(dev_key()),
                kernel_gas,
                ..solo_node::NodeConfig::default()
            },
        )
        .unwrap();
        node.start(None).unwrap();
        let mut rpc = solo_rpc::Rpc::new(node);
        rpc.set_background(Box::new(move |node| {
            let now = epoch + u64::try_from(start.elapsed().as_millis()).unwrap();
            // A starved kernel fails its slots; the faults are what the doctor reports.
            let _ = node.tick(now);
        }));
        let listener = solo_rpc::http::bind("127.0.0.1:0").unwrap();
        tx.send(listener.local_addr().unwrap().to_string()).unwrap();
        solo_rpc::http::serve(&listener, &mut rpc, |_| !stopping.load(Ordering::SeqCst));
    });
    Served {
        addr: rx.recv().unwrap(),
        stop,
        thread: Some(thread),
    }
}

fn doctor(addr: &str, extra: &[&str]) -> Result<String, String> {
    let mut args = vec!["solo".to_owned(), "doctor".to_owned(), "--rpc".to_owned()];
    args.push(format!("http://{addr}/"));
    args.extend(extra.iter().map(|a| (*a).to_owned()));
    solo_cli::doctor::run(&args)
}

/// Waits until the node's status satisfies `ready`; fails the test at the deadline.
fn wait_for(addr: &str, ready: impl Fn(&solo_metrics::Status) -> bool) {
    // Generous: an instrumented build under a heavily loaded machine is slow.
    let deadline = Instant::now() + Duration::from_mins(2);
    loop {
        let status = parse_status(&get(addr, "/status").unwrap()).unwrap();
        if ready(&status) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "node never got ready: {status:?}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn a_producing_node_is_healthy_until_the_limits_say_otherwise() {
    let node = serve(solo_node::node::KERNEL_GAS);
    wait_for(&node.addr, |s| s.head >= 2);
    let report = doctor(&node.addr, &TOLERANT).unwrap();
    assert!(
        report.starts_with("solo 0.0.1: chain 1337, head "),
        "{report}"
    );
    assert!(report.contains("no p2p"), "{report}");
    assert!(report.ends_with("\nhealthy"), "{report}");
    // Every limit can be set; these are generous enough to stay healthy.
    let report = doctor(
        &node.addr,
        &[
            "--max-head-age",
            "600",
            "--max-finality-lag",
            "100",
            "--min-peers",
            "0",
            "--max-mempool",
            "10",
            "--max-call-ms",
            "60000",
        ],
    )
    .unwrap();
    assert!(report.ends_with("\nhealthy"), "{report}");
    // A head age limit of zero cannot be met.
    let report = doctor(&node.addr, &["--max-head-age", "0"]).unwrap_err();
    assert!(report.contains("\nunhealthy:\n  - head "), "{report}");
    assert!(report.contains("has not advanced for"), "{report}");
    assert_eq!(
        doctor(&node.addr, &["--max-mempool", "x"]).unwrap_err(),
        "--max-mempool must be a number"
    );
    // Through the command line: the verdict is printed and sets the exit status.
    let args = |extra: &[&str]| {
        let mut list: Vec<String> = ["solo", "doctor", "--rpc", node.addr.as_str()]
            .iter()
            .map(|a| (*a).to_owned())
            .collect();
        list.extend(extra.iter().map(|a| (*a).to_owned()));
        list
    };
    run(&args(&TOLERANT)).unwrap();
    assert!(run(&args(&["--max-head-age", "0"])).is_err());
    let out = Command::new(env!("CARGO_BIN_EXE_solo"))
        .args(&args(&TOLERANT)[1..])
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    assert!(String::from_utf8_lossy(&out.stdout).ends_with("healthy\n"));
    let out = Command::new(env!("CARGO_BIN_EXE_solo"))
        .args(&args(&["--max-head-age", "0"])[1..])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2), "{out:?}");
    assert!(String::from_utf8_lossy(&out.stderr).contains("unhealthy:"));
}

#[test]
fn a_faulting_kernel_is_unhealthy() {
    let node = serve(STARVED_GAS);
    // Wait for the first slot to fault: the status stays answerable, the head stays at zero.
    let deadline = Instant::now() + Duration::from_mins(2);
    let report = loop {
        let report = doctor(&node.addr, &[]).unwrap_err();
        if report.contains("faulted") {
            break report;
        }
        assert!(Instant::now() < deadline, "no fault reported: {report}");
        std::thread::sleep(Duration::from_millis(20));
    };
    assert!(report.contains("kernel_driver_step faulted"), "{report}");
    assert!(
        report.contains("(out_of_gas) since the node started"),
        "{report}"
    );
    assert!(report.contains("head 0 ("), "{report}");
}

/// A server that answers each connection with the next canned response.
fn canned(responses: &[&'static str]) -> (String, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let responses = responses.to_vec();
    let thread = std::thread::spawn(move || {
        for response in responses {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            while reader.read_line(&mut line).unwrap() > 2 {
                line.clear();
            }
            stream.write_all(response.as_bytes()).unwrap();
        }
    });
    (addr, thread)
}

const STATUS: &str = "HTTP/1.1 200 OK\r\n\r\n{\"version\":\"0.0.1\",\"chainId\":1,\"head\":1,\"headAgeSeconds\":0.5,\"finalized\":1,\"p2p\":true,\"peers\":2,\"mempool\":0,\"uptimeSeconds\":3}";

#[test]
fn bad_answers_are_reported() {
    let unreachable = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .to_string();
    assert!(
        get(&unreachable, "/status")
            .unwrap_err()
            .starts_with(&format!("{unreachable}: "))
    );
    assert_eq!(
        get("nope", "/status").unwrap_err(),
        "nope: not a host:port address"
    );
    let (addr, server) = canned(&[
        "garbage",
        "HTTP/1.1 404 Not Found\r\n\r\nno such page",
        "HTTP/1.1 200 OK\r\n\r\nnot json",
        "HTTP/1.1 200 OK\r\n\r\n{\"head\":1}",
        STATUS,
        "HTTP/1.1 200 OK\r\n\r\nx{",
        STATUS,
        "HTTP/1.1 200 OK\r\n\r\nethereum_peer_count 2\n",
    ]);
    assert_eq!(
        doctor(&addr, &[]).unwrap_err(),
        format!("{addr}/status: malformed HTTP response")
    );
    assert_eq!(
        doctor(&addr, &[]).unwrap_err(),
        format!("{addr}/status: HTTP/1.1 404 Not Found: no such page")
    );
    assert_eq!(
        doctor(&addr, &[]).unwrap_err(),
        "status: not a JSON document"
    );
    assert_eq!(
        doctor(&addr, &[]).unwrap_err(),
        "status: a field is missing or has the wrong type"
    );
    assert_eq!(
        doctor(&addr, &[]).unwrap_err(),
        format!("{addr}/metrics: line 1: expected label=\"value\"")
    );
    let report = doctor(&addr, &[]).unwrap();
    assert!(report.contains("2 peers"), "{report}");
    server.join().unwrap();
}

#[test]
fn the_status_carries_upgrade_alerts() {
    let body = STATUS.split_once("\r\n\r\n").unwrap().1;
    let with = |extra: &str| parse_status(&format!("{},{extra}}}", &body[..body.len() - 1]));
    // A node of an earlier release sends neither field: nothing to report.
    let plain = parse_status(body).unwrap();
    assert_eq!((plain.upgrade_alert, plain.missing_gates), (None, 0));
    let clear = with("\"upgradeAlert\":null,\"missingGates\":[]").unwrap();
    assert_eq!((clear.upgrade_alert, clear.missing_gates), (None, 0));
    let blocked = with("\"upgradeAlert\":\"cannot load\",\"missingGates\":[0,2,63]").unwrap();
    assert_eq!(blocked.upgrade_alert.as_deref(), Some("cannot load"));
    assert_eq!(blocked.missing_gates, 0b101 | 1 << 63);
    let problems = solo_metrics::assess(&blocked, &[], &solo_metrics::Limits::default());
    assert_eq!(
        problems,
        vec![
            "the pending kernel upgrade cannot be enacted: cannot load",
            "the chain locked in feature gates this release does not support: 0, 2, 63",
        ]
    );
    for bad in [
        "\"upgradeAlert\":5",
        "\"missingGates\":3",
        "\"missingGates\":[64]",
        "\"missingGates\":[\"0\"]",
    ] {
        assert!(with(bad).is_err(), "{bad}");
    }
}
