//! `GET /metrics` and `GET /status` on the JSON-RPC address (spec 11 §2).

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};

use common::{SLOT_MS, Wallet, node};
use serde_json::Value;
use solo_metrics::{CONTENT_TYPE, Status, VERSION, parse};
use solo_rpc::Rpc;
use solo_rpc::http::{bind, serve};
use solo_rpc::telemetry::{metrics_response, status_json, status_response};

fn talk(addr: std::net::SocketAddr, request: &[u8]) -> String {
    let mut stream = TcpStream::connect(addr).unwrap();
    stream.write_all(request).unwrap();
    stream.shutdown(std::net::Shutdown::Write).unwrap();
    let mut out = String::new();
    stream.read_to_string(&mut out).unwrap();
    out
}

fn body(response: &[u8]) -> String {
    let text = String::from_utf8(response.to_vec()).unwrap();
    text.split_once("\r\n\r\n").unwrap().1.to_owned()
}

#[test]
fn endpoints_report_a_block_and_its_transaction() {
    let alice = Wallet::new(1);
    let mut rpc = Rpc::new(node(&alice));
    rpc.node_mut()
        .submit(&alice.transfer(0, [9; 20], 1, 21_000))
        .unwrap();
    let pending = parse(&body(&metrics_response(&mut rpc))).unwrap();
    let value = |samples: &[solo_metrics::Sample], name: &str| {
        samples.iter().find(|s| s.name == name).unwrap().value
    };
    assert!((value(&pending, "solo_mempool_transactions") - 1.0).abs() < f64::EPSILON);
    assert!(value(&pending, "solo_mempool_bytes") > 100.0);
    rpc.node_mut().tick(1_000 + SLOT_MS).unwrap();
    let response = String::from_utf8(metrics_response(&mut rpc)).unwrap();
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.contains(&format!("Content-Type: {CONTENT_TYPE}\r\n")));
    let samples = parse(&body(response.as_bytes())).unwrap();
    for (name, expected) in [
        ("ethereum_blockchain_height", 1.0),
        ("solo_chain_finalized_height", 1.0),
        ("solo_block_transactions_total", 1.0),
        ("solo_block_gas_used_total", 21_000.0),
        ("solo_mempool_transactions", 0.0),
    ] {
        assert!(
            (value(&samples, name) - expected).abs() < f64::EPSILON,
            "{name}"
        );
    }
    let status: Value = serde_json::from_str(&body(&status_response(&mut rpc))).unwrap();
    assert_eq!(status["chainId"], 1337);
    assert_eq!(status["head"], 1);
    assert_eq!(status["finalized"], 1);
    assert_eq!(status["mempool"], 0);
    assert_eq!(status["peers"], 0);
    assert_eq!(status["p2p"], false);
    assert_eq!(status["version"], VERSION);
    assert!(status["headAgeSeconds"].as_f64().unwrap() >= 0.0);
    assert!(status["uptimeSeconds"].as_f64().unwrap() >= 0.0);
    assert_eq!(
        status["validator"].as_str().unwrap().len(),
        2 + 64,
        "{status}"
    );
}

#[test]
fn status_json_without_a_validator() {
    let status = Status {
        version: VERSION.to_owned(),
        chain_id: 5,
        head: 7,
        head_age_seconds: 1.5,
        finalized: 6,
        p2p: true,
        peers: 2,
        mempool: 3,
        uptime_seconds: 9.0,
        validator: None,
    };
    let v = status_json(&status);
    assert_eq!(v["validator"], Value::Null);
    assert_eq!(v["peers"], 2);
    assert_eq!(v["headAgeSeconds"], 1.5);
}

#[test]
fn a_kernel_that_cannot_answer_is_unavailable() {
    let alice = Wallet::new(1);
    let mut rpc = Rpc::new(node(&alice));
    rpc.node_mut().kernel_gas = 1;
    let response = String::from_utf8(status_response(&mut rpc)).unwrap();
    assert!(response.starts_with("HTTP/1.1 503"), "{response}");
    assert!(
        response.ends_with("kernel_query ended with OutOfGas"),
        "{response}"
    );
    let response = String::from_utf8(metrics_response(&mut rpc)).unwrap();
    assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
}

#[test]
fn the_server_routes_metrics_and_status() {
    let alice = Wallet::new(1);
    let mut rpc = Rpc::new(node(&alice));
    let listener = bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let results = Arc::new(Mutex::new(Vec::new()));
    let client = {
        let results = Arc::clone(&results);
        std::thread::spawn(move || {
            let mut r = results.lock().unwrap();
            r.push(talk(addr, b"GET /metrics HTTP/1.1\r\n\r\n"));
            r.push(talk(addr, b"GET /status HTTP/1.1\r\n\r\n"));
            r.push(talk(addr, b"POST /metrics HTTP/1.1\r\n\r\n"));
            let stop = r#"{"jsonrpc":"2.0","id":1,"method":"solo_stop"}"#;
            let post = format!(
                "POST / HTTP/1.1\r\nContent-Length: {}\r\n\r\n{stop}",
                stop.len()
            );
            r.push(talk(addr, post.as_bytes()));
        })
    };
    serve(&listener, &mut rpc, |_| {}, |rpc| !rpc.stopped);
    client.join().unwrap();
    let results = results.lock().unwrap();
    assert!(
        results[0].contains("\r\n\r\n# HELP ethereum_best_known_block_number "),
        "{}",
        results[0]
    );
    assert!(results[1].contains("\"chainId\":1337"), "{}", results[1]);
    // A POST anywhere is JSON-RPC.
    assert!(results[2].contains("\"error\""), "{}", results[2]);
    assert!(results[3].ends_with(r#""result":true}"#), "{}", results[3]);
}
