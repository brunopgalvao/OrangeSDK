//! `orange doctor`: asks a running node for `GET /status` and `GET /metrics`
//! and judges its health by the rules of spec 11 §7, the same conditions
//! the alert rules in `ops/alerts.yml` watch over time.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use orange_metrics::{Limits, PendingUpgrade, Status, assess, parse, summary};
use serde_json::Value;

/// Fetches `path` from the node's HTTP server at `addr` (`host:port`) and
/// returns the body of a `200` response.
///
/// # Errors
/// A message naming the address and what went wrong: no such address, no
/// connection, an I/O failure, a malformed response or another status.
pub fn get(addr: &str, path: &str) -> Result<String, String> {
    let fail = |e: std::io::Error| format!("{addr}: {e}");
    let target = addr
        .to_socket_addrs()
        .ok()
        .and_then(|mut all| all.next())
        .ok_or_else(|| format!("{addr}: not a host:port address"))?;
    let mut stream = TcpStream::connect_timeout(&target, Duration::from_secs(10)).map_err(fail)?;
    stream
        .set_read_timeout(Some(Duration::from_mins(1)))
        .map_err(fail)?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n"
    )
    .map_err(fail)?;
    let mut raw = String::new();
    stream.read_to_string(&mut raw).map_err(fail)?;
    let Some((head, body)) = raw.split_once("\r\n\r\n") else {
        return Err(format!("{addr}{path}: malformed HTTP response"));
    };
    let status_line = head.lines().next().unwrap_or_default();
    if status_line.split_whitespace().nth(1) != Some("200") {
        return Err(format!("{addr}{path}: {status_line}: {body}"));
    }
    Ok(body.to_owned())
}

/// Reads a `/status` document (spec 11 §6).
///
/// # Errors
/// If it is not JSON or lacks a field the verdict needs.
pub fn parse_status(text: &str) -> Result<Status, String> {
    let v: Value = serde_json::from_str(text)
        .ok()
        .ok_or("status: not a JSON document")?;
    let u = |key: &str| v.get(key).and_then(Value::as_u64);
    let f = |key: &str| v.get(key).and_then(Value::as_f64);
    // A list of gates as a bit set; a field a node of an earlier release does
    // not send reads as empty.
    let mask = |key: &str| match v.get(key) {
        None => Some(0),
        Some(gates) => gates.as_array()?.iter().try_fold(0u64, |mask, g| {
            let g = g.as_u64().filter(|g| *g < 64)?;
            Some(mask | 1 << g)
        }),
    };
    let hash = |value: &Value| -> Option<[u8; 32]> {
        orange_rpc::methods::parse_hex(value.as_str()?)
            .ok()?
            .try_into()
            .ok()
    };
    let status = || -> Option<Status> {
        Some(Status {
            version: v.get("version")?.as_str()?.to_owned(),
            chain_id: u("chainId")?,
            chain_name: match v.get("chainName") {
                None => String::new(),
                Some(name) => name.as_str()?.to_owned(),
            },
            head: u("head")?,
            head_age_seconds: f("headAgeSeconds")?,
            finalized: u("finalized")?,
            p2p: v.get("p2p")?.as_bool()?,
            peers: u("peers")?,
            mempool: u("mempool")?,
            uptime_seconds: f("uptimeSeconds")?,
            // The verdict does not depend on the node's identity.
            validator: None,
            // Fields a node of an earlier release does not send read as clear.
            upgrade_alert: match v.get("upgradeAlert") {
                None | Some(Value::Null) => None,
                Some(why) => Some(why.as_str()?.to_owned()),
            },
            missing_gates: mask("missingGates")?,
            kernel_version: match v.get("kernelVersion") {
                None => 0,
                Some(n) => u32::try_from(n.as_u64()?).ok()?,
            },
            kernel_hash: match v.get("kernelHash") {
                None => [0; 32],
                Some(h) => hash(h)?,
            },
            active_gates: mask("activeGates")?,
            pending_upgrade: match v.get("pendingUpgrade") {
                None | Some(Value::Null) => None,
                Some(p) => Some(PendingUpgrade {
                    code_hash: hash(p.get("codeHash")?)?,
                    activation_height: p.get("activationHeight")?.as_u64()?,
                }),
            },
            sync_alert: match v.get("syncAlert") {
                None | Some(Value::Null) => None,
                Some(why) => Some(why.as_str()?.to_owned()),
            },
        })
    };
    status().ok_or_else(|| "status: a field is missing or has the wrong type".to_owned())
}

#[allow(clippy::cast_precision_loss)]
fn seconds(n: u64) -> f64 {
    n as f64
}

fn limits(args: &[String]) -> Result<Limits, String> {
    let d = Limits::default();
    let number = |name: &str| crate::parse_number(args, name);
    Ok(Limits {
        max_head_age_seconds: number("--max-head-age")?.map_or(d.max_head_age_seconds, seconds),
        max_finality_lag: number("--max-finality-lag")?.unwrap_or(d.max_finality_lag),
        min_peers: number("--min-peers")?.unwrap_or(d.min_peers),
        max_mempool: number("--max-mempool")?.unwrap_or(d.max_mempool),
        max_call_seconds: number("--max-call-ms")?
            .map_or(d.max_call_seconds, |ms| seconds(ms) / 1000.0),
    })
}

/// Runs `orange doctor`. Returns the report of a healthy node.
///
/// # Errors
/// The report of an unhealthy node, with every reason, or why the node
/// could not be asked; the command exits non-zero either way.
pub fn run(args: &[String]) -> Result<String, String> {
    let rpc = crate::arg(args, "--rpc");
    let addr = rpc.as_deref().unwrap_or(crate::DEFAULT_RPC);
    let addr = addr.trim_start_matches("http://").trim_end_matches('/');
    let limits = limits(args)?;
    let status = parse_status(&get(addr, "/status")?)?;
    let metrics = get(addr, "/metrics")?;
    let samples = parse(&metrics).map_err(|e| format!("{addr}/metrics: {e}"))?;
    let problems = assess(&status, &samples, &limits);
    let mut report = summary(&status);
    if problems.is_empty() {
        report.push_str("\nhealthy");
        return Ok(report);
    }
    report.push_str("\nunhealthy:");
    for problem in problems {
        report.push_str("\n  - ");
        report.push_str(&problem);
    }
    Err(report)
}
