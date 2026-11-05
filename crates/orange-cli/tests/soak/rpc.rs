//! JSON-RPC and HTTP calls with a short timeout of the soak's choosing: a
//! node that stops answering must show up as a failed call, not as a
//! checker stuck for the two minutes `orange_cli::client` allows.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use serde_json::{Value, json};

/// Why a call failed.
#[derive(Debug, Clone)]
pub enum Fail {
    /// No connection, a timeout, a malformed answer.
    Transport(String),
    /// The node answered with a JSON-RPC error.
    Node(String),
}

impl std::fmt::Display for Fail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Fail::Transport(e) => write!(f, "transport: {e}"),
            Fail::Node(e) => write!(f, "node: {e}"),
        }
    }
}

/// One HTTP request to `addr`; the body of a 200 answer.
pub fn http(addr: &str, request: &str, timeout: Duration) -> Result<String, Fail> {
    let t = |e: std::io::Error| Fail::Transport(format!("{addr}: {e}"));
    let target: SocketAddr = addr
        .parse()
        .map_err(|_| Fail::Transport(format!("{addr}: not an address")))?;
    let mut stream =
        TcpStream::connect_timeout(&target, timeout.min(Duration::from_secs(3))).map_err(t)?;
    stream.set_read_timeout(Some(timeout)).map_err(t)?;
    stream.set_write_timeout(Some(timeout)).map_err(t)?;
    stream.write_all(request.as_bytes()).map_err(t)?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).map_err(t)?;
    let raw = String::from_utf8_lossy(&raw);
    let Some((head, body)) = raw.split_once("\r\n\r\n") else {
        return Err(Fail::Transport(format!("{addr}: malformed HTTP answer")));
    };
    let status = head.lines().next().unwrap_or_default();
    if status.split_whitespace().nth(1) != Some("200") {
        return Err(Fail::Transport(format!("{addr}: {status}")));
    }
    Ok(body.to_owned())
}

/// `GET path` on `addr`.
pub fn get(addr: &str, path: &str, timeout: Duration) -> Result<String, Fail> {
    let request = format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
    http(addr, &request, timeout)
}

/// JSON-RPC `method` on `addr`.
pub fn call(addr: &str, method: &str, params: &Value, timeout: Duration) -> Result<Value, Fail> {
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).to_string();
    let request = format!(
        "POST / HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let reply = http(addr, &request, timeout)?;
    let mut v: Value = serde_json::from_str(&reply)
        .map_err(|_| Fail::Transport(format!("{addr} {method}: not JSON")))?;
    if let Some(error) = v.get("error") {
        let message = error
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("error");
        return Err(Fail::Node(message.to_owned()));
    }
    Ok(v.get_mut("result").map_or(Value::Null, Value::take))
}

/// A `0x` quantity.
pub fn quantity(v: &Value) -> Option<u128> {
    let s = v.as_str()?.strip_prefix("0x")?;
    u128::from_str_radix(s, 16).ok()
}

/// A `0x` quantity that fits a `u64`.
pub fn q64(v: &Value) -> Option<u64> {
    quantity(v).and_then(|n| u64::try_from(n).ok())
}

/// `0x` hex of `bytes`.
pub fn hex(bytes: &[u8]) -> String {
    orange_rpc::methods::data(bytes)
}
