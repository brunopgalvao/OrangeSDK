//! What the `solo` tooling needs from a running node: JSON-RPC calls over
//! HTTP, the status document, and legacy transactions signed for the chain.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

use k256::ecdsa::SigningKey;
use serde_json::{Value, json};
use solo_host::hash::keccak256;
use solo_metrics::Status;
use solo_rlp::{encode_bytes, encode_list, encode_uint};

/// How long a connection attempt may take.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// How long one request may take once connected: a node answers between
/// its consensus steps, and a slow block execution comes first.
pub const READ_TIMEOUT: Duration = Duration::from_mins(2);

/// `addr` without an `http://` prefix or a trailing slash.
#[must_use]
pub fn host_port(addr: &str) -> &str {
    addr.trim_start_matches("http://").trim_end_matches('/')
}

/// Sends one HTTP request to `addr` and returns the body of a `200` response.
///
/// # Errors
/// A message naming `what` and what went wrong: no such address, no
/// connection, an I/O failure, a malformed response or another status.
pub fn exchange(addr: &str, what: &str, request: &str) -> Result<String, String> {
    let fail = |e: std::io::Error| format!("{what}: {e}");
    let target = host_port(addr)
        .to_socket_addrs()
        .ok()
        .and_then(|mut all| all.next())
        .ok_or_else(|| format!("{what}: {addr} is not a host:port address"))?;
    let mut stream = TcpStream::connect_timeout(&target, CONNECT_TIMEOUT).map_err(fail)?;
    stream.set_read_timeout(Some(READ_TIMEOUT)).map_err(fail)?;
    stream.write_all(request.as_bytes()).map_err(fail)?;
    let mut raw = String::new();
    stream.read_to_string(&mut raw).map_err(fail)?;
    let Some((head, body)) = raw.split_once("\r\n\r\n") else {
        return Err(format!("{what}: malformed HTTP response"));
    };
    let status_line = head.lines().next().unwrap_or_default();
    if status_line.split_whitespace().nth(1) != Some("200") {
        return Err(format!("{what}: {status_line}: {body}"));
    }
    Ok(body.to_owned())
}

/// Calls JSON-RPC `method` with `params` on the node at `addr` and returns
/// its result.
///
/// # Errors
/// The transport error, or the node's error message for the method.
pub fn call(addr: &str, method: &str, params: &Value) -> Result<Value, String> {
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).to_string();
    let request = format!(
        "POST / HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        host_port(addr),
        body.len()
    );
    let reply = exchange(addr, &format!("{addr} {method}"), &request)?;
    let mut v: Value = serde_json::from_str(&reply)
        .ok()
        .ok_or_else(|| format!("{addr} {method}: not a JSON-RPC response"))?;
    if let Some(error) = v.get("error") {
        let message = error
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("error");
        return Err(format!("{addr} {method}: {message}"));
    }
    Ok(v.get_mut("result").map_or(Value::Null, Value::take))
}

/// A quantity (`0x` hex) result as a number.
///
/// # Errors
/// If `v` is not a quantity.
pub fn quantity(v: &Value) -> Result<u64, String> {
    v.as_str()
        .and_then(|s| solo_rpc::methods::parse_quantity(s).ok())
        .ok_or_else(|| format!("expected a quantity, got {v}"))
}

/// The node's `GET /status` document (spec 11 §6).
///
/// # Errors
/// If the node cannot be reached or the document does not parse.
pub fn status(addr: &str) -> Result<Status, String> {
    crate::doctor::parse_status(&crate::doctor::get(host_port(addr), "/status")?)
}

/// The Ethereum address of a consensus key: the last 20 bytes of its
/// validator id (spec 13 §2.2).
///
/// # Panics
/// Never: a validator id is 32 bytes.
#[must_use]
pub fn address(key: &SigningKey) -> [u8; 20] {
    solo_node::validator_id(key)[12..]
        .try_into()
        .expect("20 bytes")
}

/// A legacy EIP-155 transaction signed by `key` for `chain_id`.
///
/// # Panics
/// Never: signing a 32-byte digest with a valid key cannot fail.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn legacy_tx(
    key: &SigningKey,
    chain_id: u64,
    nonce: u64,
    gas_price: u128,
    gas: u64,
    to: [u8; 20],
    value: u128,
    data: &[u8],
) -> Vec<u8> {
    let fields = |out: &mut Vec<u8>| {
        encode_uint(u128::from(nonce), out);
        encode_uint(gas_price, out);
        encode_uint(u128::from(gas), out);
        encode_bytes(&to, out);
        encode_uint(value, out);
        encode_bytes(data, out);
    };
    let mut unsigned = Vec::new();
    fields(&mut unsigned);
    encode_uint(u128::from(chain_id), &mut unsigned);
    encode_uint(0, &mut unsigned);
    encode_uint(0, &mut unsigned);
    let mut list = Vec::new();
    encode_list(&unsigned, &mut list);
    let sig = solo_node::sign_recoverable(key, &keccak256(&list)).expect("a digest signs");
    let strip = |b: &[u8]| b[b.iter().take_while(|x| **x == 0).count()..].to_vec();
    let mut signed = Vec::new();
    fields(&mut signed);
    encode_uint(
        u128::from(chain_id) * 2 + 35 + u128::from(sig[64]),
        &mut signed,
    );
    encode_bytes(&strip(&sig[..32]), &mut signed);
    encode_bytes(&strip(&sig[32..64]), &mut signed);
    let mut out = Vec::new();
    encode_list(&signed, &mut out);
    out
}

/// Polls `check` every 250 ms until it holds or `timeout` passes.
///
/// # Errors
/// `what` with the time waited, when it does not hold in time.
pub fn poll_until(
    timeout: Duration,
    what: &str,
    check: &mut dyn FnMut() -> bool,
) -> Result<(), String> {
    let started = Instant::now();
    loop {
        if check() {
            return Ok(());
        }
        if started.elapsed() >= timeout {
            return Err(format!(
                "{what} within {:.1}s",
                started.elapsed().as_secs_f64()
            ));
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// Waits for the receipt of transaction `hash` and returns it. A deadline
/// already passed means no waiting at all: the error comes before the
/// first request.
///
/// # Errors
/// A transport or node error, or `what` when no receipt arrives in time.
pub fn wait_receipt(
    addr: &str,
    hash: &str,
    what: &str,
    deadline: Instant,
) -> Result<Value, String> {
    loop {
        if Instant::now() >= deadline {
            return Err(format!("{what}: no receipt for {hash} before the timeout"));
        }
        let receipt = call(addr, "eth_getTransactionReceipt", &json!([hash]))?;
        if !receipt.is_null() {
            return Ok(receipt);
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}
