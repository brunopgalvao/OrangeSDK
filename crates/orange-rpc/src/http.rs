//! A minimal HTTP/1.1 server for JSON-RPC: one request per connection,
//! `POST` bodies dispatched to [`Rpc`], `OPTIONS` answered for browsers,
//! and `GET /health`, `/metrics` and `/status` for operators (spec 11 §2).
//! A request from a browser page (one with an `Origin` header) is answered
//! only when [`Rpc::cors`] allows its origin, and only then with CORS
//! headers (spec 20 §8.5): otherwise any page the node's operator opened
//! could call the node, `orange_stop` included.
//! Deliberately small; a production node fronts this with a real server.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::time::Duration;

use crate::Rpc;

/// A parsed request: method, path, body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// HTTP method.
    pub method: String,
    /// Request path.
    pub path: String,
    /// Body bytes.
    pub body: Vec<u8>,
    /// The `Origin` header, which browsers send with every cross-origin
    /// request and every `POST`, if there is one.
    pub origin: Option<String>,
}

/// Largest request body read, geth's default: a `Content-Length` above it is
/// refused before anything is allocated for the body.
pub const MAX_BODY: usize = 5 * 1024 * 1024;

/// Reads one HTTP request from a stream.
///
/// # Errors
/// Any I/O or framing problem, or a body longer than [`MAX_BODY`], as a
/// message.
pub fn read_request(stream: &mut (impl Read + ?Sized)) -> Result<Request, String> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).map_err(|e| e.to_string())?;
    let mut parts = line.split_whitespace();
    let method = parts.next().ok_or("empty request line")?.to_owned();
    let path = parts.next().ok_or("missing path")?.to_owned();
    let mut content_length = 0usize;
    let mut origin = None;
    loop {
        let mut header = String::new();
        let n = reader.read_line(&mut header).map_err(|e| e.to_string())?;
        if n == 0 || header == "\r\n" || header == "\n" {
            break;
        }
        let Some((name, value)) = header.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("content-length") {
            content_length = value.trim().parse().map_err(|_| "bad content-length")?;
        } else if name.eq_ignore_ascii_case("origin") {
            origin = Some(value.trim().to_owned());
        }
    }
    if content_length > MAX_BODY {
        return Err(format!(
            "body too large: {content_length} bytes, the limit is {MAX_BODY}"
        ));
    }
    let mut body = vec![0u8; content_length];
    reader.read_exact(&mut body).map_err(|e| e.to_string())?;
    Ok(Request {
        method,
        path,
        body,
        origin,
    })
}

/// Builds an HTTP response, without CORS headers.
#[must_use]
pub fn response(status: &str, content_type: &str, body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

/// `reply` with the CORS headers that let a page of `allowed` read it:
/// `allowed` is `*` or the origin as the operator configured it, never
/// text taken from the request.
fn with_cors(reply: &[u8], allowed: &str) -> Vec<u8> {
    let end = reply
        .windows(2)
        .position(|w| w == b"\r\n")
        .map_or(reply.len(), |i| i + 2);
    let mut out = reply[..end].to_vec();
    out.extend_from_slice(
        format!(
            "Access-Control-Allow-Origin: {allowed}\r\nVary: Origin\r\nAccess-Control-Allow-Headers: content-type\r\nAccess-Control-Allow-Methods: POST, OPTIONS\r\n"
        )
        .as_bytes(),
    );
    out.extend_from_slice(&reply[end..]);
    out
}

/// The entry of `cors` that allows `origin`: `*`, or the origin itself
/// (compared without case, as origins' schemes and hosts are).
fn allowed_by<'a>(cors: &'a [String], origin: &str) -> Option<&'a str> {
    cors.iter()
        .find(|a| *a == "*" || a.eq_ignore_ascii_case(origin))
        .map(String::as_str)
}

/// Serves one connection. A request with an `Origin` header that
/// [`Rpc::cors`] does not allow gets `403` and reaches nothing.
pub fn serve_connection(rpc: &mut Rpc, stream: &mut TcpStream) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let reply = match read_request(stream) {
        Ok(req) => match req.origin.as_deref() {
            None => dispatch(rpc, &req),
            Some(origin) => match allowed_by(&rpc.cors, origin).map(str::to_owned) {
                Some(allowed) => with_cors(&dispatch(rpc, &req), &allowed),
                None => response(
                    "403 Forbidden",
                    "text/plain",
                    "this node answers browser pages only from the origins its --rpc-cors names",
                ),
            },
        },
        Err(e) => response("400 Bad Request", "text/plain", &e),
    };
    let _ = stream.write_all(&reply);
    let _ = stream.flush();
}

/// The reply to one request whose origin, if any, is allowed.
fn dispatch(rpc: &mut Rpc, req: &Request) -> Vec<u8> {
    match req.method.as_str() {
        "OPTIONS" => response("204 No Content", "text/plain", ""),
        "POST" => {
            let body = String::from_utf8_lossy(&req.body).into_owned();
            response(
                "200 OK",
                "application/json",
                &rpc.handle_body(&body).to_string(),
            )
        }
        "GET" if req.path == "/health" => response("200 OK", "text/plain", "ok"),
        "GET" if req.path == "/metrics" => crate::telemetry::metrics_response(rpc),
        "GET" if req.path == "/status" => crate::telemetry::status_response(rpc),
        _ => response("405 Method Not Allowed", "text/plain", "POST JSON-RPC here"),
    }
}

/// Binds a non-blocking listener for [`serve`].
///
/// # Errors
/// If the address cannot be bound or the socket cannot be made non-blocking.
pub fn bind(addr: impl ToSocketAddrs) -> std::io::Result<TcpListener> {
    let listener = TcpListener::bind(addr)?;
    listener.set_nonblocking(true)?;
    Ok(listener)
}

/// Accepts connections until `keep_going` returns false (checked between
/// connections, so an `orange_stop` request ends the loop), serving each one on
/// the calling thread. The node's background work ([`Rpc::run_background`]) runs
/// after every connection as well as while none is waiting, so a stream of
/// requests cannot keep the node from its clock and its peers. The listener
/// must be non-blocking, as [`bind`] leaves it.
pub fn serve(listener: &TcpListener, rpc: &mut Rpc, mut keep_going: impl FnMut(&Rpc) -> bool) {
    while keep_going(rpc) {
        let served = if let Ok((mut stream, _)) = listener.accept() {
            let _ = stream.set_nonblocking(false);
            serve_connection(rpc, &mut stream);
            true
        } else {
            false
        };
        rpc.run_background();
        if !served {
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}
