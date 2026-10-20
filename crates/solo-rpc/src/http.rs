//! A minimal HTTP/1.1 server for JSON-RPC: one request per connection,
//! `POST` bodies dispatched to [`Rpc`], `OPTIONS` answered for browsers.
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
}

/// Reads one HTTP request from a stream.
///
/// # Errors
/// Any I/O or framing problem, as a message.
pub fn read_request(stream: &mut (impl Read + ?Sized)) -> Result<Request, String> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).map_err(|e| e.to_string())?;
    let mut parts = line.split_whitespace();
    let method = parts.next().ok_or("empty request line")?.to_owned();
    let path = parts.next().ok_or("missing path")?.to_owned();
    let mut content_length = 0usize;
    loop {
        let mut header = String::new();
        let n = reader.read_line(&mut header).map_err(|e| e.to_string())?;
        if n == 0 || header == "\r\n" || header == "\n" {
            break;
        }
        if let Some((name, value)) = header.split_once(':')
            && name.eq_ignore_ascii_case("content-length")
        {
            content_length = value.trim().parse().map_err(|_| "bad content-length")?;
        }
    }
    let mut body = vec![0u8; content_length];
    reader.read_exact(&mut body).map_err(|e| e.to_string())?;
    Ok(Request { method, path, body })
}

/// Builds an HTTP response with CORS headers.
#[must_use]
pub fn response(status: &str, content_type: &str, body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Headers: content-type\r\nAccess-Control-Allow-Methods: POST, OPTIONS\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

/// Serves one connection.
pub fn serve_connection(rpc: &mut Rpc, stream: &mut TcpStream) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let reply = match read_request(stream) {
        Ok(req) if req.method == "OPTIONS" => response("204 No Content", "text/plain", ""),
        Ok(req) if req.method == "POST" => {
            let body = String::from_utf8_lossy(&req.body).into_owned();
            response(
                "200 OK",
                "application/json",
                &rpc.handle_body(&body).to_string(),
            )
        }
        Ok(req) if req.method == "GET" && req.path == "/health" => {
            response("200 OK", "text/plain", "ok")
        }
        Ok(_) => response("405 Method Not Allowed", "text/plain", "POST JSON-RPC here"),
        Err(e) => response("400 Bad Request", "text/plain", &e),
    };
    let _ = stream.write_all(&reply);
    let _ = stream.flush();
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
/// connections, so a `solo_stop` request ends the loop), serving each one on
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
