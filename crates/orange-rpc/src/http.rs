//! A minimal HTTP/1.1 server for JSON-RPC: one request per connection,
//! `POST` bodies dispatched to [`Rpc`], `OPTIONS` answered for browsers,
//! and `GET /health`, `/metrics` and `/status` for operators (spec 11 §2).
//! A request from a browser page (one with an `Origin` header) is answered
//! only when [`Rpc::cors`] allows its origin, and only then with CORS
//! headers (spec 20 §8.5): otherwise any page the node's operator opened
//! could call the node, `orange_stop` included.
//!
//! Connections are read and written on threads of their own, under the
//! deadlines and bounds of [`Limits`]; the thread that drives the node only
//! answers parsed requests, between its steps ([`Server::turn`]), so no
//! client can hold it (spec 20 §8.6).
//!
//! A `GET` that asks for a WebSocket is upgraded (spec 20 §8.7, [`crate::ws`]):
//! the socket's messages are answered in the same turns, and the
//! subscriptions made on it are notified after them.
//! Deliberately small; a production node fronts this with a real server.

use std::cell::RefCell;
use std::io::{self, BufRead, BufReader, ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::Rpc;
use crate::subscriptions::Subscriptions;

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
    /// What the request says of a WebSocket, when its `Upgrade` header is
    /// `websocket` (spec 20 §8.7.1).
    pub websocket: Option<Handshake>,
}

/// The headers of a request to upgrade to a WebSocket.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Handshake {
    /// Whether the `Connection` header lists `upgrade`.
    pub connection_upgrade: bool,
    /// `Sec-WebSocket-Key`.
    pub key: Option<String>,
    /// `Sec-WebSocket-Version`.
    pub version: Option<String>,
}

/// Largest request body read, geth's default: a `Content-Length` above it is
/// refused before anything is allocated for the body.
pub const MAX_BODY: usize = 5 * 1024 * 1024;

/// Longest request line or header line, its line end included (spec 20
/// §8.6).
pub const MAX_LINE: usize = 8 << 10;

/// Most header lines one request may carry (spec 20 §8.6).
pub const MAX_HEADERS: usize = 64;

/// Most bytes of request line and headers together (spec 20 §8.6).
pub const MAX_HEADER_BYTES: usize = 64 << 10;

/// Most connections open at once (spec 20 §8.6); one past them is answered
/// `503` and closed.
pub const MAX_CONNECTIONS: usize = 64;

/// How long a connection has, from being accepted, to deliver its whole
/// request (spec 20 §8.6).
pub const REQUEST_MS: u64 = 10_000;

/// How long an answer may take to be written once the node hands it over
/// (spec 20 §8.6).
pub const WRITE_MS: u64 = 10_000;

/// Most requests the node answers in one turn of its loop (spec 20 §8.6).
pub const REQUESTS_PER_TURN: usize = 16;

/// What one client may cost the server (spec 20 §8.6). The default is the
/// constants of this module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Longest request or header line ([`MAX_LINE`]).
    pub max_line: usize,
    /// Most header lines ([`MAX_HEADERS`]).
    pub max_headers: usize,
    /// Most bytes of request line and headers ([`MAX_HEADER_BYTES`]).
    pub max_header_bytes: usize,
    /// Largest body ([`MAX_BODY`]).
    pub max_body: usize,
    /// Most connections open at once ([`MAX_CONNECTIONS`]).
    pub max_connections: usize,
    /// How long the whole request may take to arrive ([`REQUEST_MS`]).
    pub request_ms: u64,
    /// How long the answer may take to be written ([`WRITE_MS`]).
    pub write_ms: u64,
    /// Most requests answered per turn ([`REQUESTS_PER_TURN`]).
    pub per_turn: usize,
    /// Most sockets open at once ([`crate::ws::MAX_WS_CONNECTIONS`]).
    pub max_ws_connections: usize,
    /// Most subscriptions per socket ([`crate::ws::MAX_SUBSCRIPTIONS`]).
    pub max_subscriptions: usize,
    /// Longest frame or message on a socket ([`crate::ws::MAX_MESSAGE`]).
    pub max_message: usize,
    /// Most bytes queued for one socket ([`crate::ws::WS_QUEUE_BYTES`]).
    pub ws_queue_bytes: usize,
    /// How long a socket may be silent before it is pinged, and again
    /// before it is closed ([`crate::ws::PING_MS`]).
    pub ping_ms: u64,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits {
            max_line: MAX_LINE,
            max_headers: MAX_HEADERS,
            max_header_bytes: MAX_HEADER_BYTES,
            max_body: MAX_BODY,
            max_connections: MAX_CONNECTIONS,
            request_ms: REQUEST_MS,
            write_ms: WRITE_MS,
            per_turn: REQUESTS_PER_TURN,
            max_ws_connections: crate::ws::MAX_WS_CONNECTIONS,
            max_subscriptions: crate::ws::MAX_SUBSCRIPTIONS,
            max_message: crate::ws::MAX_MESSAGE,
            ws_queue_bytes: crate::ws::WS_QUEUE_BYTES,
            ping_ms: crate::ws::PING_MS,
        }
    }
}

/// Why a request was not read: the status it is answered with, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// The HTTP status line's code and reason.
    pub status: &'static str,
    /// What went wrong, the answer's body.
    pub message: String,
}

fn bad(message: impl Into<String>) -> Refusal {
    Refusal {
        status: "400 Bad Request",
        message: message.into(),
    }
}

fn too_large(message: String) -> Refusal {
    Refusal {
        status: "431 Request Header Fields Too Large",
        message,
    }
}

/// A read that failed: a deadline that passed is `408`, anything else `400`.
fn failed(e: &io::Error) -> Refusal {
    match e.kind() {
        ErrorKind::TimedOut | ErrorKind::WouldBlock => Refusal {
            status: "408 Request Timeout",
            message: "the request did not arrive in time".to_owned(),
        },
        _ => bad(e.to_string()),
    }
}

/// One line of the request head, at most [`Limits::max_line`] bytes and
/// within what [`Limits::max_header_bytes`] leaves after `spent`; empty at
/// the end of the stream.
fn read_line(
    reader: &mut impl BufRead,
    limits: &Limits,
    spent: &mut usize,
) -> Result<String, Refusal> {
    let room = limits.max_header_bytes.saturating_sub(*spent);
    let cap = limits.max_line.min(room);
    let mut line = Vec::new();
    let n = reader
        .take(cap as u64)
        .read_until(b'\n', &mut line)
        .map_err(|e| failed(&e))?;
    *spent += n;
    if n == cap && !line.ends_with(b"\n") {
        return Err(too_large(if cap < limits.max_line {
            format!(
                "request headers too large: the limit is {} bytes",
                limits.max_header_bytes
            )
        } else {
            format!(
                "header line too long: the limit is {} bytes",
                limits.max_line
            )
        }));
    }
    String::from_utf8(line).map_err(|_| bad("stream did not contain valid UTF-8"))
}

/// Reads one HTTP request from a stream, within `limits`.
///
/// # Errors
/// Any I/O or framing problem, a head past the header limits or a body
/// longer than [`Limits::max_body`], with the status to answer it with.
pub fn read_request(
    stream: &mut (impl Read + ?Sized),
    limits: &Limits,
) -> Result<Request, Refusal> {
    let mut reader = BufReader::new(stream);
    let mut spent = 0;
    let line = read_line(&mut reader, limits, &mut spent)?;
    let mut parts = line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| bad("empty request line"))?
        .to_owned();
    let path = parts.next().ok_or_else(|| bad("missing path"))?.to_owned();
    let mut content_length = 0usize;
    let mut origin = None;
    let mut upgrade = false;
    let mut handshake = Handshake::default();
    let mut headers = 0;
    loop {
        let header = read_line(&mut reader, limits, &mut spent)?;
        if header.is_empty() || header == "\r\n" || header == "\n" {
            break;
        }
        headers += 1;
        if headers > limits.max_headers {
            return Err(too_large(format!(
                "too many headers: the limit is {}",
                limits.max_headers
            )));
        }
        let Some((name, value)) = header.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("content-length") {
            content_length = value
                .trim()
                .parse()
                .map_err(|_| bad("bad content-length"))?;
        } else if name.eq_ignore_ascii_case("origin") {
            origin = Some(value.trim().to_owned());
        } else if name.eq_ignore_ascii_case("upgrade") {
            upgrade = value.trim().eq_ignore_ascii_case("websocket");
        } else if name.eq_ignore_ascii_case("connection") {
            handshake.connection_upgrade = value
                .split(',')
                .any(|t| t.trim().eq_ignore_ascii_case("upgrade"));
        } else if name.eq_ignore_ascii_case("sec-websocket-key") {
            handshake.key = Some(value.trim().to_owned());
        } else if name.eq_ignore_ascii_case("sec-websocket-version") {
            handshake.version = Some(value.trim().to_owned());
        }
    }
    if content_length > limits.max_body {
        return Err(bad(format!(
            "body too large: {content_length} bytes, the limit is {}",
            limits.max_body
        )));
    }
    let mut body = vec![0u8; content_length];
    reader.read_exact(&mut body).map_err(|e| failed(&e))?;
    Ok(Request {
        method,
        path,
        body,
        origin,
        websocket: upgrade.then_some(handshake),
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
pub(crate) fn allowed_by<'a>(cors: &'a [String], origin: &str) -> Option<&'a str> {
    cors.iter()
        .find(|a| *a == "*" || a.eq_ignore_ascii_case(origin))
        .map(String::as_str)
}

/// The node's answer to one parsed request. A request with an `Origin`
/// header that [`Rpc::cors`] does not allow gets `403` and reaches nothing.
pub fn answer(rpc: &mut Rpc, req: &Request) -> Vec<u8> {
    match req.origin.as_deref() {
        None => dispatch(rpc, req),
        Some(origin) => match allowed_by(&rpc.cors, origin).map(str::to_owned) {
            Some(allowed) => with_cors(&dispatch(rpc, req), &allowed),
            None => forbidden(),
        },
    }
}

/// The `403` of a page whose origin `--rpc-cors` does not name.
pub(crate) fn forbidden() -> Vec<u8> {
    response(
        "403 Forbidden",
        "text/plain",
        "this node answers browser pages only from the origins its --rpc-cors names",
    )
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

/// What a connection hands the node's thread.
pub(crate) enum Job {
    /// A parsed request, and where its answer goes.
    Http {
        request: Request,
        reply: SyncSender<Vec<u8>>,
    },
    /// A request to upgrade to a WebSocket, the socket it would open, and
    /// where the answer goes, with the socket's id when it opened.
    Upgrade {
        request: Request,
        socket: Arc<crate::ws::Socket>,
        reply: SyncSender<(Vec<u8>, Option<u64>)>,
    },
    /// A message of an open socket, answered on the socket; `done` says
    /// it was.
    Message {
        socket: u64,
        body: String,
        done: SyncSender<()>,
    },
}

/// The time left until `at`; none left is a timeout.
fn left_until(at: Instant) -> io::Result<Duration> {
    let left = at.saturating_duration_since(Instant::now());
    (!left.is_zero())
        .then_some(left)
        .ok_or(ErrorKind::TimedOut.into())
}

/// A stream read until a deadline: each read waits at most what is left.
struct Deadline<'a> {
    stream: &'a TcpStream,
    at: Instant,
}

impl Read for Deadline<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let left = left_until(self.at)?;
        let mut stream = self.stream;
        // Refused on some systems once the peer has closed both ends, when
        // the read does not block anyway.
        let _ = stream.set_read_timeout(Some(left));
        stream.read(buf)
    }
}

/// Writes `bytes` to `stream` by `at`; a write that has not finished then
/// fails, as does any write that fails.
pub(crate) fn write_by(mut stream: &TcpStream, mut bytes: &[u8], at: Instant) -> io::Result<()> {
    while !bytes.is_empty() {
        // As for reads: refused only when the write fails at once anyway.
        let _ = stream.set_write_timeout(Some(left_until(at)?));
        let n = stream.write(bytes)?;
        bytes = &bytes[n..];
    }
    Ok(())
}

/// Waits while `busy` holds, at most `wait`.
pub(crate) fn wait_while(wait: Duration, busy: impl Fn() -> bool) {
    let until = Instant::now() + wait;
    while busy() && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// What the acceptor, the connections and the node's loop share.
pub(crate) struct Shared {
    pub(crate) limits: Limits,
    /// Connections open, sockets aside.
    open: AtomicUsize,
    /// Requests handed to the node and not yet taken.
    pub(crate) waiting: AtomicUsize,
    /// Answers handed back and not yet written.
    pub(crate) writing: AtomicUsize,
    stop: AtomicBool,
}

/// Counts a connection open for as long as it lives, panics included.
pub(crate) struct Open(pub(crate) Arc<Shared>);

impl Drop for Open {
    fn drop(&mut self) {
        self.0.open.fetch_sub(1, Ordering::SeqCst);
    }
}

/// One connection, on its own thread: read the request by its deadline,
/// hand it to the node, write the answer by its deadline. A request to
/// upgrade goes on as a WebSocket ([`crate::ws`]).
fn connection(stream: TcpStream, open: Open, jobs: &SyncSender<Job>) {
    let shared = Arc::clone(&open.0);
    let limits = shared.limits;
    let mut reader = Deadline {
        stream: &stream,
        at: Instant::now() + Duration::from_millis(limits.request_ms),
    };
    let (reply, answered) = match read_request(&mut reader, &limits) {
        Ok(request) if request.method == "GET" && request.websocket.is_some() => {
            crate::ws::serve(stream, request, open, jobs);
            return;
        }
        Ok(request) => {
            let (reply, answered) = sync_channel(1);
            shared.waiting.fetch_add(1, Ordering::SeqCst);
            let sent = jobs.send(Job::Http { request, reply }).is_ok();
            // Nothing answers once the node's loop has stopped.
            let Some(reply) = sent.then(|| answered.recv().ok()).flatten() else {
                return;
            };
            (reply, true)
        }
        Err(refusal) => (
            response(refusal.status, "text/plain", &refusal.message),
            false,
        ),
    };
    let _ = write_by(
        &stream,
        &reply,
        Instant::now() + Duration::from_millis(limits.write_ms),
    );
    if answered {
        shared.writing.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Takes connections until told to stop, each on a thread of its own, at
/// most [`Limits::max_connections`] at once.
fn accept(listener: &TcpListener, shared: &Arc<Shared>, jobs: &SyncSender<Job>) {
    while !shared.stop.load(Ordering::SeqCst) {
        let Ok((stream, _)) = listener.accept() else {
            std::thread::sleep(Duration::from_millis(5));
            continue;
        };
        if shared.open.load(Ordering::SeqCst) >= shared.limits.max_connections {
            // Non-blocking, so a client that reads nothing holds nothing.
            let _ = stream.set_nonblocking(true);
            let busy = response(
                "503 Service Unavailable",
                "text/plain",
                "too many connections",
            );
            let _ = (&stream).write(&busy);
            continue;
        }
        let _ = stream.set_nonblocking(false);
        shared.open.fetch_add(1, Ordering::SeqCst);
        let open = Open(Arc::clone(shared));
        let jobs = jobs.clone();
        std::thread::spawn(move || connection(stream, open, &jobs));
    }
}

/// The server: an acceptor thread and a thread per connection, which hand
/// parsed requests to whoever drives the node ([`Server::turn`]). Dropping
/// it stops the acceptor and waits, at most [`Limits::write_ms`], for the
/// answers already handed back to be written.
pub struct Server {
    shared: Arc<Shared>,
    jobs: Receiver<Job>,
    acceptor: Option<JoinHandle<()>>,
    /// The open sockets and their subscriptions (spec 20 §8.7).
    sockets: RefCell<Subscriptions>,
}

impl Server {
    /// Starts taking connections on `listener`, which is made non-blocking.
    #[must_use]
    pub fn start(listener: TcpListener, limits: Limits) -> Server {
        let _ = listener.set_nonblocking(true);
        let shared = Arc::new(Shared {
            limits,
            open: AtomicUsize::new(0),
            waiting: AtomicUsize::new(0),
            writing: AtomicUsize::new(0),
            stop: AtomicBool::new(false),
        });
        // One request per connection or socket, so the queue never makes
        // one wait.
        let (send, jobs) = sync_channel(limits.max_connections + limits.max_ws_connections);
        let acceptor = {
            let shared = Arc::clone(&shared);
            std::thread::spawn(move || accept(&listener, &shared, &send))
        };
        Server {
            shared,
            jobs,
            acceptor: Some(acceptor),
            sockets: RefCell::new(Subscriptions::new(limits.max_subscriptions)),
        }
    }

    /// Connections open.
    #[must_use]
    pub fn connections(&self) -> usize {
        self.shared.open.load(Ordering::SeqCst)
    }

    /// Sockets open, as the node's thread counts them: those it opened
    /// and has not yet seen close.
    #[must_use]
    pub fn sockets(&self) -> usize {
        self.sockets.borrow().len()
    }

    /// Requests read and waiting for the node.
    #[must_use]
    pub fn waiting(&self) -> usize {
        self.shared.waiting.load(Ordering::SeqCst)
    }

    /// One turn of the node's loop: waits up to `wait` for a request, then
    /// answers at most [`Limits::per_turn`] of those waiting, running the
    /// node's background work after each answer, or once when none came,
    /// and then sends the sockets' notifications (spec 20 §8.7.3).
    /// Returns how many it answered.
    pub fn turn(&self, rpc: &mut Rpc, wait: Duration) -> usize {
        let mut answered = 0;
        let mut next = self.jobs.recv_timeout(wait).ok();
        let mut sockets = self.sockets.borrow_mut();
        while let Some(job) = next {
            self.take(rpc, &mut sockets, job);
            answered += 1;
            rpc.run_background();
            next = if answered < self.shared.limits.per_turn {
                self.jobs.try_recv().ok()
            } else {
                None
            };
        }
        if answered == 0 {
            rpc.run_background();
        }
        sockets.notify(rpc);
        answered
    }

    /// Answers one job.
    fn take(&self, rpc: &mut Rpc, sockets: &mut Subscriptions, job: Job) {
        match job {
            Job::Http { request, reply } => {
                self.shared.waiting.fetch_sub(1, Ordering::SeqCst);
                let answer = answer(rpc, &request);
                self.shared.writing.fetch_add(1, Ordering::SeqCst);
                let _ = reply.send(answer);
            }
            Job::Upgrade {
                request,
                socket,
                reply,
            } => {
                self.shared.waiting.fetch_sub(1, Ordering::SeqCst);
                sockets.sweep();
                let max = self.shared.limits.max_ws_connections;
                let answer = match crate::ws::handshake(&rpc.cors, &request, sockets.len(), max) {
                    Ok(accepted) => (accepted, Some(sockets.open(socket))),
                    Err(refused) => (refused, None),
                };
                self.shared.writing.fetch_add(1, Ordering::SeqCst);
                let _ = reply.send(answer);
            }
            Job::Message { socket, body, done } => {
                sockets.message(rpc, socket, &body);
                let _ = done.send(());
            }
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::SeqCst);
        if let Some(acceptor) = self.acceptor.take() {
            let _ = acceptor.join();
        }
        let wait = Duration::from_millis(self.shared.limits.write_ms);
        let shared = &self.shared;
        wait_while(wait, || shared.writing.load(Ordering::SeqCst) > 0);
        self.sockets.get_mut().close_all(wait);
    }
}

/// [`serve_with`] under the default [`Limits`].
pub fn serve(listener: TcpListener, rpc: &mut Rpc, keep_going: impl FnMut(&Rpc) -> bool) {
    serve_with(listener, rpc, Limits::default(), keep_going);
}

/// Serves `listener` until `keep_going` returns false, checked between the
/// turns of [`Server::turn`], so an `orange_stop` request ends the loop.
/// Connections are read and written off the calling thread, which only
/// answers requests and runs the node's background work
/// ([`Rpc::run_background`]) after each answer and every 5 ms while none
/// waits, so no client can keep the node from its clock and its peers.
pub fn serve_with(
    listener: TcpListener,
    rpc: &mut Rpc,
    limits: Limits,
    mut keep_going: impl FnMut(&Rpc) -> bool,
) {
    let server = Server::start(listener, limits);
    while keep_going(rpc) {
        server.turn(rpc, Duration::from_millis(5));
    }
}
