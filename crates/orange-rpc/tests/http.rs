//! The minimal HTTP front: request framing and its limits, responses, the
//! connection threads and the node's turns (spec 20 §8.5, §8.6).

mod common;

use std::cell::Cell;
use std::io::{Cursor, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use common::{Wallet, node};
use orange_rpc::Rpc;
use orange_rpc::http::{
    Limits, MAX_BODY, MAX_CONNECTIONS, MAX_HEADER_BYTES, MAX_HEADERS, MAX_LINE, REQUEST_MS,
    REQUESTS_PER_TURN, Refusal, Request, Server, WRITE_MS, answer, bind, read_request, response,
    serve, serve_with,
};

fn read(bytes: &[u8]) -> Result<Request, Refusal> {
    read_request(&mut Cursor::new(bytes.to_vec()), &Limits::default())
}

fn refused(bytes: &[u8], limits: &Limits) -> (&'static str, String) {
    let r = read_request(&mut Cursor::new(bytes.to_vec()), limits).unwrap_err();
    (r.status, r.message)
}

#[test]
fn request_parsing() {
    assert_eq!(
        read(b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello").unwrap(),
        Request {
            method: "POST".to_owned(),
            path: "/".to_owned(),
            body: b"hello".to_vec(),
            origin: None,
            websocket: None,
        }
    );
    // The origin of a browser page, whatever the header's case; a line
    // without a colon is skipped.
    let req = read(b"POST / HTTP/1.1\r\norigin:  http://a.example \r\nnot a header\r\n\r\n");
    assert_eq!(req.unwrap().origin.as_deref(), Some("http://a.example"));
    let req = read(b"GET /health HTTP/1.1\n\n").unwrap();
    assert_eq!((req.method.as_str(), req.path.as_str()), ("GET", "/health"));
    assert!(req.body.is_empty());
    // No headers at all, stream ends.
    assert_eq!(read(b"GET / HTTP/1.1\r\n").unwrap().body, Vec::<u8>::new());
    let bad = |bytes: &[u8]| {
        let r = read(bytes).unwrap_err();
        assert_eq!(r.status, "400 Bad Request");
        r.message
    };
    assert_eq!(bad(b"\r\n"), "empty request line");
    assert_eq!(bad(b"POST\r\n"), "missing path");
    assert_eq!(
        bad(b"POST / HTTP/1.1\r\nContent-Length: abc\r\n\r\n"),
        "bad content-length"
    );
    assert!(
        bad(b"POST / HTTP/1.1\r\nContent-Length: 10\r\n\r\nshort").contains("fill whole buffer")
    );
    assert_eq!(
        bad(b"POST / HTTP/1.1\r\nX: \xff\r\n\r\n"),
        "stream did not contain valid UTF-8"
    );
    // A body over the limit is refused from its length alone, a body at the
    // limit is read.
    let over = format!(
        "POST / HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
        MAX_BODY + 1
    );
    assert_eq!(
        bad(over.as_bytes()),
        format!(
            "body too large: {} bytes, the limit is {MAX_BODY}",
            MAX_BODY + 1
        )
    );
    let mut at = format!("POST / HTTP/1.1\r\nContent-Length: {MAX_BODY}\r\n\r\n").into_bytes();
    at.resize(at.len() + MAX_BODY, b'x');
    assert_eq!(read(&at).unwrap().body.len(), MAX_BODY);
    let clone = Request {
        method: "A".into(),
        path: "/".into(),
        body: vec![],
        origin: None,
        websocket: None,
    }
    .clone();
    assert!(format!("{clone:?}").contains('A'));
    let refusal = read(b"\r\n").unwrap_err().clone();
    assert!(format!("{refusal:?}").contains("empty request line"));
}

#[test]
fn limits_default_to_the_constants() {
    let limits = Limits::default();
    assert_eq!(
        limits,
        Limits {
            max_line: MAX_LINE,
            max_headers: MAX_HEADERS,
            max_header_bytes: MAX_HEADER_BYTES,
            max_body: MAX_BODY,
            max_connections: MAX_CONNECTIONS,
            request_ms: REQUEST_MS,
            write_ms: WRITE_MS,
            per_turn: REQUESTS_PER_TURN,
            max_ws_connections: 32,
            max_subscriptions: 128,
            max_message: MAX_BODY,
            ws_queue_bytes: 32 << 20,
            ping_ms: 30_000,
        }
    );
    assert_eq!(
        (MAX_LINE, MAX_HEADERS, MAX_HEADER_BYTES, MAX_CONNECTIONS),
        (8192, 64, 65_536, 64)
    );
    assert_eq!(
        (REQUEST_MS, WRITE_MS, REQUESTS_PER_TURN),
        (10_000, 10_000, 16)
    );
    assert!(format!("{limits:?}").contains("max_line"));
}

/// The head of a request is bounded line by line, in lines and in bytes
/// (spec 20 §8.6). Before, a header line was read whatever its length, and
/// any number of them, so one connection could make the node buffer
/// without end.
#[test]
fn request_heads_are_bounded() {
    let limits = Limits {
        max_line: 32,
        max_headers: 3,
        max_header_bytes: 80,
        ..Limits::default()
    };
    let too_large = "431 Request Header Fields Too Large";
    // A line of exactly the limit, its line end included, is read; one byte
    // more is not, request line or header.
    let line = |n: usize| format!("X: {}\r\n", "a".repeat(n - 5));
    let at = format!("GET / HTTP/1.1\r\n{}\r\n", line(32));
    assert!(read_request(&mut Cursor::new(at.into_bytes()), &limits).is_ok());
    let over = format!("GET / HTTP/1.1\r\n{}\r\n", line(33));
    let long = (
        too_large,
        "header line too long: the limit is 32 bytes".to_owned(),
    );
    assert_eq!(refused(over.as_bytes(), &limits), long);
    let request_line = format!("GET /{} HTTP/1.1\r\n\r\n", "p".repeat(32));
    assert_eq!(refused(request_line.as_bytes(), &limits), long);
    // At most three header lines.
    let three = "GET / HTTP/1.1\r\nA: 1\r\nB: 2\r\nC: 3\r\n\r\n";
    assert!(read_request(&mut Cursor::new(three.as_bytes().to_vec()), &limits).is_ok());
    let four = "GET / HTTP/1.1\r\nA: 1\r\nB: 2\r\nC: 3\r\nD: 4\r\n\r\n";
    assert_eq!(
        refused(four.as_bytes(), &limits),
        (too_large, "too many headers: the limit is 3".to_owned())
    );
    // At most 80 bytes of head, whatever the lines' lengths.
    let head = format!("GET / HTTP/1.1\r\n{}{}\r\n", line(30), line(30));
    assert_eq!(head.len(), 78);
    assert!(read_request(&mut Cursor::new(head.into_bytes()), &limits).is_ok());
    let head = format!("GET / HTTP/1.1\r\n{}{}{}\r\n", line(30), line(30), line(6));
    assert_eq!(
        refused(head.as_bytes(), &limits),
        (
            too_large,
            "request headers too large: the limit is 80 bytes".to_owned()
        )
    );
    // The defaults refuse a header line of a megabyte.
    let huge = format!("GET / HTTP/1.1\r\nX: {}\r\n\r\n", "a".repeat(1 << 20));
    assert_eq!(read(huge.as_bytes()).unwrap_err().status, too_large);
}

/// A reader that fails after `ok_reads` successful reads.
struct Flaky {
    data: Cursor<Vec<u8>>,
    ok_reads: usize,
}

impl Read for Flaky {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.ok_reads == 0 {
            return Err(std::io::Error::other("boom"));
        }
        self.ok_reads -= 1;
        self.data.read(buf)
    }
}

#[test]
fn io_errors_are_reported() {
    let limits = Limits::default();
    let mut first = Flaky {
        data: Cursor::new(b"POST / HTTP/1.1\r\n".to_vec()),
        ok_reads: 0,
    };
    let boom = Refusal {
        status: "400 Bad Request",
        message: "boom".to_owned(),
    };
    assert_eq!(read_request(&mut first, &limits).unwrap_err(), boom);
    // The request line arrives whole; the headers are cut off mid-line and the next read fails.
    let mut later = Flaky {
        data: Cursor::new(b"POST / HTTP/1.1\r\nX: ".to_vec()),
        ok_reads: 1,
    };
    assert_eq!(read_request(&mut later, &limits).unwrap_err(), boom);
}

#[test]
fn response_format() {
    let bytes = response("200 OK", "application/json", "{}");
    let text = String::from_utf8(bytes).unwrap();
    assert!(text.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(text.contains("Content-Length: 2\r\n"));
    // No CORS headers: a browser page reads nothing it was not allowed to.
    assert!(!text.contains("Access-Control"), "{text}");
    assert!(text.ends_with("\r\n\r\n{}"));
}

/// Browser pages (requests with an `Origin` header) are answered only from
/// the origins the node was told to serve, and only those get CORS headers
/// (spec 20 §8.5). Before, every answer carried
/// `Access-Control-Allow-Origin: *`, and any page an operator opened could
/// `POST` `orange_stop` to `127.0.0.1:8545` and stop the node.
#[test]
fn browser_pages_are_answered_only_from_allowed_origins() {
    let alice = Wallet::new(1);
    let mut rpc = Rpc::new(node(&alice));
    rpc.stop_allowed = true;
    let stop = r#"{"jsonrpc":"2.0","id":1,"method":"orange_stop"}"#;
    let request = |method: &str, path: &str, origin: Option<&str>| Request {
        method: method.to_owned(),
        path: path.to_owned(),
        body: stop.as_bytes().to_vec(),
        origin: origin.map(str::to_owned),
        websocket: None,
    };
    let post = |origin| request("POST", "/", origin);
    let ask = |rpc: &mut Rpc, req: Request| String::from_utf8(answer(rpc, &req)).unwrap();
    // By default no page is answered, its preflight included, and the stop
    // a page sends reaches nothing.
    let refused = ask(&mut rpc, post(Some("http://evil.example")));
    assert!(refused.starts_with("HTTP/1.1 403 Forbidden"), "{refused}");
    assert!(!refused.contains("Access-Control"), "{refused}");
    assert!(!rpc.stopped);
    let preflight = request("OPTIONS", "/", Some("http://evil.example"));
    assert!(ask(&mut rpc, preflight).starts_with("HTTP/1.1 403"));
    let telemetry = request("GET", "/status", Some("null"));
    assert!(ask(&mut rpc, telemetry).starts_with("HTTP/1.1 403"));
    // An allowed origin is answered, with headers naming the origin as
    // configured.
    rpc.cors = vec!["http://localhost:5173".to_owned()];
    let preflight = request("OPTIONS", "/", Some("HTTP://LOCALHOST:5173"));
    let allowed = ask(&mut rpc, preflight);
    assert!(
        allowed.starts_with("HTTP/1.1 204 No Content\r\n"),
        "{allowed}"
    );
    for header in [
        "Access-Control-Allow-Origin: http://localhost:5173\r\n",
        "Vary: Origin\r\n",
        "Access-Control-Allow-Headers: content-type\r\n",
        "Access-Control-Allow-Methods: POST, OPTIONS\r\n",
    ] {
        assert!(allowed.contains(header), "{allowed}");
    }
    assert!(ask(&mut rpc, post(Some("http://evil.example"))).starts_with("HTTP/1.1 403"));
    // `*` allows every page.
    rpc.cors = vec!["*".to_owned()];
    let any = ask(&mut rpc, post(Some("http://evil.example")));
    assert!(any.contains("Access-Control-Allow-Origin: *\r\n"), "{any}");
    assert!(any.ends_with(r#""result":true}"#), "{any}");
    assert!(rpc.stopped);
    // Clients outside browsers send no origin, and are answered whatever
    // the list says.
    rpc.cors.clear();
    rpc.stopped = false;
    let plain = ask(&mut rpc, post(None));
    assert!(plain.ends_with(r#""result":true}"#), "{plain}");
    assert!(!plain.contains("Access-Control"), "{plain}");
}

/// Waits for `ready`, failing the test after ten seconds.
fn wait_until(what: &str, mut ready: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !ready() {
        assert!(Instant::now() < deadline, "never: {what}");
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// Connects and sends `request` whole, keeping the stream open to read.
fn send(addr: SocketAddr, request: &[u8]) -> TcpStream {
    let mut stream = TcpStream::connect(addr).unwrap();
    stream.write_all(request).unwrap();
    stream.shutdown(std::net::Shutdown::Write).unwrap();
    stream
}

/// What the server sent until it closed the stream; empty if it closed it
/// without a word or reset it.
fn answer_of(mut stream: TcpStream) -> String {
    // Refused on some systems once the server has closed its end.
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let mut out = Vec::new();
    match stream.read_to_end(&mut out) {
        Ok(_) => {}
        Err(e) => assert_eq!(e.kind(), std::io::ErrorKind::ConnectionReset, "{e}"),
    }
    String::from_utf8(out).unwrap()
}

fn post(body: &str) -> Vec<u8> {
    format!(
        "POST / HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

const CHAIN_ID: &str = r#"{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}"#;

/// Requests are read on connection threads and answered in the node's
/// turns, at most `per_turn` of them a turn, with the node's background
/// work after each answer and once in a turn that answers none.
#[test]
fn the_node_answers_parsed_requests_in_bounded_turns() {
    let alice = Wallet::new(1);
    let mut rpc = Rpc::new(node(&alice));
    let runs = Rc::new(Cell::new(0));
    let counter = Rc::clone(&runs);
    rpc.set_background(Box::new(move |_| counter.set(counter.get() + 1)));
    let listener = bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let limits = Limits {
        per_turn: 2,
        ..Limits::default()
    };
    let server = Server::start(listener, limits);
    assert_eq!(server.turn(&mut rpc, Duration::ZERO), 0);
    assert_eq!(runs.get(), 1, "one idle turn");
    let requests: [&[u8]; 5] = [
        &post(CHAIN_ID),
        b"GET /health HTTP/1.1\r\n\r\n",
        b"GET /other HTTP/1.1\r\n\r\n",
        b"PUT / HTTP/1.1\r\n\r\n",
        b"OPTIONS / HTTP/1.1\r\n\r\n",
    ];
    let streams: Vec<TcpStream> = requests.iter().map(|r| send(addr, r)).collect();
    // A request that does not parse is answered by its own thread.
    let unparsed = answer_of(send(addr, b"\r\n"));
    assert!(unparsed.starts_with("HTTP/1.1 400"), "{unparsed}");
    assert!(unparsed.ends_with("empty request line"), "{unparsed}");
    wait_until("every request read", || server.waiting() == requests.len());
    assert_eq!(server.turn(&mut rpc, Duration::ZERO), 2);
    assert_eq!(runs.get(), 3, "once after each answer");
    assert_eq!(server.turn(&mut rpc, Duration::ZERO), 2);
    assert_eq!(server.turn(&mut rpc, Duration::ZERO), 1);
    assert_eq!(server.waiting(), 0);
    assert_eq!(runs.get(), 6);
    let results: Vec<String> = streams.into_iter().map(answer_of).collect();
    assert!(results[0].starts_with("HTTP/1.1 200 OK"), "{}", results[0]);
    assert!(
        results[0].ends_with(r#""result":"0x539"}"#),
        "{}",
        results[0]
    );
    assert!(results[1].ends_with("\r\n\r\nok"), "{}", results[1]);
    assert!(results[2].starts_with("HTTP/1.1 405"), "{}", results[2]);
    assert!(results[3].starts_with("HTTP/1.1 405"), "{}", results[3]);
    assert!(results[4].starts_with("HTTP/1.1 204"), "{}", results[4]);
    wait_until("every connection closed", || server.connections() == 0);
}

/// `serve` runs turns until told to stop; the answer to `orange_stop` is
/// written before it returns.
#[test]
fn the_loop_stops_on_orange_stop_after_answering_it() {
    let alice = Wallet::new(1);
    let mut rpc = Rpc::new(node(&alice));
    rpc.stop_allowed = true;
    let listener = bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let stop = send(
        addr,
        &post(r#"{"jsonrpc":"2.0","id":9,"method":"orange_stop"}"#),
    );
    let chain_id = send(addr, &post(CHAIN_ID));
    serve(listener, &mut rpc, |rpc| !rpc.stopped);
    assert!(rpc.stopped);
    let out = answer_of(stop);
    assert!(out.ends_with(r#""result":true}"#), "{out}");
    // The other request may or may not have been answered first; either
    // way its connection is closed.
    let other = answer_of(chain_id);
    assert!(
        other.is_empty() || other.ends_with(r#""result":"0x539"}"#),
        "{other}"
    );
}

/// A client that sends its request a byte at a time does not hold the
/// node: another client is answered meanwhile, and the node's background
/// work keeps running. Before, connections were served on the node's
/// thread one at a time with a 5 s timeout on each read, so a byte every
/// few seconds froze the node for as long as the client liked.
#[test]
fn a_slow_client_does_not_hold_the_node() {
    let stop = Arc::new(AtomicBool::new(false));
    let (tx, rx) = std::sync::mpsc::channel();
    let node_thread = {
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            let alice = Wallet::new(1);
            let mut rpc = Rpc::new(node(&alice));
            let listener = bind("127.0.0.1:0").unwrap();
            tx.send(listener.local_addr().unwrap()).unwrap();
            serve(listener, &mut rpc, |_| !stop.load(Ordering::SeqCst));
        })
    };
    let addr = rx.recv().unwrap();
    let dripping = Arc::new(AtomicBool::new(true));
    let slow = {
        let dripping = Arc::clone(&dripping);
        std::thread::spawn(move || {
            let mut stream = TcpStream::connect(addr).unwrap();
            // A head of 64 bytes over three seconds, well within every limit.
            let head =
                b"POST / HTTP/1.1\r\nX-Slow: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n";
            for byte in head {
                if stream.write_all(&[*byte]).is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(3_000 / 64));
            }
            dripping.store(false, Ordering::SeqCst);
        })
    };
    // Let the slow client's first bytes reach the server.
    std::thread::sleep(Duration::from_millis(200));
    let fast = answer_of(send(addr, &post(CHAIN_ID)));
    assert!(
        dripping.load(Ordering::SeqCst),
        "the fast client waited for the slow one"
    );
    assert!(fast.ends_with(r#""result":"0x539"}"#), "{fast}");
    slow.join().unwrap();
    stop.store(true, Ordering::SeqCst);
    node_thread.join().unwrap();
}

/// A request must arrive whole within `request_ms` of the connection,
/// however steadily its bytes come; past it the connection is answered
/// `408` and closed.
#[test]
fn a_request_has_a_deadline() {
    let alice = Wallet::new(1);
    let mut rpc = Rpc::new(node(&alice));
    let listener = bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let limits = Limits {
        request_ms: 200,
        ..Limits::default()
    };
    let server = Server::start(listener, limits);
    // A request that stops halfway.
    let started = Instant::now();
    let mut half = TcpStream::connect(addr).unwrap();
    half.write_all(b"POST / HTTP/1.1\r\nContent-Length: 10\r\n\r\nhalf")
        .unwrap();
    let timed_out = answer_of(half);
    assert!(
        timed_out.starts_with("HTTP/1.1 408 Request Timeout\r\n"),
        "{timed_out}"
    );
    assert!(timed_out.ends_with("the request did not arrive in time"));
    assert!(started.elapsed() >= Duration::from_millis(200));
    // A body that keeps coming, a kilobyte every millisecond, five seconds'
    // worth: closed at the deadline all the same.
    let started = Instant::now();
    let stream = TcpStream::connect(addr).unwrap();
    let mut writer = stream.try_clone().unwrap();
    let dripper = std::thread::spawn(move || {
        let head = format!("POST / HTTP/1.1\r\nContent-Length: {MAX_BODY}\r\n\r\n");
        writer.write_all(head.as_bytes()).unwrap();
        for _ in 0..MAX_BODY / 1024 {
            if writer.write_all(&[b' '; 1024]).is_err() {
                return;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    });
    let cut = answer_of(stream);
    assert!(cut.is_empty() || cut.starts_with("HTTP/1.1 408"), "{cut}");
    assert!(started.elapsed() < Duration::from_secs(5));
    dripper.join().unwrap();
    wait_until("both connections closed", || server.connections() == 0);
    assert_eq!(
        server.turn(&mut rpc, Duration::ZERO),
        0,
        "nothing reached the node"
    );
}

/// An answer must be written within `write_ms`: a client that never reads
/// a large answer is closed, and holds neither the node nor, for longer
/// than that, the end of the loop. Before, the node's own thread wrote the
/// answer, and a client that read nothing blocked it for good.
#[test]
fn an_answer_has_a_deadline() {
    let alice = Wallet::new(1);
    let mut rpc = Rpc::new(node(&alice));
    let listener = bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let limits = Limits {
        write_ms: 300,
        max_body: 64 << 20,
        ..Limits::default()
    };
    let server = Server::start(listener, limits);
    // The answer echoes a 24 MiB id: more than any socket buffers hold.
    let id = "i".repeat(24 << 20);
    let request = post(&format!(
        r#"{{"jsonrpc":"2.0","id":"{id}","method":"eth_chainId"}}"#
    ));
    let unread = |request: Vec<u8>| {
        let stream = TcpStream::connect(addr).unwrap();
        let mut writer = stream.try_clone().unwrap();
        std::thread::spawn(move || writer.write_all(&request).unwrap());
        stream
    };
    let first = unread(request.clone());
    let deadline = Instant::now() + Duration::from_secs(10);
    while server.turn(&mut rpc, Duration::from_millis(5)) == 0 {
        assert!(Instant::now() < deadline, "the request never arrived");
    }
    // While that answer waits for its reader, the node answers others.
    let fast = send(addr, &post(CHAIN_ID));
    wait_until("the fast request read", || server.waiting() == 1);
    assert_eq!(server.turn(&mut rpc, Duration::ZERO), 1);
    assert!(answer_of(fast).ends_with(r#""result":"0x539"}"#));
    wait_until("the unread answer abandoned", || server.connections() == 0);
    drop(first);
    // One more, with the server dropped while its answer is unwritten: the
    // drop waits for the deadline, then returns.
    let second = unread(request);
    let deadline = Instant::now() + Duration::from_secs(10);
    while server.turn(&mut rpc, Duration::from_millis(5)) == 0 {
        assert!(Instant::now() < deadline, "the request never arrived");
    }
    let dropping = Instant::now();
    drop(server);
    assert!(dropping.elapsed() < Duration::from_secs(5));
    drop(second);
}

/// At most `max_connections` connections are open at once; one past them is
/// answered `503` without being read.
#[test]
fn connections_are_bounded() {
    let alice = Wallet::new(1);
    let mut rpc = Rpc::new(node(&alice));
    let listener = bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let limits = Limits {
        max_connections: 2,
        ..Limits::default()
    };
    let server = Server::start(listener, limits);
    let held: Vec<TcpStream> = (0..2).map(|_| TcpStream::connect(addr).unwrap()).collect();
    wait_until("two connections open", || server.connections() == 2);
    let busy = answer_of(TcpStream::connect(addr).unwrap());
    assert!(
        busy.starts_with("HTTP/1.1 503 Service Unavailable"),
        "{busy}"
    );
    assert!(busy.ends_with("too many connections"), "{busy}");
    drop(held);
    wait_until("the held connections closed", || server.connections() == 0);
    let stream = send(addr, &post(CHAIN_ID));
    wait_until("the request read", || server.waiting() == 1);
    assert_eq!(server.turn(&mut rpc, Duration::ZERO), 1);
    assert!(answer_of(stream).ends_with(r#""result":"0x539"}"#));
}

/// Once the server is dropped, a request waiting for the node, or read
/// afterwards, is closed without an answer.
#[test]
fn a_stopped_server_answers_nothing_more() {
    let listener = bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = Server::start(listener, Limits::default());
    let waiting = send(addr, &post(CHAIN_ID));
    wait_until("the request read", || server.waiting() == 1);
    let mut late = TcpStream::connect(addr).unwrap();
    wait_until("the late connection open", || server.connections() == 2);
    drop(server);
    assert_eq!(answer_of(waiting), "");
    late.write_all(&post(CHAIN_ID)).unwrap();
    late.shutdown(std::net::Shutdown::Write).unwrap();
    assert_eq!(answer_of(late), "");
}

/// `serve_with` takes its limits.
#[test]
fn serve_with_takes_limits() {
    let alice = Wallet::new(1);
    let mut rpc = Rpc::new(node(&alice));
    let listener = bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let limits = Limits {
        max_line: 16,
        ..Limits::default()
    };
    let stream = send(addr, b"GET /a-long-path HTTP/1.1\r\n\r\n");
    let mut turns = 0;
    let mut answer = None;
    let mut stream = Some(stream);
    serve_with(listener, &mut rpc, limits, |_| {
        turns += 1;
        if let Some(s) = stream.take() {
            answer = Some(answer_of(s));
        }
        answer.is_none()
    });
    assert!(answer.unwrap().starts_with("HTTP/1.1 431"));
    assert!(turns >= 1);
}
