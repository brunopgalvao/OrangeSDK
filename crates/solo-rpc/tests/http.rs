//! The minimal HTTP front: request framing, responses, the accept loop.

mod common;

use std::cell::Cell;
use std::io::{Cursor, Read, Write};
use std::net::TcpStream;
use std::rc::Rc;

use common::{Wallet, node};
use solo_rpc::Rpc;
use solo_rpc::http::{Request, bind, read_request, response, serve, serve_connection};

#[test]
fn request_parsing() {
    let mut input =
        Cursor::new(b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello".to_vec());
    assert_eq!(
        read_request(&mut input).unwrap(),
        Request {
            method: "POST".to_owned(),
            path: "/".to_owned(),
            body: b"hello".to_vec()
        }
    );
    let mut input = Cursor::new(b"GET /health HTTP/1.1\n\n".to_vec());
    let req = read_request(&mut input).unwrap();
    assert_eq!((req.method.as_str(), req.path.as_str()), ("GET", "/health"));
    assert!(req.body.is_empty());
    // No headers at all, stream ends.
    let mut input = Cursor::new(b"GET / HTTP/1.1\r\n".to_vec());
    assert_eq!(read_request(&mut input).unwrap().body, Vec::<u8>::new());
    assert_eq!(
        read_request(&mut Cursor::new(b"\r\n".to_vec())).unwrap_err(),
        "empty request line"
    );
    assert_eq!(
        read_request(&mut Cursor::new(b"POST\r\n".to_vec())).unwrap_err(),
        "missing path"
    );
    assert_eq!(
        read_request(&mut Cursor::new(
            b"POST / HTTP/1.1\r\nContent-Length: abc\r\n\r\n".to_vec()
        ))
        .unwrap_err(),
        "bad content-length"
    );
    assert!(
        read_request(&mut Cursor::new(
            b"POST / HTTP/1.1\r\nContent-Length: 10\r\n\r\nshort".to_vec()
        ))
        .unwrap_err()
        .contains("fill whole buffer")
    );
    let clone = Request {
        method: "A".into(),
        path: "/".into(),
        body: vec![],
    }
    .clone();
    assert!(format!("{clone:?}").contains('A'));
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
    let mut first = Flaky {
        data: Cursor::new(b"POST / HTTP/1.1\r\n".to_vec()),
        ok_reads: 0,
    };
    assert_eq!(read_request(&mut first).unwrap_err(), "boom");
    // The request line arrives whole; the headers are cut off mid-line and the next read fails.
    let mut later = Flaky {
        data: Cursor::new(b"POST / HTTP/1.1\r\nX: ".to_vec()),
        ok_reads: 1,
    };
    assert_eq!(read_request(&mut later).unwrap_err(), "boom");
}

#[test]
fn response_format() {
    let bytes = response("200 OK", "application/json", "{}");
    let text = String::from_utf8(bytes).unwrap();
    assert!(text.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(text.contains("Content-Length: 2\r\n"));
    assert!(text.contains("Access-Control-Allow-Origin: *\r\n"));
    assert!(text.ends_with("\r\n\r\n{}"));
}

fn talk(addr: std::net::SocketAddr, request: &[u8]) -> String {
    let mut stream = TcpStream::connect(addr).unwrap();
    stream.write_all(request).unwrap();
    stream.shutdown(std::net::Shutdown::Write).unwrap();
    let mut out = String::new();
    stream.read_to_string(&mut out).unwrap();
    out
}

#[test]
fn connections_and_accept_loop() {
    let alice = Wallet::new(1);
    let mut rpc = Rpc::new(node(&alice));
    let listener = bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    // Direct per-connection serving on a blocking accept.
    listener.set_nonblocking(false).unwrap();
    let client = std::thread::spawn(move || {
        talk(
            addr,
            b"OPTIONS / HTTP/1.1\r\nOrigin: http://localhost\r\n\r\n",
        )
    });
    let (mut stream, _) = listener.accept().unwrap();
    serve_connection(&mut rpc, &mut stream);
    drop(stream);
    assert!(client.join().unwrap().starts_with("HTTP/1.1 204"));
    listener.set_nonblocking(true).unwrap();

    // The accept loop runs the node's background work while no connection
    // is waiting...
    let runs = Rc::new(Cell::new(0));
    let counter = Rc::clone(&runs);
    rpc.set_background(Box::new(move |_| counter.set(counter.get() + 1)));
    let mut checks = 0;
    serve(&listener, &mut rpc, |_| {
        checks += 1;
        checks == 1
    });
    assert_eq!(runs.get(), 1, "one idle turn");
    // ...and after every connection, so a queue of requests cannot starve
    // the node: these are all waiting before the loop starts.
    let body = r#"{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}"#;
    let chain_id = format!(
        "POST / HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    let body = r#"{"jsonrpc":"2.0","id":9,"method":"solo_stop"}"#;
    let stop = format!(
        "POST / HTTP/1.1\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    let requests: [&[u8]; 6] = [
        chain_id.as_bytes(),
        b"GET /health HTTP/1.1\r\n\r\n",
        b"GET /other HTTP/1.1\r\n\r\n",
        b"PUT / HTTP/1.1\r\n\r\n",
        b"\r\n",
        stop.as_bytes(),
    ];
    let streams: Vec<TcpStream> = requests
        .iter()
        .map(|request| {
            let mut stream = TcpStream::connect(addr).unwrap();
            stream.write_all(request).unwrap();
            stream.shutdown(std::net::Shutdown::Write).unwrap();
            stream
        })
        .collect();
    serve(&listener, &mut rpc, |rpc| !rpc.stopped);
    assert_eq!(runs.get(), 1 + requests.len());
    let results: Vec<String> = streams
        .into_iter()
        .map(|mut stream| {
            let mut out = String::new();
            stream.read_to_string(&mut out).unwrap();
            out
        })
        .collect();
    assert!(results[0].starts_with("HTTP/1.1 200 OK"), "{}", results[0]);
    assert!(
        results[0].ends_with(r#""result":"0x539"}"#),
        "{}",
        results[0]
    );
    assert!(results[1].ends_with("\r\n\r\nok"), "{}", results[1]);
    assert!(results[2].starts_with("HTTP/1.1 405"), "{}", results[2]);
    assert!(results[3].starts_with("HTTP/1.1 405"), "{}", results[3]);
    assert!(results[4].starts_with("HTTP/1.1 400"), "{}", results[4]);
    assert!(results[5].ends_with(r#""result":true}"#), "{}", results[5]);
    assert!(rpc.stopped);
}
