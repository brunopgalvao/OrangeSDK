//! The WebSocket beside HTTP (spec 20 §8.7): the frame codec and the
//! handshake's hash, the upgrade and its refusals, every method and the
//! three subscriptions over a socket, and what one socket may cost.

mod common;

use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use common::{Fields, SLOT_MS, Wallet, calldata, counter_initcode, created_address, node};
use orange_host::hash::keccak256;
use orange_rpc::Rpc;
use orange_rpc::http::{Handshake, Limits, Request, Server, bind, read_request, serve};
use orange_rpc::methods::data;
use orange_rpc::subscriptions::{BLOCKS_PER_TURN, PENDING_MS};
use orange_rpc::ws::{
    self, Assembler, Event, Frame, MAX_MESSAGE, MAX_SUBSCRIPTIONS, MAX_WS_CONNECTIONS, PING_MS,
    WS_QUEUE_BYTES, accept_key, base64, base64_len, close_frame, decode, encode, encode_masked,
    handshake, opcode, sha1, status,
};
use serde_json::{Value, json};

/// RFC 6455's example key.
const KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::new(), |s, b| s + &format!("{b:02x}"))
}

#[test]
fn the_hash_the_encoding_and_the_accept_key_follow_their_standards() {
    // FIPS 180-4's examples, one block, two blocks, and a padding that
    // needs a block of its own.
    assert_eq!(hex(&sha1(b"")), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    assert_eq!(
        hex(&sha1(b"abc")),
        "a9993e364706816aba3e25717850c26c9cd0d89d"
    );
    assert_eq!(
        hex(&sha1(
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        )),
        "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
    );
    assert_eq!(
        hex(&sha1(&[b'a'; 1000])),
        "291e9a6c66994949b57ba5e650361e98fc36b1ba"
    );
    // RFC 4648's examples.
    let cases = [
        ("", ""),
        ("f", "Zg=="),
        ("fo", "Zm8="),
        ("foo", "Zm9v"),
        ("foob", "Zm9vYg=="),
        ("fooba", "Zm9vYmE="),
        ("foobar", "Zm9vYmFy"),
    ];
    for (plain, encoded) in cases {
        assert_eq!(base64(plain.as_bytes()), encoded);
        assert_eq!(base64_len(encoded), Some(plain.len()), "{encoded}");
    }
    assert_eq!(base64_len(KEY), Some(16));
    assert_eq!(base64_len("abc"), None);
    assert_eq!(base64_len("ab!d"), None);
    assert_eq!(base64_len("a==="), None);
    // RFC 6455's example (§1.3).
    assert_eq!(accept_key(KEY), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
}

#[test]
fn frames_decode_and_encode_as_rfc_6455_says() {
    let key = [1, 2, 3, 4];
    for len in [0, 1, 125, 126, 65_535, 65_536] {
        let payload: Vec<u8> = (0..len).map(|i| u8::try_from(i % 251).unwrap()).collect();
        let wire = encode_masked(true, opcode::BINARY, &payload, key);
        let header = match len {
            0..=125 => 2,
            126..=65_535 => 4,
            _ => 10,
        };
        assert_eq!(wire.len(), header + 4 + len);
        let frame = Frame {
            fin: true,
            opcode: opcode::BINARY,
            payload: payload.clone(),
        };
        assert_eq!(decode(&wire, 1 << 20), Ok(Some((frame, wire.len()))));
        // Every prefix is a frame still to come.
        for cut in [0, 1, header - 1, header + 3, wire.len() - 1] {
            if cut < wire.len() && (cut != header - 1 || header > 2) {
                assert_eq!(decode(&wire[..cut], 1 << 20), Ok(None), "{len} cut {cut}");
            }
        }
        // The server's frames are not masked.
        let out = encode(opcode::TEXT, &payload);
        assert_eq!(out.len(), header + len);
        assert_eq!(out[0], 0x81);
        assert_eq!(&out[header..], &payload[..]);
    }
    assert_eq!(encode(opcode::TEXT, b"hi"), [0x81, 2, b'h', b'i']);
    assert_eq!(close_frame(status::NORMAL), [0x88, 2, 0x03, 0xe8]);
    let fragment = encode_masked(false, opcode::TEXT, b"a", key);
    assert!(!decode(&fragment, 10).unwrap().unwrap().0.fin);
    let frame = decode(&fragment, 10).unwrap().unwrap().0;
    assert!(format!("{frame:?}").contains("fin: false"));
    // What breaks the protocol, and what is too long, from the header.
    let refused = |wire: &[u8], max| decode(wire, max).unwrap_err();
    assert_eq!(refused(&[0xc1, 0x80], 10), status::PROTOCOL, "reserved bit");
    assert_eq!(refused(&[0x83, 0x80], 10), status::PROTOCOL, "opcode 3");
    assert_eq!(refused(&[0x8b, 0x80], 10), status::PROTOCOL, "opcode 11");
    assert_eq!(refused(&[0x81, 0x00], 10), status::PROTOCOL, "unmasked");
    assert_eq!(
        refused(&[0x09, 0x80], 10),
        status::PROTOCOL,
        "fragmented ping"
    );
    assert_eq!(refused(&[0x89, 0xfe], 10), status::PROTOCOL, "long ping");
    assert_eq!(refused(&[0x81, 0x8b], 10), status::TOO_BIG);
    assert_eq!(refused(&[0x81, 0xfe, 0, 11], 10), status::TOO_BIG);
    assert_eq!(
        refused(
            &[0x81, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            10
        ),
        status::TOO_BIG
    );
    // A ping of 125 bytes is a ping.
    let ping = encode_masked(true, opcode::PING, &[7; 125], key);
    assert_eq!(decode(&ping, 125).unwrap().unwrap().0.payload, vec![7; 125]);
}

#[test]
fn messages_are_assembled_from_their_frames() {
    let frame = |fin, opcode, payload: &[u8]| Frame {
        fin,
        opcode,
        payload: payload.to_vec(),
    };
    let mut a = Assembler::new(8);
    assert_eq!(
        a.push(frame(true, opcode::CLOSE, b"")),
        Ok(Some(Event::Close))
    );
    let ping = a.push(frame(true, opcode::PING, b"p")).unwrap().unwrap();
    assert_eq!(ping, Event::Ping(b"p".to_vec()));
    assert!(format!("{ping:?}").contains("Ping"));
    assert_eq!(a.push(frame(true, opcode::PONG, b"")), Ok(None));
    assert_eq!(
        a.push(frame(true, opcode::TEXT, b"{}")),
        Ok(Some(Event::Message("{}".into())))
    );
    // Fragments, with a ping between them.
    assert_eq!(a.push(frame(false, opcode::TEXT, b"ab")), Ok(None));
    assert!(a.push(frame(true, opcode::PING, b"")).unwrap().is_some());
    assert_eq!(a.push(frame(false, opcode::CONTINUATION, b"cd")), Ok(None));
    assert_eq!(
        a.push(frame(true, opcode::CONTINUATION, b"ef")),
        Ok(Some(Event::Message("abcdef".into())))
    );
    // Binary is taken as text where it is not UTF-8.
    assert_eq!(
        a.push(frame(true, opcode::BINARY, b"\xffz")),
        Ok(Some(Event::Message("\u{fffd}z".into())))
    );
    let refused = |frames: &[Frame]| {
        let mut a = Assembler::new(8);
        let (last, first) = frames.split_last().unwrap();
        for f in first {
            assert_eq!(a.push(f.clone_frame()), Ok(None));
        }
        a.push(last.clone_frame()).unwrap_err()
    };
    assert_eq!(
        refused(&[frame(true, opcode::CONTINUATION, b"x")]),
        status::PROTOCOL
    );
    assert_eq!(
        refused(&[
            frame(false, opcode::TEXT, b"x"),
            frame(true, opcode::TEXT, b"y")
        ]),
        status::PROTOCOL
    );
    assert_eq!(
        refused(&[
            frame(false, opcode::TEXT, b"12345"),
            frame(true, opcode::CONTINUATION, b"6789")
        ]),
        status::TOO_BIG
    );
    assert_eq!(
        refused(&[frame(true, opcode::TEXT, b"\xff")]),
        status::INVALID
    );
}

/// Frames are not `Clone`; the tests copy them.
trait CloneFrame {
    fn clone_frame(&self) -> Frame;
}

impl CloneFrame for Frame {
    fn clone_frame(&self) -> Frame {
        Frame {
            fin: self.fin,
            opcode: self.opcode,
            payload: self.payload.clone(),
        }
    }
}

fn upgrade_request(extra: &str) -> Vec<u8> {
    format!(
        "GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: keep-alive, Upgrade\r\nSec-WebSocket-Key: {KEY}\r\nSec-WebSocket-Version: 13\r\n{extra}\r\n"
    )
    .into_bytes()
}

/// An upgrade is read with the request (spec 20 §8.7.1) and answered `101`
/// only when it is valid, from an allowed origin and within the limit.
#[test]
fn an_upgrade_opens_a_socket_only_when_valid_allowed_and_within_the_limit() {
    let read = |bytes: &[u8]| {
        read_request(
            &mut std::io::Cursor::new(bytes.to_vec()),
            &Limits::default(),
        )
        .unwrap()
    };
    let req = read(&upgrade_request("Origin: http://a.example\r\n"));
    let expected = Handshake {
        connection_upgrade: true,
        key: Some(KEY.to_owned()),
        version: Some("13".to_owned()),
    };
    assert_eq!(req.websocket, Some(expected.clone()));
    assert!(format!("{req:?}").contains("connection_upgrade"));
    let other = read(b"GET / HTTP/1.1\r\nUpgrade: h2c\r\nConnection: close\r\n\r\n");
    assert_eq!(other.websocket, None);
    let answer = |cors: &[&str], req: &Request, open| {
        let cors: Vec<String> = cors.iter().map(|c| (*c).to_owned()).collect();
        match handshake(&cors, req, open, 2) {
            Ok(bytes) | Err(bytes) => String::from_utf8(bytes).unwrap(),
        }
    };
    let with = |hs: Handshake, origin: Option<&str>| Request {
        method: "GET".into(),
        path: "/".into(),
        body: vec![],
        origin: origin.map(str::to_owned),
        websocket: Some(hs),
    };
    let ok = answer(&["http://a.example"], &req, 1);
    assert!(
        ok.starts_with("HTTP/1.1 101 Switching Protocols\r\n"),
        "{ok}"
    );
    assert!(ok.contains("Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"));
    assert!(!ok.contains("Access-Control"));
    assert!(answer(&[], &with(expected.clone(), None), 0).starts_with("HTTP/1.1 101"));
    assert!(answer(&["*"], &req, 1).starts_with("HTTP/1.1 101"));
    let status = |s: String| s.split("\r\n").next().unwrap().to_owned();
    assert_eq!(status(answer(&[], &req, 0)), "HTTP/1.1 403 Forbidden");
    assert_eq!(
        status(answer(&["http://a.example"], &req, 2)),
        "HTTP/1.1 503 Service Unavailable"
    );
    let bad = [
        Handshake {
            connection_upgrade: false,
            ..expected.clone()
        },
        Handshake {
            key: None,
            ..expected.clone()
        },
        Handshake {
            key: Some("c2hvcnQ=".into()),
            ..expected.clone()
        },
    ];
    for hs in bad {
        assert_eq!(
            status(answer(&[], &with(hs, None), 0)),
            "HTTP/1.1 400 Bad Request"
        );
    }
    let mut no_ws = with(expected.clone(), None);
    no_ws.websocket = None;
    assert_eq!(status(answer(&[], &no_ws, 0)), "HTTP/1.1 400 Bad Request");
    for version in [None, Some("8".to_owned())] {
        let old = answer(
            &[],
            &with(
                Handshake {
                    version,
                    ..expected.clone()
                },
                None,
            ),
            0,
        );
        assert!(
            old.starts_with("HTTP/1.1 426 Upgrade Required\r\n"),
            "{old}"
        );
        assert!(old.contains("Sec-WebSocket-Version: 13\r\n"));
    }
    assert_eq!(
        (MAX_WS_CONNECTIONS, MAX_SUBSCRIPTIONS, MAX_MESSAGE),
        (32, 128, 5 << 20)
    );
    assert_eq!((WS_QUEUE_BYTES, PING_MS), (32 << 20, 30_000));
    assert_eq!((PENDING_MS, BLOCKS_PER_TURN), (200, 16));
}

/// A test client: masked frames out, the server's frames in.
struct Client {
    stream: TcpStream,
    buf: Vec<u8>,
    eof: bool,
}

impl Client {
    fn connect(addr: SocketAddr, extra: &str) -> Client {
        let mut stream = TcpStream::connect(addr).unwrap();
        stream.write_all(&upgrade_request(extra)).unwrap();
        stream.set_nonblocking(true).unwrap();
        Client {
            stream,
            buf: Vec::new(),
            eof: false,
        }
    }

    fn pump(&mut self) {
        let mut chunk = vec![0u8; 16_384];
        loop {
            match self.stream.read(&mut chunk) {
                Ok(0) => {
                    self.eof = true;
                    return;
                }
                Ok(n) => self.buf.extend_from_slice(&chunk[..n]),
                Err(e) if e.kind() == ErrorKind::WouldBlock => return,
                Err(_) => {
                    self.eof = true;
                    return;
                }
            }
        }
    }

    /// The answer's head, once it is all there.
    fn head(&mut self) -> Option<String> {
        self.pump();
        let end = self.buf.windows(4).position(|w| w == b"\r\n\r\n")? + 4;
        let head = String::from_utf8(self.buf.drain(..end).collect()).unwrap();
        Some(head)
    }

    /// The next frame from the server, once it is all there.
    fn frame(&mut self) -> Option<(u8, Vec<u8>)> {
        self.pump();
        let b = &self.buf;
        if b.len() < 2 {
            return None;
        }
        assert_eq!(b[1] & 0x80, 0, "the server does not mask");
        let (len, at) = match b[1] & 0x7f {
            126 if b.len() >= 4 => (usize::from(u16::from_be_bytes([b[2], b[3]])), 4),
            127 if b.len() >= 10 => (
                usize::try_from(u64::from_be_bytes(b[2..10].try_into().unwrap())).unwrap(),
                10,
            ),
            126 | 127 => return None,
            n => (usize::from(n), 2),
        };
        if b.len() < at + len {
            return None;
        }
        assert_eq!(b[0] & 0x80, 0x80, "the server does not fragment");
        let op = b[0] & 0x0f;
        let payload = b[at..at + len].to_vec();
        self.buf.drain(..at + len);
        Some((op, payload))
    }

    fn send(&mut self, op: u8, payload: &[u8]) {
        let wire = encode_masked(true, op, payload, [9, 8, 7, 6]);
        self.stream.write_all(&wire).unwrap();
    }

    fn call(&mut self, body: &Value) {
        self.send(opcode::TEXT, body.to_string().as_bytes());
    }
}

/// Turns the server until `ready` gives something, at most 10 s.
fn until<T>(server: &Server, rpc: &mut Rpc, mut ready: impl FnMut() -> Option<T>) -> T {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        server.turn(rpc, Duration::from_millis(1));
        if let Some(out) = ready() {
            return out;
        }
        assert!(Instant::now() < deadline, "nothing came");
    }
}

/// The next text message the client gets, as JSON.
fn message(server: &Server, rpc: &mut Rpc, client: &mut Client) -> Value {
    let (op, payload) = until(server, rpc, || client.frame());
    assert_eq!(op, opcode::TEXT);
    serde_json::from_slice(&payload).unwrap()
}

/// The answer to `body` sent over the socket.
fn ask(server: &Server, rpc: &mut Rpc, client: &mut Client, body: &Value) -> Value {
    client.call(body);
    message(server, rpc, client)
}

fn request(id: u64, method: &str, params: &Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params })
}

fn opened(server: &Server, rpc: &mut Rpc, client: &mut Client) {
    let head = until(server, rpc, || client.head());
    assert!(head.starts_with("HTTP/1.1 101"), "{head}");
}

fn mine(rpc: &mut Rpc) {
    let height = rpc.node_mut().block_number().unwrap();
    rpc.node_mut().tick(1_000 + (height + 1) * SLOT_MS).unwrap();
}

fn send_raw(rpc: &mut Rpc, raw: &[u8]) -> String {
    let answer = rpc.handle(&request(1, "eth_sendRawTransaction", &json!([data(raw)])));
    answer["result"].as_str().unwrap().to_owned()
}

/// Every ordinary method is served over the socket as over HTTP, and the
/// three subscriptions announce what the node executes and pools (spec 20
/// §8.7.2, §8.7.3).
#[test]
#[allow(clippy::too_many_lines)]
fn a_socket_serves_every_method_and_the_three_subscriptions() {
    let alice = Wallet::new(1);
    let mut rpc = Rpc::new(node(&alice));
    let listener = bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = Server::start(
        listener,
        Limits {
            max_subscriptions: 4,
            ..Limits::default()
        },
    );
    let mut client = Client::connect(addr, "");
    opened(&server, &mut rpc, &mut client);
    assert_eq!(server.sockets(), 1);
    let s = &server;
    let chain = ask(
        s,
        &mut rpc,
        &mut client,
        &request(1, "eth_chainId", &json!([])),
    );
    assert_eq!(chain["result"], "0x539");
    // Over HTTP a subscription is still refused as geth refuses it.
    let http = rpc.handle(&request(1, "eth_subscribe", &json!(["newHeads"])));
    assert_eq!(http["error"]["message"], "notifications not supported");
    // A batch mixes subscriptions and other methods; a binary message is a
    // body too.
    let batch = json!([
        request(2, "eth_subscribe", &json!(["newHeads"])),
        request(3, "eth_blockNumber", &json!([])),
    ]);
    client.send(opcode::BINARY, batch.to_string().as_bytes());
    let answers = message(s, &mut rpc, &mut client);
    let heads = answers[0]["result"].as_str().unwrap().to_owned();
    assert_eq!(heads.len(), 34);
    assert_eq!(answers[1]["result"], "0x0");
    let parse_error = ask(s, &mut rpc, &mut client, &json!("not json"));
    assert_eq!(parse_error["error"]["code"], -32600);
    client.send(opcode::TEXT, b"{");
    assert_eq!(message(s, &mut rpc, &mut client)["error"]["code"], -32700);
    // Deploy the counter; `newHeads` announces block 1 as its header.
    let initcode = counter_initcode(5);
    send_raw(
        &mut rpc,
        &alice.legacy(&Fields {
            nonce: 0,
            to: None,
            value: 0,
            gas_limit: 1_000_000,
            data: &initcode,
        }),
    );
    mine(&mut rpc);
    let head = message(s, &mut rpc, &mut client);
    assert_eq!(head["method"], "eth_subscription");
    assert_eq!(head["params"]["subscription"], heads.as_str());
    let header = &head["params"]["result"];
    assert_eq!(header["number"], "0x1");
    let block = rpc.handle(&request(1, "eth_getBlockByNumber", &json!(["0x1", false])));
    assert_eq!(header["hash"], block["result"]["hash"]);
    assert_eq!(header["stateRoot"], block["result"]["stateRoot"]);
    for body in ["transactions", "uncles", "withdrawals", "size"] {
        assert!(header.get(body).is_none(), "{body}");
    }
    let counter = data(&created_address(&alice.address, 0));
    let incremented = data(&keccak256(b"Incremented(address,uint256,uint256)"));
    // Two log subscriptions, one that matches and one that does not, and
    // one with no filter at all.
    let sub = |rpc: &mut Rpc, client: &mut Client, params: Value| {
        let answer = ask(s, rpc, client, &request(4, "eth_subscribe", &params));
        answer["result"]
            .as_str()
            .expect("a subscription id")
            .to_owned()
    };
    let logs = sub(
        &mut rpc,
        &mut client,
        json!(["logs", { "address": counter, "topics": [incremented], "fromBlock": "0x0" }]),
    );
    let none = sub(
        &mut rpc,
        &mut client,
        json!(["logs", { "address": data(&[9; 20]) }]),
    );
    assert!(
        ask(
            s,
            &mut rpc,
            &mut client,
            &request(5, "eth_unsubscribe", &json!([none]))
        )["result"]
            == true
    );
    let any = sub(&mut rpc, &mut client, json!(["logs"]));
    // The limit of four: heads, logs and any hold three, a fourth fits, a
    // fifth does not.
    let pending = sub(&mut rpc, &mut client, json!(["newPendingTransactions"]));
    let refused = ask(
        s,
        &mut rpc,
        &mut client,
        &request(6, "eth_subscribe", &json!(["newHeads"])),
    );
    assert_eq!(refused["error"]["code"], -32000);
    assert_eq!(
        refused["error"]["message"],
        "too many subscriptions on this connection, the limit is 4"
    );
    let increment = |nonce| {
        alice.legacy(&Fields {
            nonce,
            to: Some(created_address(&alice.address, 0)),
            value: 0,
            gas_limit: 100_000,
            data: &calldata("increment(uint256)", &[2]),
        })
    };
    // The pool's new transaction is announced once the pool is looked at.
    let hash = send_raw(&mut rpc, &increment(1));
    let announced = message(s, &mut rpc, &mut client);
    assert_eq!(announced["params"]["subscription"], pending.as_str());
    assert_eq!(announced["params"]["result"], hash.as_str());
    mine(&mut rpc);
    // Block 2: its head, then each matching log, under each subscription.
    let mut seen = Vec::new();
    while seen.len() < 3 {
        seen.push(message(s, &mut rpc, &mut client)["params"].clone());
    }
    let by = |id: &str| seen.iter().find(|n| n["subscription"] == id).unwrap()["result"].clone();
    assert_eq!(by(&heads)["number"], "0x2");
    let log = by(&logs);
    assert_eq!(log, by(&any));
    assert_eq!(log["address"], counter.as_str());
    assert_eq!(log["topics"][0], incremented.as_str());
    assert_eq!(log["transactionHash"], hash.as_str());
    assert_eq!(log["blockNumber"], "0x2");
    assert_eq!(log["removed"], false);
    let got = rpc.handle(&request(
        1,
        "eth_getLogs",
        &json!([{ "fromBlock": "0x2", "toBlock": "0x2" }]),
    ));
    assert_eq!(got["result"][0], log);
    // Unsubscribed, nothing more under that id; an unknown id is false.
    let gone = ask(
        s,
        &mut rpc,
        &mut client,
        &request(7, "eth_unsubscribe", &json!([logs])),
    );
    assert_eq!(gone["result"], true);
    let again = ask(
        s,
        &mut rpc,
        &mut client,
        &request(8, "eth_unsubscribe", &json!([logs])),
    );
    assert_eq!(again["result"], false);
    // Refusals: kinds not served, a filter that does not parse, no kind.
    let error = |rpc: &mut Rpc, client: &mut Client, params: Value| {
        let answer = ask(s, rpc, client, &request(9, "eth_unsubscribe", &json!([])));
        assert_eq!(answer["error"]["code"], -32602);
        let answer = ask(s, rpc, client, &request(9, "eth_subscribe", &params));
        (
            answer["error"]["code"].clone(),
            answer["error"]["message"].clone(),
        )
    };
    assert_eq!(
        error(&mut rpc, &mut client, json!(["syncing"])),
        (
            json!(-32602),
            json!("unsupported subscription kind: syncing")
        )
    );
    assert_eq!(
        error(
            &mut rpc,
            &mut client,
            json!(["newPendingTransactions", true])
        ),
        (
            json!(-32602),
            json!("full pending transactions are not served")
        )
    );
    assert_eq!(
        error(&mut rpc, &mut client, json!(["logs", 7])).0,
        json!(-32602)
    );
    assert_eq!(error(&mut rpc, &mut client, json!([])).0, json!(-32602));
    // Blocks executed at once are announced over several turns, in order.
    for nonce in 2..2 + BLOCKS_PER_TURN + 2 {
        send_raw(&mut rpc, &increment(nonce));
        mine(&mut rpc);
    }
    let mut numbers = Vec::new();
    while numbers.len() < usize::try_from(BLOCKS_PER_TURN).unwrap() + 2 {
        let n = message(s, &mut rpc, &mut client);
        if n["params"]["subscription"] == heads.as_str() {
            numbers.push(n["params"]["result"]["number"].as_str().unwrap().to_owned());
        }
    }
    let expected: Vec<String> = (3..3 + BLOCKS_PER_TURN + 2)
        .map(|h| format!("{h:#x}"))
        .collect();
    assert_eq!(numbers, expected);
    // A socket the client closes is forgotten, with its subscriptions.
    drop(client);
    until(s, &mut rpc, || (server.sockets() == 0).then_some(()));
}

/// A socket's pings, its closing handshake and the frames that end it
/// (spec 20 §8.7.2, §8.7.4).
#[test]
fn pings_closes_and_frames_that_break_the_protocol() {
    let alice = Wallet::new(1);
    let mut rpc = Rpc::new(node(&alice));
    let listener = bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = Server::start(
        listener,
        Limits {
            ping_ms: 150,
            max_message: 64,
            ..Limits::default()
        },
    );
    let s = &server;
    // A ping is answered with its payload, and a silent socket is pinged.
    let mut client = Client::connect(addr, "");
    opened(s, &mut rpc, &mut client);
    client.send(opcode::PING, b"hello");
    assert_eq!(
        until(s, &mut rpc, || client.frame()),
        (opcode::PONG, b"hello".to_vec())
    );
    assert_eq!(
        until(s, &mut rpc, || client.frame()),
        (opcode::PING, vec![])
    );
    // Answered, it is kept: pinged again later rather than closed.
    client.send(opcode::PONG, b"");
    client.send(opcode::PONG, b"");
    assert_eq!(
        until(s, &mut rpc, || client.frame()),
        (opcode::PING, vec![])
    );
    // Silent after a ping, it is closed.
    until(s, &mut rpc, || {
        client.pump();
        client.eof.then_some(())
    });
    // A client's `Close` is answered with one.
    let mut client = Client::connect(addr, "");
    opened(s, &mut rpc, &mut client);
    client.send(opcode::CLOSE, &1000u16.to_be_bytes());
    assert_eq!(
        until(s, &mut rpc, || client.frame()),
        (opcode::CLOSE, vec![3, 0xe8])
    );
    until(s, &mut rpc, || {
        client.pump();
        client.eof.then_some(())
    });
    // Frames that break the protocol close it with their status.
    let closes = |rpc: &mut Rpc, wire: &[u8]| {
        let mut client = Client::connect(addr, "");
        opened(s, rpc, &mut client);
        client.stream.write_all(wire).unwrap();
        let (op, payload) = until(s, rpc, || client.frame());
        assert_eq!(op, opcode::CLOSE);
        u16::from_be_bytes([payload[0], payload[1]])
    };
    assert_eq!(
        closes(&mut rpc, &ws::encode(opcode::TEXT, b"{}")),
        status::PROTOCOL
    );
    assert_eq!(
        closes(
            &mut rpc,
            &encode_masked(true, opcode::TEXT, &[b' '; 65], [1; 4])
        ),
        status::TOO_BIG
    );
    assert_eq!(
        closes(
            &mut rpc,
            &encode_masked(true, opcode::TEXT, b"\xff", [1; 4])
        ),
        status::INVALID
    );
    assert_eq!(
        closes(
            &mut rpc,
            &encode_masked(true, opcode::CONTINUATION, b"x", [1; 4])
        ),
        status::PROTOCOL
    );
    until(s, &mut rpc, || (server.sockets() == 0).then_some(()));
}

/// A socket that would be queued more than its bound is cut off, sockets
/// past the limit and pages of other origins are refused, and a socket
/// that closed frees its place (spec 20 §8.7.1, §8.7.4).
#[test]
fn a_slow_consumer_is_cut_off_and_sockets_are_bounded() {
    let alice = Wallet::new(1);
    let mut rpc = Rpc::new(node(&alice));
    rpc.cors = vec!["http://ok.example".to_owned()];
    let listener = bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = Server::start(
        listener,
        Limits {
            max_ws_connections: 1,
            ws_queue_bytes: 300,
            ..Limits::default()
        },
    );
    let s = &server;
    let mut client = Client::connect(addr, "Origin: http://ok.example\r\n");
    opened(s, &mut rpc, &mut client);
    // One socket is the limit; a page of another origin is refused first.
    let mut evil = Client::connect(addr, "Origin: http://evil.example\r\n");
    let head = until(s, &mut rpc, || evil.head());
    assert!(head.starts_with("HTTP/1.1 403 Forbidden"), "{head}");
    let mut second = Client::connect(addr, "");
    let head = until(s, &mut rpc, || second.head());
    assert!(head.starts_with("HTTP/1.1 503"), "{head}");
    // A header of about 1 300 bytes does not fit a queue of 300: the socket
    // is closed rather than queued past it.
    let sub = ask(
        s,
        &mut rpc,
        &mut client,
        &request(1, "eth_subscribe", &json!(["newHeads"])),
    );
    assert!(sub["result"].is_string(), "{sub}");
    mine(&mut rpc);
    until(s, &mut rpc, || {
        client.pump();
        client.eof.then_some(())
    });
    until(s, &mut rpc, || (server.sockets() == 0).then_some(()));
    let mut third = Client::connect(addr, "");
    opened(s, &mut rpc, &mut third);
}

/// `orange_stop` over a socket is answered before the node stops; a socket
/// whose node stopped while it waited ends (spec 20 §8.7.4).
#[test]
fn a_socket_is_answered_before_the_node_stops_and_ends_with_it() {
    let stop = Arc::new(AtomicBool::new(false));
    let (tx, rx) = std::sync::mpsc::channel();
    let node_thread = {
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            let alice = Wallet::new(1);
            let mut rpc = Rpc::new(node(&alice));
            rpc.stop_allowed = true;
            let listener = bind("127.0.0.1:0").unwrap();
            tx.send(listener.local_addr().unwrap()).unwrap();
            serve(listener, &mut rpc, |rpc| {
                !rpc.stopped && !stop.load(Ordering::SeqCst)
            });
        })
    };
    let addr = rx.recv().unwrap();
    let mut client = Client::connect(addr, "");
    let wait = |client: &mut Client| {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(frame) = client.frame() {
                return frame;
            }
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(1));
        }
    };
    let deadline = Instant::now() + Duration::from_secs(10);
    while client.head().is_none() {
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(1));
    }
    client.call(&request(1, "orange_stop", &json!([])));
    let (_, payload) = wait(&mut client);
    let answer: Value = serde_json::from_slice(&payload).unwrap();
    assert_eq!(answer["result"], true);
    node_thread.join().unwrap();
    while !client.eof {
        assert!(Instant::now() < deadline);
        client.pump();
        std::thread::sleep(Duration::from_millis(1));
    }

    // A node that never turns again: an upgrade waiting for it, and a
    // message waiting for it, end when it stops.
    let alice = Wallet::new(1);
    let mut rpc = Rpc::new(node(&alice));
    let listener = bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = Server::start(listener, Limits::default());
    let mut open = Client::connect(addr, "");
    opened(&server, &mut rpc, &mut open);
    open.call(&request(1, "eth_chainId", &json!([])));
    let mut waiting = Client::connect(addr, "");
    let deadline = Instant::now() + Duration::from_secs(10);
    while server.waiting() == 0 {
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(1));
    }
    // Both the message and the upgrade have reached the queue.
    std::thread::sleep(Duration::from_millis(50));
    drop(server);
    for client in [&mut open, &mut waiting] {
        while !client.eof {
            assert!(Instant::now() < deadline);
            client.pump();
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    stop.store(true, Ordering::SeqCst);
}
