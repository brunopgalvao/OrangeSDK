//! The WebSocket (RFC 6455) beside HTTP on the JSON-RPC port (spec 20
//! §8.7): the frame codec, the handshake and the threads of one socket.
//!
//! A `GET` that asks to upgrade is read as any request is ([`crate::http`])
//! and decided on the node's thread ([`handshake`]). An accepted socket gets
//! a reader, the connection's own thread, which assembles messages and hands
//! the node one at a time, and a writer, which writes what the node and the
//! reader queue for it ([`Socket`]) under the write deadline of HTTP. What
//! is queued is bounded; a socket that would be queued more is closed, so
//! the node's thread never waits for one.
//!
//! The codec and the SHA-1 of the handshake are written here: a server's
//! half of RFC 6455 is small, and the crates that provide it bring an HTTP
//! parser and features of their own beside the server whose bounds the
//! socket shares.

use std::io::{ErrorKind, Read};
use std::net::{Shutdown, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, Sender, SyncSender, channel, sync_channel};
use std::time::{Duration, Instant};

use crate::http::{Job, Limits, Request, response, wait_while, write_by};

/// Most sockets open at once (spec 20 §8.7.1); one past them is answered
/// `503`.
pub const MAX_WS_CONNECTIONS: usize = 32;

/// Most subscriptions one socket holds (spec 20 §8.7.3).
pub const MAX_SUBSCRIPTIONS: usize = 128;

/// Longest frame, and longest message once assembled (spec 20 §8.7.4): the
/// HTTP body limit.
pub const MAX_MESSAGE: usize = crate::http::MAX_BODY;

/// Most bytes queued for one socket (spec 20 §8.7.4); a frame past it
/// closes the socket.
pub const WS_QUEUE_BYTES: usize = 32 << 20;

/// How long a socket may be silent before it is pinged, and then before it
/// is closed (spec 20 §8.7.4).
pub const PING_MS: u64 = 30_000;

/// The GUID RFC 6455 appends to a client's key.
const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// Frame opcodes.
pub mod opcode {
    /// A later fragment of a message.
    pub const CONTINUATION: u8 = 0;
    /// A text message.
    pub const TEXT: u8 = 1;
    /// A binary message.
    pub const BINARY: u8 = 2;
    /// The closing handshake.
    pub const CLOSE: u8 = 8;
    /// A ping.
    pub const PING: u8 = 9;
    /// A pong.
    pub const PONG: u8 = 10;
}

/// Close status codes.
pub mod status {
    /// The socket did what it was for.
    pub const NORMAL: u16 = 1000;
    /// A frame broke the protocol.
    pub const PROTOCOL: u16 = 1002;
    /// A text message that is not UTF-8.
    pub const INVALID: u16 = 1007;
    /// A frame or message past [`super::MAX_MESSAGE`].
    pub const TOO_BIG: u16 = 1009;
}

/// One frame, unmasked.
#[derive(Debug, PartialEq, Eq)]
pub struct Frame {
    /// Whether it ends its message.
    pub fin: bool,
    /// Its opcode ([`opcode`]).
    pub opcode: u8,
    /// Its payload.
    pub payload: Vec<u8>,
}

/// The client's frame at the front of `buf`, unmasked, and the bytes it
/// takes, if it is all there. A frame that breaks the protocol, or longer
/// than `max`, is the status the socket closes with; a length is judged
/// as soon as it is read.
///
/// # Errors
/// [`status::PROTOCOL`] for a reserved bit, an unknown opcode, an unmasked
/// frame or a control frame fragmented or longer than 125 bytes;
/// [`status::TOO_BIG`] for a payload longer than `max`.
pub fn decode(buf: &[u8], max: usize) -> Result<Option<(Frame, usize)>, u16> {
    let [b0, b1, rest @ ..] = buf else {
        return Ok(None);
    };
    let (fin, op) = (b0 & 0x80 != 0, b0 & 0x0f);
    let known = matches!(op, 0..=2 | 8..=10);
    let control = op >= 8;
    let short = u64::from(b1 & 0x7f);
    if b0 & 0x70 != 0 || !known || b1 & 0x80 == 0 || (control && (!fin || short > 125)) {
        return Err(status::PROTOCOL);
    }
    let big_endian = |bytes: &[u8]| bytes.iter().fold(0u64, |n, b| n << 8 | u64::from(*b));
    let (len, ext) = match short {
        126 => (rest.get(..2).map(big_endian), 2),
        127 => (rest.get(..8).map(big_endian), 8),
        n => (Some(n), 0),
    };
    let Some(len) = len else { return Ok(None) };
    let len = usize::try_from(len)
        .ok()
        .filter(|len| *len <= max)
        .ok_or(status::TOO_BIG)?;
    let start = 2 + ext + 4;
    let end = start + len;
    if buf.len() < end {
        return Ok(None);
    }
    let mask = &buf[2 + ext..start];
    let payload = buf[start..end]
        .iter()
        .enumerate()
        .map(|(i, b)| b ^ mask[i % 4])
        .collect();
    Ok(Some((
        Frame {
            fin,
            opcode: op,
            payload,
        },
        end,
    )))
}

/// The header of a frame of `len` bytes: `first` and the length.
fn header(first: u8, mask: u8, len: usize) -> Vec<u8> {
    let mut out = vec![first];
    match (u8::try_from(len), u16::try_from(len)) {
        (Ok(tiny), _) if tiny < 0x7e => out.push(mask | tiny),
        (_, Ok(short)) => {
            out.push(mask | 0x7e);
            out.extend_from_slice(&short.to_be_bytes());
        }
        _ => {
            out.push(mask | 0x7f);
            out.extend_from_slice(&(len as u64).to_be_bytes());
        }
    }
    out
}

/// A whole unmasked frame, as the server sends it.
#[must_use]
pub fn encode(op: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = header(0x80 | op, 0, payload.len());
    out.extend_from_slice(payload);
    out
}

/// A frame masked under `key`, as a client sends it.
#[must_use]
pub fn encode_masked(fin: bool, op: u8, payload: &[u8], key: [u8; 4]) -> Vec<u8> {
    let mut out = header(u8::from(fin) << 7 | op, 0x80, payload.len());
    out.extend_from_slice(&key);
    out.extend(payload.iter().enumerate().map(|(i, b)| b ^ key[i % 4]));
    out
}

/// A `Close` frame with `code`.
#[must_use]
pub fn close_frame(code: u16) -> Vec<u8> {
    encode(opcode::CLOSE, &code.to_be_bytes())
}

/// What a socket's frames come to.
#[derive(Debug, PartialEq, Eq)]
pub enum Event {
    /// A whole message: a JSON-RPC body.
    Message(String),
    /// A ping, with the payload its pong carries back.
    Ping(Vec<u8>),
    /// The client closes.
    Close,
}

/// Assembles a socket's frames into messages, at most `max` bytes each.
pub struct Assembler {
    max: usize,
    /// The message being assembled: whether it is text, and its bytes.
    partial: Option<(bool, Vec<u8>)>,
}

impl Assembler {
    /// An assembler of messages of at most `max` bytes.
    #[must_use]
    pub fn new(max: usize) -> Assembler {
        Assembler { max, partial: None }
    }

    /// Takes one frame: what it completes, if anything.
    ///
    /// # Errors
    /// The status the socket closes with: [`status::PROTOCOL`] for a
    /// continuation of nothing or a new message before the last ended,
    /// [`status::TOO_BIG`] for a message past `max`, [`status::INVALID`]
    /// for text that is not UTF-8.
    pub fn push(&mut self, frame: Frame) -> Result<Option<Event>, u16> {
        let (text, mut bytes) = match frame.opcode {
            opcode::CLOSE => return Ok(Some(Event::Close)),
            opcode::PING => return Ok(Some(Event::Ping(frame.payload))),
            opcode::PONG => return Ok(None),
            opcode::CONTINUATION => self.partial.take().ok_or(status::PROTOCOL)?,
            op if self.partial.is_none() => (op == opcode::TEXT, Vec::new()),
            _ => return Err(status::PROTOCOL),
        };
        if bytes.len() + frame.payload.len() > self.max {
            return Err(status::TOO_BIG);
        }
        bytes.extend_from_slice(&frame.payload);
        if !frame.fin {
            self.partial = Some((text, bytes));
            return Ok(None);
        }
        let message = if text {
            String::from_utf8(bytes).ok().ok_or(status::INVALID)?
        } else {
            String::from_utf8_lossy(&bytes).into_owned()
        };
        Ok(Some(Event::Message(message)))
    }
}

/// SHA-1 (FIPS 180-4), which the handshake's accept key is made with and
/// nothing else uses.
#[must_use]
#[allow(clippy::many_single_char_names)]
pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [
        0x6745_2301,
        0xEFCD_AB89,
        0x98BA_DCFE,
        0x1032_5476,
        0xC3D2_E1F0,
    ];
    let mut message = data.to_vec();
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&((data.len() as u64) * 8).to_be_bytes());
    for block in message.chunks(64) {
        let mut w = [0u32; 80];
        for (i, word) in block.chunks(4).enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = h;
        for (i, wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | (!b & d), 0x5A82_7999),
                20..=39 => (b ^ c ^ d, 0x6ED9_EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
                _ => (b ^ c ^ d, 0xCA62_C1D6),
            };
            let t = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(*wi);
            (e, d, c, b, a) = (d, c, b.rotate_left(30), a, t);
        }
        for (x, y) in h.iter_mut().zip([a, b, c, d, e]) {
            *x = x.wrapping_add(y);
        }
    }
    let mut out = [0u8; 20];
    for (chunk, word) in out.chunks_mut(4).zip(h) {
        chunk.copy_from_slice(&word.to_be_bytes());
    }
    out
}

const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64 with padding.
#[must_use]
pub fn base64(data: &[u8]) -> String {
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, b)| n | u32::from(*b) << (16 - 8 * i));
        for i in 0..4 {
            out.push(if i <= chunk.len() {
                char::from(BASE64[(n >> (18 - 6 * i) & 63) as usize])
            } else {
                '='
            });
        }
    }
    out
}

/// How many bytes `text` is the standard base64 of, if it is such text.
#[must_use]
pub fn base64_len(text: &str) -> Option<usize> {
    let bytes = text.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return None;
    }
    let pad = bytes.iter().rev().take_while(|b| **b == b'=').count();
    let body = &bytes[..bytes.len() - pad];
    (pad <= 2 && body.iter().all(|b| BASE64.contains(b))).then(|| body.len() * 3 / 4)
}

/// The `Sec-WebSocket-Accept` of a client's key.
#[must_use]
pub fn accept_key(key: &str) -> String {
    base64(&sha1(format!("{key}{GUID}").as_bytes()))
}

/// The node's answer to a request to upgrade (spec 20 §8.7.1): the `101`
/// that opens the socket, or the refusal that closes the connection.
/// `open` sockets are open already, at most `max` may be.
///
/// # Errors
/// The refusal: `400` for a request that is not a valid upgrade, `426` for
/// another protocol version, `403` for an origin `cors` does not allow,
/// `503` when `max` sockets are open.
pub fn handshake(
    cors: &[String],
    req: &Request,
    open: usize,
    max: usize,
) -> Result<Vec<u8>, Vec<u8>> {
    let hs = req.websocket.clone().unwrap_or_default();
    let key = hs.key.filter(|k| base64_len(k) == Some(16));
    let Some(key) = key.filter(|_| hs.connection_upgrade) else {
        return Err(response(
            "400 Bad Request",
            "text/plain",
            "a WebSocket upgrade needs Connection: upgrade and a Sec-WebSocket-Key of 16 bytes",
        ));
    };
    if hs.version.as_deref() != Some("13") {
        return Err(
            b"HTTP/1.1 426 Upgrade Required\r\nSec-WebSocket-Version: 13\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                .to_vec(),
        );
    }
    if let Some(origin) = &req.origin
        && crate::http::allowed_by(cors, origin).is_none()
    {
        return Err(crate::http::forbidden());
    }
    if open >= max {
        return Err(response(
            "503 Service Unavailable",
            "text/plain",
            "too many WebSocket connections",
        ));
    }
    Ok(format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n",
        accept_key(&key)
    )
    .into_bytes())
}

/// What a socket's reader, its writer and the node's thread share: the
/// stream, the queue of frames to write and how many bytes it holds, and
/// whether the socket is still open.
pub struct Socket {
    stream: TcpStream,
    out: Sender<Vec<u8>>,
    queued: AtomicUsize,
    alive: AtomicBool,
    max_queue: usize,
}

impl Socket {
    /// Queues `frame` for the writer. A frame that would take the queue
    /// past its bound closes the socket instead (spec 20 §8.7.4). Whether
    /// it was queued.
    pub fn send(&self, frame: Vec<u8>) -> bool {
        let queued = self.queued.fetch_add(frame.len(), Ordering::SeqCst) + frame.len();
        if !self.is_alive() || queued > self.max_queue {
            self.queued.fetch_sub(frame.len(), Ordering::SeqCst);
            self.close();
            return false;
        }
        // The writer holds the receiver for as long as the socket can be sent to.
        let _ = self.out.send(frame);
        true
    }

    /// Bytes queued and not yet written.
    #[must_use]
    pub fn queued(&self) -> usize {
        self.queued.load(Ordering::SeqCst)
    }

    /// Whether the socket is still open.
    #[must_use]
    pub fn is_alive(&self) -> bool {
        self.alive.load(Ordering::SeqCst)
    }

    /// Closes the socket: both its threads stop at their next read or write.
    pub fn close(&self) {
        self.alive.store(false, Ordering::SeqCst);
        let _ = self.stream.shutdown(Shutdown::Both);
    }
}

/// Writes what is queued for `socket` until it closes; a frame not written
/// within the write deadline, or a `Close` written, closes it.
fn write_queue(socket: &Socket, frames: &Receiver<Vec<u8>>, write_ms: u64) {
    while socket.is_alive() {
        let Ok(frame) = frames.recv_timeout(Duration::from_millis(20)) else {
            continue;
        };
        let at = Instant::now() + Duration::from_millis(write_ms);
        let written = write_by(&socket.stream, &frame, at).is_ok();
        socket.queued.fetch_sub(frame.len(), Ordering::SeqCst);
        if !written || frame.first() == Some(&(0x80 | opcode::CLOSE)) {
            socket.close();
        }
    }
}

/// Serves an upgrade request on its connection's thread: hands it to the
/// node, writes the answer, and, when the node opened a socket, runs its
/// reader here and its writer on a thread of its own until it closes.
/// `open` counts the connection among HTTP's until the socket opens.
pub(crate) fn serve(
    stream: TcpStream,
    request: Request,
    open: crate::http::Open,
    jobs: &SyncSender<Job>,
) {
    let shared = Arc::clone(&open.0);
    let limits = shared.limits;
    let (out, frames) = channel();
    let socket = Arc::new(Socket {
        stream,
        out,
        queued: AtomicUsize::new(0),
        alive: AtomicBool::new(true),
        max_queue: limits.ws_queue_bytes,
    });
    let (reply, answered) = sync_channel(1);
    shared.waiting.fetch_add(1, Ordering::SeqCst);
    let job = Job::Upgrade {
        request,
        socket: Arc::clone(&socket),
        reply,
    };
    // Nothing answers once the node's loop has stopped.
    let Some((answer, id)) = jobs.send(job).ok().and_then(|()| answered.recv().ok()) else {
        return;
    };
    let at = Instant::now() + Duration::from_millis(limits.write_ms);
    let written = write_by(&socket.stream, &answer, at).is_ok();
    shared.writing.fetch_sub(1, Ordering::SeqCst);
    // A socket the node opened and that never heard it is forgotten at
    // the node's next turn.
    let Some(id) = id.filter(|_| written) else {
        socket.close();
        return;
    };
    // An open socket counts among the node's sockets, which it forgets once
    // closed, no longer among HTTP connections.
    drop(open);
    let writer = {
        let socket = Arc::clone(&socket);
        std::thread::spawn(move || write_queue(&socket, &frames, limits.write_ms))
    };
    read_socket(&socket.stream, &socket, id, &limits, jobs);
    // The writer stops once the socket is closed, after a `Close` it was
    // given or at once; a socket the reader leaves open is closed.
    let wait = Duration::from_millis(limits.write_ms);
    wait_while(wait, || socket.is_alive() && socket.queued() > 0);
    socket.close();
    let _ = writer.join();
}

/// The reader of socket `id`: frames in, one message at a time to the
/// node, pings answered and sent, until the client closes, breaks the
/// protocol, goes silent past [`Limits::ping_ms`] twice, or the socket is
/// closed.
fn read_socket(
    stream: &TcpStream,
    socket: &Socket,
    id: u64,
    limits: &Limits,
    jobs: &SyncSender<Job>,
) {
    let mut buf = Vec::new();
    let mut chunk = vec![0u8; 16 << 10];
    let mut assembler = Assembler::new(limits.max_message);
    let mut heard = Instant::now();
    let mut pinged = false;
    let silence = Duration::from_millis(limits.ping_ms);
    while socket.is_alive() {
        match decode(&buf, limits.max_message) {
            Err(code) => {
                socket.send(close_frame(code));
                return;
            }
            Ok(Some((frame, n))) => {
                buf.drain(..n);
                match assembler.push(frame) {
                    Err(code) => {
                        socket.send(close_frame(code));
                        return;
                    }
                    Ok(Some(Event::Close)) => {
                        socket.send(close_frame(status::NORMAL));
                        return;
                    }
                    Ok(Some(Event::Ping(payload))) => {
                        socket.send(encode(opcode::PONG, &payload));
                    }
                    Ok(Some(Event::Message(body))) => {
                        let (done, answered) = sync_channel(1);
                        let job = Job::Message {
                            socket: id,
                            body,
                            done,
                        };
                        if jobs
                            .send(job)
                            .ok()
                            .and_then(|()| answered.recv().ok())
                            .is_none()
                        {
                            return;
                        }
                    }
                    Ok(None) => {}
                }
                continue;
            }
            Ok(None) => {}
        }
        let deadline = heard + silence * (1 + u32::from(pinged));
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            if pinged {
                return;
            }
            pinged = true;
            socket.send(encode(opcode::PING, b""));
            continue;
        }
        // Refused only when the stream is closed, which the read then says.
        let _ = stream.set_read_timeout(Some(left));
        match (&*stream).read(&mut chunk) {
            Ok(n) if n > 0 => {
                buf.extend_from_slice(&chunk[..n]);
                heard = Instant::now();
                pinged = false;
            }
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
            _ => return,
        }
    }
}
