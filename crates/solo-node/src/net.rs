//! The TCP transport: peers exchange length-prefixed frames carrying
//! consensus messages, transaction gossip and sync requests. One
//! non-blocking [`Transport::poll`] call moves bytes in both directions and
//! feeds the node, so a node and its transport run on one thread.
//!
//! A frame on the wire is a `u32` little-endian length followed by a
//! [`Frame`] in the canonical encoding (spec 06 §2). The first frame on
//! every connection is `Hello`; a peer on another chain is disconnected.

use std::collections::BTreeMap;
use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::Duration;

use solo_abi::codec::{Decode, DecodeError, Decoder, Encode, Encoder};
use solo_abi::types::Input;
use solo_metrics::{Direction, Traffic};

use crate::extension::Outbound;
use crate::node::{Node, NodeError};

/// Largest frame accepted, in bytes.
pub const MAX_FRAME: usize = 16 << 20;

/// How often a lost outbound peer is redialled.
pub const REDIAL_MS: u64 = 500;

/// One unit on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum Frame {
    Hello { id: [u8; 32], chain_id: u64 },
    Message { topic: u16, payload: Vec<u8> },
    Tx { raw: Vec<u8> },
    Request { request_id: u64, payload: Vec<u8> },
    Response { request_id: u64, payload: Vec<u8> },
}

impl Encode for Frame {
    fn encode(&self, e: &mut Encoder) {
        match self {
            Frame::Hello { id, chain_id } => {
                e.raw(&[0]);
                e.put(id).put(chain_id);
            }
            Frame::Message { topic, payload } => {
                e.raw(&[1]);
                e.put(topic).put(payload);
            }
            Frame::Tx { raw } => {
                e.raw(&[2]);
                e.put(raw);
            }
            Frame::Request {
                request_id,
                payload,
            } => {
                e.raw(&[3]);
                e.put(request_id).put(payload);
            }
            Frame::Response {
                request_id,
                payload,
            } => {
                e.raw(&[4]);
                e.put(request_id).put(payload);
            }
        }
    }
}

impl Decode for Frame {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(match d.raw(1)?[0] {
            0 => Frame::Hello {
                id: d.get()?,
                chain_id: d.get()?,
            },
            1 => Frame::Message {
                topic: d.get()?,
                payload: d.get()?,
            },
            2 => Frame::Tx { raw: d.get()? },
            3 => Frame::Request {
                request_id: d.get()?,
                payload: d.get()?,
            },
            4 => Frame::Response {
                request_id: d.get()?,
                payload: d.get()?,
            },
            tag => return Err(DecodeError::BadTag(tag)),
        })
    }
}

/// Prefixes an encoded frame with its length.
#[must_use]
pub fn frame_bytes(frame: &Frame) -> Vec<u8> {
    let body = frame.to_bytes();
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&u32::try_from(body.len()).unwrap_or(u32::MAX).to_le_bytes());
    out.extend_from_slice(&body);
    out
}

/// Splits complete frames off the front of `buf`. `Err` means the stream is
/// unusable (oversized or undecodable frame) and the connection must close.
///
/// # Errors
/// A message naming the problem.
pub fn take_frames(buf: &mut Vec<u8>) -> Result<Vec<Frame>, String> {
    let mut frames = Vec::new();
    while let Some(header) = buf.get(..4) {
        let len = u32::from_le_bytes([header[0], header[1], header[2], header[3]]) as usize;
        if len > MAX_FRAME {
            return Err(format!("frame of {len} bytes exceeds the limit"));
        }
        if buf.len() < 4 + len {
            break;
        }
        let Ok(frame) = Frame::from_bytes(&buf[4..4 + len]) else {
            return Err("undecodable frame".to_owned());
        };
        frames.push(frame);
        buf.drain(..4 + len);
    }
    Ok(frames)
}

/// Reads everything available into `inbuf`. Returns `false` once the peer
/// has closed or the stream failed.
pub fn read_available(stream: &mut impl Read, inbuf: &mut Vec<u8>) -> bool {
    let mut chunk = [0u8; 16 * 1024];
    loop {
        match stream.read(&mut chunk) {
            Ok(n) if n > 0 => inbuf.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == ErrorKind::WouldBlock => return true,
            _ => return false,
        }
    }
}

/// Writes as much of `outbuf` as the stream takes. Returns `false` once the
/// stream failed.
pub fn write_available(stream: &mut impl Write, outbuf: &mut Vec<u8>) -> bool {
    while !outbuf.is_empty() {
        match stream.write(outbuf) {
            Ok(n) if n > 0 => {
                outbuf.drain(..n);
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => return true,
            _ => return false,
        }
    }
    true
}

struct Conn {
    stream: TcpStream,
    inbuf: Vec<u8>,
    outbuf: Vec<u8>,
    peer: Option<[u8; 32]>,
    /// The address this connection was dialled at, if we dialled it.
    dialled: Option<SocketAddr>,
    dead: bool,
}

impl Conn {
    fn new(stream: TcpStream, dialled: Option<SocketAddr>, hello: &Frame) -> Conn {
        let _ = stream.set_nonblocking(true);
        let _ = stream.set_nodelay(true);
        Conn {
            stream,
            inbuf: Vec::new(),
            outbuf: frame_bytes(hello),
            peer: None,
            dialled,
            dead: false,
        }
    }

    fn send(&mut self, frame: &Frame) {
        self.outbuf.extend_from_slice(&frame_bytes(frame));
    }

    fn read(&mut self) {
        self.dead |= !read_available(&mut self.stream, &mut self.inbuf);
    }

    fn flush(&mut self) {
        self.dead |= !write_available(&mut self.stream, &mut self.outbuf);
    }
}

/// A node's TCP endpoint.
pub struct Transport {
    listener: TcpListener,
    conns: Vec<Conn>,
    hello: Frame,
    chain_id: u64,
    peers: Vec<SocketAddr>,
    last_dial_ms: Option<u64>,
    /// Requests this node is serving: local id to `(peer, the peer's id)`.
    serving: BTreeMap<u64, ([u8; 32], u64)>,
    next_local_id: u64,
    /// Traffic counted since the last poll handed it to the node's telemetry.
    traffic: Traffic,
}

impl Transport {
    /// Listens on `listen` and keeps connections to `peers` open.
    ///
    /// # Errors
    /// If the address cannot be bound.
    pub fn bind(
        listen: &str,
        id: [u8; 32],
        chain_id: u64,
        peers: Vec<SocketAddr>,
    ) -> std::io::Result<Transport> {
        let listener = TcpListener::bind(listen)?;
        listener.set_nonblocking(true)?;
        Ok(Transport {
            listener,
            conns: Vec::new(),
            hello: Frame::Hello { id, chain_id },
            chain_id,
            peers,
            last_dial_ms: None,
            serving: BTreeMap::new(),
            next_local_id: 0,
            traffic: Traffic::default(),
        })
    }

    /// The bound address.
    ///
    /// # Errors
    /// If the socket has no local address.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Identities of the peers that completed the handshake.
    #[must_use]
    pub fn connected(&self) -> Vec<[u8; 32]> {
        self.conns.iter().filter_map(|c| c.peer).collect()
    }

    fn accept(&mut self) {
        while let Ok((stream, _)) = self.listener.accept() {
            self.conns.push(Conn::new(stream, None, &self.hello));
            self.traffic.frame(Direction::Out, "hello");
        }
    }

    fn redial(&mut self, now_ms: u64) {
        if self.last_dial_ms.is_some_and(|t| now_ms < t + REDIAL_MS) {
            return;
        }
        self.last_dial_ms = Some(now_ms);
        for addr in self.peers.clone() {
            if self.conns.iter().any(|c| c.dialled == Some(addr)) {
                continue;
            }
            if let Ok(stream) = TcpStream::connect_timeout(&addr, Duration::from_millis(200)) {
                self.conns.push(Conn::new(stream, Some(addr), &self.hello));
                self.traffic.frame(Direction::Out, "hello");
            }
        }
    }

    fn handle(&mut self, index: usize, frame: Frame, node: &mut Node) -> Result<(), NodeError> {
        let conn = &mut self.conns[index];
        let Some(peer) = conn.peer else {
            match frame {
                Frame::Hello { id, chain_id } if chain_id == self.chain_id => conn.peer = Some(id),
                _ => conn.dead = true,
            }
            return Ok(());
        };
        match frame {
            Frame::Hello { .. } => conn.dead = true,
            Frame::Message { topic, payload } => node.deliver(peer, topic, payload)?,
            Frame::Tx { raw } => {
                // A peer's transaction we already hold, or cannot admit, is not an error.
                let _ = node.submit(&raw);
            }
            Frame::Request {
                request_id,
                payload,
            } => {
                self.next_local_id += 1;
                self.serving.insert(self.next_local_id, (peer, request_id));
                node.step(Input::Request {
                    peer,
                    request_id: self.next_local_id,
                    payload,
                })?;
            }
            Frame::Response {
                request_id,
                payload,
            } => node.step(Input::Response {
                request_id,
                payload,
            })?,
        }
        Ok(())
    }

    fn send_to(&mut self, peer: &[u8; 32], frame: &Frame) {
        if let Some(conn) = self.conns.iter_mut().find(|c| c.peer == Some(*peer)) {
            conn.send(frame);
            self.traffic.frame(Direction::Out, frame.kind());
        }
    }

    fn broadcast(&mut self, frame: &Frame) {
        for conn in self.conns.iter_mut().filter(|c| c.peer.is_some()) {
            conn.send(frame);
            self.traffic.frame(Direction::Out, frame.kind());
        }
    }

    /// Accepts, dials, reads and delivers, then sends whatever the node queued.
    ///
    /// # Errors
    /// A node error while handling input; the transport stays usable.
    pub fn poll(&mut self, node: &mut Node, now_ms: u64) -> Result<(), NodeError> {
        self.accept();
        self.redial(now_ms);
        for i in 0..self.conns.len() {
            let before = self.conns[i].inbuf.len();
            self.conns[i].read();
            let read = self.conns[i].inbuf.len() - before;
            self.traffic.bytes(Direction::In, read);
            let frames = take_frames(&mut self.conns[i].inbuf).unwrap_or_else(|_| {
                self.conns[i].dead = true;
                Vec::new()
            });
            for frame in frames {
                self.traffic.frame(Direction::In, frame.kind());
                self.handle(i, frame, node)?;
            }
        }
        // What the driver did is on disk before any peer hears of it (spec
        // 08 §7): a node whose store refuses sends nothing until it accepts.
        node.sync_store()?;
        for message in node.take_outbound() {
            match message {
                Outbound::Broadcast { topic, payload } => {
                    self.broadcast(&Frame::Message { topic, payload });
                }
                Outbound::Send {
                    peer,
                    topic,
                    payload,
                } => self.send_to(&peer, &Frame::Message { topic, payload }),
                Outbound::Request {
                    peer,
                    request_id,
                    payload,
                } => self.send_to(
                    &peer,
                    &Frame::Request {
                        request_id,
                        payload,
                    },
                ),
                Outbound::Respond {
                    request_id,
                    payload,
                } => {
                    if let Some((peer, their_id)) = self.serving.remove(&request_id) {
                        self.send_to(
                            &peer,
                            &Frame::Response {
                                request_id: their_id,
                                payload,
                            },
                        );
                    }
                }
                Outbound::Disseminate { .. } | Outbound::PeerScore { .. } => {}
            }
        }
        for raw in node.take_tx_gossip() {
            self.broadcast(&Frame::Tx { raw });
        }
        for conn in &mut self.conns {
            let before = conn.outbuf.len();
            conn.flush();
            self.traffic
                .bytes(Direction::Out, before - conn.outbuf.len());
        }
        self.conns.retain(|c| !c.dead);
        node.telemetry
            .p2p(self.connected().len(), &mut self.traffic);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stream that yields the scripted results in order.
    struct Script(Vec<std::io::Result<usize>>);

    impl Read for Script {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let r = self.0.remove(0);
            if let Ok(n) = r {
                buf[..n].fill(7);
            }
            r
        }
    }

    impl Write for Script {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            self.0.remove(0)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn would_block() -> std::io::Result<usize> {
        Err(ErrorKind::WouldBlock.into())
    }

    #[test]
    fn reading_stops_on_block_close_or_failure() {
        let mut buf = Vec::new();
        assert!(read_available(
            &mut Script(vec![Ok(2), would_block()]),
            &mut buf
        ));
        assert_eq!(buf, vec![7, 7]);
        assert!(!read_available(&mut Script(vec![Ok(0)]), &mut buf));
        assert!(!read_available(
            &mut Script(vec![Err(ErrorKind::ConnectionReset.into())]),
            &mut buf
        ));
    }

    #[test]
    fn writing_stops_on_block_or_failure() {
        let mut out = vec![1, 2, 3];
        assert!(write_available(
            &mut Script(vec![Ok(1), would_block()]),
            &mut out
        ));
        assert_eq!(out, vec![2, 3]);
        assert!(write_available(&mut Script(vec![Ok(2)]), &mut out));
        assert!(out.is_empty());
        let mut out = vec![1];
        assert!(!write_available(&mut Script(vec![Ok(0)]), &mut out));
        assert!(!write_available(
            &mut Script(vec![Err(ErrorKind::BrokenPipe.into())]),
            &mut out
        ));
        let mut script = Script(vec![]);
        assert!(Write::flush(&mut script).is_ok());
    }
}
