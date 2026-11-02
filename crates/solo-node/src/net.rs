//! The TCP transport: peers exchange length-prefixed frames carrying
//! consensus messages, transaction gossip and sync requests. One
//! non-blocking [`Transport::poll`] call moves bytes in both directions and
//! feeds the node, so a node and its transport run on one thread.
//!
//! A frame on the wire is a `u32` little-endian length followed by a
//! [`Frame`] in the canonical encoding (spec 06 §2). The first frame on
//! every connection is `Hello`, in the clear, with a fresh nonce and a
//! fresh key; every frame after it is sealed under the session the two
//! fresh keys agree (spec 09 §3a, [`crate::session`]). The second is
//! `Auth` (spec 09 §3): each end signs both ends' nonces and fresh keys with
//! its node key, so a peer is known by an id only once it has proved it
//! holds that id's key, and the session is bound to that proof. A peer on
//! another chain or protocol version, that fails or omits the proof, or
//! whose frame does not open, is disconnected.
//!
//! With [`Transport::enable_discovery`] a node also runs peer exchange
//! (spec 09 §5a): it trades signed address records with its peers, keeps
//! them in a bounded [`PeerTable`], and dials from it, on threads of their
//! own, up to its outbound target, and, given a file, keeps the peers that
//! answered across restarts.

use std::collections::BTreeMap;
use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::Duration;

use solo_abi::codec::{Decode, DecodeError, Decoder, Encode, Encoder, Seq};
use solo_abi::staking::{StakingStatus, query::STAKING};
use solo_abi::types::Input;
use solo_metrics::{Direction, Traffic};

use crate::extension::Outbound;
use crate::node::{Node, NodeError};
use crate::peers::{self, PeerRecord, PeerTable};
use crate::session::{Ephemeral, Session, Side, VERSION};
use crate::statesync::StateSync;

/// Largest frame accepted, in bytes, before it is sealed (spec 09 §2).
pub const MAX_FRAME: usize = 16 << 20;

/// Length of an encoded `Hello`, the one frame sent in the clear; a longer
/// frame before the session is agreed closes the connection.
pub const HELLO_LEN: usize = 1 + 2 + 32 + 8 + 32 + 32 + 33;

/// How often a lost outbound peer is redialled.
pub const REDIAL_MS: u64 = 500;

/// How long a dial of a discovered or bootstrap address may take.
pub const DIAL_TIMEOUT_MS: u64 = 1_000;

/// How long a connection may take to complete its handshake (spec 09 §3).
pub const HANDSHAKE_MS: u64 = 5_000;

/// How long a state sync waits with no handshaken peer before it gives up
/// (spec 09 §6).
pub const SYNC_PEER_WAIT_MS: u64 = 60_000;

/// Domain of a handshake's signature.
const HELLO_DOMAIN: &[u8] = b"SOLO-HELLO";

/// What an end's `Auth` signs (spec 09 §3): `keccak256("SOLO-HELLO" ‖
/// version ‖ chain_id ‖ genesis ‖ signer_nonce ‖ verifier_nonce ‖
/// signer_ephemeral ‖ verifier_ephemeral)`, where `signer` is what the
/// signer's `Hello` committed to and `verifier` what the other end's did.
#[must_use]
pub fn hello_digest(chain_id: u64, genesis: &[u8; 32], signer: &Side, verifier: &Side) -> [u8; 32] {
    let mut preimage = HELLO_DOMAIN.to_vec();
    preimage.extend_from_slice(&VERSION.to_le_bytes());
    preimage.extend_from_slice(&chain_id.to_le_bytes());
    preimage.extend_from_slice(genesis);
    preimage.extend_from_slice(&signer.nonce);
    preimage.extend_from_slice(&verifier.nonce);
    preimage.extend_from_slice(&signer.ephemeral);
    preimage.extend_from_slice(&verifier.ephemeral);
    solo_host::hash::keccak256(&preimage)
}

/// A node key drawn from the operating system's randomness, for a node
/// without a consensus key (spec 09 §3).
///
/// # Errors
/// If the operating system gives no randomness.
///
/// # Panics
/// Only if a hash is at or above the group order, odds about 2^-128.
pub fn fresh_key() -> std::io::Result<k256::ecdsa::SigningKey> {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed)
        .ok()
        .ok_or(std::io::ErrorKind::Other)?;
    let digest = solo_host::hash::keccak256(&seed);
    Ok(k256::ecdsa::SigningKey::from_slice(&digest)
        .expect("a hash is a scalar, bar a negligible chance"))
}

/// One unit on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum Frame {
    Hello {
        version: u16,
        id: [u8; 32],
        chain_id: u64,
        genesis: [u8; 32],
        nonce: [u8; 32],
        ephemeral: [u8; 33],
    },
    Message {
        topic: u16,
        payload: Vec<u8>,
    },
    Tx {
        raw: Vec<u8>,
    },
    Request {
        request_id: u64,
        payload: Vec<u8>,
    },
    Response {
        request_id: u64,
        payload: Vec<u8>,
    },
    SyncRequest {
        request_id: u64,
        payload: Vec<u8>,
    },
    SyncResponse {
        request_id: u64,
        payload: Vec<u8>,
    },
    GetPeers,
    Peers {
        records: Seq<PeerRecord>,
    },
    Auth {
        signature: [u8; 65],
    },
}

impl Encode for Frame {
    fn encode(&self, e: &mut Encoder) {
        match self {
            Frame::Hello {
                version,
                id,
                chain_id,
                genesis,
                nonce,
                ephemeral,
            } => {
                e.raw(&[0]);
                e.put(version).put(id).put(chain_id).put(genesis);
                e.put(nonce).put(ephemeral);
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
            Frame::SyncRequest {
                request_id,
                payload,
            } => {
                e.raw(&[5]);
                e.put(request_id).put(payload);
            }
            Frame::SyncResponse {
                request_id,
                payload,
            } => {
                e.raw(&[6]);
                e.put(request_id).put(payload);
            }
            Frame::GetPeers => {
                e.raw(&[7]);
            }
            Frame::Peers { records } => {
                e.raw(&[8]);
                e.put(records);
            }
            Frame::Auth { signature } => {
                e.raw(&[9]);
                e.put(signature);
            }
        }
    }
}

impl Decode for Frame {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(match d.raw(1)?[0] {
            0 => Frame::Hello {
                version: d.get()?,
                id: d.get()?,
                chain_id: d.get()?,
                genesis: d.get()?,
                nonce: d.get()?,
                ephemeral: d.get()?,
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
            5 => Frame::SyncRequest {
                request_id: d.get()?,
                payload: d.get()?,
            },
            6 => Frame::SyncResponse {
                request_id: d.get()?,
                payload: d.get()?,
            },
            7 => Frame::GetPeers,
            8 => Frame::Peers { records: d.get()? },
            9 => Frame::Auth {
                signature: d.get()?,
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
    while let Some(frame) = take_frame(buf, MAX_FRAME)? {
        frames.push(frame);
    }
    Ok(frames)
}

/// Splits the frame in the clear at the front of `buf` off it, if it is all
/// there. `Err` means the stream is unusable (a frame longer than `max`, or
/// one that does not decode) and the connection must close.
///
/// # Errors
/// A message naming the problem.
pub fn take_frame(buf: &mut Vec<u8>, max: usize) -> Result<Option<Frame>, String> {
    let Some(header) = buf.get(..4) else {
        return Ok(None);
    };
    let len = u32::from_le_bytes([header[0], header[1], header[2], header[3]]) as usize;
    if len > max {
        return Err(format!("frame of {len} bytes exceeds the limit"));
    }
    if buf.len() < 4 + len {
        return Ok(None);
    }
    let Ok(frame) = Frame::from_bytes(&buf[4..4 + len]) else {
        return Err("undecodable frame".to_owned());
    };
    buf.drain(..4 + len);
    Ok(Some(frame))
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
    /// What this end's `Hello` committed it to: its nonce and fresh key.
    side: Side,
    /// This end's fresh secret, until the peer's `Hello` agrees the session.
    ephemeral: Option<Ephemeral>,
    /// The keys every frame after the `Hello`s is sealed with (spec 09 §3a).
    session: Option<Session>,
    /// The id the peer's `Hello` named and what it committed to, until its
    /// `Auth` proves them.
    claimed: Option<([u8; 32], Side)>,
    /// The peer, once its handshake completed (spec 09 §3).
    peer: Option<[u8; 32]>,
    /// The address this connection was dialled at, if we dialled it.
    dialled: Option<SocketAddr>,
    dead: bool,
    /// The peer closed, or reading failed: the connection dies once the
    /// frames it sent before are taken.
    closed: bool,
    /// What peer exchange dialled this connection for, if it did.
    target: Option<Target>,
    /// Where an accepted connection comes from.
    remote: Option<SocketAddr>,
    /// When the connection gives up waiting for its handshake to complete.
    hello_by_ms: u64,
    /// When this node next asks the peer for its records.
    next_exchange_ms: u64,
    /// When the peer's last `GetPeers`, and its last `Peers`, were handled.
    last_get_ms: Option<u64>,
    last_peers_ms: Option<u64>,
}

impl Conn {
    fn new(
        stream: TcpStream,
        side: Side,
        ephemeral: Ephemeral,
        hello: &Frame,
        now_ms: u64,
    ) -> Conn {
        let _ = stream.set_nonblocking(true);
        let _ = stream.set_nodelay(true);
        Conn {
            stream,
            inbuf: Vec::new(),
            outbuf: frame_bytes(hello),
            side,
            ephemeral: Some(ephemeral),
            session: None,
            claimed: None,
            peer: None,
            dialled: None,
            dead: false,
            closed: false,
            target: None,
            remote: None,
            hello_by_ms: now_ms + HANDSHAKE_MS,
            next_exchange_ms: 0,
            last_get_ms: None,
            last_peers_ms: None,
        }
    }

    /// Queues `frame` sealed under the session; a connection without one,
    /// or whose counter is spent, is closed instead.
    fn send(&mut self, frame: &Frame) {
        let sealed = self.session.as_mut().and_then(|s| s.seal(frame));
        self.dead |= sealed.is_none();
        self.outbuf.extend(sealed.unwrap_or_default());
    }

    fn read(&mut self) {
        self.closed |= !read_available(&mut self.stream, &mut self.inbuf);
    }

    /// The next whole frame read: the peer's `Hello` in the clear until the
    /// session is agreed, sealed frames after it. A frame that is too long,
    /// does not open or does not decode closes the connection, and so does
    /// a closed one once its frames are taken: a peer that sends its
    /// `Hello` and closes, as one of another genesis does, is still heard.
    fn next_frame(&mut self) -> Option<Frame> {
        if self.dead {
            return None;
        }
        let taken = match self.session.as_mut() {
            Some(session) => session.open(&mut self.inbuf),
            None => take_frame(&mut self.inbuf, HELLO_LEN),
        };
        let frame = taken.unwrap_or_else(|_| {
            self.dead = true;
            None
        });
        self.dead |= frame.is_none() && self.closed;
        frame
    }

    fn flush(&mut self) {
        self.dead |= !write_available(&mut self.stream, &mut self.outbuf);
    }
}

/// Peer exchange settings (spec 09 §5a).
#[derive(Clone)]
pub struct Discovery {
    /// The node key that signs this node's record; without one the node
    /// advertises nothing, and still learns and dials.
    pub key: Option<k256::ecdsa::SigningKey>,
    /// The address to advertise; by default the listen address, unless
    /// that is unspecified.
    pub advertise: Option<SocketAddr>,
    /// Addresses dialled to learn the network, with no id expected.
    pub bootstrap: Vec<SocketAddr>,
    /// Most connections in all, configured peers aside.
    pub max_peers: usize,
    /// Connections this node dials itself, configured peers included.
    pub outbound: usize,
    /// Where the table is kept across restarts (spec 09 §5a.7), if anywhere.
    pub peer_file: Option<PathBuf>,
}

impl Default for Discovery {
    fn default() -> Discovery {
        Discovery {
            key: None,
            advertise: None,
            bootstrap: Vec::new(),
            max_peers: peers::DEFAULT_MAX_PEERS,
            outbound: peers::DEFAULT_OUTBOUND,
            peer_file: None,
        }
    }
}

/// What peer exchange dialled a connection for: an entry of the table, or
/// a bootstrap address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Target {
    Entry([u8; 32]),
    Boot(SocketAddr),
}

/// A bootstrap address and how its dials went.
struct Boot {
    addr: SocketAddr,
    /// The id its last handshake named.
    id: Option<[u8; 32]>,
    failures: u32,
    next_dial_ms: u64,
}

/// A finished dial: what it was for, and the stream or the error.
type Dialled = (Target, std::io::Result<TcpStream>);

/// The state of peer exchange.
struct Exchange {
    key: Option<k256::ecdsa::SigningKey>,
    advertise: Option<SocketAddr>,
    /// This node's record, signed at the first poll.
    own: Option<PeerRecord>,
    table: PeerTable,
    boot: Vec<Boot>,
    max_peers: usize,
    outbound: usize,
    /// Dials in flight.
    dialing: Vec<Target>,
    done: (Sender<Dialled>, Receiver<Dialled>),
    next_validators_ms: u64,
    /// Where the table is kept, whether it was read yet, what was last
    /// written there and when it may be written next.
    peer_file: Option<PathBuf>,
    restored: bool,
    written: Option<Vec<u8>>,
    next_save_ms: u64,
}

impl Exchange {
    fn boot(&mut self, addr: SocketAddr) -> Option<&mut Boot> {
        self.boot.iter_mut().find(|b| b.addr == addr)
    }

    /// A dial of `target` failed, or its connection closed before its handshake.
    fn failed(&mut self, target: Target, now_ms: u64) {
        match target {
            Target::Entry(id) => self.table.dial_failed(&id, now_ms),
            Target::Boot(addr) => {
                if let Some(b) = self.boot(addr) {
                    b.failures += 1;
                    b.next_dial_ms = now_ms + peers::backoff_ms(b.failures);
                }
            }
        }
    }

    /// Writes the table's seen entries to the peer file when they changed
    /// since the last write (spec 09 §5a.7); a failed write is tried again
    /// at the next turn.
    fn save(&mut self) {
        let Some(path) = &self.peer_file else {
            return;
        };
        let bytes = Seq(self.table.saved(self.max_peers)).to_bytes();
        if self.written.as_ref() != Some(&bytes) && peers::write_saved(path, &bytes).is_ok() {
            self.written = Some(bytes);
        }
    }
}

/// A node's TCP endpoint.
pub struct Transport {
    listener: TcpListener,
    conns: Vec<Conn>,
    /// The node key that signs this node's handshakes.
    key: k256::ecdsa::SigningKey,
    /// This node's id, as its `Hello` names it: the hash of its key.
    id: [u8; 32],
    chain_id: u64,
    genesis: [u8; 32],
    /// The secret every connection's nonce and fresh key are drawn from,
    /// replaced by its hash at every draw.
    seed: [u8; 32],
    peers: Vec<SocketAddr>,
    last_dial_ms: Option<u64>,
    /// Requests this node is serving: local id to `(peer, the peer's id)`.
    serving: BTreeMap<u64, ([u8; 32], u64)>,
    next_local_id: u64,
    /// Traffic counted since the last poll handed it to the node's telemetry.
    traffic: Traffic,
    /// Peer exchange, when enabled.
    exchange: Option<Exchange>,
    /// Whether a `Hello` of this chain id named another genesis.
    foreign: bool,
    /// Since when a state sync has had no handshaken peer.
    alone_since_ms: Option<u64>,
}

impl Transport {
    /// Listens on `listen` and keeps connections to `peers` open, proving
    /// in every handshake that it holds `key` (spec 09 §3) for the chain of
    /// `chain_id` and `genesis`.
    ///
    /// # Errors
    /// If the address cannot be bound, or the operating system gives no
    /// randomness for the handshakes' nonces.
    pub fn bind(
        listen: &str,
        key: k256::ecdsa::SigningKey,
        chain_id: u64,
        genesis: [u8; 32],
        peers: Vec<SocketAddr>,
    ) -> std::io::Result<Transport> {
        let listener = TcpListener::bind(listen)?;
        listener.set_nonblocking(true)?;
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed)
            .ok()
            .ok_or(std::io::ErrorKind::Other)?;
        Ok(Transport {
            listener,
            conns: Vec::new(),
            id: crate::validator_id(&key),
            key,
            chain_id,
            genesis,
            seed,
            peers,
            last_dial_ms: None,
            serving: BTreeMap::new(),
            next_local_id: 0,
            traffic: Traffic::default(),
            exchange: None,
            foreign: false,
            alone_since_ms: None,
        })
    }

    /// Runs peer exchange from now on (spec 09 §5a).
    pub fn enable_discovery(&mut self, discovery: Discovery) {
        let advertise = discovery
            .advertise
            .or_else(|| self.local_addr().ok().filter(peers::dialable));
        self.exchange = Some(Exchange {
            key: discovery.key,
            advertise,
            own: None,
            table: PeerTable::new(self.chain_id, self.id),
            boot: discovery
                .bootstrap
                .into_iter()
                .map(|addr| Boot {
                    addr,
                    id: None,
                    failures: 0,
                    next_dial_ms: 0,
                })
                .collect(),
            max_peers: discovery.max_peers,
            outbound: discovery.outbound,
            dialing: Vec::new(),
            done: channel(),
            next_validators_ms: 0,
            peer_file: discovery.peer_file,
            restored: false,
            written: None,
            next_save_ms: 0,
        });
    }

    /// This node's id: the hash of its node key.
    #[must_use]
    pub fn id(&self) -> [u8; 32] {
        self.id
    }

    /// A new connection over `stream`, with a nonce and a fresh key of its
    /// own and this node's `Hello` queued. Both are drawn from a seed that
    /// is replaced by its hash first, so that what the node holds later
    /// tells nothing of the keys of the connections it opened before.
    fn open(&mut self, stream: TcpStream, now_ms: u64) -> Conn {
        let draw = |label: &[u8], seed: &[u8; 32]| {
            solo_host::hash::keccak256(&[label, seed.as_slice()].concat())
        };
        self.seed = draw(b"SOLO-SEED", &self.seed);
        let ephemeral = Ephemeral::from_seed(&draw(b"SOLO-EPHEMERAL", &self.seed));
        let side = Side {
            nonce: draw(b"SOLO-NONCE", &self.seed),
            ephemeral: ephemeral.public(),
        };
        let hello = Frame::Hello {
            version: VERSION,
            id: self.id,
            chain_id: self.chain_id,
            genesis: self.genesis,
            nonce: side.nonce,
            ephemeral: side.ephemeral,
        };
        self.traffic.frame(Direction::Out, "hello");
        Conn::new(stream, side, ephemeral, &hello, now_ms)
    }

    /// The peer table, when peer exchange runs.
    #[must_use]
    pub fn peer_table(&self) -> Option<&PeerTable> {
        self.exchange.as_ref().map(|x| &x.table)
    }

    /// The record this node advertises, once signed.
    #[must_use]
    pub fn own_record(&self) -> Option<&PeerRecord> {
        self.exchange.as_ref().and_then(|x| x.own.as_ref())
    }

    /// Connections this node dialled itself (configured peers and peer
    /// exchange's), open or opening.
    #[must_use]
    pub fn outbound(&self) -> usize {
        self.conns
            .iter()
            .filter(|c| c.dialled.is_some() || c.target.is_some())
            .count()
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

    fn accept(&mut self, now_ms: u64) {
        while let Ok((stream, remote)) = self.listener.accept() {
            // A connection beyond the limits is closed as it is dropped.
            if self.admits(&remote) {
                let mut conn = self.open(stream, now_ms);
                conn.remote = Some(remote);
                self.conns.push(conn);
            }
        }
    }

    /// Whether peer exchange's limits let a connection from `remote` in:
    /// fewer than `max_peers` connections besides the configured peers', and
    /// fewer than `PER_PREFIX` from its prefix (spec 09 §5a). Without peer
    /// exchange, every connection is accepted.
    fn admits(&self, remote: &SocketAddr) -> bool {
        let Some(x) = &self.exchange else {
            return true;
        };
        let open = self.conns.iter().filter(|c| c.dialled.is_none()).count();
        let prefix = peers::prefix(remote);
        let same = self
            .conns
            .iter()
            .filter(|c| prefix.is_some() && c.remote.as_ref().and_then(peers::prefix) == prefix)
            .count();
        open < x.max_peers && same < peers::PER_PREFIX
    }

    /// Peer exchange's dialling (spec 09 §5a): takes up the peer file and
    /// signs this node's record at the first call, takes the dials that
    /// finished, and starts new ones while the node has fewer outbound
    /// connections than its target.
    fn discover(&mut self, now_ms: u64) {
        // Taken out for the call, so that new connections can be opened meanwhile.
        if let Some(mut x) = self.exchange.take() {
            self.dial(&mut x, now_ms);
            self.exchange = Some(x);
        }
    }

    /// [`Transport::discover`] with the state of peer exchange, `x`.
    fn dial(&mut self, x: &mut Exchange, now_ms: u64) {
        let mut busy = self.connected();
        if !x.restored {
            x.restored = true;
            if let Some(path) = &x.peer_file {
                let saved = peers::load_saved(path);
                x.table.restore(&saved, now_ms, x.max_peers);
            }
        }
        if x.own.is_none()
            && let (Some(key), Some(addr)) = (&x.key, x.advertise)
        {
            x.own = PeerRecord::sign(key, self.chain_id, addr, now_ms);
        }
        let mut finished = Vec::new();
        while let Ok((target, result)) = x.done.1.try_recv() {
            x.dialing.retain(|t| *t != target);
            match result {
                Ok(stream) => finished.push((target, stream)),
                Err(_) => x.failed(target, now_ms),
            }
        }
        for (target, stream) in finished {
            let mut conn = self.open(stream, now_ms);
            conn.target = Some(target);
            self.conns.push(conn);
        }
        let open = self
            .conns
            .iter()
            .filter(|c| c.dialled.is_some() || c.target.is_some())
            .count();
        let room = x
            .outbound
            .saturating_sub(open + x.dialing.len())
            .min(peers::MAX_DIALING.saturating_sub(x.dialing.len()));
        if room == 0 {
            return;
        }
        let entry = |t: &Target| match t {
            Target::Entry(id) => Some(*id),
            Target::Boot(_) => None,
        };
        busy.extend(
            self.conns
                .iter()
                .filter_map(|c| c.target.as_ref().and_then(entry)),
        );
        busy.extend(x.dialing.iter().filter_map(entry));
        let mut targets: Vec<(Target, SocketAddr)> = x
            .table
            .candidates(now_ms, &busy, room)
            .into_iter()
            .map(|(id, addr)| (Target::Entry(id), addr))
            .collect();
        for boot in &x.boot {
            let target = Target::Boot(boot.addr);
            let open = self.conns.iter().any(|c| c.target == Some(target))
                || x.dialing.contains(&target)
                || boot.id.is_some_and(|id| busy.contains(&id));
            if targets.len() < room && boot.next_dial_ms <= now_ms && !open {
                targets.push((target, boot.addr));
            }
        }
        for (target, addr) in targets {
            x.dialing.push(target);
            let done = x.done.0.clone();
            std::thread::spawn(move || {
                let stream =
                    TcpStream::connect_timeout(&addr, Duration::from_millis(DIAL_TIMEOUT_MS));
                // A transport dropped meanwhile no longer listens.
                let _ = done.send((target, stream));
            });
        }
    }

    /// A frame on connection `index` before its handshake completed (spec
    /// 09 §3): first a `Hello` of this version, chain and genesis, which
    /// agrees the session (§3a) and which this end answers with its `Auth`,
    /// then the peer's `Auth`, which must recover to the id its `Hello`
    /// named. Anything else closes the connection, and so does a `Hello`
    /// that repeats this end's own nonce or fresh key (a connection looped
    /// back on itself) or whose key is not a point of the curve.
    fn handshake(&mut self, index: usize, frame: Frame, now_ms: u64) {
        let conn = &mut self.conns[index];
        match (conn.claimed, frame) {
            (
                None,
                Frame::Hello {
                    version,
                    id,
                    chain_id,
                    genesis,
                    nonce,
                    ephemeral,
                },
            ) if version == VERSION && chain_id == self.chain_id && genesis == self.genesis => {
                let theirs = Side { nonce, ephemeral };
                let looped = nonce == conn.side.nonce || ephemeral == conn.side.ephemeral;
                conn.session = conn.ephemeral.take().filter(|_| !looped).and_then(|e| {
                    Session::new(e, self.chain_id, &self.genesis, &conn.side, &theirs)
                });
                conn.claimed = Some((id, theirs));
                let digest = hello_digest(self.chain_id, &self.genesis, &conn.side, &theirs);
                // A key signs any digest; a failure would send a proof the peer refuses.
                let signature = crate::sign_recoverable(&self.key, &digest).unwrap_or([0; 65]);
                // Without a session this closes the connection and sends nothing.
                conn.send(&Frame::Auth { signature });
                self.traffic.frame(Direction::Out, "auth");
            }
            (Some((id, theirs)), Frame::Auth { signature })
                if peers::recover_id(
                    &hello_digest(self.chain_id, &self.genesis, &theirs, &conn.side),
                    &signature,
                ) == Some(id) =>
            {
                self.authenticated(index, id, now_ms);
            }
            (
                None,
                Frame::Hello {
                    version, chain_id, ..
                },
            ) if version == VERSION && chain_id == self.chain_id => {
                self.foreign = true;
                conn.dead = true;
            }
            _ => conn.dead = true,
        }
    }

    /// Why a state sync over this transport cannot go on (spec 09 §6), while
    /// it has no handshaken peer it still asks: a peer of this chain id named
    /// another genesis, or it has had no such peer for
    /// [`SYNC_PEER_WAIT_MS`]. Read after [`Transport::poll_sync`].
    #[must_use]
    pub fn sync_stalled(&self, now_ms: u64) -> Option<&'static str> {
        let since = self.alone_since_ms?;
        if self.foreign {
            return Some("a peer is on a chain with another genesis block");
        }
        (now_ms >= since + SYNC_PEER_WAIT_MS).then_some("no peer to sync from in time")
    }

    /// Connection `index` completed its handshake as `id`. With peer
    /// exchange, a peer that is this node itself, or another id than the one
    /// it was dialled for, is closed, and a bootstrap address learns the id
    /// it answers with.
    fn authenticated(&mut self, index: usize, id: [u8; 32], now_ms: u64) {
        let conn = &mut self.conns[index];
        conn.peer = Some(id);
        let Some(x) = self.exchange.as_mut() else {
            return;
        };
        conn.dead |= id == self.id;
        match conn.target {
            Some(Target::Entry(expected)) => {
                conn.dead |= !x.table.handshake(&expected, &id, now_ms);
            }
            // A bootstrap address that is this node's own is never dialled again.
            Some(Target::Boot(addr)) if id == self.id => x.boot.retain(|b| b.addr != addr),
            Some(Target::Boot(addr)) => {
                if let Some(b) = x.boot(addr) {
                    b.failures = 0;
                    b.id = Some(id);
                }
            }
            None => {}
        }
    }

    /// A `GetPeers` from `peer` on connection `index`: answered with this
    /// node's records, at most once per `PEER_GAP_MS` (spec 09 §5a).
    fn get_peers(&mut self, index: usize, peer: [u8; 32], now_ms: u64) {
        let Some(x) = self.exchange.as_ref() else {
            return;
        };
        let conn = &mut self.conns[index];
        if conn
            .last_get_ms
            .is_some_and(|t| now_ms < t + peers::PEER_GAP_MS)
        {
            return;
        }
        conn.last_get_ms = Some(now_ms);
        let records = Seq(x.table.answer(&peer, x.own.as_ref()));
        conn.send(&Frame::Peers { records });
        self.traffic.frame(Direction::Out, "peers");
    }

    /// A `Peers` from `peer` on connection `index`: its records go into the
    /// table, at most once per `PEER_GAP_MS`; a frame the table refuses
    /// closes the connection (spec 09 §5a).
    fn peers(&mut self, index: usize, peer: [u8; 32], records: &[PeerRecord], now_ms: u64) {
        let connected = self.connected();
        let Some(x) = self.exchange.as_mut() else {
            return;
        };
        let conn = &mut self.conns[index];
        if conn
            .last_peers_ms
            .is_some_and(|t| now_ms < t + peers::PEER_GAP_MS)
        {
            return;
        }
        conn.last_peers_ms = Some(now_ms);
        conn.dead |= x.table.learn(peer, records, &connected).is_err();
    }

    /// Asks every handshaken peer for its records when its turn has come:
    /// right after the handshake, then every `EXCHANGE_MS`.
    fn ask_peers(&mut self, now_ms: u64) {
        if self.exchange.is_none() {
            return;
        }
        for conn in self
            .conns
            .iter_mut()
            .filter(|c| c.peer.is_some() && !c.dead && now_ms >= c.next_exchange_ms)
        {
            conn.next_exchange_ms = now_ms + peers::EXCHANGE_MS;
            conn.send(&Frame::GetPeers);
            self.traffic.frame(Direction::Out, "get_peers");
        }
    }

    /// Drops the dead connections. Peer exchange learns from those it
    /// dialled: one lost after its handshake is dialled again after a
    /// backoff, one closed before its handshake, or still without one
    /// `HANDSHAKE_MS` after it opened, counts as a failed dial.
    fn reap(&mut self, now_ms: u64) {
        for conn in &mut self.conns {
            // A peer that has not completed its handshake in time is closed;
            // one peer exchange dialled counts as a failed dial.
            conn.dead |= conn.peer.is_none() && now_ms >= conn.hello_by_ms;
        }
        if let Some(x) = self.exchange.as_mut() {
            for conn in self.conns.iter().filter(|c| c.dead) {
                match (conn.target, conn.peer) {
                    (Some(target), None) => x.failed(target, now_ms),
                    (Some(Target::Entry(id)), Some(peer)) if peer == id => {
                        x.table.lost(&id, now_ms);
                    }
                    (Some(Target::Boot(addr)), Some(_)) => {
                        if let Some(b) = x.boot(addr) {
                            b.next_dial_ms = now_ms + peers::BACKOFF_MS;
                        }
                    }
                    // Not dialled by peer exchange, or a mismatch it counted already.
                    _ => {}
                }
            }
        }
        self.conns.retain(|c| !c.dead);
    }

    /// Writes the peer file at most every `SAVE_MS` (spec 09 §5a.7).
    fn persist(&mut self, now_ms: u64) {
        if let Some(x) = self.exchange.as_mut()
            && now_ms >= x.next_save_ms
        {
            x.next_save_ms = now_ms + peers::SAVE_MS;
            x.save();
        }
    }

    /// Reads the current validator set from the node's chain state every
    /// `VALIDATOR_REFRESH_MS`, for the table to prefer and protect.
    fn refresh_validators(&mut self, node: &mut Node, now_ms: u64) {
        let Some(x) = self.exchange.as_mut() else {
            return;
        };
        if now_ms < x.next_validators_ms {
            return;
        }
        x.next_validators_ms = now_ms + peers::VALIDATOR_REFRESH_MS;
        let status = node
            .query(STAKING, &[])
            .ok()
            .filter(|r| r.status == 0)
            .and_then(|r| StakingStatus::from_bytes(&r.body).ok());
        // A query that fails keeps the set the table has.
        let previous = x.table.validators().to_vec();
        let ids = status.map_or(previous, |s| {
            s.validators.validators.0.iter().map(|v| v.id).collect()
        });
        x.table.set_validators(ids);
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
                let mut conn = self.open(stream, now_ms);
                conn.dialled = Some(addr);
                self.conns.push(conn);
            }
        }
    }

    fn handle(
        &mut self,
        index: usize,
        frame: Frame,
        node: &mut Node,
        now_ms: u64,
    ) -> Result<(), NodeError> {
        let conn = &mut self.conns[index];
        let Some(peer) = conn.peer else {
            self.handshake(index, frame, now_ms);
            return Ok(());
        };
        match frame {
            Frame::Hello { .. } | Frame::Auth { .. } => conn.dead = true,
            Frame::GetPeers => self.get_peers(index, peer, now_ms),
            Frame::Peers { records } => self.peers(index, peer, &records.0, now_ms),
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
            } => node.response(request_id, payload)?,
            Frame::SyncRequest {
                request_id,
                payload,
            } => {
                let payload = node.answer_sync(&payload);
                self.conns[index].send(&Frame::SyncResponse {
                    request_id,
                    payload,
                });
                self.traffic.frame(Direction::Out, "sync_response");
            }
            // A running node fetches no snapshot.
            Frame::SyncResponse { .. } => {}
        }
        Ok(())
    }

    /// Handles one frame while the node joins from its peers' snapshots
    /// (spec 09 §6): state-sync answers go to `sync`, requests get the
    /// answer of a node that serves nothing, and everything else is
    /// dropped until the driver runs.
    fn handle_syncing(&mut self, index: usize, frame: Frame, sync: &mut StateSync, now_ms: u64) {
        let conn = &mut self.conns[index];
        let Some(peer) = conn.peer else {
            self.handshake(index, frame, now_ms);
            return;
        };
        match frame {
            Frame::Hello { .. } | Frame::Auth { .. } => conn.dead = true,
            Frame::GetPeers => self.get_peers(index, peer, now_ms),
            Frame::Peers { records } => self.peers(index, peer, &records.0, now_ms),
            Frame::SyncResponse {
                request_id,
                payload,
            } => sync.on_response(peer, request_id, &payload, now_ms),
            Frame::SyncRequest {
                request_id,
                payload,
            } => {
                conn.send(&Frame::SyncResponse {
                    request_id,
                    payload: crate::statesync::answer_unserved(&payload),
                });
                self.traffic.frame(Direction::Out, "sync_response");
            }
            _ => {}
        }
    }

    /// Accepts, dials, reads and flushes like [`Transport::poll`], for a
    /// node that is not running yet and joins from its peers' snapshots
    /// (spec 22 §7.4): it hands `sync` the handshaken peers and their
    /// answers, and sends the requests `sync` returns.
    pub fn poll_sync(&mut self, sync: &mut StateSync, now_ms: u64) {
        self.accept(now_ms);
        self.redial(now_ms);
        self.discover(now_ms);
        for i in 0..self.conns.len() {
            self.read_in(i);
            while let Some(frame) = self.next_frame(i) {
                self.handle_syncing(i, frame, sync, now_ms);
            }
        }
        self.ask_peers(now_ms);
        self.reap(now_ms);
        self.persist(now_ms);
        // A peer the sync no longer asks keeps it going no more than none.
        let asked = self.connected().iter().any(|id| !sync.drops(id));
        self.alone_since_ms = if asked {
            None
        } else {
            Some(self.alone_since_ms.unwrap_or(now_ms))
        };
        for (peer, request_id, payload) in sync.poll(now_ms, &self.connected()) {
            self.send_to(
                &peer,
                &Frame::SyncRequest {
                    request_id,
                    payload,
                },
            );
        }
        self.flush_all();
    }

    /// Reads what connection `i` has.
    fn read_in(&mut self, i: usize) {
        let before = self.conns[i].inbuf.len();
        self.conns[i].read();
        let read = self.conns[i].inbuf.len() - before;
        self.traffic.bytes(Direction::In, read);
    }

    /// The next whole frame connection `i` has read, one at a time, since
    /// the peer's `Hello` changes how the frames after it are read; a
    /// connection that sends a bad frame is marked dead.
    fn next_frame(&mut self, i: usize) -> Option<Frame> {
        let frame = self.conns[i].next_frame()?;
        self.traffic.frame(Direction::In, frame.kind());
        Some(frame)
    }

    /// Writes what every connection has queued.
    fn flush_all(&mut self) {
        for conn in &mut self.conns {
            let before = conn.outbuf.len();
            conn.flush();
            self.traffic
                .bytes(Direction::Out, before - conn.outbuf.len());
        }
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
        self.accept(now_ms);
        self.redial(now_ms);
        self.discover(now_ms);
        for i in 0..self.conns.len() {
            self.read_in(i);
            while let Some(frame) = self.next_frame(i) {
                self.handle(i, frame, node, now_ms)?;
            }
        }
        self.ask_peers(now_ms);
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
        self.flush_all();
        self.reap(now_ms);
        self.persist(now_ms);
        self.refresh_validators(node, now_ms);
        node.telemetry
            .p2p(self.connected().len(), &mut self.traffic);
        Ok(())
    }
}

impl Drop for Transport {
    /// A transport that stops writes its peer file one last time.
    fn drop(&mut self) {
        if let Some(x) = self.exchange.as_mut() {
            x.save();
        }
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
