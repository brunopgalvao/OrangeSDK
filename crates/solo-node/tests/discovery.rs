//! Peer exchange over real sockets (spec 09 §5a): nodes told of one
//! bootstrap address find the rest of a four-validator network and keep it
//! when the bootstrap goes away; forged, unsigned and oversized record
//! frames close their connection; a flood of junk records from many
//! sources stays within the per-source, per-prefix and table limits and
//! never displaces a peer that answers; and the dial bookkeeping (backoff,
//! a handshake naming another id, a connection lost before or after its
//! handshake, a node dialling itself) and the limits on accepted
//! connections.

use std::collections::BTreeSet;
use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::{Duration, Instant};

use k256::ecdsa::SigningKey;
use solo_abi::Encode;
use solo_abi::chain::GenesisParams;
use solo_abi::codec::Seq;
use solo_abi::types::Genesis;
use solo_host::hash::keccak256;
use solo_node::net::{Frame, frame_bytes, take_frames};
use solo_node::peers::{MAX_RECORDS, PER_PREFIX, PER_SOURCE, PeerRecord, TABLE_CAP, prefix};
use solo_node::{Discovery, Node, NodeConfig, Sim, Transport, validator_id};

const KERNEL: &[u8] = include_bytes!("fixtures/kernel.elf");
const CHAIN_ID: u64 = 1337;
const SLOT_MS: u64 = 100;

fn kernel_module() -> &'static [u8] {
    static MODULE: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
    MODULE.get_or_init(|| {
        solo_recompile::recompile(
            &solo_recompile::Input::load(KERNEL).unwrap(),
            &solo_recompile::Options::default(),
        )
        .unwrap()
    })
}

fn keys(n: u8) -> Vec<SigningKey> {
    (1..=n)
        .map(|i| SigningKey::from_slice(&[0x50 + i; 32]).unwrap())
        .collect()
}

/// A key of its own for each `i`, as a stranger generates them.
fn stranger(i: u64) -> SigningKey {
    SigningKey::from_slice(&keccak256(&i.to_le_bytes())).unwrap()
}

fn genesis(validators: &[SigningKey]) -> Genesis {
    let params = GenesisParams {
        slot_ms: SLOT_MS,
        max_txs: 8,
        ..GenesisParams::default()
    };
    Genesis {
        chain_id: CHAIN_ID,
        fee_schedule: vec![],
        modules: Seq(vec![]),
        params: params.to_bytes(),
        validators: Sim::validator_set(validators).to_bytes(),
    }
}

/// Distinct peers a transport has completed a handshake with.
fn distinct(t: &Transport) -> usize {
    t.connected().into_iter().collect::<BTreeSet<_>>().len()
}

/// Nodes and their transports on one thread, with one clock.
struct Net {
    genesis: Genesis,
    nodes: Vec<Node>,
    transports: Vec<Transport>,
    start: Instant,
    epoch: u64,
}

impl Net {
    fn new(validators: &[SigningKey]) -> Net {
        Net {
            genesis: genesis(validators),
            nodes: Vec::new(),
            transports: Vec::new(),
            start: Instant::now(),
            epoch: 1_000_000,
        }
    }

    fn now(&self) -> u64 {
        self.epoch + u64::try_from(self.start.elapsed().as_millis()).unwrap()
    }

    /// A node that signs with `key` if it validates, its transport named by
    /// `identity` and running peer exchange as `discovery` says.
    fn add(
        &mut self,
        key: Option<&SigningKey>,
        identity: &SigningKey,
        discovery: Option<Discovery>,
    ) -> usize {
        let mut node = Node::open(
            kernel_module(),
            &self.genesis,
            NodeConfig {
                now_ms: self.now(),
                key: key.cloned(),
                ..NodeConfig::default()
            },
        )
        .unwrap();
        node.start(None).unwrap();
        let mut t =
            Transport::bind("127.0.0.1:0", validator_id(identity), CHAIN_ID, vec![]).unwrap();
        if let Some(d) = discovery {
            t.enable_discovery(Discovery {
                key: Some(identity.clone()),
                ..d
            });
        }
        self.nodes.push(node);
        self.transports.push(t);
        self.nodes.len() - 1
    }

    fn addr(&self, i: usize) -> SocketAddr {
        self.transports[i].local_addr().unwrap()
    }

    /// Polls everything, also between the calls of `between`, until `done`
    /// or `max`; generous deadlines, as every node shares this thread.
    fn pump(&mut self, max: Duration, mut done: impl FnMut(&mut Net) -> bool) -> bool {
        let deadline = Instant::now() + max;
        while Instant::now() < deadline {
            if done(self) {
                return true;
            }
            self.poll();
            std::thread::sleep(Duration::from_millis(2));
        }
        done(self)
    }

    fn poll(&mut self) {
        let now = self.now();
        for (node, t) in self.nodes.iter_mut().zip(self.transports.iter_mut()) {
            node.tick(now).unwrap();
            t.poll(node, now).unwrap();
        }
    }

    fn remove(&mut self, i: usize) {
        self.nodes.remove(i);
        self.transports.remove(i);
    }
}

#[test]
fn one_bootstrap_address_finds_the_network_and_outlives_it() {
    let keys = keys(4);
    let mut net = Net::new(&keys);
    net.add(Some(&keys[0]), &keys[0], Some(Discovery::default()));
    let boot = net.addr(0);
    for key in &keys[1..] {
        net.add(
            Some(key),
            key,
            Some(Discovery {
                bootstrap: vec![boot],
                ..Discovery::default()
            }),
        );
    }
    // Each validator but the first was told of the first alone, and finds all three others.
    let meshed = net.pump(Duration::from_mins(2), |net| {
        net.transports.iter().all(|t| distinct(t) == 3)
    });
    assert!(
        meshed,
        "{:?}",
        net.transports.iter().map(distinct).collect::<Vec<_>>()
    );
    // The last one learned the middle two from signed records naming where they listen.
    for i in [1, 2] {
        let table = net.transports[3].peer_table().unwrap();
        let entry = &table.entries()[&validator_id(&keys[i])];
        assert_eq!(entry.addr, net.addr(i));
        assert_eq!(entry.record.verify(CHAIN_ID), Some(net.addr(i)));
    }
    assert_eq!(
        net.transports[3].own_record().unwrap().verify(CHAIN_ID),
        Some(net.addr(3))
    );
    // Each read the validator set from its chain state.
    let set: Vec<[u8; 32]> = keys.iter().map(validator_id).collect();
    assert!(
        net.transports
            .iter()
            .all(|t| t.peer_table().unwrap().validators() == set.as_slice())
    );
    let finalized = net.pump(Duration::from_mins(3), |net| {
        net.nodes.iter().all(|n| n.finalized.len() >= 5)
    });
    assert!(finalized);
    // The bootstrap goes away. The other three keep each other and finalize on: three of
    // four validators are a quorum.
    net.remove(0);
    let before = net.nodes.iter().map(|n| n.finalized.len()).max().unwrap();
    let on = net.pump(Duration::from_mins(3), |net| {
        net.nodes.iter().all(|n| n.finalized.len() >= before + 5)
    });
    assert!(
        on,
        "{:?}",
        net.nodes
            .iter()
            .map(|n| n.finalized.len())
            .collect::<Vec<_>>()
    );
    assert!(net.transports.iter().all(|t| distinct(t) == 2));
    // They keep dialling the bootstrap address with backoff, and keep it out of their
    // validator preference only by its failures: it stays in their tables.
    let gone = validator_id(&keys[0]);
    assert!(
        net.transports
            .iter()
            .all(|t| t.peer_table().unwrap().entries().contains_key(&gone))
    );
}

/// A raw peer: a socket that has said `Hello` as `id`.
fn raw(addr: SocketAddr, id: [u8; 32]) -> TcpStream {
    let mut s = TcpStream::connect(addr).unwrap();
    send(
        &mut s,
        &Frame::Hello {
            id,
            chain_id: CHAIN_ID,
        },
    );
    s
}

fn send(s: &mut TcpStream, frame: &Frame) {
    s.write_all(&frame_bytes(frame)).unwrap();
}

fn peers(records: Vec<PeerRecord>) -> Frame {
    Frame::Peers {
        records: Seq(records),
    }
}

/// Polls `net` while reading `s` for up to `max`: the frames it got, and
/// whether the other end closed.
fn read_while(net: &mut Net, s: &mut TcpStream, max: Duration) -> (Vec<Frame>, bool) {
    s.set_nonblocking(true).unwrap();
    let deadline = Instant::now() + max;
    let (mut buf, mut frames, mut chunk) = (Vec::new(), Vec::new(), [0u8; 4096]);
    let mut closed = false;
    while Instant::now() < deadline && !closed {
        net.poll();
        loop {
            match s.read(&mut chunk) {
                Ok(0) => {
                    closed = true;
                    break;
                }
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(_) => {
                    closed = true;
                    break;
                }
            }
        }
        frames.extend(take_frames(&mut buf).unwrap());
        std::thread::sleep(Duration::from_millis(2));
    }
    (frames, closed)
}

#[test]
#[allow(clippy::too_many_lines)]
fn forged_records_are_refused_and_a_flood_displaces_no_good_peer() {
    let keys = keys(1);
    let good = stranger(1);
    let mut net = Net::new(&keys);
    // A good peer, an observer that advertises itself, and the node under attack, a
    // validator told of the good peer alone.
    net.add(None, &good, Some(Discovery::default()));
    let good_id = validator_id(&good);
    let target = net.add(
        Some(&keys[0]),
        &keys[0],
        Some(Discovery {
            bootstrap: vec![net.addr(0)],
            ..Discovery::default()
        }),
    );
    let addr = net.addr(target);
    let learned = net.pump(Duration::from_mins(1), |net| {
        net.transports[1]
            .peer_table()
            .unwrap()
            .entries()
            .contains_key(&good_id)
            && net.transports[1].connected().contains(&good_id)
    });
    assert!(learned);
    let good_addr = net.addr(0);
    // A record naming the good peer's id at the attacker's address, signed by the
    // attacker: the connection closes and the table keeps the good address.
    let attacker = stranger(2);
    let attacker_addr: SocketAddr = "127.0.0.1:9".parse().unwrap();
    let mut forged = PeerRecord::sign(&attacker, CHAIN_ID, attacker_addr, u64::MAX).unwrap();
    forged.id = good_id;
    let mut s = raw(addr, validator_id(&attacker));
    send(&mut s, &peers(vec![forged]));
    assert!(read_while(&mut net, &mut s, Duration::from_secs(10)).1);
    // An unsigned record, and more records than a frame may carry, close it too.
    let mut s = raw(addr, validator_id(&attacker));
    let unsigned = PeerRecord {
        id: [7; 32],
        addr: b"127.0.0.1:7".to_vec(),
        seq: 1,
        signature: [0; 65],
    };
    send(&mut s, &peers(vec![unsigned]));
    assert!(read_while(&mut net, &mut s, Duration::from_secs(10)).1);
    let mut s = raw(addr, validator_id(&attacker));
    let many = (0..=MAX_RECORDS as u64)
        .map(|i| PeerRecord::sign(&stranger(100 + i), CHAIN_ID, attacker_addr, 1).unwrap())
        .collect();
    send(&mut s, &peers(many));
    assert!(read_while(&mut net, &mut s, Duration::from_secs(10)).1);
    let table = net.transports[target].peer_table().unwrap();
    assert_eq!(table.entries()[&good_id].addr, good_addr);
    assert_eq!(table.entries().len(), 1);
    // A flood: twenty sources, each sending full frames of validly signed junk at
    // closed loopback ports and at three documentation prefixes nobody routes.
    let nets = ["192.0.2", "198.51.100", "203.0.113"];
    let mut sources = Vec::new();
    let mut junk = 1_000u64;
    for c in 0..20u64 {
        let id = validator_id(&stranger(10_000 + c));
        let mut s = raw(addr, id);
        let records = (0..MAX_RECORDS as u64)
            .map(|j| {
                junk += 1;
                let at: SocketAddr = if j % 2 == 0 {
                    format!("127.0.0.1:{}", 40_000 + junk).parse().unwrap()
                } else {
                    let n = nets[usize::try_from(j % 3).unwrap()];
                    format!("{n}.{}:30333", j + 1).parse().unwrap()
                };
                PeerRecord::sign(&stranger(junk), CHAIN_ID, at, 1).unwrap()
            })
            .collect();
        send(&mut s, &peers(records));
        sources.push((id, s));
        for _ in 0..20 {
            net.poll();
            std::thread::sleep(Duration::from_millis(2));
        }
    }
    // Let the target dial the junk and fail.
    net.pump(Duration::from_secs(5), |_| false);
    let table = net.transports[target].peer_table().unwrap();
    assert!(table.entries().len() <= TABLE_CAP);
    for (id, _) in &sources {
        let from = table
            .entries()
            .values()
            .filter(|e| e.source == Some(*id))
            .count();
        assert!(from <= PER_SOURCE, "{from} from one source");
    }
    for n in nets {
        let p = prefix(&format!("{n}.1:1").parse().unwrap());
        let held = table
            .entries()
            .values()
            .filter(|e| prefix(&e.addr) == p)
            .count();
        assert!(held <= PER_PREFIX, "{held} in {n}");
    }
    assert!(
        table.entries().len() > PER_SOURCE,
        "the flood got in, bounded"
    );
    assert_eq!(table.entries()[&good_id].addr, good_addr);
    assert!(table.entries()[&good_id].score >= 0);
    assert!(net.transports[target].connected().contains(&good_id));
    // The node under attack still makes blocks.
    let made = net.nodes[target].finalized.len();
    assert!(net.pump(Duration::from_mins(1), |net| {
        net.nodes[target].finalized.len() > made + 3
    }));
}

#[test]
#[allow(clippy::too_many_lines)]
fn dials_are_judged_by_their_handshakes() {
    let keys = keys(1);
    let mut net = Net::new(&keys);
    // A closed port and the node's own address as bootstrap addresses.
    let closed = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap()
    };
    let me = net.add(Some(&keys[0]), &keys[0], None);
    let own = net.addr(me);
    net.transports[me].enable_discovery(Discovery {
        key: Some(keys[0].clone()),
        bootstrap: vec![closed, own],
        ..Discovery::default()
    });
    // A listener the test answers for, advertised by key X.
    let fake = TcpListener::bind("127.0.0.1:0").unwrap();
    fake.set_nonblocking(true).unwrap();
    let x = stranger(1);
    let x_id = validator_id(&x);
    let record = PeerRecord::sign(&x, CHAIN_ID, fake.local_addr().unwrap(), 1).unwrap();
    let source = validator_id(&stranger(2));
    let mut s = raw(own, source);
    send(&mut s, &peers(vec![record]));
    // Asked twice in a row, the node answers once: its own record first, then X's.
    send(&mut s, &Frame::GetPeers);
    // A second frame of records within the gap is dropped.
    let z = PeerRecord::sign(&stranger(3), CHAIN_ID, "127.0.0.1:3".parse().unwrap(), 1).unwrap();
    send(&mut s, &peers(vec![z]));
    std::thread::sleep(Duration::from_millis(20));
    send(&mut s, &Frame::GetPeers);
    let (frames, closed_on_us) = read_while(&mut net, &mut s, Duration::from_secs(2));
    assert!(!closed_on_us);
    let answers: Vec<&Seq<PeerRecord>> = frames
        .iter()
        .filter_map(|f| match f {
            Frame::Peers { records } => Some(records),
            _ => None,
        })
        .collect();
    assert_eq!(answers.len(), 1, "{frames:?}");
    let ids: Vec<[u8; 32]> = answers[0].0.iter().map(|r| r.id).collect();
    assert_eq!(ids, vec![validator_id(&keys[0]), x_id]);
    assert!(frames.contains(&Frame::GetPeers));
    let table = net.transports[me].peer_table().unwrap();
    assert!(!table.entries().contains_key(&validator_id(&stranger(3))));
    // The node dials X: the first time X's listener answers as X and hangs up, the
    // second time as somebody else, the third time not at all.
    let accept = |net: &mut Net| -> TcpStream {
        let deadline = Instant::now() + Duration::from_mins(1);
        loop {
            assert!(Instant::now() < deadline, "no dial");
            net.poll();
            if let Ok((c, _)) = fake.accept() {
                return c;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    };
    let mut c = accept(&mut net);
    send(
        &mut c,
        &Frame::Hello {
            id: x_id,
            chain_id: CHAIN_ID,
        },
    );
    let verified = net.pump(Duration::from_secs(10), |net| {
        net.transports[me].peer_table().unwrap().entries()[&x_id].verified
    });
    assert!(verified);
    assert_eq!(net.transports[me].outbound(), 1);
    drop(c);
    let mut c = accept(&mut net);
    send(
        &mut c,
        &Frame::Hello {
            id: [9; 32],
            chain_id: CHAIN_ID,
        },
    );
    assert!(read_while(&mut net, &mut c, Duration::from_secs(10)).1);
    let c = accept(&mut net);
    drop(c);
    let judged = net.pump(Duration::from_secs(10), |net| {
        net.transports[me].peer_table().unwrap().entries()[&x_id].failures == 2
    });
    let entry = net.transports[me].peer_table().unwrap().entries()[&x_id].clone();
    assert!(judged, "{entry:?}");
    assert_eq!(entry.score, 10 - 50 - 5);
    // The fourth time it answers nothing and keeps the connection open: the node gives
    // up waiting for its Hello.
    let mut c = accept(&mut net);
    assert!(read_while(&mut net, &mut c, Duration::from_secs(20)).1);
    let entry = net.transports[me].peer_table().unwrap().entries()[&x_id].clone();
    assert_eq!(
        (entry.failures, entry.score),
        (3, 10 - 50 - 5 - 5),
        "{entry:?}"
    );
    // The node never kept a connection to itself, nor to the closed port.
    assert!(
        !net.transports[me]
            .connected()
            .contains(&validator_id(&keys[0]))
    );
    drop(s);
}

#[test]
fn accepted_connections_are_limited() {
    let keys = keys(1);
    let mut net = Net::new(&keys);
    let me = net.add(
        Some(&keys[0]),
        &keys[0],
        Some(Discovery {
            max_peers: 2,
            outbound: 1,
            ..Discovery::default()
        }),
    );
    let addr = net.addr(me);
    let mut first = raw(addr, [1; 32]);
    let mut second = raw(addr, [2; 32]);
    net.pump(Duration::from_millis(200), |_| false);
    let mut third = raw(addr, [3; 32]);
    assert!(read_while(&mut net, &mut third, Duration::from_secs(5)).1);
    assert!(!read_while(&mut net, &mut first, Duration::from_millis(300)).1);
    assert!(!read_while(&mut net, &mut second, Duration::from_millis(300)).1);
    assert_eq!(distinct(&net.transports[me]), 2);
}

#[test]
fn a_syncing_node_exchanges_peers_and_one_without_exchange_ignores_them() {
    use solo_node::statesync::{StateSync, SyncConfig};
    let keys = keys(1);
    let dir = solo_scratch::Scratch::new("discovery", "syncing");
    let mut sync = StateSync::new(SyncConfig {
        chain_id: CHAIN_ID,
        trust: solo_store::Trust::Genesis(Sim::validator_set(&keys)),
        genesis_hash: None,
        dir: dir.to_path_buf(),
    })
    .unwrap();
    let me = stranger(5);
    let mut syncing = Transport::bind("127.0.0.1:0", validator_id(&me), CHAIN_ID, vec![]).unwrap();
    syncing.enable_discovery(Discovery {
        key: Some(me.clone()),
        advertise: Some("127.0.0.1:4444".parse().unwrap()),
        ..Discovery::default()
    });
    let plain = Transport::bind("127.0.0.1:0", [1; 32], CHAIN_ID, vec![]).unwrap();
    let r = PeerRecord::sign(&stranger(6), CHAIN_ID, "127.0.0.1:6".parse().unwrap(), 1).unwrap();
    let mut s = raw(syncing.local_addr().unwrap(), [2; 32]);
    send(&mut s, &Frame::GetPeers);
    send(&mut s, &peers(vec![r.clone()]));
    let mut q = raw(plain.local_addr().unwrap(), [3; 32]);
    send(&mut q, &Frame::GetPeers);
    send(&mut q, &peers(vec![r.clone()]));
    let mut plain = plain;
    let mut node = Node::open(kernel_module(), &genesis(&keys), NodeConfig::default()).unwrap();
    node.start(None).unwrap();
    for i in 0..50 {
        syncing.poll_sync(&mut sync, 1_000 + i);
        plain.poll(&mut node, 1_000 + i).unwrap();
        std::thread::sleep(Duration::from_millis(2));
    }
    assert!(syncing.peer_table().unwrap().entries().contains_key(&r.id));
    assert_eq!(
        syncing.own_record().unwrap().verify(CHAIN_ID),
        Some("127.0.0.1:4444".parse().unwrap())
    );
    assert!(plain.peer_table().is_none() && plain.own_record().is_none());
    assert_eq!(plain.connected(), vec![[3; 32]]);
    // The syncing node answered with its own record and asked for the peer's.
    s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let (mut buf, mut got, mut chunk) = (Vec::new(), Vec::new(), [0u8; 4096]);
    while !got.iter().any(|f| matches!(f, Frame::Peers { .. })) {
        let n = s.read(&mut chunk).unwrap();
        buf.extend_from_slice(&chunk[..n]);
        got.extend(take_frames(&mut buf).unwrap());
    }
    let answer = got.iter().find_map(|f| match f {
        Frame::Peers { records } => Some(records.0[0].id),
        _ => None,
    });
    assert_eq!(answer, Some(validator_id(&me)));
    // Frames of peer exchange round-trip, and count under their own kinds.
    for f in [Frame::GetPeers, peers(vec![r])] {
        let mut bytes = frame_bytes(&f);
        assert_eq!(take_frames(&mut bytes).unwrap(), vec![f.clone()]);
        assert!(!f.kind().is_empty());
    }
}
