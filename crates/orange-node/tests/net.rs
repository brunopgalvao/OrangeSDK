//! The TCP transport: framing, the handshake, and real sockets carrying a
//! four-validator chain to finality, a transaction gossiped between peers,
//! and a late observer syncing over the wire. The handshake proves every
//! peer's id (spec 09 §3): an impostor naming a validator's id is dropped.

#[path = "support/raw_peer.rs"]
mod raw_peer;

use std::collections::BTreeMap;
use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::time::{Duration, Instant};

use k256::ecdsa::SigningKey;
use orange_abi::chain::{Allocation, GenesisParams};
use orange_abi::codec::Seq;
use orange_abi::types::Genesis;
use orange_abi::{Decode, Encode};
use orange_host::hash::keccak256;
use orange_node::net::{
    AUTH_LEN, Frame, HELLO_LEN, IDLE_MS, Limits, MAX_FRAME, MAX_SERVING, READ_FRAMES, SERVE_MS,
    Transport, frame_bytes, fresh_key, hello_digest, take_frames,
};
use orange_node::peers::recover_id;
use orange_node::session::{Side, TAG, VERSION};
use orange_node::{Node, NodeConfig, Sim, validator_id};
use raw_peer::{Chain, Wire};

const KERNEL: &[u8] = include_bytes!("fixtures/kernel.elf");
const CHAIN_ID: u64 = 1337;
const SLOT_MS: u64 = 100;

fn kernel_module() -> Vec<u8> {
    orange_recompile::recompile(
        &orange_recompile::Input::load(KERNEL).unwrap(),
        &orange_recompile::Options::default(),
    )
    .unwrap()
}

fn keys(n: u8) -> Vec<SigningKey> {
    (1..=n)
        .map(|i| SigningKey::from_slice(&[0x30 + i; 32]).unwrap())
        .collect()
}

fn address(key: &SigningKey) -> [u8; 20] {
    let mut out = [0u8; 20];
    out.copy_from_slice(&orange_node::validator_id(key)[12..]);
    out
}

/// A signed EIP-155 transfer.
fn transfer(key: &SigningKey, to: [u8; 20], value: u128) -> Vec<u8> {
    use orange_rlp::{encode_bytes, encode_list, encode_uint};
    let fields = |out: &mut Vec<u8>| {
        encode_uint(0, out);
        encode_uint(1, out);
        encode_uint(21_000, out);
        encode_bytes(&to, out);
        encode_uint(value, out);
        encode_bytes(&[], out);
    };
    let mut unsigned = Vec::new();
    fields(&mut unsigned);
    encode_uint(u128::from(CHAIN_ID), &mut unsigned);
    encode_uint(0, &mut unsigned);
    encode_uint(0, &mut unsigned);
    let mut list = Vec::new();
    encode_list(&unsigned, &mut list);
    let (sig, rid) = key.sign_prehash_recoverable(&keccak256(&list)).unwrap();
    let mut signed = Vec::new();
    fields(&mut signed);
    encode_uint(
        u128::from(CHAIN_ID * 2 + 35 + u64::from(rid.to_byte())),
        &mut signed,
    );
    let strip = |b: &[u8]| -> Vec<u8> {
        let skip = b.iter().take_while(|x| **x == 0).count();
        b[skip..].to_vec()
    };
    encode_bytes(&strip(&sig.r().to_bytes()), &mut signed);
    encode_bytes(&strip(&sig.s().to_bytes()), &mut signed);
    let mut out = Vec::new();
    encode_list(&signed, &mut out);
    out
}

fn genesis(keys: &[SigningKey]) -> Genesis {
    let params = GenesisParams {
        slot_ms: SLOT_MS,
        max_txs: 8,
        allocations: Seq(vec![Allocation {
            address: address(&keys[0]),
            balance: 1_000_000,
            ..Allocation::default()
        }]),
        ..GenesisParams::default()
    };
    Genesis {
        chain_id: CHAIN_ID,
        fee_schedule: vec![],
        modules: Seq(vec![]),
        params: params.to_bytes(),
        validators: Sim::validator_set(keys).to_bytes(),
    }
}

#[test]
fn framing() {
    let frames = [
        Frame::Hello {
            version: 1,
            id: [1; 32],
            chain_id: 5,
            genesis: [2; 32],
            nonce: [3; 32],
            ephemeral: [2; 33],
        },
        Frame::Auth { signature: [4; 65] },
        Frame::Message {
            topic: 1,
            payload: vec![9],
        },
        Frame::Tx { raw: vec![1, 2] },
        Frame::Request {
            request_id: 3,
            payload: vec![],
        },
        Frame::Response {
            request_id: 3,
            payload: vec![4],
        },
        Frame::SyncRequest {
            request_id: 4,
            payload: vec![5],
        },
        Frame::SyncResponse {
            request_id: 4,
            payload: vec![6],
        },
    ];
    let mut buf = Vec::new();
    for f in &frames {
        buf.extend(frame_bytes(f));
    }
    // A partial trailing frame stays buffered.
    let partial = frame_bytes(&Frame::Tx { raw: vec![5; 10] });
    buf.extend_from_slice(&partial[..7]);
    assert_eq!(take_frames(&mut buf).unwrap(), frames.to_vec());
    assert_eq!(buf, partial[..7].to_vec());
    buf.extend_from_slice(&partial[7..]);
    assert_eq!(
        take_frames(&mut buf).unwrap(),
        vec![Frame::Tx { raw: vec![5; 10] }]
    );
    assert!(buf.is_empty());
    // Oversized and undecodable frames poison the stream.
    let mut big = u32::try_from(MAX_FRAME + 1).unwrap().to_le_bytes().to_vec();
    assert!(take_frames(&mut big).unwrap_err().contains("exceeds"));
    let mut bad = vec![1, 0, 0, 0, 9];
    assert_eq!(take_frames(&mut bad).unwrap_err(), "undecodable frame");
    assert!(format!("{:?}", frames[0]).contains("Hello"));
    // A Hello is exactly as long as the longest frame accepted before the session.
    assert_eq!(frame_bytes(&frames[0]).len(), 4 + HELLO_LEN);
}

/// Polls every live node and its transport until `done` or the deadline. Deadlines are
/// generous because every node shares this one thread and the machine may be loaded;
/// the callers assert `done`, so reaching a deadline fails the test.
fn pump(
    nodes: &mut [Node],
    transports: &mut [Transport],
    start: Instant,
    epoch: u64,
    max: Duration,
    done: impl FnMut(&mut [Node], &[Transport]) -> bool,
) -> bool {
    pump_throttled(nodes, transports, (start, epoch), max, None, done)
}

/// [`pump`] with the transport of node `slow.0` polled only every
/// `slow.1`: a loaded peer, whose answers and blocks leave in bursts.
fn pump_throttled(
    nodes: &mut [Node],
    transports: &mut [Transport],
    (start, epoch): (Instant, u64),
    max: Duration,
    slow: Option<(usize, Duration)>,
    mut done: impl FnMut(&mut [Node], &[Transport]) -> bool,
) -> bool {
    let deadline = Instant::now() + max;
    let mut polled = Instant::now();
    while Instant::now() < deadline {
        if done(nodes, transports) {
            return true;
        }
        let now = epoch + u64::try_from(start.elapsed().as_millis()).unwrap();
        let burst = slow.is_none_or(|(_, every)| polled.elapsed() >= every);
        if burst {
            polled = Instant::now();
        }
        for (i, (node, transport)) in nodes.iter_mut().zip(transports.iter_mut()).enumerate() {
            node.tick(now).unwrap();
            if burst || slow.is_some_and(|(s, _)| s != i) {
                transport.poll(node, now).unwrap();
            }
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    done(nodes, transports)
}

#[test]
fn validators_finalize_over_tcp_and_a_late_observer_syncs() {
    let keys = keys(4);
    let kernel = kernel_module();
    let genesis = genesis(&keys);
    let start = Instant::now();
    let epoch = 1_000_000;
    let mut nodes = Vec::new();
    let mut transports: Vec<Transport> = Vec::new();
    for key in &keys {
        let mut node = Node::open(
            &kernel,
            &genesis,
            NodeConfig {
                now_ms: epoch,
                key: Some(key.clone()),
                ..NodeConfig::default()
            },
        )
        .unwrap();
        node.start(None).unwrap();
        // Each node dials every earlier one, so every pair has one connection.
        let peers = transports.iter().map(|t| t.local_addr().unwrap()).collect();
        let genesis = node.genesis_hash();
        transports
            .push(Transport::bind("127.0.0.1:0", key.clone(), CHAIN_ID, genesis, peers).unwrap());
        nodes.push(node);
    }
    // Gossip reaches connected peers only, so let every pair connect first.
    let connected = pump(
        &mut nodes,
        &mut transports,
        start,
        epoch,
        Duration::from_mins(2),
        |_, transports| transports.iter().all(|t| t.connected().len() == 3),
    );
    assert!(connected);
    // A transaction submitted to the last node travels by gossip and lands everywhere.
    let to = address(&keys[1]);
    let tx_hash = nodes[3].submit(&transfer(&keys[0], to, 5)).unwrap();
    let finalized = pump(
        &mut nodes,
        &mut transports,
        start,
        epoch,
        Duration::from_mins(5),
        |nodes, _| nodes.iter().all(|n| n.finalized.len() >= 20),
    );
    assert!(
        finalized,
        "{:?} in views {:?}",
        nodes.iter().map(|n| n.finalized.len()).collect::<Vec<_>>(),
        nodes
            .iter()
            .map(|n| n.simplex_state().unwrap().view)
            .collect::<Vec<_>>()
    );
    for node in &mut nodes {
        assert!(node.receipt(&tx_hash).unwrap().is_some());
        assert_eq!(node.account(&to).unwrap().balance, 5);
    }
    for t in &transports {
        assert_eq!(t.connected().len(), 3);
    }
    let reference = nodes[0].executed[..20].to_vec();
    for node in &nodes {
        assert_eq!(&node.executed[..20], reference.as_slice());
    }
    // An observer joins late, dialling one validator, and syncs over the wire.
    let now = epoch + u64::try_from(start.elapsed().as_millis()).unwrap();
    let mut observer = Node::open(
        &kernel,
        &genesis,
        NodeConfig {
            now_ms: now,
            ..NodeConfig::default()
        },
    )
    .unwrap();
    observer.start(None).unwrap();
    let genesis = observer.genesis_hash();
    nodes.push(observer);
    // The observer has no consensus key and proves an id of its own.
    let dial = vec![transports[0].local_addr().unwrap()];
    let own = fresh_key().unwrap();
    transports.push(Transport::bind("127.0.0.1:0", own.clone(), CHAIN_ID, genesis, dial).unwrap());
    assert_eq!(transports[4].id(), validator_id(&own));
    let synced = pump(
        &mut nodes,
        &mut transports,
        start,
        epoch,
        Duration::from_mins(3),
        |nodes, _| {
            let head = nodes[0].finalized.len();
            nodes[4].finalized.len() + 2 >= head && head > 20
        },
    );
    assert!(
        synced,
        "{:?}",
        nodes.iter().map(|n| n.finalized.len()).collect::<Vec<_>>()
    );
    let n = nodes[4].executed.len();
    assert_eq!(nodes[4].executed[..], nodes[0].executed[..n]);
}

/// One validator at 60 ms slots, loaded so that its transport runs only
/// every 250 ms, and an observer that joins 60 blocks late, over real
/// sockets on one thread. Each burst from the validator brings the
/// observer blocks that move it into later views before the answer to its
/// sync request, which its driver has abandoned by then (spec 08 §3); the
/// host keeps the request (spec 09 §6a) and hands the answer to the next.
#[test]
fn an_observer_catches_up_with_a_loaded_60_ms_chain_over_tcp() {
    let (observer, validator) = late_observer(true, Duration::from_mins(3));
    assert!(observer + 2 >= validator, "{observer} of {validator}");
}

/// Runs [`an_observer_catches_up_with_a_loaded_60_ms_chain_over_tcp`] with
/// the host's catch-up on or off for at most `max` after the observer
/// joins; the blocks the observer and the validator finalized.
fn late_observer(catch_up: bool, max: Duration) -> (usize, usize) {
    let keys = keys(1);
    let kernel = kernel_module();
    let mut genesis = genesis(&keys);
    let mut params = GenesisParams::from_bytes(&genesis.params).unwrap();
    params.slot_ms = 60;
    genesis.params = params.to_bytes();
    let start = Instant::now();
    let epoch = 1_000_000;
    let config = |now_ms, key| NodeConfig {
        now_ms,
        key,
        background: true,
        ..NodeConfig::default()
    };
    let validator = Node::open(&kernel, &genesis, config(epoch, Some(keys[0].clone()))).unwrap();
    let hash = validator.genesis_hash();
    let bind = |key: &SigningKey, dial| {
        Transport::bind("127.0.0.1:0", key.clone(), CHAIN_ID, hash, dial).unwrap()
    };
    let mut transports = vec![bind(&keys[0], vec![])];
    let mut nodes = vec![validator];
    nodes[0].start(None).unwrap();
    let ahead = pump(
        &mut nodes,
        &mut transports,
        start,
        epoch,
        Duration::from_mins(3),
        |nodes, _| nodes[0].finalized.len() >= 60,
    );
    assert!(ahead);
    let now = epoch + u64::try_from(start.elapsed().as_millis()).unwrap();
    let mut observer = Node::open(&kernel, &genesis, config(now, None)).unwrap();
    observer.set_catch_up(catch_up);
    observer.start(None).unwrap();
    nodes.push(observer);
    let dial = vec![transports[0].local_addr().unwrap()];
    transports.push(bind(&fresh_key().unwrap(), dial));
    let caught = pump_throttled(
        &mut nodes,
        &mut transports,
        (start, epoch),
        max,
        Some((0, Duration::from_millis(250))),
        |nodes, _| nodes[1].finalized.len() + 2 >= nodes[0].finalized.len(),
    );
    if caught {
        let n = nodes[1].executed.len();
        assert_eq!(nodes[1].executed[..], nodes[0].executed[..n]);
    }
    (nodes[1].finalized.len(), nodes[0].finalized.len())
}

#[test]
#[ignore = "shows the loop of a node without the host's catch-up; timing-dependent"]
fn without_the_hosts_catch_up_a_loaded_chain_is_never_caught() {
    let (observer, validator) = late_observer(false, Duration::from_secs(20));
    eprintln!("observer {observer} of {validator}");
    assert_eq!(observer, 0);
}

/// How an impostor answers the transport's `Hello`: its own side and the
/// transport's.
type Proof<'a> = dyn Fn(&Side, &Side) -> Frame + 'a;

fn peer_key(i: u8) -> SigningKey {
    SigningKey::from_slice(&[0x70 + i; 32]).unwrap()
}

/// Polls `t` a few times at `now_ms`, with pauses for the sockets.
fn poll_n(t: &mut Transport, n: &mut Node, now_ms: u64) {
    for _ in 0..5 {
        t.poll(n, now_ms).unwrap();
        std::thread::sleep(Duration::from_millis(2));
    }
}

/// A started one-validator node and its chain.
fn one_node() -> (Node, Chain) {
    let keys = keys(1);
    let mut node = Node::open(&kernel_module(), &genesis(&keys), NodeConfig::default()).unwrap();
    node.start(None).unwrap();
    let chain = Chain {
        chain_id: CHAIN_ID,
        genesis: node.genesis_hash(),
    };
    (node, chain)
}

#[test]
#[allow(clippy::too_many_lines)]
fn handshake_rules() {
    let keys = keys(1);
    let (mut node, chain) = one_node();
    assert_ne!(chain.genesis, [0; 32], "the kernel stores a genesis block");
    let me = peer_key(1);
    let mut transport =
        Transport::bind("127.0.0.1:0", me.clone(), CHAIN_ID, chain.genesis, vec![]).unwrap();
    assert_eq!(transport.id(), validator_id(&me));
    let addr = transport.local_addr().unwrap();
    let speak = |frames: &[Frame], raw: &[u8]| {
        let mut s = TcpStream::connect(addr).unwrap();
        for f in frames {
            s.write_all(&frame_bytes(f)).unwrap();
        }
        s.write_all(raw).unwrap();
        s
    };
    let good_key = peer_key(2);
    let good_id = validator_id(&good_key);
    let hello = chain.hello(good_id, [2; 32]);
    let poll = |t: &mut Transport, n: &mut Node| {
        for _ in 0..20 {
            t.poll(n, 0).unwrap();
            std::thread::sleep(Duration::from_millis(2));
        }
    };
    // Wrong chain, wrong genesis, a message before hello, a second hello or a message in
    // place of the proof (neither sealed), a proof before hello, garbage: all dropped.
    let other_chain = Chain {
        chain_id: 1,
        ..chain
    };
    let other_genesis = Chain {
        genesis: [9; 32],
        ..chain
    };
    let _a = speak(&[other_chain.hello(good_id, [3; 32])], &[]);
    let _g = speak(&[other_genesis.hello(good_id, [3; 32])], &[]);
    let _b = speak(&[Frame::Tx { raw: vec![] }], &[]);
    let _c = speak(&[hello.clone(), hello.clone()], &[]);
    let _e = speak(&[hello.clone(), Frame::Tx { raw: vec![] }], &[]);
    let _f = speak(&[Frame::Auth { signature: [0; 65] }], &[]);
    let _d = speak(&[], &[1, 0, 0, 0, 0xFF]);
    poll(&mut transport, &mut node);
    assert!(
        transport.connected().is_empty(),
        "{:?}",
        transport.connected()
    );
    // Impostors name the validator's id. Each reads the transport's own proof, which
    // recovers to the transport's id over both Hellos, and answers, sealed, with a proof
    // that is not the validator's for this connection: signed by another key, by the
    // validator for another connection, another chain or another genesis, with the sides
    // swapped, over another fresh key than the one its Hello carried (a party in the
    // middle that put its own key in the Hello), or not a signature at all. Each is
    // dropped and never connected.
    let validator = validator_id(&keys[0]);
    let mine = [5; 32];
    let stranger = raw_peer::ephemeral(&[6; 32]).public();
    let attempts: Vec<Box<Proof>> = vec![
        Box::new(|m, t| chain.auth(&peer_key(3), m, t)),
        Box::new(|m, t| {
            let elsewhere = Side {
                nonce: [6; 32],
                ..*t
            };
            chain.auth(&keys[0], m, &elsewhere)
        }),
        Box::new(|m, t| other_chain.auth(&keys[0], m, t)),
        Box::new(|m, t| other_genesis.auth(&keys[0], m, t)),
        Box::new(|m, t| chain.auth(&keys[0], t, m)),
        Box::new(|m, t| {
            let swapped = Side {
                ephemeral: stranger,
                ..*m
            };
            chain.auth(&keys[0], &swapped, t)
        }),
        Box::new(|_, _| Frame::Auth {
            signature: [0xFF; 65],
        }),
    ];
    for (i, attempt) in attempts.iter().enumerate() {
        let mut w = Wire::dial(addr, chain, mine);
        w.send_clear(&w.hello(validator));
        let (frames, _) = w.read_until(&mut || poll_n(&mut transport, &mut node, 0), |f| {
            f.iter().any(|f| matches!(f, Frame::Auth { .. }))
        });
        let theirs = w.theirs.unwrap();
        let proof = frames.iter().find_map(|f| match f {
            Frame::Auth { signature } => Some(*signature),
            _ => None,
        });
        let digest = hello_digest(CHAIN_ID, &chain.genesis, &theirs, &w.side);
        assert_eq!(recover_id(&digest, &proof.unwrap()), Some(transport.id()));
        let proof = attempt(&w.side, &theirs);
        w.send(&proof);
        assert!(
            w.closes(&mut || poll_n(&mut transport, &mut node, 0)),
            "impostor {i} was not dropped"
        );
        assert!(transport.connected().is_empty(), "impostor {i}");
    }
    // The validator itself, with the same nonce, gets in; so does a peer that proves a key
    // of its own.
    let (mut real, _) = raw_peer::connect(addr, &keys[0], chain, &mut || {
        poll_n(&mut transport, &mut node, 0);
    });
    assert!(connected_as(&mut transport, &mut node, &[validator]));
    // A proof after the handshake closes the connection.
    real.send(&real.auth(&keys[0]));
    assert!(real.closes(&mut || poll_n(&mut transport, &mut node, 0)));
    // A good peer stays; its requests are served and unknown responses ignored.
    let (mut good, _) = raw_peer::connect(addr, &good_key, chain, &mut || {
        poll_n(&mut transport, &mut node, 0);
    });
    for f in [
        Frame::Tx { raw: vec![1] },
        Frame::Message {
            topic: 7,
            payload: vec![],
        },
        Frame::Request {
            request_id: 9,
            payload: orange_abi::chain::SyncRequest { from_height: 1 }.to_bytes(),
        },
        Frame::Response {
            request_id: 4,
            payload: vec![],
        },
    ] {
        good.send(&f);
    }
    // The request is answered before the effects below are applied, so that the order
    // the peer sees does not depend on how fast the transport reads.
    let answered = |f: &Frame| matches!(f, Frame::Response { request_id: 9, .. });
    let (got, closed) = good.read_until(&mut || poll_n(&mut transport, &mut node, 0), |f| {
        f.iter().any(answered)
    });
    assert!(got.iter().any(answered) && !closed, "{got:?}");
    assert_eq!(transport.connected(), vec![good_id]);
    // Point-to-point sends reach the named peer; blobs and scores are not transported.
    for effect in [
        orange_abi::types::Effect::Send {
            peer: good_id,
            topic: 5,
            payload: vec![8],
        },
        orange_abi::types::Effect::Disseminate {
            blob_id: [0; 32],
            payload: vec![],
        },
        orange_abi::types::Effect::PeerScore {
            peer: good_id,
            delta: 1,
        },
    ] {
        node.apply_effect(effect).unwrap();
    }
    let message = Frame::Message {
        topic: 5,
        payload: vec![8],
    };
    let (got, closed) = good.read_until(&mut || poll_n(&mut transport, &mut node, 0), |f| {
        f.contains(&message)
    });
    assert!(got.contains(&message) && !closed, "{got:?}");
    // A peer that says Hello and never proves it is dropped once HANDSHAKE_MS has passed.
    let mut silent = Wire::dial(addr, chain, [4; 32]);
    silent.send_clear(&silent.hello(validator_id(&peer_key(4))));
    poll(&mut transport, &mut node);
    assert!(connected_as(&mut transport, &mut node, &[good_id]));
    assert!(silent.closes(&mut || {
        poll_n(&mut transport, &mut node, orange_node::net::HANDSHAKE_MS);
    }));
    // A closed peer is forgotten; a dial target that is down is retried without error.
    drop(good);
    assert!(connected_as(&mut transport, &mut node, &[]));
    let unused = TcpListener::bind("127.0.0.1:0").unwrap();
    let down = unused.local_addr().unwrap();
    drop(unused);
    let mut dialer = Transport::bind(
        "127.0.0.1:0",
        peer_key(5),
        CHAIN_ID,
        chain.genesis,
        vec![down],
    )
    .unwrap();
    dialer.poll(&mut node, 0).unwrap();
    dialer.poll(&mut node, 1).unwrap();
    assert!(dialer.connected().is_empty());
    assert!(Transport::bind("nope", peer_key(6), 1, [0; 32], vec![]).is_err());
}

/// Every frame after the `Hello`s is sealed (spec 09 §3a): what goes over the wire does
/// not show the frames it carries, and a frame that is altered, replayed, reordered,
/// sent in the clear or of a length no sealed frame has closes the connection, before
/// or after the handshake.
#[test]
#[allow(clippy::too_many_lines)]
fn frames_after_the_hellos_are_sealed() {
    let (mut node, chain) = one_node();
    let mut transport =
        Transport::bind("127.0.0.1:0", peer_key(1), CHAIN_ID, chain.genesis, vec![]).unwrap();
    let addr = transport.local_addr().unwrap();
    let key = peer_key(2);
    let id = validator_id(&key);
    let mut poll = || poll_n(&mut transport, &mut node, 0);
    // A passive observer sees the Hellos and the lengths, not what the frames carry.
    let (mut observer, _) = raw_peer::connect(addr, &key, chain, &mut poll);
    let secret = vec![0xA5; 64];
    let message = Frame::Message {
        topic: 3,
        payload: secret.clone(),
    };
    assert!(connected_as(&mut transport, &mut node, &[id]));
    node.apply_effect(orange_abi::types::Effect::Send {
        peer: id,
        topic: 3,
        payload: secret.clone(),
    })
    .unwrap();
    let mut poll = || poll_n(&mut transport, &mut node, 0);
    let (got, closed) = observer.read_until(&mut poll, |f| f.contains(&message));
    assert!(got.contains(&message) && !closed, "{got:?}");
    let seen = &observer.seen;
    assert!(!seen.windows(secret.len()).any(|x| x == secret));
    assert!(seen.len() >= HELLO_LEN + secret.len() + TAG);
    drop(observer);
    // Altered: a byte of the body, of the tag, or of the length, one less.
    let tx = Frame::Tx { raw: vec![1] };
    for at in [6, 0, usize::MAX] {
        let (mut w, _) = raw_peer::connect(addr, &key, chain, &mut poll);
        let mut sealed = w.seal(&tx);
        let at = at.min(sealed.len() - 1);
        sealed[at] = sealed[at].wrapping_sub(1);
        w.write(&sealed);
        assert!(w.closes(&mut poll), "a frame altered at {at} was taken");
    }
    // Replayed: the same sealed frame twice. The first is taken, the second closes.
    let (mut w, _) = raw_peer::connect(addr, &key, chain, &mut poll);
    let sealed = w.seal(&tx);
    w.write(&sealed);
    let (_, closed) = w.read_for(Duration::from_millis(100), &mut poll, |_| false);
    assert!(!closed);
    w.write(&sealed);
    assert!(w.closes(&mut poll));
    // Reordered: the second frame sealed sent first.
    let (mut w, _) = raw_peer::connect(addr, &key, chain, &mut poll);
    let first = w.seal(&tx);
    let second = w.seal(&Frame::Tx { raw: vec![2] });
    w.write(&second);
    w.write(&first);
    assert!(w.closes(&mut poll));
    // Dropped from the middle: the third frame sent after the first.
    let (mut w, _) = raw_peer::connect(addr, &key, chain, &mut poll);
    let first = w.seal(&tx);
    let _skipped = w.seal(&tx);
    let third = w.seal(&tx);
    w.write(&first);
    w.write(&third);
    assert!(w.closes(&mut poll));
    // In the clear after the handshake.
    let (mut w, _) = raw_peer::connect(addr, &key, chain, &mut poll);
    w.send_clear(&Frame::Tx { raw: vec![0; 40] });
    assert!(w.closes(&mut poll));
    // A peer that skips encryption altogether, its proof in the clear, never gets in.
    let mut w = Wire::dial(addr, chain, [8; 32]);
    w.send_clear(&w.hello(id));
    let (_, closed) = w.read_until(&mut poll, |f| f.len() >= 2);
    assert!(!closed);
    w.send_clear(&w.auth(&key));
    assert!(w.closes(&mut poll));
    assert!(connected_as(&mut transport, &mut node, &[]));
    let mut poll = || poll_n(&mut transport, &mut node, 0);
    // A sealed frame's length is at least the tag's and at most `MAX_FRAME` past it.
    for len in [0, TAG - 1, MAX_FRAME + TAG + 1] {
        let (mut w, _) = raw_peer::connect(addr, &key, chain, &mut poll);
        w.write(&u32::try_from(len).unwrap().to_le_bytes());
        assert!(w.closes(&mut poll), "a sealed length of {len} was taken");
    }
    // Before the session: a frame longer than a Hello, a Hello of another version, one
    // in the layout of version 0, one whose fresh key is not a point, and the
    // transport's own Hello sent back to it.
    let mut w = Wire::dial(addr, chain, [9; 32]);
    w.write(&u32::try_from(HELLO_LEN + 1).unwrap().to_le_bytes());
    assert!(w.closes(&mut poll));
    let hello = |version, ephemeral| Frame::Hello {
        version,
        id,
        chain_id: CHAIN_ID,
        genesis: chain.genesis,
        nonce: [9; 32],
        ephemeral,
    };
    let point = raw_peer::ephemeral(&[9; 32]).public();
    for bad in [
        hello(VERSION + 1, point),
        hello(0, point),
        hello(VERSION, [0; 33]),
    ] {
        let mut w = Wire::dial(addr, chain, [9; 32]);
        w.send_clear(&bad);
        assert!(w.closes(&mut poll), "{bad:?}");
    }
    let mut old = vec![0];
    old.extend_from_slice(&id);
    old.extend_from_slice(&CHAIN_ID.to_le_bytes());
    old.extend_from_slice(&chain.genesis);
    old.extend_from_slice(&[9; 32]);
    let mut w = Wire::dial(addr, chain, [9; 32]);
    w.write(&u32::try_from(old.len()).unwrap().to_le_bytes());
    w.write(&old);
    assert!(w.closes(&mut poll));
    let mut w = Wire::dial(addr, chain, [9; 32]);
    let (got, _) = w.read_until(&mut poll, |f| !f.is_empty());
    w.send_clear(&got[0]);
    assert!(w.closes(&mut poll));
    assert!(connected_as(&mut transport, &mut node, &[]));
}

/// Polls `t` until its handshaken peers are `want`: whether they got there.
/// Two validators that both dial each other hold two connections and are
/// one peer to each other: the peer count counts peers, not connections.
#[test]
fn a_peer_connected_twice_counts_once() {
    let keys = keys(2);
    let kernel = kernel_module();
    let genesis = genesis(&keys);
    let mut nodes: Vec<Node> = keys
        .iter()
        .map(|key| {
            let mut node = Node::open(
                &kernel,
                &genesis,
                NodeConfig {
                    key: Some(key.clone()),
                    ..NodeConfig::default()
                },
            )
            .unwrap();
            node.start(None).unwrap();
            node
        })
        .collect();
    let listeners: Vec<std::net::TcpListener> = (0..2)
        .map(|_| std::net::TcpListener::bind("127.0.0.1:0").unwrap())
        .collect();
    let addrs: Vec<String> = listeners
        .iter()
        .map(|l| l.local_addr().unwrap().to_string())
        .collect();
    drop(listeners);
    let mut transports: Vec<Transport> = (0..2)
        .map(|i| {
            let other = addrs[1 - i].parse().unwrap();
            let genesis = nodes[i].genesis_hash();
            Transport::bind(&addrs[i], keys[i].clone(), CHAIN_ID, genesis, vec![other]).unwrap()
        })
        .collect();
    let mut both = false;
    for _ in 0..500 {
        for (t, n) in transports.iter_mut().zip(nodes.iter_mut()) {
            t.poll(n, 0).unwrap();
        }
        if transports.iter().all(|t| t.connected().len() == 2) {
            both = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    assert!(
        both,
        "{:?}",
        transports
            .iter()
            .map(|t| t.connected().len())
            .collect::<Vec<_>>()
    );
    for n in &mut nodes {
        assert_eq!(n.status().unwrap().peers, 1);
    }
}

fn connected_as(t: &mut Transport, n: &mut Node, want: &[[u8; 32]]) -> bool {
    for _ in 0..200 {
        if t.connected() == want {
            return true;
        }
        poll_n(t, n, 0);
    }
    t.connected() == want
}

#[test]
#[allow(clippy::too_many_lines)]
fn state_sync_frames_are_the_hosts() {
    use orange_abi::Decode;
    use orange_node::statesync::{StateSync, SyncConfig, SyncRequest, SyncResponse};
    let offers = SyncRequest::Offers.to_bytes();
    let nothing = SyncResponse::Offers(vec![]).to_bytes();
    let peer = peer_key(2);
    // A running node answers a sync request from what it serves (nothing
    // here) and ignores a sync answer.
    let keys = keys(1);
    let genesis = genesis(&keys);
    let mut node = Node::open(&kernel_module(), &genesis, NodeConfig::default()).unwrap();
    node.start(None).unwrap();
    let chain = Chain {
        chain_id: CHAIN_ID,
        genesis: node.genesis_hash(),
    };
    let mut running =
        Transport::bind("127.0.0.1:0", peer_key(1), CHAIN_ID, chain.genesis, vec![]).unwrap();
    let (mut s, _) = raw_peer::connect(running.local_addr().unwrap(), &peer, chain, &mut || {
        poll_n(&mut running, &mut node, 0);
    });
    s.send(&Frame::SyncResponse {
        request_id: 1,
        payload: vec![],
    });
    s.send(&Frame::SyncRequest {
        request_id: 5,
        payload: offers.clone(),
    });
    let answer = Frame::SyncResponse {
        request_id: 5,
        payload: nothing.clone(),
    };
    let (got, _) = s.read_until(&mut || poll_n(&mut running, &mut node, 0), |f| {
        f.contains(&answer)
    });
    assert!(got.contains(&answer), "{got:?}");
    // A node that syncs drops what is not state sync, closes a peer of
    // another chain or one that says hello twice, answers a sync request as
    // a node that serves nothing, and asks its peers for their offers.
    let dir = orange_scratch::Scratch::new("net", "syncing");
    let mut sync = StateSync::new(SyncConfig {
        chain_id: CHAIN_ID,
        trust: orange_store::Trust::Genesis(Sim::validator_set(&keys)),
        genesis_hash: None,
        dir: dir.to_path_buf(),
    })
    .unwrap();
    let mut syncing =
        Transport::bind("127.0.0.1:0", peer_key(1), CHAIN_ID, chain.genesis, vec![]).unwrap();
    let addr = syncing.local_addr().unwrap();
    let speak = |frames: &[Frame]| {
        let mut s = TcpStream::connect(addr).unwrap();
        for f in frames {
            s.write_all(&frame_bytes(f)).unwrap();
        }
        s
    };
    let hello = chain.hello(validator_id(&peer), [2; 32]);
    let other = Chain {
        chain_id: 1,
        ..chain
    };
    let _other = speak(&[other.hello(validator_id(&peer), [3; 32])]);
    let _twice = speak(&[hello.clone(), hello]);
    let mut clock = 0;
    let mut poll_sync = |t: &mut Transport, sync: &mut StateSync| {
        for _ in 0..5 {
            clock += 1;
            t.poll_sync(sync, clock);
            std::thread::sleep(Duration::from_millis(2));
        }
    };
    let (mut good, _) = raw_peer::connect(addr, &peer, chain, &mut || {
        poll_sync(&mut syncing, &mut sync);
    });
    good.send(&Frame::Message {
        topic: 1,
        payload: vec![],
    });
    good.send(&Frame::SyncRequest {
        request_id: 6,
        payload: offers,
    });
    let unserved = Frame::SyncResponse {
        request_id: 6,
        payload: nothing,
    };
    let asked = |f: &Frame| match f {
        Frame::SyncRequest {
            request_id,
            payload,
        } => Some((*request_id, SyncRequest::from_bytes(payload).unwrap())),
        _ => None,
    };
    let (got, _) = good.read_until(&mut || poll_sync(&mut syncing, &mut sync), |f| {
        f.contains(&unserved) && f.iter().any(|f| asked(f).is_some())
    });
    assert_eq!(syncing.connected(), vec![validator_id(&peer)]);
    assert!(got.contains(&unserved), "{got:?}");
    let (id, request) = got.iter().find_map(asked).unwrap();
    assert_eq!(request, SyncRequest::Offers);
    // Its answer reaches the sync.
    good.send(&Frame::SyncResponse {
        request_id: id,
        payload: SyncResponse::Offers(vec![]).to_bytes(),
    });
    for _ in 0..4 {
        poll_sync(&mut syncing, &mut sync);
    }
    assert!(sync.failed().is_none());
}

/// A state sync gives up instead of waiting for ever (spec 09 §6): at once
/// when the only peers are of another genesis, after `SYNC_PEER_WAIT_MS`
/// when no peer completes a handshake, and never while a peer is handshaken.
#[test]
fn a_state_sync_without_peers_gives_up() {
    use orange_node::net::SYNC_PEER_WAIT_MS;
    use orange_node::statesync::{StateSync, SyncConfig};
    let keys = keys(1);
    let dir = orange_scratch::Scratch::new("net", "stalled");
    let mut sync = StateSync::new(SyncConfig {
        chain_id: CHAIN_ID,
        trust: orange_store::Trust::Genesis(Sim::validator_set(&keys)),
        genesis_hash: None,
        dir: dir.to_path_buf(),
    })
    .unwrap();
    let chain = Chain {
        chain_id: CHAIN_ID,
        genesis: [7; 32],
    };
    let bind =
        || Transport::bind("127.0.0.1:0", peer_key(1), CHAIN_ID, chain.genesis, vec![]).unwrap();
    // Nobody answers: not stalled before the wait, stalled after it.
    let mut lonely = bind();
    assert_eq!(lonely.sync_stalled(0), None, "not polled yet");
    lonely.poll_sync(&mut sync, 1_000);
    assert_eq!(lonely.sync_stalled(1_000 + SYNC_PEER_WAIT_MS - 1), None);
    lonely.poll_sync(&mut sync, 2_000);
    assert_eq!(
        lonely.sync_stalled(1_000 + SYNC_PEER_WAIT_MS),
        Some("no peer to sync from in time")
    );
    // A handshaken peer keeps it going, however long; once it leaves, the wait starts again.
    let mut served = bind();
    let addr = served.local_addr().unwrap();
    let mut clock = 0;
    let (peer, _) = raw_peer::connect(addr, &peer_key(2), chain, &mut || {
        clock += 1;
        served.poll_sync(&mut sync, clock);
    });
    let deadline = Instant::now() + Duration::from_secs(10);
    while served.connected().is_empty() && Instant::now() < deadline {
        clock += 1;
        served.poll_sync(&mut sync, clock);
        std::thread::sleep(Duration::from_millis(2));
    }
    assert_eq!(served.connected().len(), 1);
    assert_eq!(served.sync_stalled(clock + 10 * SYNC_PEER_WAIT_MS), None);
    drop(peer);
    let left = loop {
        clock += 1;
        served.poll_sync(&mut sync, clock);
        if served.connected().is_empty() {
            break clock;
        }
        std::thread::sleep(Duration::from_millis(2));
    };
    assert_eq!(served.sync_stalled(left + SYNC_PEER_WAIT_MS - 1), None);
    assert!(served.sync_stalled(left + SYNC_PEER_WAIT_MS).is_some());
    // A peer of this chain id on another genesis: stalled at once.
    let mut foreign = bind();
    let mut s = Wire::dial(foreign.local_addr().unwrap(), chain, [3; 32]);
    let elsewhere = Chain {
        genesis: [8; 32],
        ..chain
    };
    s.send(&elsewhere.hello(validator_id(&peer_key(3)), [3; 32]));
    let (_, closed) = s.read_until(&mut || foreign.poll_sync(&mut sync, 5), |_| false);
    assert!(closed);
    assert_eq!(
        foreign.sync_stalled(5),
        Some("a peer is on a chain with another genesis block")
    );
}

/// A handshaken peer the sync no longer asks keeps it going no longer than
/// none (spec 09 §6): the connection stays open, and the wait starts.
#[test]
fn a_state_sync_whose_peers_are_dropped_gives_up() {
    use orange_node::net::SYNC_PEER_WAIT_MS;
    use orange_node::statesync::{StateSync, SyncConfig};
    let keys = keys(1);
    let dir = orange_scratch::Scratch::new("net", "dropped");
    let mut sync = StateSync::new(SyncConfig {
        chain_id: CHAIN_ID,
        trust: orange_store::Trust::Genesis(Sim::validator_set(&keys)),
        genesis_hash: None,
        dir: dir.to_path_buf(),
    })
    .unwrap();
    let chain = Chain {
        chain_id: CHAIN_ID,
        genesis: [7; 32],
    };
    let mut garbled =
        Transport::bind("127.0.0.1:0", peer_key(1), CHAIN_ID, chain.genesis, vec![]).unwrap();
    let mut clock = 0;
    let addr = garbled.local_addr().unwrap();
    let (mut peer, _) = raw_peer::connect(addr, &peer_key(4), chain, &mut || {
        clock += 1;
        garbled.poll_sync(&mut sync, clock);
    });
    let (got, _) = peer.read_until(
        &mut || {
            clock += 1;
            garbled.poll_sync(&mut sync, clock);
        },
        |f| f.iter().any(|f| matches!(f, Frame::SyncRequest { .. })),
    );
    let request_id = got
        .iter()
        .find_map(|f| match f {
            Frame::SyncRequest { request_id, .. } => Some(*request_id),
            _ => None,
        })
        .unwrap();
    assert_eq!(garbled.sync_stalled(clock + 10 * SYNC_PEER_WAIT_MS), None);
    peer.send(&Frame::SyncResponse {
        request_id,
        payload: vec![0xff],
    });
    let dropped = loop {
        clock += 1;
        garbled.poll_sync(&mut sync, clock);
        if sync.drops(&validator_id(&peer_key(4))) {
            break clock;
        }
        std::thread::sleep(Duration::from_millis(2));
    };
    assert_eq!(garbled.connected().len(), 1, "the connection stays open");
    assert_eq!(garbled.sync_stalled(dropped + SYNC_PEER_WAIT_MS - 1), None);
    assert_eq!(
        garbled.sync_stalled(dropped + SYNC_PEER_WAIT_MS),
        Some("no peer to sync from in time")
    );
    // A second Hello after the handshake closes the connection.
    peer.send(&chain.hello(validator_id(&peer_key(4)), [9; 32]));
    loop {
        clock += 1;
        garbled.poll_sync(&mut sync, clock);
        if garbled.connected().is_empty() {
            break;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}

#[test]
fn a_hello_of_another_genesis_is_heard_though_its_peer_closes_at_once() {
    use orange_node::statesync::{StateSync, SyncConfig};
    let keys = keys(1);
    let dir = orange_scratch::Scratch::new("net", "foreign");
    let mut sync = StateSync::new(SyncConfig {
        chain_id: CHAIN_ID,
        trust: orange_store::Trust::Genesis(Sim::validator_set(&keys)),
        genesis_hash: None,
        dir: dir.to_path_buf(),
    })
    .unwrap();
    let mut transport =
        Transport::bind("127.0.0.1:0", peer_key(1), CHAIN_ID, [7; 32], vec![]).unwrap();
    let elsewhere = Chain {
        chain_id: CHAIN_ID,
        genesis: [8; 32],
    };
    // The Hello and the close arrive together, as from a node that refuses
    // this one's genesis as soon as it reads it.
    let mut peer = raw_peer::Wire::dial(transport.local_addr().unwrap(), elsewhere, [3; 32]);
    peer.send_clear(&peer.hello(validator_id(&peer_key(4))));
    drop(peer);
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    let mut clock = 0;
    let why = loop {
        clock += 1;
        transport.poll_sync(&mut sync, clock);
        if let Some(why) = transport.sync_stalled(clock) {
            break why;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the Hello was not heard"
        );
        std::thread::sleep(Duration::from_millis(2));
    };
    assert_eq!(why, "a peer is on a chain with another genesis block");
}

/// A transaction a node accepted while it had no peer reaches the peers it
/// connects to later (spec 09 §4): sent when it became pending, it went to
/// nobody, and an observer, which never proposes, would hold it for ever.
/// Found by the soak test (`crates/orange-cli/tests/soak`) isolating an
/// observer that had accepted transactions.
#[test]
fn a_transaction_accepted_without_peers_reaches_the_peers_that_connect_later() {
    let keys = keys(1);
    let kernel = kernel_module();
    let genesis = genesis(&keys);
    let start = Instant::now();
    let epoch = 1_000_000;
    let open = |key: Option<SigningKey>| {
        let mut node = Node::open(
            &kernel,
            &genesis,
            NodeConfig {
                now_ms: epoch,
                key,
                ..NodeConfig::default()
            },
        )
        .unwrap();
        node.start(None).unwrap();
        node
    };
    let validator = open(Some(keys[0].clone()));
    let genesis_hash = validator.genesis_hash();
    let listening = Transport::bind(
        "127.0.0.1:0",
        keys[0].clone(),
        CHAIN_ID,
        genesis_hash,
        vec![],
    )
    .unwrap();
    let dial = vec![listening.local_addr().unwrap()];
    let mut observer = open(None);
    let to = address(&keys[0]);
    // Submitted before the observer's transport ever ran: no peer yet.
    let tx_hash = observer.submit(&transfer(&keys[0], to, 5)).unwrap();
    let alone = Transport::bind(
        "127.0.0.1:0",
        fresh_key().unwrap(),
        CHAIN_ID,
        genesis_hash,
        dial,
    )
    .unwrap();
    let mut nodes = vec![validator, observer];
    let mut transports = vec![listening, alone];
    let landed = pump(
        &mut nodes,
        &mut transports,
        start,
        epoch,
        Duration::from_mins(2),
        |nodes, _| nodes[0].receipt(&tx_hash).unwrap().is_some(),
    );
    assert!(
        landed,
        "the validator finalized {} blocks without the observer's transaction",
        nodes[0].finalized.len()
    );
    // And a peer already holding it is not sent it again in a loop: both
    // pools are empty once the block carried it.
    let drained = pump(
        &mut nodes,
        &mut transports,
        start,
        epoch,
        Duration::from_mins(1),
        |nodes, _| nodes.iter().all(|n| n.mempool().is_empty()),
    );
    assert!(drained);
}

/// A validator killed after its driver state recorded a finalized height
/// and before its journal did (the driver store writes the state first,
/// so that a restart never forgets a vote) comes back with tables that
/// lack its finalized head. Every block its peers sent it then failed to
/// chain onto a head it could not name, and it stayed at that height for
/// good. The host now takes the head from the block log in chain state
/// before the driver starts (spec 08 §7). Found by the soak test
/// (`crates/orange-cli/tests/soak`, seed 7), whose validator v0 stopped at
/// block 2691 after a kill -9.
#[test]
#[allow(clippy::too_many_lines)]
fn a_validator_whose_journal_lost_its_finalized_head_catches_up() {
    let keys = keys(4);
    let kernel = kernel_module();
    let genesis = genesis(&keys);
    let start = Instant::now();
    let epoch = 1_000_000;
    let dir = orange_scratch::Scratch::new("net", "lost-head");
    let open = |key: &SigningKey, persisted, store, now| {
        Node::open(
            &kernel,
            &genesis,
            NodeConfig {
                now_ms: now,
                key: Some(key.clone()),
                persisted,
                store,
                ..NodeConfig::default()
            },
        )
        .unwrap()
    };
    let disk = orange_node::StoreConfig::Disk(dir.to_path_buf());
    let mut nodes = Vec::new();
    let mut transports: Vec<Transport> = Vec::new();
    for (i, key) in keys.iter().enumerate() {
        let store = if i == 3 {
            disk.clone()
        } else {
            orange_node::StoreConfig::Memory
        };
        let mut node = open(key, BTreeMap::new(), store, epoch);
        node.start(None).unwrap();
        let peers = transports.iter().map(|t| t.local_addr().unwrap()).collect();
        let genesis_hash = node.genesis_hash();
        transports.push(
            Transport::bind("127.0.0.1:0", key.clone(), CHAIN_ID, genesis_hash, peers).unwrap(),
        );
        nodes.push(node);
    }
    let up = pump(
        &mut nodes,
        &mut transports,
        start,
        epoch,
        Duration::from_mins(3),
        |nodes, _| nodes.iter().all(|n| n.finalized.len() >= 10),
    );
    assert!(up);
    // Validator 3 stops; what its journal lost is its finalized head.
    let mut lost = nodes.pop().unwrap();
    drop(transports.pop());
    let state = lost.persisted_driver_state.clone();
    let finalized = lost.simplex_state().unwrap().finalized_height;
    assert_eq!(lost.block_number().unwrap(), finalized);
    let mut tables = lost.persisted();
    let at = |prefix: &[u8]| [prefix, &finalized.to_le_bytes()[..]].concat();
    let head = tables.remove(&at(b"final/")).unwrap();
    assert!(
        tables
            .remove(&[b"prop/".as_slice(), &head].concat())
            .is_some()
    );
    assert!(tables.remove(&at(b"cert/")).is_some());
    drop(lost);
    // The others go on without it.
    let ahead = finalized + 20;
    let past = pump(
        &mut nodes,
        &mut transports,
        start,
        epoch,
        Duration::from_mins(3),
        |nodes, _| {
            nodes
                .iter()
                .all(|n| n.finalized.last().is_some_and(|h| *h >= ahead))
        },
    );
    assert!(past);
    // Back, it takes its head from the block log and syncs the rest.
    let now = epoch + u64::try_from(start.elapsed().as_millis()).unwrap();
    let mut back = open(&keys[3], tables, disk, now);
    back.start(state).unwrap();
    assert_eq!(back.persisted().get(&at(b"final/")), Some(&head));
    let peers = transports.iter().map(|t| t.local_addr().unwrap()).collect();
    let genesis_hash = back.genesis_hash();
    transports.push(
        Transport::bind(
            "127.0.0.1:0",
            keys[3].clone(),
            CHAIN_ID,
            genesis_hash,
            peers,
        )
        .unwrap(),
    );
    nodes.push(back);
    let caught = pump(
        &mut nodes,
        &mut transports,
        start,
        epoch,
        Duration::from_mins(3),
        |nodes, _| nodes[3].finalized.last().is_some_and(|h| *h >= ahead),
    );
    assert!(
        caught,
        "{:?}",
        nodes
            .iter()
            .map(|n| n.finalized.last().copied())
            .collect::<Vec<_>>()
    );
}

/// What the transport counted of frames of `kind` coming in.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn frames_in(node: &Node, kind: &str) -> usize {
    let frames = &orange_metrics::node::P2P_FRAMES;
    let value = node.telemetry().registry().value(frames, &["in", kind]);
    // A count, held exactly by an f64 this small.
    value.unwrap_or_default() as usize
}

/// A transport of a started one-validator node, without peer exchange, with
/// `limits`, and a raw peer handshaken with it at time 0.
fn limited(limits: Limits) -> (Node, Transport, Wire) {
    let (mut node, chain) = one_node();
    let mut transport =
        Transport::bind("127.0.0.1:0", peer_key(1), CHAIN_ID, chain.genesis, vec![]).unwrap();
    let addr = transport.local_addr().unwrap();
    let key = peer_key(2);
    let (w, _) = raw_peer::connect(addr, &key, chain, &mut || {
        poll_n(&mut transport, &mut node, 0);
    });
    assert!(connected_as(
        &mut transport,
        &mut node,
        &[validator_id(&key)]
    ));
    // Limits apply to the connections open already.
    transport.set_limits(limits);
    assert_eq!(transport.limits(), limits);
    assert!(format!("{limits:?}").contains("max_output"));
    (node, transport, w)
}

/// A peer that streams tiny frames is read a share at a time: at most
/// `READ_FRAMES` frames a poll, however many it has sent (spec 09 §5b), so
/// that it cannot hold the thread the node's consensus runs on.
#[test]
fn a_peer_streaming_tiny_frames_is_handled_a_share_a_poll() {
    let (mut node, mut transport, mut w) = limited(Limits::default());
    let sent = 4 * READ_FRAMES + 10;
    let flood: Vec<u8> = (0..sent).flat_map(|_| w.seal(&Frame::GetPeers)).collect();
    assert_eq!(flood.len(), sent * (4 + 1 + TAG));
    w.write(&flood);
    // Loopback carries the flood at once; give the socket a moment anyway.
    std::thread::sleep(Duration::from_millis(200));
    let before = frames_in(&node, "get_peers");
    let mut polls = 0;
    while frames_in(&node, "get_peers") < before + sent {
        let seen = frames_in(&node, "get_peers");
        transport.poll(&mut node, 0).unwrap();
        let handled = frames_in(&node, "get_peers") - seen;
        assert!(handled <= READ_FRAMES, "{handled} frames in one poll");
        if polls == 0 {
            assert_eq!(handled, READ_FRAMES);
            let (unread, _) = transport.backlog()[0];
            assert_eq!(unread, (sent - READ_FRAMES) * (4 + 1 + TAG));
        }
        polls += 1;
        assert!(polls < 1_000, "the flood was not taken");
    }
    assert!(polls > 4, "{polls}");
    assert_eq!(transport.backlog()[0].0, 0);
    assert_eq!(transport.connected().len(), 1);
}

/// Before its handshake completes, a peer may send nothing longer than an
/// `Auth`: a sealed length past it closes the connection at once, before the
/// frame it announces arrives (spec 09 §3).
#[test]
fn a_frame_before_the_proof_is_no_longer_than_one() {
    let (mut node, chain) = one_node();
    let mut transport =
        Transport::bind("127.0.0.1:0", peer_key(1), CHAIN_ID, chain.genesis, vec![]).unwrap();
    let addr = transport.local_addr().unwrap();
    let mut poll = || poll_n(&mut transport, &mut node, 0);
    let hello = |w: &mut Wire, poll: &mut dyn FnMut()| {
        w.send_clear(&w.hello(validator_id(&peer_key(2))));
        let (_, closed) = w.read_until(poll, |f| raw_peer::nonce_of(f).is_some());
        assert!(!closed);
    };
    let mut w = Wire::dial(addr, chain, [7; 32]);
    hello(&mut w, &mut poll);
    w.write(&u32::try_from(MAX_FRAME + TAG).unwrap().to_le_bytes());
    let (_, closed) = w.read_for(Duration::from_secs(5), &mut poll, |_| false);
    assert!(closed, "a frame of 16 MiB was awaited before the proof");
    let mut w = Wire::dial(addr, chain, [8; 32]);
    hello(&mut w, &mut poll);
    w.write(&u32::try_from(AUTH_LEN + TAG + 1).unwrap().to_le_bytes());
    let (_, closed) = w.read_for(Duration::from_secs(5), &mut poll, |_| false);
    assert!(
        closed,
        "a frame longer than an Auth was awaited before the proof"
    );
    // An Auth's length is read: a proof that does not recover closes as such.
    assert_eq!(
        Frame::Auth { signature: [0; 65] }.to_bytes().len(),
        AUTH_LEN
    );
    let mut w = Wire::dial(addr, chain, [9; 32]);
    hello(&mut w, &mut poll);
    w.send(&Frame::Auth { signature: [0; 65] });
    assert!(w.closes(&mut poll));
    assert!(connected_as(&mut transport, &mut node, &[]));
}

/// Sealed `SyncRequest`s, which a node answers without its driver, from
/// `w`'s session: about `bytes` of them.
fn sync_requests(w: &mut Wire, bytes: usize) -> Vec<u8> {
    let request = Frame::SyncRequest {
        request_id: 0,
        payload: orange_node::statesync::SyncRequest::Offers.to_bytes(),
    };
    let one = 4 + request.to_bytes().len() + TAG;
    (0..bytes / one).flat_map(|_| w.seal(&request)).collect()
}

/// Writes `bytes` to `w`'s socket from a thread until they are written or
/// the node closes the connection: the bytes written. A write that waits
/// is not taken to mean the node stopped reading, since a loaded machine
/// can leave the polling thread unscheduled for longer than any wait.
fn write_from_a_thread(w: &Wire, bytes: Vec<u8>) -> std::thread::JoinHandle<usize> {
    let mut s = w.s.try_clone().unwrap();
    std::thread::spawn(move || {
        let mut written = 0;
        while written < bytes.len() {
            match s.write(&bytes[written..]) {
                Ok(n) if n > 0 => written += n,
                _ => break,
            }
        }
        written
    })
}

/// A peer that asks and never reads the answers is no longer read once
/// `output_high` bytes wait for it, and its connection closes once they
/// have waited `write_stall_ms` without a byte taken (spec 09 §5b): about
/// 50 bytes of request buy a snapshot page or a batch of blocks, and the
/// node would otherwise queue whatever the peer asks.
#[test]
fn a_peer_that_does_not_read_is_not_served_more() {
    let limits = Limits {
        output_high: 64 << 10,
        read_frames: 4_096,
        ..Limits::default()
    };
    let (mut node, mut transport, mut w) = limited(limits);
    // Far more answers than the sockets' buffers hold (a few MiB on Linux),
    // so that they back up. Polled until they do, however slowly the
    // machine runs the poll; the deadline only ends a test that fails.
    let flood = sync_requests(&mut w, 32 << 20);
    let sent = flood.len();
    let writer = write_from_a_thread(&w, flood);
    let deadline = Instant::now() + Duration::from_mins(5);
    let mut queued = 0;
    while queued < limits.output_high {
        assert!(Instant::now() < deadline, "answers never backed up");
        assert!(!writer.is_finished(), "every request was answered");
        transport.poll(&mut node, 0).unwrap();
        let unread;
        (unread, queued) = transport.backlog()[0];
        assert!(unread <= 4 + MAX_FRAME + TAG);
        // Past the mark only by the one answer read below it.
        assert!(queued < limits.output_high + 100, "{queued} bytes queued");
    }
    // No longer read, it is no longer answered, and its queue stays put.
    let answered = frames_in(&node, "sync_request");
    let backlog = transport.backlog();
    for _ in 0..10 {
        transport.poll(&mut node, 0).unwrap();
    }
    assert_eq!(frames_in(&node, "sync_request"), answered);
    assert_eq!(transport.backlog(), backlog);
    assert_eq!(transport.connected().len(), 1);
    // Taking nothing for `write_stall_ms` closes it; reading while it waits
    // does not count as the peer going quiet.
    transport
        .poll(&mut node, limits.write_stall_ms - 1)
        .unwrap();
    assert_eq!(transport.connected().len(), 1);
    transport.poll(&mut node, limits.write_stall_ms).unwrap();
    assert!(transport.connected().is_empty());
    // The writer was held back, then cut off: the node never read it all.
    assert!(writer.join().unwrap() < sent, "the node read everything");
}

/// A connection whose queue a frame would put past `max_output` is closed
/// instead of queueing it (spec 09 §5b).
#[test]
fn a_queue_past_its_cap_closes_the_connection() {
    let limits = Limits {
        output_high: usize::MAX,
        max_output: 64 << 10,
        ..Limits::default()
    };
    let (mut node, mut transport, mut w) = limited(limits);
    let flood = sync_requests(&mut w, 32 << 20);
    let writer = write_from_a_thread(&w, flood);
    let deadline = Instant::now() + Duration::from_mins(5);
    let mut most = 0;
    while !transport.connected().is_empty() {
        assert!(Instant::now() < deadline, "the connection was kept");
        assert!(!writer.is_finished(), "every request was answered");
        transport.poll(&mut node, 0).unwrap();
        if let Some((_, queued)) = transport.backlog().first() {
            assert!(*queued <= limits.max_output, "{queued} bytes queued");
            most = most.max(*queued);
        }
    }
    // It closed with its queue filling, a poll's answers short of the cap
    // at most, not for anything else.
    assert!(most > limits.max_output / 2, "{most}");
    assert!(transport.backlog().is_empty());
    drop(w);
    let _ = writer.join();
}

/// A connection that sends nothing for `IDLE_MS` is closed, in every mode;
/// a node keeps its own connections from going idle by asking for peers
/// every `EXCHANGE_MS`, with or without peer exchange (spec 09 §5b).
#[test]
fn a_quiet_connection_is_closed() {
    let (mut node, mut transport, mut w) = limited(Limits::default());
    let mut poll = || transport.poll(&mut node, 0).unwrap();
    let (got, _) = w.read_until(&mut poll, |f| f.contains(&Frame::GetPeers));
    assert!(got.contains(&Frame::GetPeers), "{got:?}");
    transport.poll(&mut node, IDLE_MS - 1).unwrap();
    assert_eq!(transport.connected().len(), 1);
    transport.poll(&mut node, IDLE_MS).unwrap();
    assert!(transport.connected().is_empty());
}

/// Without peer exchange, a node still accepts no more than `max_peers`
/// connections (spec 09 §5).
#[test]
fn accepted_connections_are_limited_without_peer_exchange() {
    let (mut node, chain) = one_node();
    let mut transport =
        Transport::bind("127.0.0.1:0", peer_key(1), CHAIN_ID, chain.genesis, vec![]).unwrap();
    transport.set_limits(Limits {
        max_peers: 2,
        ..Limits::default()
    });
    let addr = transport.local_addr().unwrap();
    let mut poll = || poll_n(&mut transport, &mut node, 0);
    let (mut first, _) = raw_peer::connect(addr, &peer_key(2), chain, &mut poll);
    let (mut second, _) = raw_peer::connect(addr, &peer_key(3), chain, &mut poll);
    let both = [validator_id(&peer_key(2)), validator_id(&peer_key(3))];
    assert!(connected_as(&mut transport, &mut node, &both));
    // A third is closed as it is accepted, before any handshake.
    let mut third = Wire::dial(addr, chain, [3; 32]);
    let mut poll = || poll_n(&mut transport, &mut node, 0);
    let (got, closed) = third.read_for(Duration::from_secs(5), &mut poll, |_| false);
    assert!(closed && got.is_empty(), "{got:?}");
    let short = Duration::from_millis(100);
    assert!(!first.read_for(short, &mut poll, |_| false).1);
    assert!(!second.read_for(short, &mut poll, |_| false).1);
    assert_eq!(transport.connected().len(), 2);
}

/// Copies what `from` reads to `to` until either end closes, then closes both.
fn relay(mut from: TcpStream, mut to: TcpStream) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let _ = std::io::copy(&mut from, &mut to);
        let _ = from.shutdown(std::net::Shutdown::Both);
        let _ = to.shutdown(std::net::Shutdown::Both);
    })
}

/// A party that relays two of a node's connections into each other hands
/// each the node's own genuine `Hello` and `Auth`; without peer exchange
/// the node peered with itself. It closes both instead (spec 09 §3).
#[test]
fn a_node_relayed_to_itself_closes_both_connections() {
    let (mut node, _) = one_node();
    let mut transport = Transport::bind(
        "127.0.0.1:0",
        peer_key(1),
        CHAIN_ID,
        node.genesis_hash(),
        vec![],
    )
    .unwrap();
    let addr = transport.local_addr().unwrap();
    let a = TcpStream::connect(addr).unwrap();
    let b = TcpStream::connect(addr).unwrap();
    let relays = [
        relay(a.try_clone().unwrap(), b.try_clone().unwrap()),
        relay(b, a),
    ];
    let deadline = Instant::now() + Duration::from_secs(10);
    while !relays.iter().all(std::thread::JoinHandle::is_finished) {
        transport.poll(&mut node, 0).unwrap();
        assert!(transport.connected().is_empty(), "peered with itself");
        assert!(Instant::now() < deadline, "the connections stay open");
        std::thread::sleep(Duration::from_millis(2));
    }
    transport.poll(&mut node, 0).unwrap();
    assert_eq!(transport.backlog().len(), 0);
}

/// A peer's driver requests that the driver leaves unanswered are answered
/// with nothing, by the host: at once past `MAX_SERVING` of them, without a
/// step of the driver, and the others after `SERVE_MS` (spec 09 §4).
#[test]
fn a_request_the_driver_leaves_unanswered_is_answered_with_nothing() {
    let (mut node, mut transport, mut w) = limited(Limits::default());
    // The reference driver answers no request whose payload does not decode.
    let asked = MAX_SERVING as u64 + 2;
    for request_id in 1..=asked {
        w.send(&Frame::Request {
            request_id,
            payload: vec![0xFF],
        });
    }
    let answer = |f: &Frame| match f {
        Frame::Response {
            request_id,
            payload,
        } if payload.is_empty() => Some(*request_id),
        _ => None,
    };
    let answered = |frames: &[Frame]| frames.iter().filter_map(answer).collect::<Vec<_>>();
    let mut poll = || transport.poll(&mut node, 0).unwrap();
    let (got, _) = w.read_until(&mut poll, |f| answered(f).len() == 2);
    assert_eq!(answered(&got), [asked - 1, asked]);
    let (got, _) = w.read_for(Duration::from_millis(200), &mut poll, |_| false);
    assert!(answered(&got).is_empty());
    let mut poll = || transport.poll(&mut node, SERVE_MS).unwrap();
    let (got, _) = w.read_until(&mut poll, |f| answered(f).len() == MAX_SERVING);
    let early: Vec<u64> = (1..=MAX_SERVING as u64).collect();
    assert_eq!(answered(&got), early);
    assert_eq!(transport.connected().len(), 1);
}
