//! The TCP transport: framing, the handshake, and real sockets carrying a
//! four-validator chain to finality, a transaction gossiped between peers,
//! and a late observer syncing over the wire. The handshake proves every
//! peer's id (spec 09 §3): an impostor naming a validator's id is dropped.

#[path = "support/raw_peer.rs"]
mod raw_peer;

use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::time::{Duration, Instant};

use k256::ecdsa::SigningKey;
use raw_peer::{Chain, nonce_of, read_until, send};
use solo_abi::chain::{Allocation, GenesisParams};
use solo_abi::codec::Seq;
use solo_abi::types::Genesis;
use solo_abi::{Decode, Encode};
use solo_host::hash::keccak256;
use solo_node::net::{
    Frame, MAX_FRAME, Transport, frame_bytes, fresh_key, hello_digest, take_frames,
};
use solo_node::peers::recover_id;
use solo_node::{Node, NodeConfig, Sim, validator_id};

const KERNEL: &[u8] = include_bytes!("fixtures/kernel.elf");
const CHAIN_ID: u64 = 1337;
const SLOT_MS: u64 = 100;

fn kernel_module() -> Vec<u8> {
    solo_recompile::recompile(
        &solo_recompile::Input::load(KERNEL).unwrap(),
        &solo_recompile::Options::default(),
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
    out.copy_from_slice(&solo_node::validator_id(key)[12..]);
    out
}

/// A signed EIP-155 transfer.
fn transfer(key: &SigningKey, to: [u8; 20], value: u128) -> Vec<u8> {
    use solo_rlp::{encode_bytes, encode_list, encode_uint};
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
            id: [1; 32],
            chain_id: 5,
            genesis: [2; 32],
            nonce: [3; 32],
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

/// How an impostor answers the transport's nonce.
type Proof<'a> = dyn Fn(&[u8; 32]) -> Frame + 'a;

/// A key for a peer the tests play by hand.
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

#[test]
#[allow(clippy::too_many_lines)]
fn handshake_rules() {
    let keys = keys(1);
    let kernel = kernel_module();
    let genesis = genesis(&keys);
    let mut node = Node::open(&kernel, &genesis, NodeConfig::default()).unwrap();
    node.start(None).unwrap();
    let chain = Chain {
        chain_id: CHAIN_ID,
        genesis: node.genesis_hash(),
    };
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
    // place of the proof, a proof before hello, garbage: all dropped.
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
    // recovers to the transport's id over its nonce and the impostor's, and answers with a
    // proof that is not the validator's for this connection: signed by another key, by the
    // validator for another connection, another chain or another genesis, with the nonces
    // swapped, or not a signature at all. Each is dropped and never connected.
    let validator = validator_id(&keys[0]);
    let mine = [5; 32];
    let attempts: Vec<Box<Proof>> = vec![
        Box::new(|theirs| chain.auth(&peer_key(3), &mine, theirs)),
        Box::new(|_| chain.auth(&keys[0], &mine, &[6; 32])),
        Box::new(|theirs| other_chain.auth(&keys[0], &mine, theirs)),
        Box::new(|theirs| other_genesis.auth(&keys[0], &mine, theirs)),
        Box::new(|theirs| chain.auth(&keys[0], theirs, &mine)),
        Box::new(|_| Frame::Auth {
            signature: [0xFF; 65],
        }),
    ];
    for (i, attempt) in attempts.iter().enumerate() {
        let mut s = TcpStream::connect(addr).unwrap();
        send(&mut s, &chain.hello(validator, mine));
        let (frames, _) = read_until(&mut s, &mut || poll_n(&mut transport, &mut node, 0), |f| {
            f.iter().any(|f| matches!(f, Frame::Auth { .. }))
        });
        let theirs = nonce_of(&frames).unwrap();
        let proof = frames.iter().find_map(|f| match f {
            Frame::Auth { signature } => Some(*signature),
            _ => None,
        });
        let digest = hello_digest(CHAIN_ID, &chain.genesis, &theirs, &mine);
        assert_eq!(recover_id(&digest, &proof.unwrap()), Some(transport.id()));
        send(&mut s, &attempt(&theirs));
        let (_, closed) = read_until(&mut s, &mut || poll_n(&mut transport, &mut node, 0), |_| {
            false
        });
        assert!(closed, "impostor {i} was not dropped");
        assert!(transport.connected().is_empty(), "impostor {i}");
    }
    // The validator itself, with the same nonces, gets in; so does a peer that proves a key
    // of its own.
    let (mut real, _) = raw_peer::connect(addr, &keys[0], chain, &mut || {
        poll_n(&mut transport, &mut node, 0);
    });
    poll(&mut transport, &mut node);
    assert_eq!(transport.connected(), vec![validator]);
    // A proof after the handshake closes the connection.
    send(&mut real, &chain.auth(&keys[0], &mine, &mine));
    assert!(
        read_until(
            &mut real,
            &mut || poll_n(&mut transport, &mut node, 0),
            |_| false
        )
        .1
    );
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
            payload: solo_abi::chain::SyncRequest { from_height: 1 }.to_bytes(),
        },
        Frame::Response {
            request_id: 4,
            payload: vec![],
        },
    ] {
        send(&mut good, &f);
    }
    poll(&mut transport, &mut node);
    assert_eq!(transport.connected(), vec![good_id]);
    // Point-to-point sends reach the named peer; blobs and scores are not transported.
    for effect in [
        solo_abi::types::Effect::Send {
            peer: good_id,
            topic: 5,
            payload: vec![8],
        },
        solo_abi::types::Effect::Disseminate {
            blob_id: [0; 32],
            payload: vec![],
        },
        solo_abi::types::Effect::PeerScore {
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
    let (got, closed) = read_until(
        &mut good,
        &mut || poll_n(&mut transport, &mut node, 0),
        |f| f.contains(&message),
    );
    assert!(!closed);
    let answered = got
        .iter()
        .position(|f| matches!(f, Frame::Response { request_id: 9, .. }));
    let sent = got.iter().position(|f| *f == message);
    assert!(answered.unwrap() < sent.unwrap(), "{got:?}");
    // A peer that says Hello and never proves it is dropped once HANDSHAKE_MS has passed.
    let mut silent = speak(&[chain.hello(validator_id(&peer_key(4)), [4; 32])], &[]);
    poll(&mut transport, &mut node);
    assert_eq!(transport.connected(), vec![good_id]);
    let (_, closed) = read_until(
        &mut silent,
        &mut || poll_n(&mut transport, &mut node, solo_node::net::HANDSHAKE_MS),
        |_| false,
    );
    assert!(closed);
    // A closed peer is forgotten; a dial target that is down is retried without error.
    drop(good);
    poll(&mut transport, &mut node);
    assert!(transport.connected().is_empty());
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

#[test]
#[allow(clippy::too_many_lines)]
fn state_sync_frames_are_the_hosts() {
    use solo_abi::Decode;
    use solo_node::statesync::{StateSync, SyncConfig, SyncRequest, SyncResponse};
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
    send(
        &mut s,
        &Frame::SyncResponse {
            request_id: 1,
            payload: vec![],
        },
    );
    send(
        &mut s,
        &Frame::SyncRequest {
            request_id: 5,
            payload: offers.clone(),
        },
    );
    let answer = Frame::SyncResponse {
        request_id: 5,
        payload: nothing.clone(),
    };
    let (got, _) = read_until(&mut s, &mut || poll_n(&mut running, &mut node, 0), |f| {
        f.contains(&answer)
    });
    assert!(got.contains(&answer), "{got:?}");
    // A node that syncs drops what is not state sync, closes a peer of
    // another chain or one that says hello twice, answers a sync request as
    // a node that serves nothing, and asks its peers for their offers.
    let dir = solo_scratch::Scratch::new("net", "syncing");
    let mut sync = StateSync::new(SyncConfig {
        chain_id: CHAIN_ID,
        trust: solo_store::Trust::Genesis(Sim::validator_set(&keys)),
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
    send(
        &mut good,
        &Frame::Message {
            topic: 1,
            payload: vec![],
        },
    );
    send(
        &mut good,
        &Frame::SyncRequest {
            request_id: 6,
            payload: offers,
        },
    );
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
    let (got, _) = read_until(&mut good, &mut || poll_sync(&mut syncing, &mut sync), |f| {
        f.contains(&unserved) && f.iter().any(|f| asked(f).is_some())
    });
    assert_eq!(syncing.connected(), vec![validator_id(&peer)]);
    assert!(got.contains(&unserved), "{got:?}");
    let (id, request) = got.iter().find_map(asked).unwrap();
    assert_eq!(request, SyncRequest::Offers);
    // Its answer reaches the sync.
    send(
        &mut good,
        &Frame::SyncResponse {
            request_id: id,
            payload: SyncResponse::Offers(vec![]).to_bytes(),
        },
    );
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
    use solo_node::net::SYNC_PEER_WAIT_MS;
    use solo_node::statesync::{StateSync, SyncConfig};
    let keys = keys(1);
    let dir = solo_scratch::Scratch::new("net", "stalled");
    let mut sync = StateSync::new(SyncConfig {
        chain_id: CHAIN_ID,
        trust: solo_store::Trust::Genesis(Sim::validator_set(&keys)),
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
    for _ in 0..10 {
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
    let mut s = TcpStream::connect(foreign.local_addr().unwrap()).unwrap();
    let elsewhere = Chain {
        genesis: [8; 32],
        ..chain
    };
    send(
        &mut s,
        &elsewhere.hello(validator_id(&peer_key(3)), [3; 32]),
    );
    let (_, closed) = read_until(&mut s, &mut || foreign.poll_sync(&mut sync, 5), |_| false);
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
    use solo_node::net::SYNC_PEER_WAIT_MS;
    use solo_node::statesync::{StateSync, SyncConfig};
    let keys = keys(1);
    let dir = solo_scratch::Scratch::new("net", "dropped");
    let mut sync = StateSync::new(SyncConfig {
        chain_id: CHAIN_ID,
        trust: solo_store::Trust::Genesis(Sim::validator_set(&keys)),
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
    let (got, _) = read_until(
        &mut peer,
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
    send(
        &mut peer,
        &Frame::SyncResponse {
            request_id,
            payload: vec![0xff],
        },
    );
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
}
