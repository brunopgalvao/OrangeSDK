//! The TCP transport: framing, the handshake, and real sockets carrying a
//! four-validator chain to finality, a transaction gossiped between peers,
//! and a late observer syncing over the wire.

use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::time::{Duration, Instant};

use k256::ecdsa::SigningKey;
use solo_abi::Encode;
use solo_abi::chain::{Allocation, GenesisParams};
use solo_abi::codec::Seq;
use solo_abi::types::Genesis;
use solo_host::hash::keccak256;
use solo_node::net::{Frame, MAX_FRAME, Transport, frame_bytes, take_frames};
use solo_node::{Node, NodeConfig, Sim};

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
        },
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

/// Polls every live node and its transport until `done` or the deadline.
fn pump(
    nodes: &mut [Node],
    transports: &mut [Transport],
    start: Instant,
    epoch: u64,
    max: Duration,
    mut done: impl FnMut(&mut [Node]) -> bool,
) -> bool {
    let deadline = Instant::now() + max;
    while Instant::now() < deadline {
        if done(nodes) {
            return true;
        }
        let now = epoch + u64::try_from(start.elapsed().as_millis()).unwrap();
        for (node, transport) in nodes.iter_mut().zip(transports.iter_mut()) {
            node.tick(now).unwrap();
            transport.poll(node, now).unwrap();
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    done(nodes)
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
        let id = solo_node::validator_id(key);
        // Each node dials every earlier one, so every pair has one connection.
        let peers = transports.iter().map(|t| t.local_addr().unwrap()).collect();
        transports.push(Transport::bind("127.0.0.1:0", id, CHAIN_ID, peers).unwrap());
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
        nodes.push(node);
    }
    // A transaction submitted to the last node travels by gossip and lands everywhere.
    let to = address(&keys[1]);
    let tx_hash = nodes[3].submit(&transfer(&keys[0], to, 5)).unwrap();
    let finalized = pump(
        &mut nodes,
        &mut transports,
        start,
        epoch,
        Duration::from_secs(20),
        |nodes| nodes.iter().all(|n| n.finalized.len() >= 20),
    );
    for node in &mut nodes {
        assert!(node.receipt(&tx_hash).unwrap().is_some());
        assert_eq!(node.account(&to).unwrap().balance, 5);
    }
    assert!(
        finalized,
        "{:?}",
        nodes.iter().map(|n| n.finalized.len()).collect::<Vec<_>>()
    );
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
    nodes.push(observer);
    let dial = vec![transports[0].local_addr().unwrap()];
    transports.push(Transport::bind("127.0.0.1:0", [0xEE; 32], CHAIN_ID, dial).unwrap());
    let synced = pump(
        &mut nodes,
        &mut transports,
        start,
        epoch,
        Duration::from_secs(20),
        |nodes| {
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

#[test]
#[allow(clippy::too_many_lines)]
fn handshake_rules() {
    let keys = keys(1);
    let kernel = kernel_module();
    let genesis = genesis(&keys);
    let mut node = Node::open(&kernel, &genesis, NodeConfig::default()).unwrap();
    node.start(None).unwrap();
    let mut transport = Transport::bind("127.0.0.1:0", [1; 32], CHAIN_ID, vec![]).unwrap();
    let addr = transport.local_addr().unwrap();
    let speak = |frames: &[Frame], raw: &[u8]| {
        let mut s = TcpStream::connect(addr).unwrap();
        for f in frames {
            s.write_all(&frame_bytes(f)).unwrap();
        }
        s.write_all(raw).unwrap();
        s
    };
    let hello = Frame::Hello {
        id: [2; 32],
        chain_id: CHAIN_ID,
    };
    let poll = |t: &mut Transport, n: &mut Node| {
        for _ in 0..20 {
            t.poll(n, 0).unwrap();
            std::thread::sleep(Duration::from_millis(2));
        }
    };
    // Wrong chain, a message before hello, a second hello, garbage: all dropped.
    let _a = speak(
        &[Frame::Hello {
            id: [3; 32],
            chain_id: 1,
        }],
        &[],
    );
    let _b = speak(&[Frame::Tx { raw: vec![] }], &[]);
    let _c = speak(&[hello.clone(), hello.clone()], &[]);
    let _d = speak(&[], &[1, 0, 0, 0, 0xFF]);
    poll(&mut transport, &mut node);
    assert!(
        transport.connected().is_empty(),
        "{:?}",
        transport.connected()
    );
    // A good peer stays; its requests are served and unknown responses ignored.
    let mut good = speak(
        &[
            hello,
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
        ],
        &[],
    );
    poll(&mut transport, &mut node);
    assert_eq!(transport.connected(), vec![[2; 32]]);
    // Point-to-point sends reach the named peer; blobs and scores are not transported.
    for effect in [
        solo_abi::types::Effect::Send {
            peer: [2; 32],
            topic: 5,
            payload: vec![8],
        },
        solo_abi::types::Effect::Disseminate {
            blob_id: [0; 32],
            payload: vec![],
        },
        solo_abi::types::Effect::PeerScore {
            peer: [2; 32],
            delta: 1,
        },
    ] {
        node.apply_effect(effect).unwrap();
    }
    poll(&mut transport, &mut node);
    good.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let mut got = Vec::new();
    while got.len() < 3 {
        let n = std::io::Read::read(&mut good, &mut chunk).unwrap();
        buf.extend_from_slice(&chunk[..n]);
        got.extend(take_frames(&mut buf).unwrap());
    }
    assert!(matches!(got[0], Frame::Hello { id, .. } if id == [1; 32]));
    assert!(matches!(got[1], Frame::Response { request_id: 9, .. }));
    assert_eq!(
        got[2],
        Frame::Message {
            topic: 5,
            payload: vec![8]
        }
    );
    // A closed peer is forgotten; a dial target that is down is retried without error.
    drop(good);
    poll(&mut transport, &mut node);
    assert!(transport.connected().is_empty());
    let unused = TcpListener::bind("127.0.0.1:0").unwrap();
    let down = unused.local_addr().unwrap();
    drop(unused);
    let mut dialer = Transport::bind("127.0.0.1:0", [4; 32], CHAIN_ID, vec![down]).unwrap();
    dialer.poll(&mut node, 0).unwrap();
    dialer.poll(&mut node, 1).unwrap();
    assert!(dialer.connected().is_empty());
    assert!(Transport::bind("nope", [0; 32], 1, vec![]).is_err());
}
