//! Configured peers and bootstrap addresses given by DNS name (spec 09 §5,
//! §5a.5): resolved at every dial, so a record that changed is picked up at
//! the next one; every address a name gives tried in order; a resolver
//! that fails counts as a failed dial; and one that hangs never holds the
//! node's thread, is abandoned after `RESOLVE_MS` and holds at most
//! `MAX_RESOLVING` threads. Names resolve through a resolver the tests
//! give, or the system's for `localhost`, so nothing leaves this machine.

use std::io;
use std::net::{SocketAddr, TcpListener};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use k256::ecdsa::SigningKey;
use orange_abi::Encode;
use orange_abi::chain::GenesisParams;
use orange_abi::codec::Seq;
use orange_abi::types::Genesis;
use orange_node::net::{MAX_RESOLVING, RESOLVE_MS, Resolve};
use orange_node::{Discovery, Node, NodeConfig, PeerAddr, Sim, Transport, validator_id};

const KERNEL: &[u8] = include_bytes!("fixtures/kernel.elf");
const CHAIN_ID: u64 = 1337;

fn kernel_module() -> &'static [u8] {
    static MODULE: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
    MODULE.get_or_init(|| {
        orange_recompile::recompile(
            &orange_recompile::Input::load(KERNEL).unwrap(),
            &orange_recompile::Options::default(),
        )
        .unwrap()
    })
}

fn key(i: u8) -> SigningKey {
    SigningKey::from_slice(&[0x70 + i; 32]).unwrap()
}

/// An observer node of a one-validator chain, and its transport, which
/// dials `peers` and runs peer exchange as `discovery` says.
fn peer(i: u8, peers: Vec<PeerAddr>, discovery: Option<Discovery>) -> (Node, Transport) {
    let genesis = Genesis {
        chain_id: CHAIN_ID,
        fee_schedule: vec![],
        modules: Seq(vec![]),
        params: GenesisParams::default().to_bytes(),
        validators: Sim::validator_set(&[key(0)]).to_bytes(),
    };
    let mut node = Node::open(kernel_module(), &genesis, NodeConfig::default()).unwrap();
    node.start(None).unwrap();
    let hash = node.genesis_hash();
    let mut t = Transport::bind_named("127.0.0.1:0", key(i), CHAIN_ID, hash, peers).unwrap();
    if let Some(d) = discovery {
        t.enable_discovery(d);
    }
    (node, t)
}

/// A resolver of the tests' own: `hang.test` waits until released and then
/// fails, `fail.test` fails, and every other name gives the addresses set.
#[derive(Default)]
struct Fake {
    addrs: Mutex<Vec<SocketAddr>>,
    released: AtomicBool,
}

impl Resolve for Fake {
    fn resolve(&self, host: &str, _port: u16) -> io::Result<Vec<SocketAddr>> {
        match host {
            "hang.test" => {
                while !self.released.load(Ordering::SeqCst) {
                    std::thread::sleep(Duration::from_millis(2));
                }
                Err(io::ErrorKind::TimedOut.into())
            }
            "fail.test" => Err(io::ErrorKind::NotFound.into()),
            _ => Ok(self.addrs.lock().unwrap().clone()),
        }
    }
}

fn name(host: &str) -> PeerAddr {
    format!("{host}:30333").parse().unwrap()
}

/// An address nothing listens on.
fn closed() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

/// Milliseconds since the first call: one clock for every poll of a test.
fn now() -> u64 {
    static START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    let start = *START.get_or_init(Instant::now);
    u64::try_from(start.elapsed().as_millis()).unwrap()
}

/// Polls every peer until `done` or 20 s.
fn pump(
    peers: &mut [&mut (Node, Transport)],
    mut done: impl FnMut(&[&mut (Node, Transport)]) -> bool,
) {
    let start = Instant::now();
    while !done(peers) {
        assert!(start.elapsed() < Duration::from_secs(20), "timed out");
        for p in peers.iter_mut() {
            let (node, t) = &mut **p;
            t.poll(node, now()).unwrap();
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}

#[test]
fn a_configured_name_is_resolved_at_every_dial_and_every_address_is_tried() {
    let fake = Arc::new(Fake::default());
    let mut a = peer(1, vec![], None);
    // The name gives first an address that refuses, then the one listening.
    *fake.addrs.lock().unwrap() = vec![closed(), a.1.local_addr().unwrap()];
    let mut b = peer(2, vec![name("seed.test"), name("fail.test")], None);
    b.1.set_resolver(fake.clone());
    pump(&mut [&mut a, &mut b], |p| {
        p[1].1.connected() == [validator_id(&key(1))]
    });
    // The record moves to another node: once the first is gone, the next
    // dial resolves the name again and finds the new one.
    let mut c = peer(3, vec![], None);
    *fake.addrs.lock().unwrap() = vec![c.1.local_addr().unwrap()];
    drop(a);
    pump(&mut [&mut b, &mut c], |p| {
        p[0].1.connected() == [validator_id(&key(3))]
    });
    assert_eq!(b.1.outbound(), 1);
    assert_eq!(c.1.connected(), [validator_id(&key(2))]);
}

#[test]
fn localhost_resolves_through_the_system() {
    let mut a = peer(1, vec![], None);
    let port = a.1.local_addr().unwrap().port();
    let mut b = peer(2, vec![format!("localhost:{port}").parse().unwrap()], None);
    pump(&mut [&mut a, &mut b], |p| {
        p[1].1.connected() == [validator_id(&key(1))]
    });
}

#[test]
fn a_hung_resolver_never_holds_the_node_and_holds_a_bounded_number_of_threads() {
    let fake = Arc::new(Fake::default());
    let names = (0..MAX_RESOLVING + 2).map(|_| name("hang.test")).collect();
    let (mut node, mut t) = peer(1, names, None);
    t.set_resolver(fake.clone());
    let timed = |t: &mut Transport, node: &mut Node, now: u64| {
        let start = Instant::now();
        t.poll(node, now).unwrap();
        assert!(start.elapsed() < Duration::from_millis(500));
    };
    timed(&mut t, &mut node, 0);
    assert_eq!(t.resolving(), MAX_RESOLVING);
    // Abandoned in time, but their threads still run: no new one starts.
    timed(&mut t, &mut node, RESOLVE_MS);
    timed(&mut t, &mut node, RESOLVE_MS + 1_000);
    assert_eq!(t.resolving(), MAX_RESOLVING);
    // Released, they end, and their late answers are dropped.
    fake.released.store(true, Ordering::SeqCst);
    let start = Instant::now();
    while t.resolving() > 0 {
        assert!(start.elapsed() < Duration::from_secs(10));
        std::thread::sleep(Duration::from_millis(2));
    }
    fake.released.store(false, Ordering::SeqCst);
    timed(&mut t, &mut node, RESOLVE_MS + 1_000);
    timed(&mut t, &mut node, RESOLVE_MS + 2_000);
    assert_eq!(t.resolving(), MAX_RESOLVING);
    assert!(t.connected().is_empty());
    fake.released.store(true, Ordering::SeqCst);
}

#[test]
fn bootstrap_names_are_dialled_resolved_and_abandoned_like_configured_ones() {
    let fake = Arc::new(Fake::default());
    let mut a = peer(
        1,
        vec![],
        Some(Discovery {
            key: Some(key(1)),
            ..Discovery::default()
        }),
    );
    *fake.addrs.lock().unwrap() = vec![a.1.local_addr().unwrap()];
    let bootstrap = vec![name("hang.test"), name("fail.test"), name("boot.test")];
    let mut b = peer(
        2,
        vec![],
        Some(Discovery {
            bootstrap,
            ..Discovery::default()
        }),
    );
    b.1.set_resolver(fake.clone());
    pump(&mut [&mut a, &mut b], |p| {
        p[1].1.connected() == [validator_id(&key(1))]
    });
    assert_eq!(b.1.resolving(), 1);
    // The hung one is abandoned at its deadline; its late answer is dropped.
    let (node, t) = &mut b;
    let later = now() + RESOLVE_MS;
    t.poll(node, later).unwrap();
    fake.released.store(true, Ordering::SeqCst);
    let start = Instant::now();
    while t.resolving() > 0 {
        assert!(start.elapsed() < Duration::from_secs(10));
        std::thread::sleep(Duration::from_millis(2));
    }
    t.poll(node, later + 1).unwrap();
    assert_eq!(t.connected(), [validator_id(&key(1))]);
}
