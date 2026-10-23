//! Block catch-up (spec 08 §7a, spec 09 §6a) against slow peers: an
//! observer that joins a fast chain whose blocks come back after its views
//! have moved on.

use k256::ecdsa::SigningKey;
use solo_abi::chain::{Certificate, GenesisParams, Proposal, SyncRequest, SyncResponse};
use solo_abi::codec::Seq;
use solo_abi::types::{Genesis, Input};
use solo_abi::{Decode, Encode};
use solo_node::catchup::{CatchUp, FIRST_WAIT_MS, HOST_IDS, MAX_WAIT_MS, PEER_TTL_MS};
use solo_node::{NodeConfig, Outbound, Sim};

const KERNEL: &[u8] = include_bytes!("fixtures/kernel.elf");
const CHAIN_ID: u64 = 1337;
const SLOT_MS: u64 = 60;

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

fn genesis(keys: &[SigningKey]) -> Genesis {
    let params = GenesisParams {
        slot_ms: SLOT_MS,
        max_txs: 8,
        allocations: Seq(vec![]),
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

/// One validator at 60 ms slots and an observer that starts 120 blocks
/// behind it, with every answer to a sync request taking 200 ms: longer
/// than the observer stays in one view, which it leaves each time the
/// validator's next block is notarized.
fn slow_peer_sim(catch_up: bool) -> Sim {
    let keys = vec![SigningKey::from_slice(&[0x51; 32]).unwrap()];
    let genesis = genesis(&keys);
    let config = NodeConfig {
        now_ms: 1_000_000,
        ..NodeConfig::default()
    };
    let mut sim = Sim::new(kernel_module(), &genesis, &keys, 1, &config, 5).unwrap();
    sim.crash(1);
    let ahead = sim
        .run_until(60_000, |s| s.nodes[0].finalized.len() >= 120)
        .unwrap();
    assert!(ahead);
    sim.revive_from_scratch(1, kernel_module(), &genesis)
        .unwrap();
    sim.nodes[1].set_catch_up(catch_up);
    sim.response_delay_ms = 200;
    sim
}

#[test]
fn an_observer_catches_up_with_a_fast_chain_through_a_slow_peer() {
    let mut sim = slow_peer_sim(true);
    let start = sim.now_ms;
    let caught = sim
        .run_until(30_000, |s| {
            s.nodes[1].finalized.len() + 2 >= s.nodes[0].finalized.len()
        })
        .unwrap();
    assert!(
        caught,
        "observer at {}, validator at {}",
        sim.nodes[1].finalized.len(),
        sim.nodes[0].finalized.len()
    );
    // Batches asked ahead as answers come back (0.9 s when measured): one
    // 16-block batch per 210 ms answer would take 1.6 s for the first 120
    // blocks alone.
    assert!(sim.now_ms - start < 1_500, "{} ms", sim.now_ms - start);
    assert!(sim.nodes[1].catch_up_depth() > 1);
}

/// What the observer did before the host kept its requests across views:
/// the driver abandons its request on entering a view (spec 08 §3), every
/// answer arrives after that and is dropped, and the observer never moves.
#[test]
fn without_the_hosts_catch_up_the_observer_loops() {
    let mut sim = slow_peer_sim(false);
    sim.advance(10_000).unwrap();
    assert_eq!(sim.nodes[1].finalized.len(), 0);
    assert!(sim.nodes[0].finalized.len() > 200);
}

// The host's catch-up state machine alone, against scripted answers.

const A: [u8; 32] = [1; 32];
const B: [u8; 32] = [2; 32];

fn ask(from: u64) -> Vec<u8> {
    SyncRequest { from_height: from }.to_bytes()
}

/// An answer with blocks `first..=top` of a peer finalized at `fin`.
fn answer(first: u64, top: u64, fin: u64) -> Vec<u8> {
    SyncResponse {
        finalized_height: fin,
        proposals: Seq((first..=top)
            .map(|height| Proposal {
                height,
                ..Proposal::default()
            })
            .collect()),
        certificate: Some(Certificate::default()),
        threshold: Vec::new(),
    }
    .to_bytes()
}

/// The requests in `out`, as `(peer, id, from)`, drained.
fn sent(out: &mut Vec<Outbound>) -> Vec<([u8; 32], u64, u64)> {
    out.drain(..)
        .map(|m| match m {
            Outbound::Request {
                peer,
                request_id,
                payload,
            } => (
                peer,
                request_id,
                SyncRequest::from_bytes(&payload).map_or(u64::MAX, |r| r.from_height),
            ),
            other => panic!("{other:?}"),
        })
        .collect()
}

/// The id an input answers and the heights it hands the driver.
fn handed(input: Option<Input>) -> (u64, Vec<u64>) {
    match input {
        Some(Input::Response {
            request_id,
            payload,
        }) => (
            request_id,
            SyncResponse::from_bytes(&payload)
                .unwrap()
                .proposals
                .0
                .iter()
                .map(|p| p.height)
                .collect(),
        ),
        other => panic!("{other:?}"),
    }
}

#[test]
fn off_or_not_a_sync_request_passes_untouched() {
    let mut c = CatchUp::default();
    let mut out = Vec::new();
    assert!(c.on_request(A, 7, vec![1], 0, &mut out).is_none());
    assert_eq!(sent(&mut out), vec![(A, 7, u64::MAX)]);
    c.set(false);
    assert!(c.on_request(A, 8, ask(1), 0, &mut out).is_none());
    assert_eq!(sent(&mut out), vec![(A, 8, 1)]);
    assert!(matches!(
        c.on_response(8, answer(1, 2, 2), 0, &mut out),
        Some(Input::Response { request_id: 8, .. })
    ));
    // An id of the host's that is no longer on the wire is dropped.
    assert_eq!(c.on_response(HOST_IDS + 5, vec![], 0, &mut out), None);
}

#[test]
fn an_answer_after_the_driver_asked_again_serves_the_new_request() {
    let mut c = CatchUp::default();
    let mut out = Vec::new();
    assert!(c.on_request(A, 1, ask(1), 0, &mut out).is_none());
    assert_eq!(sent(&mut out), vec![(A, HOST_IDS, 1)]);
    // The driver entered a view and asks again: nothing new goes out.
    assert!(c.on_request(A, 2, ask(1), 50, &mut out).is_none());
    assert!(out.is_empty());
    // The answer comes back quickly, hands blocks 1 to 16 to request 2,
    // widens the window and asks ahead for the rest.
    let input = c.on_response(HOST_IDS, answer(1, 16, 40), 100, &mut out);
    assert_eq!(handed(input), (2, (1..=16).collect()));
    assert_eq!(c.depth(), 2);
    assert_eq!(
        sent(&mut out),
        vec![(A, HOST_IDS + 1, 17), (A, HOST_IDS + 2, 33)]
    );
    // The driver finalized 1 to 16 and some of the next batch on its own:
    // the parked answer from 17 is trimmed to what it lacks.
    let input = c.on_response(HOST_IDS + 1, answer(17, 32, 40), 150, &mut out);
    assert_eq!(input, None);
    let next = c.on_request(A, 3, ask(20), 160, &mut out);
    assert_eq!(handed(next), (3, (20..=32).collect()));
    assert!(out.is_empty());
    c.settle(32);
    // An answer the driver has not asked for yet waits; it was slow, so
    // the window narrows.
    assert_eq!(
        c.on_response(HOST_IDS + 2, answer(33, 40, 40), 2_000, &mut out),
        None
    );
    assert_eq!((c.depth(), c.parked(), c.in_flight()), (1, 2, 0));
    assert_eq!(
        handed(c.on_request(A, 4, ask(33), 2_010, &mut out)).1.len(),
        8
    );
}

#[test]
fn a_refused_answer_is_dropped_and_asked_for_again() {
    let mut c = CatchUp::default();
    let mut out = Vec::new();
    c.heard(B, 0);
    c.on_request(A, 1, ask(5), 0, &mut out);
    sent(&mut out);
    // The answer goes to request 1, which the driver abandoned and drops;
    // the answer stays parked.
    let input = c.on_response(HOST_IDS, answer(5, 6, 6), 10, &mut out);
    assert_eq!(handed(input).0, 1);
    assert_eq!(handed(c.on_request(A, 2, ask(5), 20, &mut out)).0, 2);
    // The driver did not take it: it is dropped, and the next request goes
    // out again.
    c.settle(4);
    assert_eq!(c.parked(), 0);
    c.settle(4);
    assert!(c.on_request(A, 3, ask(5), 30, &mut out).is_none());
    assert_eq!(sent(&mut out), vec![(A, HOST_IDS + 1, 5)]);
}

#[test]
fn useless_answers_leave_the_request_to_another_peer() {
    let mut c = CatchUp::default();
    let mut out = Vec::new();
    c.heard(B, 0);
    c.on_request(A, 1, ask(3), 0, &mut out);
    sent(&mut out);
    // No certificate, then no blocks: nothing is handed over, and the next
    // poll asks the next peer.
    let no_certificate = SyncResponse::default().to_bytes();
    assert_eq!(c.on_response(HOST_IDS, no_certificate, 5, &mut out), None);
    c.poll(10, 2, &mut out);
    assert_eq!(sent(&mut out), vec![(B, HOST_IDS + 1, 3)]);
    let empty = SyncResponse {
        certificate: Some(Certificate::default()),
        ..SyncResponse::default()
    };
    assert_eq!(
        c.on_response(HOST_IDS + 1, empty.to_bytes(), 15, &mut out),
        None
    );
    c.poll(20, 2, &mut out);
    assert_eq!(sent(&mut out), vec![(A, HOST_IDS + 2, 3)]);
    // A poll with the request on the wire sends nothing.
    c.poll(30, 2, &mut out);
    assert!(out.is_empty());
}

#[test]
fn a_silent_peer_is_replaced_and_waited_for_longer() {
    let mut c = CatchUp::default();
    let mut out = Vec::new();
    c.heard(B, 0);
    c.on_request(A, 1, ask(9), 0, &mut out);
    sent(&mut out);
    c.poll(FIRST_WAIT_MS - 1, 8, &mut out);
    assert!(out.is_empty());
    c.poll(FIRST_WAIT_MS, 8, &mut out);
    assert_eq!(sent(&mut out), vec![(B, HOST_IDS + 1, 9)]);
    c.poll(3 * FIRST_WAIT_MS, 8, &mut out);
    assert_eq!(sent(&mut out), vec![(A, HOST_IDS + 2, 9)]);
    // B goes unheard for longer than a peer counts as reachable: every
    // later try goes to A, each waiting twice as long, up to the cap.
    let mut at = 3 * FIRST_WAIT_MS + PEER_TTL_MS + 1;
    c.heard(A, at);
    c.poll(at, 8, &mut out);
    assert_eq!(sent(&mut out)[0].0, A);
    for wait in [8_000, MAX_WAIT_MS, MAX_WAIT_MS] {
        c.poll(at + wait - 1, 8, &mut out);
        assert!(out.is_empty());
        at += wait;
        c.poll(at, 8, &mut out);
        assert_eq!(sent(&mut out)[0].0, A);
    }
    // Once the driver finalized past it, nothing is asked again.
    c.poll(at + MAX_WAIT_MS, 9, &mut out);
    assert!(out.is_empty());
    assert_eq!(c.in_flight(), 0);
}
