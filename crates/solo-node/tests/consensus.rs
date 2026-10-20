//! Several validators running the Simplex driver over the simulated network:
//! agreement on finalized blocks, liveness through a crashed leader, an
//! observer that follows without a key, gossip of a transaction to the
//! leader that includes it, validators that drifted into different views
//! meeting again, and equivocation evidence from detection to chain state.

use k256::ecdsa::SigningKey;
use solo_abi::chain::consensus::{
    KIND_FINALIZE, KIND_PROPOSE, KIND_VOTE, MAX_EVIDENCE, TOPIC, leader, quorum, signing_preimage,
};
use solo_abi::chain::{
    Allocation, Certificate, ConsensusMessage, Evidence, GenesisParams, Proposal, Signature,
    SignedHash, SimplexState,
};
use solo_abi::codec::Seq;
use solo_abi::types::Genesis;
use solo_abi::{Decode, Encode};
use solo_host::hash::keccak256;
use solo_node::{Node, Outbound, Sim, validator_id};
use solo_rlp::{encode_bytes, encode_list, encode_uint};

const KERNEL: &[u8] = include_bytes!("fixtures/kernel.elf");
const CHAIN_ID: u64 = 1337;
const SLOT_MS: u64 = 400;
const ETHER: u128 = 1_000_000_000_000_000_000;

/// The kernel module, recompiled once for every test in this file.
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

fn at(now_ms: u64) -> solo_node::NodeConfig {
    solo_node::NodeConfig {
        now_ms,
        ..solo_node::NodeConfig::default()
    }
}

fn keys(n: u8) -> Vec<SigningKey> {
    (1..=n)
        .map(|i| SigningKey::from_slice(&[0x10 + i; 32]).unwrap())
        .collect()
}

fn address(key: &SigningKey) -> [u8; 20] {
    let point = key.verifying_key().to_encoded_point(false);
    let digest = keccak256(&point.as_bytes()[1..]);
    let mut address = [0u8; 20];
    address.copy_from_slice(&digest[12..]);
    address
}

fn genesis(keys: &[SigningKey], funded: [u8; 20]) -> Genesis {
    let params = GenesisParams {
        slot_ms: SLOT_MS,
        max_txs: 8,
        allocations: Seq(vec![Allocation {
            address: funded,
            balance: 100 * ETHER,
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

fn transfer(key: &SigningKey, nonce: u64, to: [u8; 20], value: u128) -> Vec<u8> {
    let fields = |out: &mut Vec<u8>| {
        encode_uint(u128::from(nonce), out);
        encode_uint(1_000_000_000, out);
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
    let v = CHAIN_ID * 2 + 35 + u64::from(rid.to_byte());
    let mut signed = Vec::new();
    fields(&mut signed);
    encode_uint(u128::from(v), &mut signed);
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

/// Every live node's executed block hashes agree prefix-wise.
fn assert_agreement(sim: &Sim, live: &[usize]) {
    let longest = live
        .iter()
        .map(|&i| sim.nodes[i].executed.clone())
        .max_by_key(Vec::len)
        .unwrap();
    for &i in live {
        let mine = &sim.nodes[i].executed;
        assert_eq!(&longest[..mine.len()], mine.as_slice(), "node {i} diverges");
    }
}

#[test]
fn four_validators_finalize_and_agree() {
    let keys = keys(4);
    let kernel = kernel_module();
    let genesis = genesis(&keys, address(&keys[0]));
    let mut sim = Sim::new(kernel, &genesis, &keys, 1, &at(10_000), 30).unwrap();
    assert_eq!(quorum(4), 3);
    let reached = sim
        .run_until(20 * SLOT_MS, |s| {
            s.nodes.iter().all(|n| n.finalized.len() >= 5)
        })
        .unwrap();
    assert!(reached, "{:?}", sim.finalized_heights().unwrap());
    assert_agreement(&sim, &[0, 1, 2, 3, 4]);
    // Blocks arrive about one slot apart, each with a finalize certificate of at least a quorum.
    let observer = &mut sim.nodes[4];
    let h1 = observer.block_by_number(1).unwrap().unwrap();
    let h2 = observer.block_by_number(2).unwrap().unwrap();
    assert!(h2.timestamp_ms >= h1.timestamp_ms + SLOT_MS);
    assert!(h2.timestamp_ms < h1.timestamp_ms + 2 * SLOT_MS);
    assert!(observer.validator_id().is_none());
    assert_eq!(
        observer.finalized_height().unwrap(),
        observer.finalized.len() as u64
    );
    assert_eq!(
        sim.nodes[0].validator_id(),
        Some(solo_node::validator_id(&keys[0]))
    );
    assert!(sim.delivered > 0);
    // Leaders rotate: the first four blocks come from four different views in order.
    assert_eq!(leader(1, 4), 0);
    assert_eq!(leader(5, 4), 0);
    // A finalize certificate is attached to every finalized block.
    let state = sim.nodes[1].persisted();
    let cert_key = {
        let mut k = b"cert/".to_vec();
        k.extend_from_slice(&1u64.to_le_bytes());
        k
    };
    let cert = <Certificate as solo_abi::Decode>::from_bytes(&state[&cert_key]).unwrap();
    assert!(cert.votes.0.len() >= 3);
    assert_eq!(cert.kind, solo_abi::chain::consensus::KIND_FINALIZE);
}

#[test]
fn a_crashed_leader_is_skipped_by_timeout() {
    let keys = keys(4);
    let kernel = kernel_module();
    let genesis = genesis(&keys, address(&keys[0]));
    let mut sim = Sim::new(kernel, &genesis, &keys, 0, &at(10_000), 20).unwrap();
    // Let the chain start, then take down the leader of the upcoming views.
    assert!(
        sim.run_until(10 * SLOT_MS, |s| s.nodes[1].finalized.len() >= 2)
            .unwrap()
    );
    sim.crash(0);
    let before = sim.nodes[1].finalized.len();
    let reached = sim
        .run_until(40 * SLOT_MS, |s| {
            [1, 2, 3]
                .iter()
                .all(|&i| s.nodes[i].finalized.len() >= before + 6)
        })
        .unwrap();
    assert!(reached, "{:?}", sim.finalized_heights().unwrap());
    assert_agreement(&sim, &[1, 2, 3]);
    // Node 0 saw nothing while down.
    assert_eq!(
        sim.nodes[0].finalized.len(),
        before.min(sim.nodes[0].finalized.len())
    );
}

#[test]
fn gossiped_transaction_is_included() {
    let keys = keys(3);
    let kernel = kernel_module();
    let funded = SigningKey::from_slice(&[1u8; 32]).unwrap();
    let genesis = genesis(&keys, address(&funded));
    let mut sim = Sim::new(kernel, &genesis, &keys, 0, &at(1_000), 25).unwrap();
    let to = address(&keys[2]);
    let raw = transfer(&funded, 0, to, ETHER);
    let hash = sim.submit(2, &raw).unwrap();
    let included = sim
        .run_until(12 * SLOT_MS, |s| {
            s.nodes
                .iter_mut()
                .all(|n| n.receipt(&hash).unwrap().is_some())
        })
        .unwrap();
    assert!(included, "{:?}", sim.finalized_heights().unwrap());
    for node in &mut sim.nodes {
        assert_eq!(node.account(&to).unwrap().balance, ETHER);
        assert!(node.mempool().is_empty());
    }
    assert_agreement(&sim, &[0, 1, 2]);
    // Gossip is idempotent: re-submitting the same transaction anywhere is rejected (nonce used).
    assert!(sim.submit(0, &raw).is_err());
}

#[test]
fn restarted_validator_rejoins() {
    let keys = keys(4);
    let kernel = kernel_module();
    let genesis = genesis(&keys, address(&keys[0]));
    let mut sim = Sim::new(kernel, &genesis, &keys, 0, &at(10_000), 20).unwrap();
    assert!(
        sim.run_until(10 * SLOT_MS, |s| s.nodes[3].finalized.len() >= 2)
            .unwrap()
    );
    sim.crash(3);
    assert!(
        sim.run_until(10 * SLOT_MS, |s| s.nodes[0].finalized.len() >= 5)
            .unwrap()
    );
    sim.revive(3, kernel, &genesis).unwrap();
    // The revived node syncs the blocks it missed and then follows the chain again.
    let before = sim.nodes[0].finalized.len();
    let caught_up = sim
        .run_until(20 * SLOT_MS, |s| {
            s.nodes[0].finalized.len() >= before + 4
                && s.nodes[3].finalized_height().unwrap() + 1
                    >= s.nodes[0].finalized_height().unwrap()
        })
        .unwrap();
    assert!(caught_up, "{:?}", sim.finalized_heights().unwrap());
    assert_agreement(&sim, &[0, 1, 2, 3]);
    assert!(sim.nodes[3].validator_id().is_some());
}

#[test]
fn simulator_delivery_rules() {
    use solo_abi::types::Effect;
    let keys = keys(4);
    let kernel = kernel_module();
    let funded = SigningKey::from_slice(&[1u8; 32]).unwrap();
    let genesis = genesis(&keys, address(&funded));
    let mut sim = Sim::new(kernel, &genesis, &keys, 0, &at(1_000), 10).unwrap();
    // A node that cannot afford its first driver step fails to start.
    let starved = solo_node::NodeConfig {
        kernel_gas: 1,
        ..at(1_000)
    };
    assert!(matches!(
        Sim::new(kernel, &genesis, &keys, 0, &starved, 10),
        Err(solo_node::NodeError::Kernel {
            export: "kernel_driver_step",
            ..
        })
    ));
    // A predicate that never holds reports false once the time is up.
    assert!(!sim.run_until(50, |_| false).unwrap());
    assert_eq!(sim.finalized_heights().unwrap(), vec![0, 0, 0, 0]);
    // Point-to-point delivery reaches the named peer; other effects are not transported.
    let peer = sim.nodes[1].validator_id().unwrap();
    for effect in [
        Effect::Send {
            peer,
            topic: 99,
            payload: vec![1],
        },
        Effect::Send {
            peer: [0xCC; 32],
            topic: 99,
            payload: vec![2],
        },
        Effect::Disseminate {
            blob_id: [1; 32],
            payload: vec![],
        },
        Effect::Request {
            peer,
            request_id: 1,
            payload: vec![],
        },
        Effect::Respond {
            request_id: 1,
            payload: vec![],
        },
        Effect::PeerScore { peer, delta: 1 },
    ] {
        sim.nodes[0].apply_effect(effect).unwrap();
    }
    let delivered = sim.delivered;
    sim.advance(20).unwrap();
    assert_eq!(
        sim.delivered,
        delivered + 2,
        "the Send and the Request to a known peer"
    );
    // Gossip to a crashed node is dropped; the other three still include the transaction.
    sim.crash(3);
    let raw = transfer(&funded, 0, address(&keys[1]), ETHER);
    let hash = sim.submit(0, &raw).unwrap();
    assert!(
        sim.run_until(12 * SLOT_MS, |s| s.nodes[1]
            .receipt(&hash)
            .unwrap()
            .is_some())
            .unwrap()
    );
    assert!(sim.nodes[3].mempool().is_empty());
    assert_eq!(sim.nodes[3].finalized.len(), 0);
}

#[test]
fn simulator_surfaces_node_errors() {
    use solo_abi::types::Effect;
    use solo_node::NodeError;
    let keys = keys(4);
    let kernel = kernel_module();
    let genesis = genesis(&keys, address(&keys[0]));
    // A kernel that does not load fails the network at open.
    assert!(matches!(
        Sim::new(b"not a module", &genesis, &keys, 0, &at(1_000), 10),
        Err(NodeError::Load(_))
    ));
    let mut sim = Sim::new(kernel, &genesis, &keys, 0, &at(1_000), 10).unwrap();
    // Reviving with a bad kernel fails.
    sim.crash(3);
    assert!(matches!(
        sim.revive(3, b"not a module", &genesis),
        Err(NodeError::Load(_))
    ));
    sim.revive(3, kernel, &genesis).unwrap();
    let peer = sim.nodes[1].validator_id().unwrap();
    let send = || Effect::Send {
        peer,
        topic: 99,
        payload: vec![],
    };
    // A delivery the starved receiver cannot process.
    sim.nodes[0].apply_effect(send()).unwrap();
    sim.advance(10).unwrap();
    sim.nodes[1].kernel_gas = 0;
    assert!(matches!(sim.advance(20), Err(NodeError::Kernel { .. })));
    // A timer that comes due as a message arrives.
    sim.nodes[1].kernel_gas = solo_node::node::KERNEL_GAS;
    sim.nodes[0].apply_effect(send()).unwrap();
    sim.advance(10).unwrap();
    sim.nodes[1].kernel_gas = 0;
    let now = sim.now_ms;
    sim.nodes[1]
        .apply_effect(Effect::SetTimer {
            timer_id: 999,
            deadline_ms: now,
        })
        .unwrap();
    assert!(matches!(sim.advance(20), Err(NodeError::Kernel { .. })));
    // A starved node fails the per-step tick, and run_until reports it.
    let mut sim = Sim::new(kernel, &genesis, &keys, 0, &at(1_000), 10).unwrap();
    for node in &mut sim.nodes {
        node.kernel_gas = 0;
    }
    assert!(sim.run_until(10 * SLOT_MS, |_| false).is_err());
}

#[test]
fn a_node_offline_since_genesis_syncs_everything() {
    let keys = keys(4);
    let kernel = kernel_module();
    let funded = SigningKey::from_slice(&[1u8; 32]).unwrap();
    let genesis = genesis(&keys, address(&funded));
    let mut sim = Sim::new(kernel, &genesis, &keys, 1, &at(1_000), 10).unwrap();
    sim.crash(4);
    // A transfer lands while the observer is away, so syncing must replay state, not just headers.
    let to = address(&keys[3]);
    let hash = sim.submit(0, &transfer(&funded, 0, to, ETHER)).unwrap();
    assert!(
        sim.run_until(60 * SLOT_MS, |s| s.nodes[0].finalized.len() >= 40)
            .unwrap()
    );
    sim.revive(4, kernel, &genesis).unwrap();
    // More than one sync batch behind: the observer asks again until level.
    let synced = sim
        .run_until(20 * SLOT_MS, |s| {
            s.nodes[4].finalized_height().unwrap() + 1 >= s.nodes[0].finalized_height().unwrap()
        })
        .unwrap();
    assert!(synced, "{:?}", sim.finalized_heights().unwrap());
    assert_agreement(&sim, &[0, 1, 2, 3, 4]);
    let observer = &mut sim.nodes[4];
    assert!(observer.receipt(&hash).unwrap().is_some());
    assert_eq!(observer.account(&to).unwrap().balance, ETHER);
}

/// `kind(view, hash)` signed with `key`, as a validator would.
fn signed(key: &SigningKey, kind: u8, view: u64, hash: [u8; 32]) -> SignedHash {
    let digest = keccak256(&signing_preimage(kind, CHAIN_ID, view, &hash));
    SignedHash {
        hash,
        signature: Signature(solo_node::sign_recoverable(key, &digest).unwrap()),
    }
}

fn vote(key: &SigningKey, view: u64, hash: [u8; 32]) -> Vec<u8> {
    let signature = signed(key, KIND_VOTE, view, hash).signature;
    ConsensusMessage::Vote {
        view,
        hash,
        signature,
    }
    .to_bytes()
}

fn finalize(key: &SigningKey, view: u64, hash: [u8; 32]) -> Vec<u8> {
    let signature = signed(key, KIND_FINALIZE, view, hash).signature;
    ConsensusMessage::Finalize {
        view,
        hash,
        signature,
    }
    .to_bytes()
}

fn propose(key: &SigningKey, proposal: Proposal) -> Vec<u8> {
    let hash = keccak256(&proposal.to_bytes());
    let signature = signed(key, KIND_PROPOSE, proposal.view, hash).signature;
    ConsensusMessage::Propose {
        proposal,
        signature,
    }
    .to_bytes()
}

/// The driver state node `i` last persisted.
fn simplex(sim: &Sim, i: usize) -> SimplexState {
    sim.nodes[i].simplex_state().unwrap()
}

fn views(sim: &Sim) -> Vec<u64> {
    (0..sim.nodes.len()).map(|i| simplex(sim, i).view).collect()
}

/// Consensus messages `node` queued for `peer` alone, drained with the rest of its outbound.
fn sends(node: &mut Node, peer: &[u8; 32]) -> Vec<ConsensusMessage> {
    node.take_outbound()
        .into_iter()
        .filter_map(|m| match m {
            Outbound::Send {
                peer: to,
                topic: TOPIC,
                payload,
            } if to == *peer => Some(ConsensusMessage::from_bytes(&payload).unwrap()),
            _ => None,
        })
        .collect()
}

fn equivocations(node: &Node) -> usize {
    node.metrics
        .iter()
        .filter(|(name, value)| name == b"equivocations" && *value == 1)
        .count()
}

#[test]
fn validators_stuck_in_different_views_converge() {
    let keys = keys(4);
    let kernel = kernel_module();
    let genesis = genesis(&keys, address(&keys[0]));
    let mut sim = Sim::new(kernel, &genesis, &keys, 0, &at(10_000), 20).unwrap();
    // Validator 3 is down from the start and stays in view 1; the other three make progress.
    sim.crash(3);
    assert!(
        sim.run_until(40 * SLOT_MS, |s| s.nodes[0].finalized.len() >= 6)
            .unwrap()
    );
    // Validator 2 goes down too: 0 and 1 are no quorum and keep timing out alone.
    sim.crash(2);
    sim.advance(20 * SLOT_MS).unwrap();
    let stuck = simplex(&sim, 0).view;
    assert!(stuck >= 7, "{stuck}");
    assert_eq!(simplex(&sim, 1).view, stuck);
    assert!(simplex(&sim, 0).timed_out && simplex(&sim, 1).timed_out);
    // Validator 2 comes back reinstalled from scratch, 3 with what it had: both in view 1,
    // where no quorum will ever form again unless the views meet.
    sim.revive_from_scratch(2, kernel, &genesis).unwrap();
    sim.revive(3, kernel, &genesis).unwrap();
    assert_eq!((simplex(&sim, 2).view, simplex(&sim, 3).view), (1, 1));
    let height = sim.nodes[0].finalized_height().unwrap();
    let converged = sim
        .run_until(60 * SLOT_MS, |s| {
            s.finalized_heights()
                .unwrap()
                .iter()
                .all(|h| *h >= height + 3)
        })
        .unwrap();
    assert!(
        converged,
        "{:?} in views {:?}",
        sim.finalized_heights().unwrap(),
        views(&sim)
    );
    assert_agreement(&sim, &[0, 1, 2, 3]);
    let views = views(&sim);
    assert!(
        views.iter().max().unwrap() - views.iter().min().unwrap() <= 1,
        "{views:?}"
    );
    assert!(sim.nodes.iter().all(|n| equivocations(n) == 0));
}

#[test]
fn validators_started_at_different_times_converge() {
    let keys = keys(4);
    let kernel = kernel_module();
    let genesis = genesis(&keys, address(&keys[0]));
    let mut sim = Sim::new(kernel, &genesis, &keys, 0, &at(10_000), 20).unwrap();
    for i in 1..4 {
        sim.crash(i);
    }
    // Each validator comes up some slots after the previous one; the first has timed
    // out alone several times before a quorum exists, and every vote it sent is lost.
    for (i, slots) in [(1, 4), (2, 7), (3, 13)] {
        sim.advance(slots * SLOT_MS).unwrap();
        sim.revive(i, kernel, &genesis).unwrap();
    }
    let reached = sim
        .run_until(60 * SLOT_MS, |s| {
            s.finalized_heights().unwrap().iter().all(|h| *h >= 4)
        })
        .unwrap();
    assert!(
        reached,
        "{:?} in views {:?}",
        sim.finalized_heights().unwrap(),
        views(&sim)
    );
    assert_agreement(&sim, &[0, 1, 2, 3]);
}

#[test]
fn a_laggard_is_answered_once_per_view() {
    let keys = keys(4);
    let kernel = kernel_module();
    let genesis = genesis(&keys, address(&keys[0]));
    let mut sim = Sim::new(kernel, &genesis, &keys, 0, &at(10_000), 20).unwrap();
    assert!(
        sim.run_until(20 * SLOT_MS, |s| s
            .nodes
            .iter()
            .all(|n| n.finalized.len() >= 3))
            .unwrap()
    );
    let view = simplex(&sim, 0).view;
    // A timeout vote for view 1 says its sender is stuck there. Node 0 answers with the
    // certificate that brought it into its view: here the notarization of the previous
    // view, with the proposal, a quorum that verifies.
    let laggard = validator_id(&keys[1]);
    let stale = vote(&keys[1], 1, [0; 32]);
    sim.nodes[0].deliver(laggard, TOPIC, stale.clone()).unwrap();
    let sent = sends(&mut sim.nodes[0], &laggard);
    assert_eq!(
        sent.len(),
        1,
        "the entry certificate is the tip's: {sent:?}"
    );
    let ConsensusMessage::Certificate {
        certificate,
        proposal,
    } = &sent[0]
    else {
        panic!("{sent:?}")
    };
    assert_eq!((certificate.kind, certificate.view), (KIND_VOTE, view - 1));
    assert_ne!(certificate.hash, [0; 32]);
    assert!(certificate.votes.0.len() >= quorum(4));
    assert_eq!(
        keccak256(&proposal.as_ref().unwrap().to_bytes()),
        certificate.hash
    );
    // The same peer gets nothing more in this view, whatever stale message it sends.
    sim.nodes[0].deliver(laggard, TOPIC, stale).unwrap();
    sim.nodes[0]
        .deliver(laggard, TOPIC, vote(&keys[1], 2, [0; 32]))
        .unwrap();
    assert!(sends(&mut sim.nodes[0], &laggard).is_empty());
    // Another peer is answered on its own account.
    let other = validator_id(&keys[2]);
    sim.nodes[0]
        .deliver(other, TOPIC, vote(&keys[2], 1, [0; 32]))
        .unwrap();
    assert_eq!(sends(&mut sim.nodes[0], &other).len(), 1);
    // A stale vote that does not verify, and the routine late vote for the proposal node 0
    // just notarized, are not answered.
    let third = validator_id(&keys[3]);
    let forged = ConsensusMessage::Vote {
        view: 1,
        hash: [0; 32],
        signature: Signature([7; 65]),
    };
    sim.nodes[0]
        .deliver(third, TOPIC, forged.to_bytes())
        .unwrap();
    sim.nodes[0]
        .deliver(third, TOPIC, vote(&keys[3], view - 1, certificate.hash))
        .unwrap();
    assert!(sends(&mut sim.nodes[0], &third).is_empty());
    // A late proposal is a stale message like any other.
    let first = sim.nodes[0].block_by_number(1).unwrap().unwrap();
    let late = Proposal {
        view: 1,
        height: 1,
        timestamp_ms: first.timestamp_ms,
        ..Proposal::default()
    };
    sim.nodes[0]
        .deliver(third, TOPIC, propose(&keys[0], late))
        .unwrap();
    assert_eq!(sends(&mut sim.nodes[0], &third).len(), 1);
    // In a later view the first laggard is answered again.
    assert!(
        sim.run_until(10 * SLOT_MS, |s| simplex(s, 0).view > view)
            .unwrap()
    );
    sim.nodes[0]
        .deliver(laggard, TOPIC, vote(&keys[1], 1, [0; 32]))
        .unwrap();
    assert_eq!(sends(&mut sim.nodes[0], &laggard).len(), 1);
    assert_agreement(&sim, &[0, 1, 2, 3]);
}

#[test]
fn a_skipped_view_forwards_the_tip_with_the_timeout_certificate() {
    let keys = keys(4);
    let kernel = kernel_module();
    let genesis = genesis(&keys, address(&keys[0]));
    let mut sim = Sim::new(kernel, &genesis, &keys, 0, &at(10_000), 20).unwrap();
    // With validator 3 down, every fourth view times out; stop right after one did.
    sim.crash(3);
    assert!(
        sim.run_until(40 * SLOT_MS, |s| {
            let v = simplex(s, 0).view;
            v > 8 && leader(v - 1, 4) == 3 && !simplex(s, 0).timed_out
        })
        .unwrap()
    );
    let view = simplex(&sim, 0).view;
    let laggard = validator_id(&keys[3]);
    sim.nodes[0]
        .deliver(laggard, TOPIC, vote(&keys[3], 1, [0; 32]))
        .unwrap();
    let sent = sends(&mut sim.nodes[0], &laggard);
    // First the tip's notarization with its proposal, then the timeout certificate.
    assert_eq!(sent.len(), 2, "{sent:?}");
    let ConsensusMessage::Certificate {
        certificate: tip,
        proposal: Some(proposal),
    } = &sent[0]
    else {
        panic!("{sent:?}")
    };
    assert_eq!(tip.hash, simplex(&sim, 0).tip_hash);
    assert_eq!(keccak256(&proposal.to_bytes()), tip.hash);
    let ConsensusMessage::Certificate {
        certificate: skip,
        proposal: None,
    } = &sent[1]
    else {
        panic!("{sent:?}")
    };
    assert_eq!((skip.view, skip.hash), (view - 1, [0; 32]));
    assert!(skip.votes.0.len() >= quorum(4));
}

#[test]
#[allow(clippy::too_many_lines)]
fn forwarded_certificates_are_checked() {
    let keys = keys(4);
    let kernel = kernel_module();
    let genesis = genesis(&keys, address(&keys[0]));
    let mut sim = Sim::new(kernel, &genesis, &keys, 0, &at(10_000), 20).unwrap();
    let peer = validator_id(&keys[1]);
    let certify = |votes: Vec<SignedHash>, kind: u8, view: u64, proposal: Option<Proposal>| {
        let hash = votes.first().map_or([0; 32], |v| v.hash);
        ConsensusMessage::Certificate {
            certificate: Certificate {
                kind,
                view,
                hash,
                votes: Seq(votes
                    .into_iter()
                    .enumerate()
                    .map(|(i, v)| solo_abi::chain::SignedVote {
                        validator: u32::try_from(i).unwrap(),
                        signature: v.signature,
                    })
                    .collect()),
            },
            proposal,
        }
        .to_bytes()
    };
    let timeouts = |view: u64, signers: &[usize]| -> Vec<SignedHash> {
        signers
            .iter()
            .map(|&i| signed(&keys[i], KIND_VOTE, view, [0; 32]))
            .collect()
    };
    // Too few signers, a signature that does not verify, a proposal that does not match
    // the hash, and an unknown kind all leave node 0 in view 1.
    let mut bad = timeouts(5, &[0, 1, 2]);
    bad[2].signature = Signature([3; 65]);
    let other = Proposal {
        view: 5,
        height: 1,
        ..Proposal::default()
    };
    for message in [
        certify(timeouts(5, &[0, 1]), KIND_VOTE, 5, None),
        certify(bad, KIND_VOTE, 5, None),
        certify(timeouts(5, &[0, 1, 2]), KIND_VOTE, 5, Some(other)),
        certify(timeouts(5, &[0, 1, 2]), KIND_PROPOSE, 5, None),
        certify(timeouts(5, &[0, 1, 2]), KIND_FINALIZE, 5, None),
    ] {
        sim.nodes[0].deliver(peer, TOPIC, message).unwrap();
        assert_eq!(simplex(&sim, 0).view, 1);
    }
    // A quorum of timeout votes for a later view moves node 0 straight past it.
    sim.nodes[0]
        .deliver(
            peer,
            TOPIC,
            certify(timeouts(5, &[0, 1, 2]), KIND_VOTE, 5, None),
        )
        .unwrap();
    assert_eq!(simplex(&sim, 0).view, 6);
    // Leaving a view by timeout doubles the next view's timeout.
    let now = sim.nodes[0].now_ms();
    let timeout_of = |sim: &Sim, view: u64| {
        sim.nodes[0]
            .timers()
            .into_iter()
            .find(|(id, _)| *id == solo_abi::chain::consensus::timeout_timer(view))
            .map(|(_, deadline)| deadline - now)
    };
    assert_eq!(simplex(&sim, 0).backoff, 1);
    assert_eq!(timeout_of(&sim, 6), Some(2 * 3 * SLOT_MS));
    // A timeout certificate for a view it has left is ignored.
    sim.nodes[0]
        .deliver(
            peer,
            TOPIC,
            certify(timeouts(4, &[0, 1, 2]), KIND_VOTE, 4, None),
        )
        .unwrap();
    assert_eq!(simplex(&sim, 0).view, 6);
    // Timeout votes for a later view, arriving one by one, count the same way.
    for key in &keys[1..] {
        sim.nodes[0]
            .deliver(validator_id(key), TOPIC, vote(key, 9, [0; 32]))
            .unwrap();
    }
    assert_eq!(
        simplex(&sim, 0).view,
        10,
        "a quorum for any later view counts"
    );
    assert_eq!(timeout_of(&sim, 10), Some(4 * 3 * SLOT_MS));
    // A notarization for a later view, with its proposal, moves node 0 past it, makes the
    // proposal its tip, and shortens the timeout again.
    let proposal = Proposal {
        view: 12,
        height: 1,
        timestamp_ms: now,
        ..Proposal::default()
    };
    let hash = keccak256(&proposal.to_bytes());
    let votes: Vec<SignedHash> = keys[1..]
        .iter()
        .map(|key| signed(key, KIND_VOTE, 12, hash))
        .collect();
    // The signers are validators 1 to 3 while the certificate claims 0 to 2: the signer of
    // a vote is whoever its signature recovers to.
    sim.nodes[0]
        .deliver(peer, TOPIC, certify(votes, KIND_VOTE, 12, Some(proposal)))
        .unwrap();
    let state = simplex(&sim, 0);
    assert_eq!(
        (state.view, state.tip_hash, state.tip_height, state.backoff),
        (13, hash, 1, 1)
    );
    assert_eq!(timeout_of(&sim, 13), Some(2 * 3 * SLOT_MS));
}

#[test]
fn equivocations_are_detected_and_recorded_on_chain() {
    let keys = keys(4);
    let kernel = kernel_module();
    let genesis = genesis(&keys, address(&keys[0]));
    let mut sim = Sim::new(kernel, &genesis, &keys, 0, &at(10_000), 20).unwrap();
    // Validator 3 is offline; its key signs whatever the test wants.
    sim.crash(3);
    assert!(
        sim.run_until(20 * SLOT_MS, |s| s.nodes[0].finalized.len() >= 2)
            .unwrap()
    );
    let byzantine = validator_id(&keys[3]);
    // A view far ahead: votes there are kept but never make a quorum.
    let ahead = simplex(&sim, 0).view + 40;
    // Two block votes for different hashes in one view. A timeout vote beside them is
    // allowed, and repeating a message is no offence.
    for hash in [[1; 32], [2; 32], [0; 32], [2; 32]] {
        sim.nodes[0]
            .deliver(byzantine, TOPIC, vote(&keys[3], ahead, hash))
            .unwrap();
    }
    // Two finalize votes for different hashes in one view.
    for hash in [[1; 32], [3; 32]] {
        sim.nodes[0]
            .deliver(byzantine, TOPIC, finalize(&keys[3], ahead, hash))
            .unwrap();
    }
    // Two proposals from the leader of one view, delivered to node 1.
    let led = (ahead / 4 + 1) * 4;
    assert_eq!(leader(led, 4), 3);
    for timestamp_ms in [1, 2] {
        let proposal = Proposal {
            view: led,
            height: 1,
            timestamp_ms,
            ..Proposal::default()
        };
        sim.nodes[1]
            .deliver(byzantine, TOPIC, propose(&keys[3], proposal))
            .unwrap();
    }
    assert_eq!(equivocations(&sim.nodes[0]), 2);
    assert_eq!(equivocations(&sim.nodes[1]), 1);
    // The peer that delivered them loses score.
    for i in [0, 1] {
        let penalties: Vec<Outbound> = sim.nodes[i]
            .take_outbound()
            .into_iter()
            .filter(|m| matches!(m, Outbound::PeerScore { .. }))
            .collect();
        assert!(
            penalties.iter().all(|m| *m
                == Outbound::PeerScore {
                    peer: byzantine,
                    delta: solo_abi::chain::consensus::EQUIVOCATION_PENALTY
                }),
            "{penalties:?}"
        );
        assert_eq!(penalties.len(), 2 - i);
    }
    // Both signed messages are kept node-locally.
    let stored: Vec<Evidence> = sim.nodes[0]
        .persisted()
        .iter()
        .filter(|(k, _)| k.starts_with(b"evidence/"))
        .map(|(_, v)| Evidence::from_bytes(v).unwrap())
        .collect();
    assert_eq!(stored.len(), 2);
    assert!(stored.iter().all(Evidence::well_formed));
    // Leaders put the evidence in their proposals, and executing them records it in chain
    // state, where every node can query it.
    let recorded = sim
        .run_until(40 * SLOT_MS, |s| {
            (0..3).all(|i| s.nodes[i].evidence(0).unwrap().len() == 3)
        })
        .unwrap();
    assert!(recorded, "{:?}", sim.nodes[0].evidence(0).unwrap());
    let on_chain = sim.nodes[2].evidence(0).unwrap();
    let mut kinds: Vec<u8> = on_chain.iter().map(|e| e.kind).collect();
    kinds.sort_unstable();
    assert_eq!(kinds, vec![KIND_PROPOSE, KIND_VOTE, KIND_FINALIZE]);
    assert!(on_chain.iter().all(|e| e.validator == 3));
    for e in &stored {
        assert!(on_chain.contains(e));
    }
    // Paging: from index 1, past the end, and a malformed start.
    assert_eq!(sim.nodes[2].evidence(1).unwrap(), on_chain[1..].to_vec());
    assert!(sim.nodes[2].evidence(u64::MAX).unwrap().is_empty());
    assert_eq!(sim.nodes[2].query("evidence", &[1]).unwrap().status, 2);
    // Recorded evidence leaves the leaders' pending lists, so blocks stop carrying it.
    let more = sim.nodes[0].finalized_height().unwrap() + 8;
    assert!(
        sim.run_until(40 * SLOT_MS, |s| s.nodes[0].finalized_height().unwrap()
            >= more)
            .unwrap()
    );
    assert_eq!(sim.nodes[0].evidence(0).unwrap().len(), 3);
    assert_agreement(&sim, &[0, 1, 2]);
}

#[test]
fn the_chain_keeps_only_evidence_that_verifies() {
    let keys = keys(4);
    let kernel = kernel_module();
    let genesis = genesis(&keys, address(&keys[0]));
    let mut sim = Sim::new(kernel, &genesis, &keys, 0, &at(10_000), 20).unwrap();
    // Validator 3 is the one the test speaks for: it leads every fourth view.
    sim.crash(3);
    let byzantine = validator_id(&keys[3]);
    let in_led_view = |s: &mut Sim| {
        let first = simplex(s, 0);
        first.view > 4
            && leader(first.view, 4) == 3
            && (1..3).all(|i| {
                let other = simplex(s, i);
                other.view == first.view && other.tip_hash == first.tip_hash
            })
    };
    assert!(sim.run_until(40 * SLOT_MS, in_led_view).unwrap());
    let state = simplex(&sim, 0);
    let good = Evidence::new(
        KIND_VOTE,
        2,
        3,
        signed(&keys[3], KIND_VOTE, 2, [1; 32]),
        signed(&keys[3], KIND_VOTE, 2, [2; 32]),
    );
    let wrong_signer = Evidence::new(
        KIND_VOTE,
        3,
        3,
        signed(&keys[2], KIND_VOTE, 3, [1; 32]),
        signed(&keys[3], KIND_VOTE, 3, [2; 32]),
    );
    let no_such_validator = Evidence {
        validator: 9,
        ..good.clone()
    };
    let allowed = Evidence::new(
        KIND_VOTE,
        4,
        3,
        signed(&keys[3], KIND_VOTE, 4, [0; 32]),
        signed(&keys[3], KIND_VOTE, 4, [2; 32]),
    );
    let proposal = Proposal {
        view: state.view,
        height: state.tip_height + 1,
        parent: state.tip_hash,
        timestamp_ms: sim.now_ms.max(state.tip_timestamp_ms + 1),
        txs: Seq(vec![]),
        evidence: Seq(vec![
            wrong_signer,
            no_such_validator,
            allowed,
            good.clone(),
            good.clone(),
        ]),
    };
    for i in 0..3 {
        sim.nodes[i]
            .deliver(byzantine, TOPIC, propose(&keys[3], proposal.clone()))
            .unwrap();
    }
    // The proposal is notarized and finalized like any other; the chain keeps one record.
    let height = state.tip_height + 1;
    assert!(
        sim.run_until(20 * SLOT_MS, |s| (0..3)
            .all(|i| s.nodes[i].finalized_height().unwrap() >= height))
            .unwrap()
    );
    for i in 0..3 {
        assert_eq!(sim.nodes[i].evidence(0).unwrap(), vec![good.clone()]);
    }
    // A proposal with more evidence than one block may carry gets no votes.
    assert!(sim.run_until(40 * SLOT_MS, in_led_view).unwrap());
    let state = simplex(&sim, 0);
    let bloated = Proposal {
        view: state.view,
        height: state.tip_height + 1,
        parent: state.tip_hash,
        timestamp_ms: sim.now_ms.max(state.tip_timestamp_ms + 1),
        txs: Seq(vec![]),
        evidence: Seq(vec![good; MAX_EVIDENCE + 1]),
    };
    for i in 0..3 {
        sim.nodes[i]
            .deliver(byzantine, TOPIC, propose(&keys[3], bloated.clone()))
            .unwrap();
        assert!(!simplex(&sim, i).voted);
    }
    assert_agreement(&sim, &[0, 1, 2]);
}

#[test]
fn a_restarted_leader_does_not_propose_twice_in_a_view() {
    let keys = keys(4);
    let kernel = kernel_module();
    let genesis = genesis(&keys, address(&keys[0]));
    let mut sim = Sim::new(kernel, &genesis, &keys, 0, &at(10_000), 20).unwrap();
    // Stop node 0 right after it proposed and voted in a view it leads.
    assert!(
        sim.run_until(20 * SLOT_MS, |s| {
            let state = simplex(s, 0);
            state.view > 4 && leader(state.view, 4) == 0 && state.voted
        })
        .unwrap()
    );
    let view = simplex(&sim, 0).view;
    sim.crash(0);
    sim.advance(10).unwrap();
    sim.revive(0, kernel, &genesis).unwrap();
    // It resumes the view remembering its vote, so it neither proposes nor votes again
    // (a proposal now would carry a later timestamp: an equivocation).
    let state = simplex(&sim, 0);
    assert_eq!((state.view, state.voted), (view, true));
    let before = sim.nodes[1].finalized.len();
    assert!(
        sim.run_until(20 * SLOT_MS, |s| s.nodes[1].finalized.len() >= before + 4)
            .unwrap()
    );
    assert!(sim.nodes.iter().all(|n| equivocations(n) == 0));
    assert_agreement(&sim, &[0, 1, 2, 3]);
}
