//! Several validators running the Simplex driver over the simulated network:
//! agreement on finalized blocks, liveness through a crashed leader, an
//! observer that follows without a key, gossip of a transaction to the
//! leader that includes it, validators that drifted into different views
//! meeting again, and equivocation evidence from detection to chain state.

use k256::ecdsa::SigningKey;
use solo_abi::chain::consensus::{
    KIND_FETCH, KIND_FINALIZE, KIND_PROPOSE, KIND_VOTE, MAX_EVIDENCE, TOPIC, leader, quorum,
    signing_preimage,
};
use solo_abi::chain::{
    Allocation, Certificate, ConsensusMessage, Evidence, GenesisParams, Proposal, Signature,
    SignedHash, SignedVote, SimplexState, SyncResponse, keys,
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

/// The proposal `node` holds as notarized in `view`, if any.
fn notarized_in(node: &Node, view: u64) -> Option<Proposal> {
    let persisted = node.persisted();
    let mut notar = b"notar/".to_vec();
    notar.extend_from_slice(&view.to_le_bytes());
    let mut prop = b"prop/".to_vec();
    prop.extend_from_slice(persisted.get(&notar)?);
    Some(Proposal::from_bytes(persisted.get(&prop)?).unwrap())
}

/// Whether `node` stores a proposal under `hash`.
fn holds_proposal(node: &Node, hash: &[u8; 32]) -> bool {
    let mut k = b"prop/".to_vec();
    k.extend_from_slice(hash);
    node.persisted().contains_key(&k)
}

/// The evidence `node` found that it still means to put in its proposals.
fn pending_evidence(node: &Node) -> Vec<Evidence> {
    node.persisted()
        .get(b"simplex/evidence".as_slice())
        .map(|b| Seq::<Evidence>::from_bytes(b).unwrap().0)
        .unwrap_or_default()
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
    // Run until validator 3 has led a view that node 0 notarized.
    let led_by_3 = |s: &Sim| {
        (1..simplex(s, 0).view)
            .find(|&w| leader(w, 4) == 3 && notarized_in(&s.nodes[0], w).is_some())
    };
    assert!(
        sim.run_until(20 * SLOT_MS, |s| s
            .nodes
            .iter()
            .all(|n| n.finalized.len() >= 3)
            && led_by_3(s).is_some())
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
    // A stale message is answered only when its signer delivers it: an old vote or
    // proposal replayed under other peer ids draws nothing, however many ids replay it.
    let led = led_by_3(&sim).unwrap();
    let late = notarized_in(&sim.nodes[0], led).unwrap();
    for sybil in 0..20u8 {
        let id = [0xA0 + sybil; 32];
        sim.nodes[0]
            .deliver(id, TOPIC, vote(&keys[1], 1, [0; 32]))
            .unwrap();
        sim.nodes[0]
            .deliver(id, TOPIC, propose(&keys[3], late.clone()))
            .unwrap();
        assert!(sends(&mut sim.nodes[0], &id).is_empty(), "sybil {sybil}");
    }
    sim.nodes[0]
        .deliver(third, TOPIC, vote(&keys[1], 1, [0; 32]))
        .unwrap();
    assert!(sends(&mut sim.nodes[0], &third).is_empty());
    // A late proposal from the leader that made it is a stale message like any other.
    sim.nodes[0]
        .deliver(third, TOPIC, propose(&keys[3], late))
        .unwrap();
    assert_eq!(sends(&mut sim.nodes[0], &third).len(), 1);
    assert_eq!(equivocations(&sim.nodes[0]), 0);
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
    // Each vote is the validator index the certificate claims for it, and the vote.
    let certify =
        |votes: Vec<(u32, SignedHash)>, kind: u8, view: u64, proposal: Option<Proposal>| {
            let hash = votes.first().map_or([0; 32], |v| v.1.hash);
            ConsensusMessage::Certificate {
                certificate: Certificate {
                    kind,
                    view,
                    hash,
                    votes: Seq(votes
                        .into_iter()
                        .map(|(validator, v)| SignedVote {
                            validator,
                            signature: v.signature,
                        })
                        .collect()),
                },
                proposal,
            }
            .to_bytes()
        };
    let by = |kind: u8, view: u64, hash: [u8; 32], signers: &[usize]| -> Vec<(u32, SignedHash)> {
        signers
            .iter()
            .map(|&i| {
                (
                    u32::try_from(i).unwrap(),
                    signed(&keys[i], kind, view, hash),
                )
            })
            .collect()
    };
    let timeouts = |view: u64, signers: &[usize]| by(KIND_VOTE, view, [0; 32], signers);
    let now = sim.nodes[0].now_ms();
    let proposal = Proposal {
        view: 12,
        height: 1,
        timestamp_ms: now,
        ..Proposal::default()
    };
    let hash = keccak256(&proposal.to_bytes());
    let forged = Proposal {
        timestamp_ms: now + 1,
        ..proposal.clone()
    };
    // Too few signers, a signature that does not verify, a proposal with a timeout
    // certificate, and an unknown kind all leave node 0 in view 1.
    let mut bad = timeouts(5, &[0, 1, 2]);
    bad[2].1.signature = Signature([3; 65]);
    let other = Proposal {
        view: 5,
        height: 1,
        ..Proposal::default()
    };
    // So do certificates whose shape is wrong, checked before any signature: more votes
    // than validators, however many of them verify; a validator named twice; an index
    // outside the set; and votes signed by others than the validators they name.
    let mut swollen: Vec<(u32, SignedHash)> = timeouts(5, &[0, 1, 2])
        .iter()
        .cycle()
        .take(300)
        .cloned()
        .collect();
    swollen.extend(timeouts(5, &[3]));
    let mut twice = timeouts(5, &[0, 1, 2]);
    twice.push(twice[0].clone());
    let mut outside = timeouts(5, &[0, 1]);
    outside.push((7, signed(&keys[2], KIND_VOTE, 5, [0; 32])));
    let shifted: Vec<(u32, SignedHash)> = by(KIND_VOTE, 12, hash, &[1, 2, 3])
        .into_iter()
        .map(|(i, v)| (i - 1, v))
        .collect();
    for message in [
        certify(timeouts(5, &[0, 1]), KIND_VOTE, 5, None),
        certify(bad, KIND_VOTE, 5, None),
        certify(timeouts(5, &[0, 1, 2]), KIND_VOTE, 5, Some(other)),
        certify(timeouts(5, &[0, 1, 2]), KIND_PROPOSE, 5, None),
        certify(timeouts(5, &[0, 1, 2]), KIND_FINALIZE, 5, None),
        certify(swollen, KIND_VOTE, 5, None),
        certify(twice, KIND_VOTE, 5, None),
        certify(outside, KIND_VOTE, 5, None),
        certify(shifted, KIND_VOTE, 12, Some(proposal.clone())),
    ] {
        sim.nodes[0].deliver(peer, TOPIC, message).unwrap();
        assert_eq!(simplex(&sim, 0).view, 1);
    }
    // A genuine notarization of one proposal, carrying another, is dropped whole: the
    // carried proposal never becomes the tip, nor is it stored under the notarized hash.
    sim.nodes[0]
        .deliver(
            peer,
            TOPIC,
            certify(
                by(KIND_VOTE, 12, hash, &[1, 2, 3]),
                KIND_VOTE,
                12,
                Some(forged.clone()),
            ),
        )
        .unwrap();
    let state = simplex(&sim, 0);
    assert_eq!((state.view, state.tip_height), (1, 0));
    assert_ne!(state.tip_hash, hash);
    assert!(!holds_proposal(&sim.nodes[0], &hash));
    assert!(!holds_proposal(
        &sim.nodes[0],
        &keccak256(&forged.to_bytes())
    ));
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
    sim.nodes[0]
        .deliver(
            peer,
            TOPIC,
            certify(
                by(KIND_VOTE, 12, hash, &[1, 2, 3]),
                KIND_VOTE,
                12,
                Some(proposal),
            ),
        )
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
    for i in [0, 1] {
        assert_eq!(pending_evidence(&sim.nodes[i]), Vec::new(), "node {i}");
    }
    assert_agreement(&sim, &[0, 1, 2]);
}

#[test]
fn equivocations_inside_certificates_are_detected() {
    let keys = keys(4);
    let kernel = kernel_module();
    let genesis = genesis(&keys, address(&keys[0]));
    let mut sim = Sim::new(kernel, &genesis, &keys, 0, &at(10_000), 20).unwrap();
    let byzantine = validator_id(&keys[3]);
    let node = &mut sim.nodes[1];
    let finalizes = |view: u64, hash: [u8; 32], signers: &[usize]| -> Vec<SignedVote> {
        signers
            .iter()
            .map(|&i| SignedVote {
                validator: u32::try_from(i).unwrap(),
                signature: signed(&keys[i], KIND_FINALIZE, view, hash).signature,
            })
            .collect()
    };
    // Validator 3 finalizes one hash in view 7, then shows up in a certificate for
    // another. The certificate is dropped for a later bad signature, but the vote of
    // validator 3 verified before it, which is enough to convict.
    node.deliver(byzantine, TOPIC, finalize(&keys[3], 7, [1; 32]))
        .unwrap();
    let mut votes = finalizes(7, [2; 32], &[3, 0, 2]);
    votes[1].signature = Signature([3; 65]);
    let certificate = Certificate {
        kind: KIND_FINALIZE,
        view: 7,
        hash: [2; 32],
        votes: Seq(votes),
    };
    let message = ConsensusMessage::Certificate {
        certificate,
        proposal: None,
    };
    node.deliver(byzantine, TOPIC, message.to_bytes()).unwrap();
    assert_eq!(equivocations(node), 1);
    assert_eq!(node.simplex_state().unwrap().view, 1);
    // Validator 3 finalizes one hash in view 1, then signs the finalize certificate of
    // the block a sync response delivers.
    node.deliver(byzantine, TOPIC, finalize(&keys[3], 1, [9; 32]))
        .unwrap();
    let block = Proposal {
        view: 1,
        height: 1,
        timestamp_ms: 10_000 + SLOT_MS,
        ..Proposal::default()
    };
    let hash = keccak256(&block.to_bytes());
    // A proposal two heights ahead makes node 1 ask its sender for the blocks between.
    let ahead = Proposal {
        view: 1,
        height: 3,
        ..Proposal::default()
    };
    let leader_id = validator_id(&keys[0]);
    node.deliver(leader_id, TOPIC, propose(&keys[0], ahead))
        .unwrap();
    let request_id = node
        .take_outbound()
        .into_iter()
        .find_map(|m| match m {
            Outbound::Request {
                peer, request_id, ..
            } if peer == leader_id => Some(request_id),
            _ => None,
        })
        .expect("a sync request");
    let response = SyncResponse {
        finalized_height: 1,
        proposals: Seq(vec![block]),
        certificate: Some(Certificate {
            kind: KIND_FINALIZE,
            view: 1,
            hash,
            votes: Seq(finalizes(1, hash, &[0, 2, 3])),
        }),
        threshold: vec![],
    };
    node.response(request_id, response.to_bytes()).unwrap();
    assert_eq!(equivocations(node), 2);
    assert_eq!(node.simplex_state().unwrap().finalized_height, 1);
    let mut kinds: Vec<(u8, u64)> = node
        .persisted()
        .iter()
        .filter(|(k, _)| k.starts_with(b"evidence/"))
        .map(|(_, v)| {
            let e = Evidence::from_bytes(v).unwrap();
            (e.kind, e.view)
        })
        .collect();
    kinds.sort_unstable();
    assert_eq!(kinds, vec![(KIND_FINALIZE, 1), (KIND_FINALIZE, 7)]);
}

/// Block `height` of `node` carries no transactions, yet its header's root covers the
/// evidence record `good` it kept (spec 06 §5): a proof against that header shows the
/// record and the count, a proof against the header before it shows neither.
fn assert_root_covers_evidence(node: &mut Node, height: u64, good: &Evidence) {
    let header = node.block_by_number(height).unwrap().unwrap();
    assert!(header.tx_hashes.0.is_empty());
    let before = node.block_by_number(height - 1).unwrap().unwrap();
    let proven = |node: &Node, at: u64, root: &[u8; 32], key: &[u8]| {
        node.state_proof_at(at, key)
            .unwrap()
            .verify(keccak256, root, key)
            .unwrap()
    };
    let first = [keys::EVIDENCE, &0u64.to_be_bytes()].concat();
    let count = keys::EVIDENCE_COUNT;
    assert_eq!(
        proven(node, height, &header.state_root, &first),
        Some(keccak256(&good.to_bytes()))
    );
    assert_eq!(
        proven(node, height, &header.state_root, count),
        Some(keccak256(&1u64.to_bytes()))
    );
    for key in [first.as_slice(), count] {
        assert_eq!(proven(node, height - 1, &before.state_root, key), None);
    }
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
        anchor_height: 0,
        anchor_root: [0; 32],
        txs: Seq(vec![]),
        evidence: Seq(vec![
            wrong_signer,
            no_such_validator,
            allowed,
            good.clone(),
            good.clone(),
        ]),
        dkg: Seq(vec![]),
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
    // The block carries no transactions, yet its root covers the evidence it recorded.
    assert_root_covers_evidence(&mut sim.nodes[0], height, &good);
    // A proposal with more evidence than one block may carry gets no votes.
    assert!(sim.run_until(40 * SLOT_MS, in_led_view).unwrap());
    let state = simplex(&sim, 0);
    let bloated = Proposal {
        view: state.view,
        height: state.tip_height + 1,
        parent: state.tip_hash,
        timestamp_ms: sim.now_ms.max(state.tip_timestamp_ms + 1),
        anchor_height: 0,
        anchor_root: [0; 32],
        txs: Seq(vec![]),
        evidence: Seq(vec![good; MAX_EVIDENCE + 1]),
        dkg: Seq(vec![]),
    };
    for i in 0..3 {
        sim.nodes[i]
            .deliver(byzantine, TOPIC, propose(&keys[3], bloated.clone()))
            .unwrap();
        assert!(!simplex(&sim, i).voted);
    }
    assert_agreement(&sim, &[0, 1, 2]);
}

/// A proposal a validator holds before it can vote for it gets its vote as
/// soon as it can: when the validator enters the proposal's view, and when
/// a notarization makes the proposal's parent its tip. Found by the fault
/// schedules of `consensus_fuzz.rs`: without it, a validator one message
/// behind the leader never voted in the leader's view, and with the network
/// healed and every validator honest, views whose quorum needed it timed
/// out one after another.
#[test]
fn a_held_proposal_gets_its_vote_once_it_can() {
    let keys = keys(4);
    let kernel = kernel_module();
    let genesis = genesis(&keys, address(&keys[0]));
    let mut sim = Sim::new(kernel, &genesis, &keys, 0, &at(10_000), 20).unwrap();
    // Node 3 leads none of views 1 to 3; the test hands it every message.
    let node = &mut sim.nodes[3];
    let from = |i: usize| validator_id(&keys[i]);
    let now = node.now_ms();
    let p1 = Proposal {
        view: 1,
        height: 1,
        timestamp_ms: now,
        ..Proposal::default()
    };
    let h1 = keccak256(&p1.to_bytes());
    let p2 = Proposal {
        view: 2,
        height: 2,
        parent: h1,
        timestamp_ms: now + 1,
        ..Proposal::default()
    };
    let h2 = keccak256(&p2.to_bytes());
    let p3 = Proposal {
        view: 3,
        height: 3,
        parent: h2,
        timestamp_ms: now + 2,
        ..Proposal::default()
    };
    let state = |node: &Node| node.simplex_state().unwrap();
    node.deliver(from(0), TOPIC, propose(&keys[0], p1)).unwrap();
    assert!(state(node).voted);
    // The proposal of view 2 arrives before the votes that end view 1.
    node.deliver(from(1), TOPIC, propose(&keys[1], p2.clone()))
        .unwrap();
    assert_eq!(state(node).view, 1);
    for i in [0, 1] {
        node.deliver(from(i), TOPIC, vote(&keys[i], 1, h1)).unwrap();
    }
    let s = state(node);
    assert_eq!((s.view, s.tip_height), (2, 1));
    assert!(s.voted, "entering view 2 votes for its held proposal");
    // View 2 times out here, so the tip stays at height 1, and the proposal
    // of view 3, on the proposal of view 2, does not extend it.
    for i in [0, 1, 2] {
        node.deliver(from(i), TOPIC, vote(&keys[i], 2, [0; 32]))
            .unwrap();
    }
    node.deliver(from(2), TOPIC, propose(&keys[2], p3)).unwrap();
    let s = state(node);
    assert_eq!((s.view, s.tip_height), (3, 1));
    assert!(!s.voted);
    // The notarization of view 2 arrives: its proposal becomes the tip, and
    // the held proposal of view 3 extends it.
    let certificate = ConsensusMessage::Certificate {
        certificate: Certificate {
            kind: KIND_VOTE,
            view: 2,
            hash: h2,
            votes: Seq([0usize, 1, 2]
                .iter()
                .map(|&i| SignedVote {
                    validator: u32::try_from(i).unwrap(),
                    signature: signed(&keys[i], KIND_VOTE, 2, h2).signature,
                })
                .collect()),
        },
        proposal: Some(p2),
    };
    node.deliver(from(0), TOPIC, certificate.to_bytes())
        .unwrap();
    let s = state(node);
    assert_eq!((s.view, s.tip_height), (3, 2));
    assert!(s.voted, "the new tip lets it vote for the held proposal");
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

/// A leader whose tip the other validators lack is voted for within a few
/// message delays (spec 08 §5a, tip fetching). Votes for the proposal of
/// view 1 reach only validator 1, the leader of view 2: it alone notarizes
/// view 1 and proposes on it, and the others hold neither the notarization
/// nor a tip the proposal of view 2 extends. Each asks validator 1 for its
/// tip as the proposal arrives and votes once the certificate is in. Before
/// tip fetching they waited for their view-1 timeout (3 slots, more after
/// backoff) to make their messages stale and draw the certificate that way:
/// every node finalized 840 ms after the heal, against 440 ms with it, most
/// of which is the leader of view 2 waiting out its slot.
#[test]
fn a_leader_whose_tip_the_others_lack_is_voted_promptly() {
    use std::cell::Cell;
    use std::rc::Rc;
    let keys = keys(4);
    let kernel = kernel_module();
    let genesis = genesis(&keys, address(&keys[0]));
    let mut sim = Sim::new(kernel, &genesis, &keys, 0, &at(10_000), 20).unwrap();
    // Validator 0 proposes in view 1, and its proposal reaches everyone ...
    assert!(sim.run_until(4 * SLOT_MS, |s| simplex(s, 0).voted).unwrap());
    // ... but from then on only validator 1 hears anything, the votes included, until it
    // notarizes view 1.
    let cut = Rc::new(Cell::new(true));
    let open = cut.clone();
    sim.filter_links(Some(Box::new(move |_, to, _| {
        (to == 1 || !open.get()).then_some(0)
    })));
    assert!(sim.run_until(SLOT_MS, |s| simplex(s, 1).view == 2).unwrap());
    cut.set(false);
    for i in [0, 2, 3] {
        let s = simplex(&sim, i);
        assert_eq!((s.view, s.tip_height), (1, 0), "node {i} lacks the tip");
    }
    let healed = sim.now_ms;
    assert!(
        sim.run_until(20 * SLOT_MS, |s| s
            .nodes
            .iter()
            .all(|n| !n.finalized.is_empty()))
            .unwrap()
    );
    let took = sim.now_ms - healed;
    eprintln!("every node finalized {took} ms after the heal");
    assert!(took < 2 * SLOT_MS, "{took} ms");
    assert_agreement(&sim, &[0, 1, 2, 3]);
    // Nobody timed out on the way.
    assert!((0..4).all(|i| simplex(&sim, i).backoff == 0));
}

/// A validator whose vote for a proposal it held completes that view's
/// quorum notarizes the view at once. Found by the fault schedules of
/// `consensus_fuzz.rs` (base seed 1, case 1542): a validator that entered a
/// view holding its proposal and two votes for it voted, but did not count
/// its own vote, so it timed out in a view it held the notarization of;
/// every later certificate for that view then told it nothing new, and it
/// never took the proposal as its tip.
#[test]
fn a_held_vote_that_completes_a_quorum_notarizes() {
    let keys = keys(4);
    let kernel = kernel_module();
    let genesis = genesis(&keys, address(&keys[0]));
    let mut sim = Sim::new(kernel, &genesis, &keys, 0, &at(10_000), 20).unwrap();
    let node = &mut sim.nodes[3];
    let from = |i: usize| validator_id(&keys[i]);
    let now = node.now_ms();
    let p1 = Proposal {
        view: 1,
        height: 1,
        timestamp_ms: now,
        ..Proposal::default()
    };
    let h1 = keccak256(&p1.to_bytes());
    let p2 = Proposal {
        view: 2,
        height: 2,
        parent: h1,
        timestamp_ms: now + 1,
        ..Proposal::default()
    };
    let h2 = keccak256(&p2.to_bytes());
    node.deliver(from(0), TOPIC, propose(&keys[0], p1)).unwrap();
    // The proposal of view 2 and two votes for it arrive while node 3 is in view 1.
    node.deliver(from(1), TOPIC, propose(&keys[1], p2)).unwrap();
    for i in [0, 1] {
        node.deliver(from(i), TOPIC, vote(&keys[i], 2, h2)).unwrap();
    }
    // View 1 is notarized: node 3 enters view 2, votes for the held proposal, and its
    // vote is the third.
    for i in [0, 1] {
        node.deliver(from(i), TOPIC, vote(&keys[i], 1, h1)).unwrap();
    }
    let s = node.simplex_state().unwrap();
    assert_eq!((s.view, s.tip_view, s.tip_hash), (3, 2, h2));
}

/// The messages of tip fetching (spec 08 §5a): a validator that holds the
/// leader's proposal but not its parent's notarization asks the leader,
/// once per view; the leader answers a `Fetch` its delivering validator
/// signed with its tip certificate and tip, under the budget it shares with
/// stale messages, and nothing else.
#[test]
#[allow(clippy::too_many_lines)]
fn tip_fetching_messages_are_checked_and_bounded() {
    let keys = keys(4);
    let kernel = kernel_module();
    let genesis = genesis(&keys, address(&keys[0]));
    let mut sim = Sim::new(kernel, &genesis, &keys, 0, &at(10_000), 20).unwrap();
    // Run until node 0 is the leader of its current view and holds a notarized tip.
    assert!(
        sim.run_until(20 * SLOT_MS, |s| {
            let st = simplex(s, 0);
            st.tip_height >= 2 && leader(st.view, 4) == 0 && !st.voted
        })
        .unwrap()
    );
    for node in &mut sim.nodes {
        node.take_outbound();
    }
    let st = simplex(&sim, 0);
    let view = st.view;
    let fetch = |key: &SigningKey, view: u64| ConsensusMessage::Fetch {
        view,
        signature: signed(key, KIND_FETCH, view, [0; 32]).signature,
    };
    // A validator's Fetch, delivered by that validator, draws the tip certificate and the
    // tip; the entry certificate is the tip's, so that is all.
    let asker = validator_id(&keys[2]);
    sim.nodes[0]
        .deliver(asker, TOPIC, fetch(&keys[2], view).to_bytes())
        .unwrap();
    let sent = sends(&mut sim.nodes[0], &asker);
    assert_eq!(sent.len(), 1, "{sent:?}");
    let ConsensusMessage::Certificate {
        certificate,
        proposal: Some(tip),
    } = &sent[0]
    else {
        panic!("{sent:?}")
    };
    assert_eq!(certificate.hash, st.tip_hash);
    assert_eq!(keccak256(&tip.to_bytes()), st.tip_hash);
    // Once per peer per view: again, or after a stale vote, nothing more.
    sim.nodes[0]
        .deliver(asker, TOPIC, fetch(&keys[2], view).to_bytes())
        .unwrap();
    sim.nodes[0]
        .deliver(asker, TOPIC, vote(&keys[2], 1, [0; 32]))
        .unwrap();
    assert!(sends(&mut sim.nodes[0], &asker).is_empty());
    // A Fetch replayed by another peer, signed by a non-validator, or forged, draws nothing.
    let other = validator_id(&keys[3]);
    let stranger = SigningKey::from_slice(&[0x77; 32]).unwrap();
    for m in [
        fetch(&keys[2], view),
        fetch(&stranger, view),
        ConsensusMessage::Fetch {
            view,
            signature: Signature([3; 65]),
        },
    ] {
        sim.nodes[0].deliver(other, TOPIC, m.to_bytes()).unwrap();
    }
    assert!(sends(&mut sim.nodes[0], &other).is_empty());
    // The asking side: node 1 holds a proposal of node 0 in its view on a parent it has
    // never seen, and asks node 0, once.
    let node = &mut sim.nodes[1];
    let st1 = node.simplex_state().unwrap();
    let unknown = [0xAB; 32];
    let lacking = |view: u64, parent: [u8; 32], height: u64| Proposal {
        view,
        height,
        parent,
        timestamp_ms: st1.tip_timestamp_ms + 1,
        ..Proposal::default()
    };
    let leader_of = |v: u64| leader(v, 4);
    let mut v = st1.view;
    while leader_of(v) != 0 {
        v += 1;
    }
    let leader_id = validator_id(&keys[0]);
    node.deliver(
        leader_id,
        TOPIC,
        propose(&keys[0], lacking(v, unknown, st1.tip_height + 2)),
    )
    .unwrap();
    let fetched = sends(node, &leader_id);
    assert_eq!(fetched.len(), 1, "{fetched:?}");
    let ConsensusMessage::Fetch {
        view: asked_view, ..
    } = fetched[0]
    else {
        panic!("{fetched:?}")
    };
    assert_eq!(asked_view, v);
    // Not twice in one view, not for a proposal on its own tip, nor when the leader is
    // the one behind (a parent it holds from a view at or below its tip's).
    node.deliver(
        leader_id,
        TOPIC,
        propose(&keys[0], lacking(v, [0xAC; 32], st1.tip_height + 2)),
    )
    .unwrap();
    let mut w = v + 1;
    while leader_of(w) != 0 {
        w += 1;
    }
    let tip = notarized_in(node, st1.tip_view).unwrap();
    node.deliver(
        leader_id,
        TOPIC,
        propose(&keys[0], lacking(w, tip.parent, tip.height)),
    )
    .unwrap();
    node.deliver(leader_id, TOPIC, propose(&keys[0], lacking(w, [0; 32], 1)))
        .unwrap();
    assert!(
        sends(node, &leader_id)
            .iter()
            .all(|m| !matches!(m, ConsensusMessage::Fetch { .. }))
    );
    assert!(holds_proposal(
        node,
        &keccak256(&lacking(v, unknown, st1.tip_height + 2).to_bytes())
    ));
}
