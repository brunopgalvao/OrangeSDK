//! Several validators running the Simplex driver over the simulated network:
//! agreement on finalized blocks, liveness through a crashed leader, an
//! observer that follows without a key, and gossip of a transaction to the
//! leader that includes it.

use k256::ecdsa::SigningKey;
use solo_abi::Encode;
use solo_abi::chain::consensus::{leader, quorum};
use solo_abi::chain::{Allocation, Certificate, GenesisParams};
use solo_abi::codec::Seq;
use solo_abi::types::Genesis;
use solo_host::hash::keccak256;
use solo_node::Sim;
use solo_rlp::{encode_bytes, encode_list, encode_uint};

const KERNEL: &[u8] = include_bytes!("fixtures/kernel.elf");
const CHAIN_ID: u64 = 1337;
const SLOT_MS: u64 = 400;
const ETHER: u128 = 1_000_000_000_000_000_000;

fn kernel_module() -> Vec<u8> {
    solo_recompile::recompile(
        &solo_recompile::Input::load(KERNEL).unwrap(),
        &solo_recompile::Options::default(),
    )
    .unwrap()
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
    let mut sim = Sim::new(&kernel, &genesis, &keys, 1, &at(10_000), 30).unwrap();
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
    let mut sim = Sim::new(&kernel, &genesis, &keys, 0, &at(10_000), 20).unwrap();
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
    let mut sim = Sim::new(&kernel, &genesis, &keys, 0, &at(1_000), 25).unwrap();
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
    let mut sim = Sim::new(&kernel, &genesis, &keys, 0, &at(10_000), 20).unwrap();
    assert!(
        sim.run_until(10 * SLOT_MS, |s| s.nodes[3].finalized.len() >= 2)
            .unwrap()
    );
    sim.crash(3);
    assert!(
        sim.run_until(10 * SLOT_MS, |s| s.nodes[0].finalized.len() >= 5)
            .unwrap()
    );
    sim.revive(3, &kernel, &genesis).unwrap();
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
    let mut sim = Sim::new(&kernel, &genesis, &keys, 0, &at(1_000), 10).unwrap();
    // A node that cannot afford its first driver step fails to start.
    let starved = solo_node::NodeConfig {
        kernel_gas: 1,
        ..at(1_000)
    };
    assert!(matches!(
        Sim::new(&kernel, &genesis, &keys, 0, &starved, 10),
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
    let mut sim = Sim::new(&kernel, &genesis, &keys, 0, &at(1_000), 10).unwrap();
    // Reviving with a bad kernel fails.
    sim.crash(3);
    assert!(matches!(
        sim.revive(3, b"not a module", &genesis),
        Err(NodeError::Load(_))
    ));
    sim.revive(3, &kernel, &genesis).unwrap();
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
    let mut sim = Sim::new(&kernel, &genesis, &keys, 0, &at(1_000), 10).unwrap();
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
    let mut sim = Sim::new(&kernel, &genesis, &keys, 1, &at(1_000), 10).unwrap();
    sim.crash(4);
    // A transfer lands while the observer is away, so syncing must replay state, not just headers.
    let to = address(&keys[3]);
    let hash = sim.submit(0, &transfer(&funded, 0, to, ETHER)).unwrap();
    assert!(
        sim.run_until(60 * SLOT_MS, |s| s.nodes[0].finalized.len() >= 40)
            .unwrap()
    );
    sim.revive(4, &kernel, &genesis).unwrap();
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
