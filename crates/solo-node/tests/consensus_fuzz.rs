//! Seeded schedules of faults for the Simplex driver (spec 08) over the
//! simulated network: partitions, lossy links, delays that reorder
//! messages, and validators crashing and restarting from what they
//! persisted, in random phases. Safety always holds: no two nodes ever
//! finalize different blocks at one height. Liveness holds once the faults
//! end: with the network healed and every validator back, every node
//! finalizes new blocks. See `solo-fuzz` for the long mode (each case is a
//! few seconds of a debug build).

use std::collections::BTreeMap;

use k256::ecdsa::SigningKey;
use solo_abi::Encode;
use solo_abi::chain::GenesisParams;
use solo_abi::codec::Seq;
use solo_abi::types::Genesis;
use solo_fuzz::Rng;
use solo_node::{NodeConfig, Sim};

const KERNEL: &[u8] = include_bytes!("fixtures/kernel.elf");
const SLOT_MS: u64 = 400;
const VALIDATORS: usize = 4;
/// How long a healed network may take to finalize again. The faults leave
/// the views' timeouts backed off, up to `48 × slot_ms` (spec 08 §5a); the
/// view in progress at the heal may run out one such timeout, and a leader
/// whose tip the others lack is voted once they have fetched it (§5a), a
/// message round trip later. Two backed-off timeouts bound that with room
/// to spare: over 2 000 cases from each of base seeds 0 and 1
/// (`SOLO_FUZZ_SCALE=1000`, measured on 2026-10-24) the slowest took 13.3 s,
/// 33 slots, and the median 1.9 s. The kernel before tip fetching needed
/// four such timeouts and more: from seed 0 case 755 took 91.6 s and case
/// 1068 never finalized again, from seed 1 case 10 never did.
const HEAL_SLOTS: u64 = 2 * 48;

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
        chain_id: 1337,
        fee_schedule: vec![],
        modules: Seq(vec![]),
        params: params.to_bytes(),
        validators: Sim::validator_set(keys).to_bytes(),
    }
}

/// Every block any node has finalized, by height, checked against what any
/// node finalized there before: the safety property.
#[derive(Default)]
struct Finalized(BTreeMap<u64, [u8; 32]>);

impl Finalized {
    fn check(&mut self, sim: &Sim) {
        for (i, node) in sim.nodes.iter().enumerate() {
            for (height, hash) in &node.executed {
                if node.finalized.contains(height) {
                    let first = *self.0.entry(*height).or_insert(*hash);
                    assert_eq!(first, *hash, "node {i} finalized another block at {height}");
                }
            }
        }
    }

    fn top(&self) -> u64 {
        self.0.keys().next_back().copied().unwrap_or(0)
    }
}

/// One phase's faults on the links, drawing from its own generator.
fn faults(r: &mut Rng) -> Option<solo_node::sim::LinkFilter> {
    let mut rng = Rng::new(r.u64());
    match r.below(4) {
        // A partition: messages cross between the two sides only rarely.
        0 => {
            let side: Vec<bool> = (0..=VALIDATORS).map(|_| rng.chance(1, 2)).collect();
            Some(Box::new(move |from, to, _| {
                (side[from] == side[to] || rng.chance(1, 50)).then_some(0)
            }))
        }
        // A lossy network.
        1 => {
            let loss = 1 + rng.below(60);
            Some(Box::new(move |_, _, _| {
                (!rng.chance(loss, 100)).then_some(0)
            }))
        }
        // Delays of up to two slots: messages arrive late and out of order.
        2 => Some(Box::new(move |_, _, _| Some(rng.below(2 * SLOT_MS)))),
        // A healthy network.
        _ => None,
    }
}

fn schedule(r: &mut Rng) {
    let keys: Vec<SigningKey> = (1..=VALIDATORS)
        .map(|i| SigningKey::from_slice(&[0x40 + u8::try_from(i).unwrap(); 32]).unwrap())
        .collect();
    let kernel = kernel_module();
    let genesis = genesis(&keys);
    let config = NodeConfig {
        now_ms: 10_000,
        ..NodeConfig::default()
    };
    let mut sim = Sim::new(kernel, &genesis, &keys, 1, &config, 20).unwrap();
    let mut seen = Finalized::default();
    let mut down = [false; VALIDATORS];
    for _ in 0..2 + r.below(4) {
        sim.filter_links(faults(r));
        // Crash a validator, or bring a crashed one back.
        if r.chance(1, 2) {
            let i = r.index(VALIDATORS);
            if down[i] {
                sim.revive(i, kernel, &genesis).unwrap();
            } else {
                seen.check(&sim);
                sim.crash(i);
            }
            down[i] = !down[i];
        }
        sim.advance(SLOT_MS * (2 + r.below(8))).unwrap();
        seen.check(&sim);
    }
    // Heal: every validator back, every link clean.
    sim.filter_links(None);
    for (i, d) in down.iter().enumerate() {
        if *d {
            sim.revive(i, kernel, &genesis).unwrap();
        }
    }
    let target = seen.top() + 3;
    let healed = sim.now_ms;
    let live = sim
        .run_until(HEAL_SLOTS * SLOT_MS, |s| {
            s.nodes
                .iter()
                .all(|n| n.finalized.last().is_some_and(|h| *h >= target))
        })
        .unwrap();
    seen.check(&sim);
    eprintln!(
        "healed: finalized {target} after {} ms",
        sim.now_ms - healed
    );
    assert!(
        live,
        "no progress to {target} after healing: {:?}",
        sim.finalized_heights().unwrap()
    );
}

#[test]
fn random_fault_schedules_keep_safety_and_recover_liveness() {
    solo_fuzz::run("consensus-schedules", 2, schedule);
}
