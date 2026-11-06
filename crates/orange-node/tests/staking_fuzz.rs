//! Seeded schedules of staking, epochs and the threshold key under faults
//! (spec 15, spec 08, codex ADR 0047 and 0048): bonds, unbonds, withdrawals,
//! delegations, a validator joining and leaving, equivocations that slash
//! and jail, across epoch boundaries and DKG phases, while links partition,
//! drop and delay messages and validators crash and restart, now and then
//! with their data wiped. Throughout, no two nodes finalize different blocks
//! at one height, and a wiped validator is never slashed: it signs nothing
//! again in a view it may have signed in (spec 08 §7b). Once the faults end:
//! every node finalizes again; a fresh key set is adopted and the active key
//! hands off to it; every epoch's run either made a key set or left an
//! earlier key in force, its defined fallback; the staking address holds
//! exactly the stake, the unbonding stake, the delegations and the reward
//! pool; and every threshold certificate any node recorded verifies under
//! the key set it names, which was in force for its block. Every block any
//! node executes in turn ends the DKG phases chain state says it ends: a
//! complete phase after the block that completed it, an incomplete one at
//! its deadline and not before (codex ADR 0058), and some phases end early. See `orange-fuzz`
//! for the long mode.

use std::collections::BTreeMap;

use k256::ecdsa::SigningKey;
use orange_abi::chain::consensus::{KIND_VOTE, TOPIC, signing_preimage};
use orange_abi::chain::{
    Allocation, ConsensusMessage, GenesisParams, Signature, Validator, ValidatorSet,
};
use orange_abi::codec::Seq;
use orange_abi::rotation::keys as rkeys;
use orange_abi::staking::{
    DelegationEntry, DkgProgress, DkgRun, GWEI, KeySetRecord, STAKING_ADDRESS, StakingAction,
    StakingParams, StakingStatus, ValidatorKey, epoch_of, epoch_start, keys as skeys, query,
};
use orange_abi::types::Genesis;
use orange_abi::{Decode, Encode};
use orange_fuzz::Rng;
use orange_host::hash::keccak256;
use orange_node::keystore::encryption_key;
use orange_node::{Node, NodeConfig, Sim, validator_id};
use orange_rlp::{encode_bytes, encode_list, encode_uint};

const KERNEL: &[u8] = include_bytes!("fixtures/kernel.elf");
const CHAIN_ID: u64 = 1337;
const SLOT_MS: u64 = 200;
const ETHER: u128 = 1_000_000_000_000_000_000;
/// Genesis members; the next key has a node but joins only if it registers.
const MEMBERS: usize = 4;
/// Keys with a node: the members and the joiner.
const NODES: usize = MEMBERS + 1;
/// The account that delegates; it has no node.
const DELEGATOR: usize = NODES;
/// How long a healed network may take to finalize again (see
/// `consensus_fuzz.rs`).
const HEAL_SLOTS: u64 = 4 * 48;

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

fn address(key: &SigningKey) -> [u8; 20] {
    validator_id(key)[12..].try_into().unwrap()
}

fn genesis(keys: &[SigningKey], weights: &[u64], staking: &StakingParams) -> Genesis {
    let allocations = keys
        .iter()
        .map(|k| Allocation {
            address: address(k),
            balance: 1_000 * ETHER,
            ..Allocation::default()
        })
        .collect();
    let set = ValidatorSet {
        validators: Seq(keys[..MEMBERS]
            .iter()
            .zip(weights)
            .map(|(k, &weight)| Validator {
                id: validator_id(k),
                weight,
            })
            .collect()),
    };
    let params = GenesisParams {
        slot_ms: SLOT_MS,
        max_txs: 8,
        allocations: Seq(allocations),
        staking: StakingParams {
            keys: Seq(keys[..MEMBERS]
                .iter()
                .map(|k| ValidatorKey {
                    id: validator_id(k),
                    dkg_key: encryption_key(k).to_vec(),
                })
                .collect()),
            ..staking.clone()
        },
        ..GenesisParams::default()
    };
    Genesis {
        chain_id: CHAIN_ID,
        fee_schedule: vec![],
        modules: Seq(vec![]),
        params: params.to_bytes(),
        validators: set.to_bytes(),
    }
}

/// A legacy EIP-155 transaction to the staking address.
fn action(key: &SigningKey, nonce: u64, value: u128, action: &StakingAction) -> Vec<u8> {
    let data = action.encode();
    let fields = |out: &mut Vec<u8>| {
        encode_uint(u128::from(nonce), out);
        encode_uint(1_000_000_000, out);
        encode_uint(200_000, out);
        encode_bytes(&STAKING_ADDRESS, out);
        encode_uint(value, out);
        encode_bytes(&data, out);
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

fn status(node: &mut Node) -> StakingStatus {
    let r = node.query(query::STAKING, &[]).unwrap();
    assert_eq!(r.status, 0);
    StakingStatus::from_bytes(&r.body).unwrap()
}

fn key_set(node: &Node, id: u64) -> Option<KeySetRecord> {
    node.state_get(&[skeys::KEY_SET, &id.to_be_bytes()].concat())
        .map(|b| KeySetRecord::from_bytes(&b).unwrap())
}

/// A chain-state `u64` of key set `id` under `prefix`.
fn height_of(node: &Node, prefix: &[u8], id: u64) -> Option<u64> {
    node.state_get(&[prefix, &id.to_be_bytes()].concat())
        .map(|b| u64::from_bytes(&b).unwrap())
}

/// Every block any node has finalized, by height: the safety property.
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
fn faults(r: &mut Rng) -> Option<orange_node::sim::LinkFilter> {
    let mut rng = Rng::new(r.u64());
    match r.below(4) {
        0 => {
            let side: Vec<bool> = (0..NODES).map(|_| rng.chance(1, 2)).collect();
            Some(Box::new(move |from, to, _| {
                (side[from] == side[to] || rng.chance(1, 50)).then_some(0)
            }))
        }
        1 => {
            let loss = 1 + rng.below(40);
            Some(Box::new(move |_, _, _| {
                (!rng.chance(loss, 100)).then_some(0)
            }))
        }
        2 => Some(Box::new(move |_, _, _| Some(rng.below(2 * SLOT_MS)))),
        _ => None,
    }
}

/// The schedule's view of the accounts it acts for: the next nonce of each.
struct Accounts {
    keys: Vec<SigningKey>,
    nonces: Vec<u64>,
    /// The only validator that equivocates, if any may.
    byzantine: Option<usize>,
}

impl Accounts {
    /// Submits `a` with `value` from account `from` to a live node; a
    /// refusal (an action that cannot run, a full pool) changes nothing.
    fn submit(
        &mut self,
        sim: &mut Sim,
        live: &[usize],
        r: &mut Rng,
        from: usize,
        value: u128,
        a: &StakingAction,
    ) {
        let to = *r.pick(live);
        let on_chain = sim.nodes[to]
            .account(&address(&self.keys[from]))
            .unwrap()
            .nonce;
        let nonce = self.nonces[from].max(on_chain);
        if sim
            .submit(to, &action(&self.keys[from], nonce, value, a))
            .is_ok()
        {
            self.nonces[from] = nonce + 1;
        }
    }
}

/// One random staking action, or an equivocation.
fn act(sim: &mut Sim, live: &[usize], r: &mut Rng, accounts: &mut Accounts) {
    let validator = r.index(NODES);
    let stake = |r: &mut Rng| u128::from(100 + r.below(3_000)) * 1_000 * GWEI;
    match r.below(8) {
        0 => {
            let value = stake(r);
            accounts.submit(sim, live, r, validator, value, &StakingAction::Bond);
        }
        1 => {
            let amount = u128::from(1 + r.below(2_000)) * 1_000 * GWEI;
            accounts.submit(
                sim,
                live,
                r,
                validator,
                0,
                &StakingAction::Unbond { amount },
            );
        }
        2 => {
            let from = if r.chance(1, 2) { validator } else { DELEGATOR };
            accounts.submit(sim, live, r, from, 0, &StakingAction::Withdraw);
        }
        3 => {
            let value = stake(r);
            let validator = address(&accounts.keys[validator]);
            accounts.submit(
                sim,
                live,
                r,
                DELEGATOR,
                value,
                &StakingAction::Delegate { validator },
            );
        }
        4 => {
            let amount = u128::from(1 + r.below(2_000)) * 1_000 * GWEI;
            let validator = address(&accounts.keys[validator]);
            accounts.submit(
                sim,
                live,
                r,
                DELEGATOR,
                0,
                &StakingAction::Undelegate { validator, amount },
            );
        }
        // The joiner registers, or anyone replaces its encryption key with
        // its own (a no-op change).
        5 => {
            let joiner = if r.chance(2, 3) { MEMBERS } else { validator };
            let dkg_key = encryption_key(&accounts.keys[joiner]).to_vec();
            let value = if r.chance(1, 2) { stake(r) } else { 0 };
            accounts.submit(
                sim,
                live,
                r,
                joiner,
                value,
                &StakingAction::Register { dkg_key },
            );
        }
        // The joiner leaves: it unbonds everything it could have.
        6 => {
            let amount = 10_000 * 1_000 * GWEI;
            accounts.submit(sim, live, r, MEMBERS, 0, &StakingAction::Unbond { amount });
        }
        // An equivocation: two block votes in one view a little ahead,
        // delivered to a live node; the offender is slashed and jailed once
        // it is recorded (spec 08 §9, spec 15 §5). Only the one validator the
        // schedule lets misbehave signs them, the lightest genesis member,
        // whose stake is below a third: Simplex promises liveness only while
        // the faulty validators hold less than that (spec 08 §1).
        _ => {
            let Some(validator) = accounts.byzantine else {
                return;
            };
            let to = *r.pick(live);
            let Some(driver) = sim.nodes[to].simplex_state() else {
                return;
            };
            let view = driver.view + 1 + r.below(4);
            let key = &accounts.keys[validator];
            for hash in [r.array32(), r.array32()] {
                let digest = keccak256(&signing_preimage(KIND_VOTE, CHAIN_ID, view, &hash));
                let signature = Signature(orange_node::sign_recoverable(key, &digest).unwrap());
                let m = ConsensusMessage::Vote {
                    view,
                    hash,
                    signature,
                };
                sim.nodes[to]
                    .deliver(validator_id(key), TOPIC, m.to_bytes())
                    .unwrap();
            }
        }
    }
}

/// The staking address holds exactly the bonded and unbonding stake of
/// every validator and delegation and the reward pool (spec 15 §3.4,
/// §10.2), and every validator's `delegated` is the bonded stake of the
/// delegations behind it.
fn check_accounting(node: &mut Node, delegator: [u8; 20]) {
    let s = status(node);
    let r = node.query(query::DELEGATIONS, &delegator).unwrap();
    let delegations = Seq::<DelegationEntry>::from_bytes(&r.body).unwrap().0;
    let mut held = s.pool;
    for e in &s.records.0 {
        held += e.record.stake + e.record.unbonding;
        let behind: u128 = delegations
            .iter()
            .filter(|d| d.validator == e.id)
            .map(|d| d.delegation.stake)
            .sum();
        assert_eq!(e.record.delegated, behind, "delegated of {:?}", e.id);
    }
    for d in &delegations {
        assert!(s.records.0.iter().any(|e| e.id == d.validator));
        held += d.delegation.stake + d.delegation.unbonding;
    }
    let balance = node.account(&STAKING_ADDRESS).unwrap().balance;
    assert_eq!(balance, held, "the staking address against what it holds");
}

/// The key set in force at `height` by the activation and replacement
/// heights chain state keeps (spec 15 §6.5): activated below `height`, and
/// not replaced at or below it.
fn in_force(node: &Node, newest: u64, height: u64) -> Option<u64> {
    (0..=newest).find(|&id| {
        height_of(node, rkeys::ACTIVATED, id).is_some_and(|a| a < height)
            && height_of(node, rkeys::REPLACED, id).is_none_or(|r| r >= height)
    })
}

/// Every epoch before `last` whose run existed made a key set, or left an
/// earlier key set in force at its end, once any key was ever adopted; and
/// every version-2 certificate `node` recorded verifies under the key set it
/// names, which had been activated below its height.
fn check_keys(node: &Node, epoch_blocks: u64, last: u64, newest: u64) {
    let first = (0..=newest).find(|&id| key_set(node, id).is_some());
    for e in first.unwrap_or(u64::MAX)..last {
        let run = node.state_get(&[skeys::RUN, &e.to_be_bytes()].concat());
        if run.is_none() || key_set(node, e).is_some() {
            continue;
        }
        let end = (e + 1) * epoch_blocks;
        let force = in_force(node, newest, end + 1);
        assert!(
            force.is_some_and(|k| k < e),
            "epoch {e}: no key set and none in force ({force:?})"
        );
    }
    for (k, cert) in node.persisted() {
        let Some(h) = k.strip_prefix(b"bcert/".as_slice()) else {
            continue;
        };
        let height = u64::from_le_bytes(h.try_into().unwrap());
        let c = orange_bls::certificate::CertificateV2::from_bytes(&cert).unwrap();
        let record = key_set(node, c.key_id).expect("a certificate names an adopted key set");
        let key =
            orange_bls::PublicKey::from_bytes(record.key_set[..96].try_into().unwrap()).unwrap();
        assert!(c.verify(CHAIN_ID, &key), "certificate at {height}");
        assert!(height_of(node, rkeys::ACTIVATED, c.key_id).is_some_and(|a| a < height));
    }
}

/// A node's last executed block, its hash, and the progress, after it, of
/// the run the next block is in.
type Seen = (u64, [u8; 32], Option<DkgProgress>);

/// Watches every node execute block after block and checks, for each block
/// whose parent's state it saw on the same node, that the DKG phases ended
/// after it exactly as spec 15 §6.1 says, from the run's progress before and
/// after the block: a phase ends when every message it waits for is recorded
/// or at its deadline, the next one at once when it is complete too, and
/// otherwise the phase stays.
struct Phases {
    epoch_blocks: u64,
    /// Per node: the last height it executed, that block's hash, and the
    /// progress, after it, of the run the next block is in.
    last: Vec<Option<Seen>>,
    /// Phases that ended before their deadlines, complete.
    early: u64,
    /// Transitions checked.
    checked: u64,
}

impl Phases {
    fn new(epoch_blocks: u64) -> Phases {
        Phases {
            epoch_blocks,
            last: vec![None; NODES],
            early: 0,
            checked: 0,
        }
    }

    fn progress(node: &Node, epoch: u64) -> Option<DkgProgress> {
        node.state_get(&[skeys::PROGRESS, &epoch.to_be_bytes()].concat())
            .map(|b| DkgProgress::from_bytes(&b).unwrap())
    }

    fn observe(&mut self, sim: &Sim) {
        for (i, node) in sim.nodes.iter().enumerate() {
            let n = node.executed.len();
            let Some(&(height, hash)) = node.executed.last() else {
                continue;
            };
            let epoch = epoch_of(height, self.epoch_blocks);
            let parent = n.checked_sub(2).map(|k| node.executed[k]);
            if let Some((h, ph, Some(before))) = self.last[i].clone()
                && h + 1 == height
                && parent == Some((h, ph))
                && let Some(after) = Self::progress(node, epoch)
                && let Some(run) = node.state_get(&[skeys::RUN, &epoch.to_be_bytes()].concat())
            {
                let run = DkgRun::from_bytes(&run).unwrap();
                self.check(&run, height, &before, &after);
            }
            // The run the next block is in, as this block left it.
            let ahead = Self::progress(node, epoch_of(height + 1, self.epoch_blocks));
            self.last[i] = Some((height, hash, ahead));
        }
    }

    fn check(&mut self, run: &DkgRun, height: u64, before: &DkgProgress, after: &DkgProgress) {
        let start = epoch_start(run.epoch, self.epoch_blocks);
        let span = self.epoch_blocks / 4;
        let next = height + 1;
        let complete = |phase: u8| match phase {
            0 => after.dealings as usize == run.dealers.0.len(),
            1 => after.complaints as usize == run.recipients.0.len(),
            _ => after.justified as usize == after.accused.0.len(),
        };
        let deadline = |phase: u8| next >= start + (u64::from(phase) + 1) * span;
        let mut phase = before.phase;
        while phase < 3 && (deadline(phase) || complete(phase)) {
            if !deadline(phase) {
                self.early += 1;
            }
            phase += 1;
        }
        let since = if phase == before.phase {
            before.since
        } else {
            next
        };
        assert_eq!(
            (after.phase, after.since),
            (phase, since),
            "epoch {}, block {height}: {before:?} then {after:?}",
            run.epoch
        );
        // The deadlines hold: by `start + 3S` the run is confirming.
        assert!(next < start + 3 * span || after.phase == 3);
        self.checked += 1;
    }
}

/// Advances `sim` by `ms`, slot by slot, watching the DKG phases.
fn advance(sim: &mut Sim, ms: u64, phases: &mut Phases) {
    let end = sim.now_ms + ms;
    while sim.now_ms < end {
        let step = SLOT_MS.min(end - sim.now_ms);
        sim.advance(step).unwrap();
        phases.observe(sim);
    }
}

/// Runs every node's kernel on the native backend, which gives the same
/// results and gas as the interpreter (spec 07 §4.1), faster.
fn native(sim: &mut Sim) {
    for node in &mut sim.nodes {
        node.set_backend(orange_host::Backend::Native);
    }
}

#[allow(clippy::too_many_lines)]
fn schedule(r: &mut Rng) {
    let keys: Vec<SigningKey> = (1..=NODES + 1)
        .map(|i| SigningKey::from_slice(&[0x50 + u8::try_from(i).unwrap(); 32]).unwrap())
        .collect();
    let epoch_blocks = *r.pick(&[12u64, 16, 20, 24]);
    let dkg_phase_blocks = 1 + r.below(epoch_blocks / 4);
    let staking = StakingParams {
        epoch_blocks,
        unbonding_epochs: 4,
        min_stake: 100 * 1_000 * GWEI,
        max_validators: 0,
        dkg_phase_blocks,
        max_key_age: 2,
        keys: Seq(vec![]),
    };
    let weights: Vec<u64> = (0..MEMBERS).map(|_| 500_000 + r.below(2_000_000)).collect();
    let total: u64 = weights.iter().sum();
    let byzantine = (0..MEMBERS)
        .min_by_key(|&i| weights[i])
        .filter(|&i| 3 * weights[i] < total);
    let kernel = kernel_module();
    let genesis = genesis(&keys, &weights, &staking);
    let config = NodeConfig {
        now_ms: 10_000,
        ..NodeConfig::default()
    };
    let mut sim = Sim::new(kernel, &genesis, &keys[..NODES], 0, &config, 20).unwrap();
    native(&mut sim);
    let mut accounts = Accounts {
        keys: keys.clone(),
        nonces: vec![0; keys.len()],
        byzantine,
    };
    let mut seen = Finalized::default();
    let mut phases = Phases::new(epoch_blocks);
    let mut down = [false; NODES];
    // At most one node, never the one that equivocates, comes back with its
    // data wiped in a case: it counts as faulty until its signing guard ends,
    // beside the equivocator (spec 08 §7b).
    let mut wiped = None;
    for _ in 0..3 + r.below(4) {
        sim.filter_links(faults(r));
        // At most one node down at a time beside the faults on the links.
        if r.chance(1, 2) {
            let i = r.index(NODES);
            if down[i] && wiped.is_none() && byzantine != Some(i) && r.chance(1, 3) {
                sim.revive_from_scratch(i, kernel, &genesis).unwrap();
                sim.nodes[i].set_backend(orange_host::Backend::Native);
                down[i] = false;
                wiped = Some(i);
            } else if down[i] {
                sim.revive(i, kernel, &genesis).unwrap();
                sim.nodes[i].set_backend(orange_host::Backend::Native);
                down[i] = false;
            } else if !down.iter().any(|d| *d) {
                seen.check(&sim);
                sim.crash(i);
                down[i] = true;
            }
        }
        let live: Vec<usize> = (0..NODES).filter(|i| !down[*i]).collect();
        for _ in 0..=r.below(3) {
            act(&mut sim, &live, r, &mut accounts);
        }
        advance(&mut sim, SLOT_MS * (4 + r.below(epoch_blocks)), &mut phases);
        seen.check(&sim);
    }
    // Heal: every node back, every link clean.
    sim.filter_links(None);
    for (i, d) in down.iter().enumerate() {
        if *d {
            sim.revive(i, kernel, &genesis).unwrap();
        }
    }
    native(&mut sim);
    let target = seen.top() + 3;
    let live = sim
        .run_until(HEAL_SLOTS * SLOT_MS, |s| {
            phases.observe(s);
            s.nodes
                .iter()
                .all(|n| n.finalized.last().is_some_and(|h| *h >= target))
        })
        .unwrap();
    seen.check(&sim);
    assert!(
        live,
        "no progress to {target} after healing: {:?}",
        sim.finalized_heights().unwrap()
    );
    // A key set made after healing is adopted and handed off to, at every node.
    let healed_epoch = status(&mut sim.nodes[0]).epoch;
    let rotated = sim
        .run_until(4 * epoch_blocks * 4 * SLOT_MS, |s| {
            phases.observe(s);
            (0..NODES).all(|i| {
                status(&mut s.nodes[i])
                    .active
                    .is_some_and(|k| k.id > healed_epoch)
            })
        })
        .unwrap();
    seen.check(&sim);
    assert!(
        rotated,
        "no key after epoch {healed_epoch}: {:?}",
        sim.finalized_heights().unwrap()
    );
    // Whatever the faults, the network healed made a key set: its phases
    // were watched, and once every member was in time some ended early.
    assert!(
        phases.checked > 0 && phases.early > 0,
        "{} transitions checked, {} early ends",
        phases.checked,
        phases.early
    );
    if let Some(w) = wiped {
        let id = validator_id(&keys[w]);
        let jailed = status(&mut sim.nodes[0])
            .records
            .0
            .iter()
            .any(|e| e.id == id && e.record.jailed);
        assert!(!jailed, "the wiped node {w} was slashed");
    }
    let delegator = address(&keys[DELEGATOR]);
    for i in 0..NODES {
        let node = &mut sim.nodes[i];
        check_accounting(node, delegator);
        let s = status(node);
        let newest = s.active.as_ref().map_or(0, |k| k.id);
        check_keys(node, epoch_blocks, s.epoch, newest);
    }
}

#[test]
fn random_staking_and_dkg_schedules_under_faults() {
    orange_fuzz::run("staking-schedules", 1, schedule);
}
