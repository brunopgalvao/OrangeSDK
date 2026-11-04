//! The fault scheduler: from the seed, a sequence of calm spells and
//! faults, each held for a while and then healed. A fault a quorum
//! survives (at most `f` of the current validator set impaired) keeps the
//! network *live*, and the checker expects finality to keep advancing
//! through it; one it may not survive is *severe*, and the checker expects
//! progress only once it heals. The draws depend on the seed alone; when
//! they happen depends on the machine, so a seed replays the same faults
//! in the same order, not the same interleaving of messages.

use std::fmt::Write as _;
use std::time::{Duration, Instant};

use k256::ecdsa::SigningKey;
use serde_json::json;
use solo_abi::staking::StakingAction;
use solo_fuzz::Rng;

use crate::cluster::Cluster;
use crate::load::{self, GAS_PRICE};
use crate::rpc;
use crate::world::{Mode, Role, Shared};

/// One gwei, a weight of one (spec 15 §1).
const GWEI: u128 = 1_000_000_000;

/// The staking address.
const STAKING: [u8; 20] = solo_abi::staking::STAKING_ADDRESS;

struct StakeTx {
    hash: String,
    standby: usize,
    bond: bool,
    sent: Instant,
}

pub struct Scheduler {
    pub cluster: Cluster,
    world: Shared,
    rng: Rng,
    /// Durations are scaled by this (the short run uses shorter spells).
    scale: f64,
    /// Observers beyond these are retired as fresh ones join.
    max_observers: usize,
    /// Per standby (by member id): registered, and staked now.
    registered: Vec<bool>,
    staked: Vec<bool>,
    stake_txs: Vec<StakeTx>,
    pub faults: u64,
}

impl Scheduler {
    pub fn new(
        cluster: Cluster,
        world: Shared,
        seed: u64,
        scale: f64,
        max_observers: usize,
    ) -> Scheduler {
        let n = cluster.procs.len();
        Scheduler {
            cluster,
            world,
            rng: Rng::new(seed ^ 0xfa17),
            scale,
            max_observers,
            registered: vec![false; n + 64],
            staked: vec![false; n + 64],
            stake_txs: Vec::new(),
            faults: 0,
        }
    }

    #[allow(clippy::cast_precision_loss)]
    fn secs(&mut self, lo: u64, hi: u64) -> Duration {
        let s = lo + self.rng.below(hi - lo + 1);
        Duration::from_secs_f64((s as f64 * self.scale).max(1.0))
    }

    fn violated(&self) -> bool {
        !self.world.lock().unwrap().violations.is_empty()
    }

    /// Waits `d`, reaping nodes that exit and following staking actions;
    /// false as soon as a violation is recorded.
    pub fn pause(&mut self, d: Duration) -> bool {
        let until = Instant::now() + d;
        while Instant::now() < until {
            self.cluster.reap();
            self.follow_stakes();
            if self.violated() {
                return false;
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        true
    }

    /// Waits until `cond` holds or `timeout` passes; whether it held.
    pub fn wait_for(&mut self, timeout: Duration, mut cond: impl FnMut(&mut Self) -> bool) -> bool {
        let until = Instant::now() + timeout;
        while Instant::now() < until {
            if cond(self) {
                return true;
            }
            if !self.pause(Duration::from_millis(500)) {
                return false;
            }
        }
        cond(self)
    }

    fn log(&self, what: String) {
        self.world.lock().unwrap().log(what);
    }

    fn label(&self, id: usize) -> String {
        self.cluster.label(id)
    }

    /// The member ids of the current validator set; the genesis validators
    /// until the checker has read it.
    fn set_members(&self) -> Vec<usize> {
        let w = self.world.lock().unwrap();
        let ids: Vec<usize> = (0..self.cluster.keys.len())
            .filter(|&i| {
                self.cluster.keys[i].as_ref().is_some_and(|k| {
                    let id = rpc::hex(&solo_node::validator_id(k));
                    w.chain.set.iter().any(|s| s.eq_ignore_ascii_case(&id))
                })
            })
            .collect();
        if ids.is_empty() {
            (0..self.cluster.shape.validators).collect()
        } else {
            ids
        }
    }

    fn tolerated(n: usize) -> usize {
        (n.saturating_sub(1)) / 3
    }

    fn observers(&self) -> Vec<usize> {
        let w = self.world.lock().unwrap();
        w.members
            .iter()
            .filter(|m| m.role == Role::Observer && !m.retired)
            .map(|m| m.id)
            .collect()
    }

    fn keyed(&self) -> Vec<usize> {
        (0..self.cluster.shape.validators + self.cluster.shape.standbys).collect()
    }

    /// The highest head a running node reports now.
    fn live_head(&self) -> u64 {
        let rpcs: Vec<String> = {
            let w = self.world.lock().unwrap();
            (0..self.cluster.procs.len())
                .filter(|i| self.cluster.running(*i))
                .map(|i| w.members[i].rpc.clone())
                .collect()
        };
        rpcs.iter()
            .filter_map(|r| {
                rpc::call(r, "eth_blockNumber", &json!([]), Duration::from_secs(2)).ok()
            })
            .filter_map(|n| rpc::q64(&n))
            .max()
            .unwrap_or(0)
    }

    /// The newest epoch whose snapshot a running node other than `except`
    /// serves, from the files in its data directory.
    fn newest_served(&self, except: &[usize]) -> Option<u64> {
        (0..self.cluster.procs.len())
            .filter(|i| !except.contains(i) && self.cluster.running(*i))
            .filter_map(|i| std::fs::read_dir(self.cluster.procs[i].dir.join("snapshots")).ok())
            .flatten()
            .filter_map(|e| {
                let name = e.ok()?.file_name().into_string().ok()?;
                name.strip_prefix("epoch-")?
                    .strip_suffix(".snap")?
                    .parse()
                    .ok()
            })
            .max()
    }

    fn best(&self) -> u64 {
        self.world.lock().unwrap().chain.scanned
    }

    fn set_impaired(&self, ids: &[usize], impaired: bool) {
        let mut w = self.world.lock().unwrap();
        for &i in ids {
            w.members[i].impaired = impaired;
        }
    }

    fn mode(&self, mode: Mode) {
        let mut w = self.world.lock().unwrap();
        w.set_mode(mode);
    }

    fn healed(&self) {
        let mut w = self.world.lock().unwrap();
        w.last_heal = Instant::now();
        w.set_mode(Mode::Live);
        for m in &mut w.members {
            m.impaired = false;
        }
    }

    /// A calm spell, with a staking action now and then.
    pub fn calm(&mut self) -> bool {
        if self.cluster.shape.standbys > 0 && self.rng.chance(1, 3) {
            self.stake();
        }
        let d = self.secs(8, 25);
        self.pause(d)
    }

    /// One fault, held and healed.
    #[allow(clippy::too_many_lines)]
    pub fn fault(&mut self) -> bool {
        self.faults += 1;
        let set = self.set_members();
        let f = Self::tolerated(set.len());
        let syncable = self.best() > 3 * self.cluster.shape.epoch_blocks;
        let roll = self.rng.below(100);
        let ok = match roll {
            0..18 => {
                // kill -9 and restart; a validator of the set, or another node.
                let target = if self.rng.chance(3, 4) || self.observers().is_empty() {
                    *self.rng.pick(&set)
                } else {
                    let o = self.observers();
                    *self.rng.pick(&o)
                };
                // A validator that lost its data comes back from a snapshot
                // newer than anything it signed: from nothing it would
                // replay the chain and sign again in the views it signed in
                // before (see the soak's report of 2026-11-04). An observer
                // signs nothing and may start from either.
                let validator = self.cluster.role(target) != Role::Observer;
                // Peers keep the blocks of the last DRIVER_RETENTION heights
                // (spec 22 §8.1): a node further behind joins from a
                // snapshot, so catching up from nothing is for young chains.
                let young = self.best() + 200 < solo_node::DRIVER_RETENTION;
                let wipe = self.rng.chance(1, 4) && (syncable || !validator);
                let sync = wipe && syncable && (validator || !young || self.rng.chance(1, 2));
                let down = self.secs(2, 20);
                self.kill_restart(&[target], down, wipe, sync)
            }
            18..28 => {
                let all: Vec<usize> = self.keyed().into_iter().chain(self.observers()).collect();
                let target = *self.rng.pick(&all);
                self.log(format!("fault: graceful restart of {}", self.label(target)));
                let stopped = self.cluster.stop(target);
                let down = self.secs(1, 8);
                let ok = stopped && self.pause(down);
                self.cluster.start(target, false, false);
                ok
            }
            28..40 => {
                // A validator of the set, or now and then an observer: one
                // cut off with transactions it accepted.
                let observers = self.observers();
                let target = if observers.is_empty() || self.rng.chance(3, 4) {
                    *self.rng.pick(&set)
                } else {
                    *self.rng.pick(&observers)
                };
                let d = self.secs(5, 30);
                self.isolate(&[target], d, Mode::Live)
            }
            40..50 => self.partition(&set),
            50..60 => {
                let n = 1 + self.rng.index(f.max(1));
                let targets = self.pick_distinct(&set, n.min(f.max(1)));
                let delay = 50 + self.rng.below(750);
                let d = self.secs(10, 40);
                self.slow(&targets, delay, d)
            }
            60..68 => {
                let n = 1 + self.rng.index(f.max(1));
                let targets = self.pick_distinct(&set, n);
                let d = self.secs(2, 20);
                self.freeze(&targets, d)
            }
            68..74 => {
                // More than the network tolerates: no quorum until they return.
                let targets = self.pick_distinct(&set, f + 1);
                let down = self.secs(5, 25);
                self.kill_restart(&targets, down, false, false)
            }
            74..84 => {
                if syncable {
                    self.join_observer()
                } else {
                    let target = *self.rng.pick(&set);
                    let d = self.secs(5, 15);
                    self.isolate(&[target], d, Mode::Live)
                }
            }
            _ => {
                let d = self.secs(10, 40);
                self.flap(&set, d)
            }
        };
        self.healed();
        ok
    }

    fn pick_distinct(&mut self, from: &[usize], n: usize) -> Vec<usize> {
        let mut pool = from.to_vec();
        let mut out = Vec::new();
        while out.len() < n && !pool.is_empty() {
            let i = self.rng.index(pool.len());
            out.push(pool.swap_remove(i));
        }
        out
    }

    fn labels(&self, ids: &[usize]) -> String {
        ids.iter()
            .map(|i| self.label(*i))
            .collect::<Vec<_>>()
            .join(",")
    }

    /// Kills `targets`, keeps them down `down` (and, for a wipe, until the
    /// network has moved ten blocks on, so that a validator that lost its
    /// driver state never comes back into a view it voted in), restarts.
    fn kill_restart(&mut self, targets: &[usize], down: Duration, wipe: bool, sync: bool) -> bool {
        let set = self.set_members();
        let n_set = targets.iter().filter(|t| set.contains(t)).count();
        let severe = n_set > Self::tolerated(set.len());
        let how = match (wipe, sync) {
            (false, _) => "keeping its data",
            (true, false) => "with its data directory wiped",
            (true, true) => "with its data directory wiped, syncing from peers",
        };
        self.log(format!(
            "fault: kill -9 {} for {:.0}s, {how}{}",
            self.labels(targets),
            down.as_secs_f64(),
            if severe { " (severe)" } else { "" }
        ));
        if severe {
            self.mode(Mode::Severe);
        }
        self.set_impaired(targets, true);
        // The highest head any node, the targets included, has executed:
        // the scanned height can lag it by tens of blocks, and the targets
        // may have voted up to it.
        let at = self.best().max(self.live_head());
        for &t in targets {
            self.cluster.kill(t);
        }
        let mut ok = self.pause(down);
        if ok && wipe {
            // Until a peer serves a snapshot of an epoch that ended well
            // after the kill (spec 22 §7.4: exported once a certificate
            // covers it), so that a joiner, which takes the newest epoch
            // offered and follows handoffs to its key set (§7.5), never
            // comes back below a view it voted in. Waiting on heights alone
            // was not enough once a joiner no longer needed the newest key:
            // an older snapshot it would have set aside verified, and the
            // wiped validator equivocated (seed 2).
            let epoch = self.cluster.shape.epoch_blocks;
            let need = (at + 8).div_ceil(epoch) - 1;
            ok = self.wait_for(Duration::from_mins(3), |s| {
                s.best() >= at + 10 && s.newest_served(targets) >= Some(need)
            });
        }
        for &t in targets {
            if !self.cluster.running(t) {
                self.cluster.start(t, wipe, sync);
            }
        }
        ok
    }

    /// Cuts every link of `targets` to everyone else for `d`.
    fn isolate(&mut self, targets: &[usize], d: Duration, mode: Mode) -> bool {
        self.log(format!(
            "fault: isolate {} for {:.0}s",
            self.labels(targets),
            d.as_secs_f64()
        ));
        self.mode(mode);
        self.set_impaired(targets, true);
        let n = self.cluster.procs.len();
        for &t in targets {
            for o in 0..n {
                if !targets.contains(&o) {
                    self.cluster.net.set_blocked(t, o, true);
                }
            }
        }
        let ok = self.pause(d);
        self.cluster.net.heal_all();
        self.log("heal".to_owned());
        ok
    }

    /// Splits the keyed nodes in two, each observer with one side.
    fn partition(&mut self, set: &[usize]) -> bool {
        let keyed = self.keyed();
        let observers = self.observers();
        let n = self.cluster.procs.len();
        let side: Vec<bool> = (0..n).map(|_| self.rng.chance(1, 2)).collect();
        let count = |s: bool| set.iter().filter(|i| side[**i] == s).count();
        let quorum = |c: usize| 3 * c > 2 * set.len();
        let severe = !quorum(count(true)) && !quorum(count(false));
        let d = self.secs(5, 40);
        let a: Vec<usize> = keyed
            .iter()
            .chain(&observers)
            .copied()
            .filter(|i| side[*i])
            .collect();
        let b: Vec<usize> = keyed
            .iter()
            .chain(&observers)
            .copied()
            .filter(|i| !side[*i])
            .collect();
        self.log(format!(
            "fault: partition {{{}}} | {{{}}} for {:.0}s{}",
            self.labels(&a),
            self.labels(&b),
            d.as_secs_f64(),
            if severe { " (severe)" } else { "" }
        ));
        if severe {
            self.mode(Mode::Severe);
        }
        // The side without a quorum is impaired.
        let minority = if quorum(count(true)) { &b } else { &a };
        self.set_impaired(minority, true);
        for x in 0..n {
            for y in 0..n {
                if x < y && side[x] != side[y] {
                    self.cluster.net.set_blocked(x, y, true);
                }
            }
        }
        let ok = self.pause(d);
        self.cluster.net.heal_all();
        self.log("heal".to_owned());
        ok
    }

    /// Delays every link of `targets` by `delay_ms`.
    fn slow(&mut self, targets: &[usize], delay_ms: u64, d: Duration) -> bool {
        self.log(format!(
            "fault: slow {} by {delay_ms} ms per hop for {:.0}s",
            self.labels(targets),
            d.as_secs_f64()
        ));
        self.set_impaired(targets, true);
        let n = self.cluster.procs.len();
        for &t in targets {
            for o in 0..n {
                if o != t {
                    self.cluster.net.set_delay(t, o, delay_ms);
                }
            }
        }
        let ok = self.pause(d);
        self.cluster.net.heal_all();
        self.log("heal".to_owned());
        ok
    }

    /// SIGSTOP for `d`, then SIGCONT.
    fn freeze(&mut self, targets: &[usize], d: Duration) -> bool {
        self.log(format!(
            "fault: freeze {} for {:.0}s",
            self.labels(targets),
            d.as_secs_f64()
        ));
        self.set_impaired(targets, true);
        for &t in targets {
            self.cluster.freeze(t);
        }
        let ok = self.pause(d);
        for &t in targets {
            self.cluster.thaw(t);
        }
        ok
    }

    /// Cuts a random link of the set every second or so for `d`.
    fn flap(&mut self, set: &[usize], d: Duration) -> bool {
        self.log(format!(
            "fault: flapping links among the set for {:.0}s",
            d.as_secs_f64()
        ));
        let until = Instant::now() + d;
        let mut ok = true;
        while ok && Instant::now() < until && set.len() > 1 {
            let pair = self.pick_distinct(set, 2);
            self.cluster.net.set_blocked(pair[0], pair[1], true);
            let gap = Duration::from_millis(300 + self.rng.below(1500));
            ok = self.pause(gap);
            self.cluster.net.set_blocked(pair[0], pair[1], false);
        }
        self.cluster.net.heal_all();
        self.log("heal".to_owned());
        ok
    }

    /// A fresh observer joins from its peers' snapshots; the oldest
    /// observer beyond the limit is retired.
    fn join_observer(&mut self) -> bool {
        let id = self.cluster.add_observer();
        self.log(format!(
            "fault: fresh observer {} joins with --sync-from-peers",
            self.label(id)
        ));
        self.cluster.start(id, true, true);
        let observers = self.observers();
        if observers.len() > self.max_observers {
            self.cluster.retire(observers[0]);
        }
        let d = self.secs(10, 20);
        self.pause(d)
    }

    /// A standby joins the set, or leaves it.
    fn stake(&mut self) {
        let standbys: Vec<usize> = (self.cluster.shape.validators..self.keyed().len()).collect();
        if standbys.is_empty() || self.stake_txs.len() > 2 {
            return;
        }
        let s = *self.rng.pick(&standbys);
        if self.stake_txs.iter().any(|t| t.standby == s) {
            return;
        }
        let key: SigningKey = self.cluster.keys[s].clone().unwrap();
        let (action, value, bond) = if self.staked[s] {
            (StakingAction::Unbond { amount: GWEI }, 0, false)
        } else if self.registered[s] {
            (StakingAction::Bond, GWEI, true)
        } else {
            let dkg_key = solo_node::keystore::encryption_key(&key).to_vec();
            (StakingAction::Register { dkg_key }, GWEI, true)
        };
        let live: Vec<String> = {
            let w = self.world.lock().unwrap();
            w.members
                .iter()
                .filter(|m| m.live() && m.started.elapsed() > Duration::from_secs(3))
                .map(|m| m.rpc.clone())
                .collect()
        };
        if live.is_empty() {
            return;
        }
        let rpc_addr = self.rng.pick(&live).clone();
        let addr = rpc::hex(&load::address(&key));
        let Ok(n) = rpc::call(
            &rpc_addr,
            "eth_getTransactionCount",
            &json!([addr, "pending"]),
            Duration::from_secs(10),
        ) else {
            return;
        };
        let nonce = rpc::q64(&n).unwrap_or(0);
        let raw = load::legacy(
            &key,
            self.cluster.chain_id,
            nonce,
            GAS_PRICE,
            500_000,
            Some(STAKING),
            value,
            &action.encode(),
        );
        let label = self.label(s);
        match rpc::call(
            &rpc_addr,
            "eth_sendRawTransaction",
            &json!([rpc::hex(&raw)]),
            Duration::from_secs(10),
        ) {
            Ok(h) => {
                self.log(format!(
                    "stake: {label} sends {action:?} ({}) as {h}",
                    if bond { "joins" } else { "leaves" }
                ));
                self.stake_txs.push(StakeTx {
                    hash: h.as_str().unwrap_or_default().to_owned(),
                    standby: s,
                    bond,
                    sent: Instant::now(),
                });
            }
            Err(e) => self.log(format!("stake: {label} {action:?} refused: {e}")),
        }
    }

    /// What became of the staking actions sent.
    fn follow_stakes(&mut self) {
        let bonded = format!(
            "0x{}",
            hex_of(&solo_host::hash::keccak256(b"Bonded(address,uint256)"))
        );
        let unbonded = format!(
            "0x{}",
            hex_of(&solo_host::hash::keccak256(
                b"Unbonded(address,uint256,uint64)"
            ))
        );
        let mut keep = Vec::new();
        for t in std::mem::take(&mut self.stake_txs) {
            let found = {
                let w = self.world.lock().unwrap();
                w.chain
                    .included
                    .get(&t.hash)
                    .map(|(h, ok)| (*h, *ok, w.chain.staking_logs.get(&t.hash).cloned()))
            };
            match found {
                Some((h, ok, logs)) => {
                    let logs = logs.unwrap_or_default();
                    let label = self.label(t.standby);
                    if t.bond && ok && logs.contains(&bonded) {
                        self.registered[t.standby] = true;
                        self.staked[t.standby] = true;
                        self.log(format!("stake: {label} bonded in block {h}"));
                    } else if !t.bond && ok && logs.contains(&unbonded) {
                        self.staked[t.standby] = false;
                        self.log(format!("stake: {label} unbonded in block {h}"));
                    } else {
                        self.world.lock().unwrap().violate(format!(
                            "staking action {} of {label} in block {h} did not act (status {ok}, events {logs:?})",
                            t.hash
                        ));
                    }
                }
                None if t.sent.elapsed() > Duration::from_mins(5) => {
                    let label = self.label(t.standby);
                    self.world.lock().unwrap().warn(format!(
                        "staking action {} of {label} not in a block after 5 minutes",
                        t.hash
                    ));
                }
                None => keep.push(t),
            }
        }
        self.stake_txs = keep;
    }

    /// Heals everything: links, frozen nodes, nodes down.
    pub fn heal_all(&mut self) {
        self.cluster.net.heal_all();
        let n = self.cluster.procs.len();
        for id in 0..n {
            let (frozen, retired) = {
                let w = self.world.lock().unwrap();
                (w.members[id].frozen, w.members[id].retired)
            };
            if frozen {
                self.cluster.thaw(id);
            }
            if !retired && !self.cluster.running(id) {
                self.cluster.start(id, false, false);
            }
        }
        self.healed();
    }

    /// Whether every live node has finalized within `slack` blocks of the
    /// furthest, and the furthest is at least `at_least`.
    pub fn caught_up(&self, slack: u64, at_least: u64) -> bool {
        let rpcs: Vec<(String, bool)> = {
            let w = self.world.lock().unwrap();
            w.members
                .iter()
                .filter(|m| !m.retired && m.pid.is_some())
                .map(|m| (m.rpc.clone(), m.syncs))
                .collect()
        };
        let mut heights = Vec::new();
        for (r, syncs) in rpcs {
            let Ok(body) = rpc::get(&r, "/status", Duration::from_secs(10)) else {
                // A node syncing its state serves no RPC until it has it;
                // the checker bounds how long that takes.
                if syncs {
                    continue;
                }
                return false;
            };
            let Ok(doc) = serde_json::from_str::<serde_json::Value>(&body) else {
                return false;
            };
            heights.push(doc["finalized"].as_u64().unwrap_or(0));
        }
        let top = heights.iter().copied().max().unwrap_or(0);
        top >= at_least && heights.iter().all(|h| h + slack >= top)
    }

    /// Whether any staking action is still open.
    pub fn staking_open(&self) -> bool {
        !self.stake_txs.is_empty()
    }
}

fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}
