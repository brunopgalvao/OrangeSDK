//! The invariants, checked once a second on every live node while the
//! soak runs:
//!
//! - safety: every node's finalized blocks (hash and state root) are the
//!   canonical ones, which the checker reads height by height, each
//!   block's parent the block before;
//! - no node's finalized height goes backwards, within a process and
//!   across a restart that kept its data directory;
//! - liveness: on a live network (no fault, or faults a quorum survives)
//!   the furthest finalized height advances within [`LIVE_BOUND`], and
//!   within [`HEAL_BOUND`] of a heal; a live node not under a fault does
//!   not stay more than [`LAG`] blocks behind for [`CATCHUP_BOUND`];
//! - RPC answers within [`RPC_TIMEOUT`] on every live node;
//! - balances conserve: between two checks, the balances of every account
//!   the chain has (genesis, the load's, the staking address and the fee
//!   vault, and every account a transaction touched) shrink by exactly the
//!   base fees the blocks between burned (spec 23 §4), and the counter
//!   contract counts exactly the calls that succeeded;
//! - telemetry: counters never fall within a process, nothing is dropped
//!   by the emitter, no equivocation is recorded, the finalized height the
//!   metrics give is the status document's;
//! - resources: a process's memory and open files do not grow without
//!   bound (more than [`RSS_GROWTH`] times and [`RSS_SLACK`] over what it
//!   used once warm; [`FD_SLACK`] files over its warm count).

use std::collections::{BTreeMap, HashMap};
use std::process::Command;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use solo_fuzz::Rng;

use crate::rpc::{self, q64, quantity};
use crate::world::{Member, Mode, Shared};

pub const LIVE_BOUND: Duration = Duration::from_secs(45);
pub const HEAL_BOUND: Duration = Duration::from_secs(150);
pub const CATCHUP_BOUND: Duration = Duration::from_mins(4);
pub const LAG: u64 = 8;
pub const RPC_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a node may take to answer after its process started: a state
/// sync runs before the RPC is up.
pub const START_GRACE: Duration = Duration::from_mins(2);
pub const RSS_GROWTH: u64 = 3;
pub const RSS_SLACK: u64 = 768 * 1024;
pub const FD_SLACK: u64 = 256;
/// How long a process runs before its memory and files count as warm.
const WARM: Duration = Duration::from_secs(90);

/// One node as the checker follows it.
#[derive(Default)]
struct Watch {
    generation: u32,
    /// The finalized height last seen, and whether across generations.
    finalized: u64,
    last_ok: Option<Instant>,
    lag_since: Option<Instant>,
    counters: HashMap<String, f64>,
    rss_base: Option<u64>,
    fd_base: Option<u64>,
    rss_max: u64,
    fd_max: u64,
    latency_max: Duration,
    last_metrics: Option<Instant>,
    last_resources: Option<Instant>,
}

/// What the run's summary reports per node.
#[derive(Debug, Clone)]
pub struct NodeSummary {
    pub label: String,
    pub generations: u32,
    pub finalized: u64,
    pub rss_base_kb: Option<u64>,
    pub rss_max_kb: u64,
    pub fd_base: Option<u64>,
    pub fd_max: u64,
    pub latency_max_ms: u128,
}

pub struct Checker {
    world: Shared,
    /// Accounts the conservation check always sums.
    accounts: Vec<String>,
    /// Who deploys the counter.
    deployer: String,
    watches: HashMap<usize, Watch>,
    best: u64,
    last_advance: Instant,
    cum_burned: BTreeMap<u64, u128>,
    cum_calls: BTreeMap<u64, u64>,
    last_balance: Option<(u64, Instant)>,
    last_keys: Instant,
    rng: Rng,
    /// Reported once the run ends.
    pub balance_checks: u64,
    /// The last progress line: when, and at which height.
    progress: (Instant, u64),
}

fn tag(h: u64) -> Value {
    json!(format!("{h:#x}"))
}

impl Checker {
    pub fn new(world: Shared, accounts: Vec<String>, deployer: String, seed: u64) -> Checker {
        Checker {
            world,
            accounts,
            deployer,
            watches: HashMap::new(),
            best: 0,
            last_advance: Instant::now(),
            cum_burned: BTreeMap::new(),
            cum_calls: BTreeMap::new(),
            last_balance: None,
            last_keys: Instant::now(),
            rng: Rng::new(seed ^ 0xc4ec),
            balance_checks: 0,
            progress: (Instant::now(), 0),
        }
    }

    fn violate(&self, what: String) {
        self.world.lock().unwrap().violate(what);
    }

    /// Whether `m` is still the process the checker took it for: a member
    /// restarted during a long cycle answers on the same address.
    fn same(&self, m: &Member) -> bool {
        let w = self.world.lock().unwrap();
        let now = &w.members[m.id];
        now.generation == m.generation && now.live()
    }

    fn live(&self) -> Vec<Member> {
        let w = self.world.lock().unwrap();
        w.members.iter().filter(|m| m.live()).cloned().collect()
    }

    /// One round of every check.
    pub fn cycle(&mut self) {
        let members = self.live();
        let mut finalized: HashMap<usize, u64> = HashMap::new();
        for m in &members {
            if let Some(f) = self.status(m) {
                finalized.insert(m.id, f);
            }
        }
        self.progress(&members, &finalized);
        self.scan(&members, &finalized);
        self.agree(&members, &finalized);
        if self
            .last_balance
            .is_none_or(|(_, at)| at.elapsed() > Duration::from_secs(20))
        {
            self.conserve(&members);
        }
        if self.last_keys.elapsed() > Duration::from_secs(5) {
            self.last_keys = Instant::now();
            self.keys(&members);
        }
        for m in &members {
            self.telemetry(m);
            self.resources(m);
        }
    }

    /// `GET /status`: the node's finalized height; checks it never falls
    /// and that the node answers.
    fn status(&mut self, m: &Member) -> Option<u64> {
        let started = Instant::now();
        let answer = rpc::get(&m.rpc, "/status", RPC_TIMEOUT);
        let latency = started.elapsed();
        if !self.same(m) {
            return None;
        }
        let watch = self.watches.entry(m.id).or_default();
        if watch.generation != m.generation {
            // A new process: its counters start again; its height only
            // when its data directory was emptied.
            watch.generation = m.generation;
            watch.counters.clear();
            watch.rss_base = None;
            watch.fd_base = None;
            watch.last_ok = None;
            watch.lag_since = None;
            if m.fresh {
                watch.finalized = 0;
            }
        }
        let parsed = answer
            .ok()
            .and_then(|body| serde_json::from_str::<Value>(&body).ok());
        let Some(doc) = parsed else {
            let since = watch.last_ok.unwrap_or(m.started);
            let grace = if m.syncs || watch.last_ok.is_none() {
                START_GRACE.max(Duration::from_secs(30))
            } else {
                Duration::from_secs(30)
            };
            if since.elapsed() > grace {
                let label = m.label.clone();
                self.violate(format!(
                    "{label} has not answered /status for {:.0}s",
                    since.elapsed().as_secs_f64()
                ));
            }
            return None;
        };
        watch.last_ok = Some(Instant::now());
        watch.latency_max = watch.latency_max.max(latency);
        let f = doc["finalized"].as_u64().unwrap_or(0);
        if f < watch.finalized {
            let (label, was) = (m.label.clone(), watch.finalized);
            self.violate(format!(
                "{label} (#{}) finalized height went back from {was} to {f}",
                m.generation
            ));
        }
        let watch = self.watches.get_mut(&m.id).unwrap();
        watch.finalized = watch.finalized.max(f);
        Some(f)
    }

    /// Finality advances on a live network; live nodes keep up.
    #[allow(clippy::cast_precision_loss)]
    fn progress(&mut self, members: &[Member], finalized: &HashMap<usize, u64>) {
        let top = finalized.values().copied().max().unwrap_or(0);
        if self.progress.0.elapsed() > Duration::from_mins(1) {
            let (at, was) = self.progress;
            let lowest = finalized.values().copied().min().unwrap_or(0);
            self.world.lock().unwrap().log(format!(
                "progress: finalized {top} ({:.2} blocks/s), lowest live node {lowest}, {} live nodes",
                (top.saturating_sub(was)) as f64 / at.elapsed().as_secs_f64(),
                finalized.len()
            ));
            self.progress = (Instant::now(), top);
        }
        if top > self.best {
            self.best = top;
            self.last_advance = Instant::now();
        }
        let (mode, since) = {
            let w = self.world.lock().unwrap();
            (w.mode, w.since)
        };
        if mode != Mode::Live {
            for w in self.watches.values_mut() {
                w.lag_since = None;
            }
            return;
        }
        let stalled = self.last_advance.elapsed();
        if stalled > LIVE_BOUND && since.elapsed() > HEAL_BOUND {
            self.violate(format!(
                "finality stalled at {} for {:.0}s on a live network",
                self.best,
                stalled.as_secs_f64()
            ));
        } else if stalled > HEAL_BOUND {
            self.violate(format!(
                "finality stalled at {} for {:.0}s after a heal",
                self.best,
                stalled.as_secs_f64()
            ));
        }
        for m in members {
            let Some(&f) = finalized.get(&m.id) else {
                continue;
            };
            let watch = self.watches.get_mut(&m.id).unwrap();
            if m.impaired || f + LAG >= self.best {
                watch.lag_since = None;
                continue;
            }
            let lagging = *watch.lag_since.get_or_insert_with(Instant::now);
            // A node that lost its data catches up from the first block.
            let bound = if m.fresh && !m.syncs {
                3 * CATCHUP_BOUND
            } else {
                CATCHUP_BOUND
            };
            if lagging.elapsed() > bound && since.elapsed() > CATCHUP_BOUND {
                let label = m.label.clone();
                self.violate(format!(
                    "{label} has stayed behind for {:.0}s: finalized {f}, the network {}",
                    lagging.elapsed().as_secs_f64(),
                    self.best
                ));
            }
        }
    }

    fn block(rpc_addr: &str, h: u64) -> Option<Value> {
        rpc::call(
            rpc_addr,
            "eth_getBlockByNumber",
            &json!([tag(h), false]),
            RPC_TIMEOUT,
        )
        .ok()
        .filter(|b| !b.is_null())
    }

    /// Reads the canonical chain forward from the node furthest ahead that
    /// holds the next block.
    #[allow(clippy::too_many_lines, clippy::many_single_char_names)]
    fn scan(&mut self, members: &[Member], finalized: &HashMap<usize, u64>) {
        let mut order: Vec<&Member> = members
            .iter()
            .filter(|m| finalized.contains_key(&m.id))
            .collect();
        order.sort_by_key(|m| std::cmp::Reverse(finalized[&m.id]));
        let (mut scanned, first) = {
            let w = self.world.lock().unwrap();
            (w.chain.scanned, w.chain.first)
        };
        if first == 0 && scanned == 0 {
            // Start from the first height any node finalized.
            let Some(m) = order.first() else { return };
            let f = finalized[&m.id];
            if f == 0 {
                return;
            }
            let mut w = self.world.lock().unwrap();
            w.chain.first = 1;
        }
        for _ in 0..200 {
            let h = scanned + 1;
            let Some(m) = order.iter().find(|m| finalized[&m.id] >= h) else {
                return;
            };
            let Some(b) = order
                .iter()
                .filter(|m| finalized[&m.id] >= h)
                .find_map(|m| Self::block(&m.rpc, h).map(|b| (m.rpc.clone(), b)))
            else {
                let label = m.label.clone();
                self.world.lock().unwrap().warn(format!(
                    "no node holds finalized block {h} (asked {label} first)"
                ));
                return;
            };
            let (rpc_addr, block) = b;
            let hash = block["hash"].as_str().unwrap_or_default().to_owned();
            let root = block["stateRoot"].as_str().unwrap_or_default().to_owned();
            let parent = block["parentHash"].as_str().unwrap_or_default().to_owned();
            let base_fee = quantity(&block["baseFeePerGas"]).unwrap_or(0);
            let txs = block["transactions"]
                .as_array()
                .cloned()
                .unwrap_or_default();
            let receipts = if txs.is_empty() {
                Vec::new()
            } else {
                match rpc::call(
                    &rpc_addr,
                    "eth_getBlockReceipts",
                    &json!([tag(h)]),
                    RPC_TIMEOUT,
                ) {
                    Ok(Value::Array(r)) if r.len() == txs.len() => r,
                    other => {
                        self.world
                            .lock()
                            .unwrap()
                            .warn(format!("{rpc_addr}: receipts of block {h}: {other:?}"));
                        return;
                    }
                }
            };
            let mut w = self.world.lock().unwrap();
            if let Some((prev, _)) = w.chain.blocks.get(&(h - 1))
                && *prev != parent
            {
                let what = format!(
                    "block {h} {hash} names parent {parent}, but the finalized block {} is {prev}",
                    h - 1
                );
                w.violate(what);
            }
            let mut burned = 0u128;
            let mut calls = 0u64;
            let counter = w.counter.clone();
            for r in &receipts {
                let tx = r["transactionHash"].as_str().unwrap_or_default().to_owned();
                let ok = q64(&r["status"]) == Some(1);
                let gas = quantity(&r["gasUsed"]).unwrap_or(0);
                burned += gas * base_fee;
                let from = r["from"].as_str().unwrap_or_default().to_lowercase();
                let to = r["to"].as_str().map(str::to_lowercase);
                if let Some(created) = r["contractAddress"].as_str()
                    && ok
                    && from == self.deployer
                    && w.counter.is_none()
                {
                    let created = created.to_lowercase();
                    w.log(format!("counter contract {created} deployed in block {h}"));
                    w.counter = Some(created.clone());
                    w.chain.touched.insert(created);
                }
                if ok && to.is_some() && to == counter {
                    calls += 1;
                }
                if to.as_deref() == Some("0x0000000000000000000000000000000000005354") {
                    let topics: Vec<String> = r["logs"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter_map(|l| l["topics"][0].as_str().map(str::to_owned))
                        .collect();
                    w.chain.staking_logs.insert(tx.clone(), topics);
                }
                w.chain.touched.insert(from);
                if let Some(to) = to {
                    w.chain.touched.insert(to);
                }
                w.chain.included.insert(tx, (h, ok));
            }
            w.chain.burned += burned;
            w.chain.counter_calls += calls;
            let (b, c) = (w.chain.burned, w.chain.counter_calls);
            w.chain.blocks.insert(h, (hash, root));
            w.chain.scanned = h;
            drop(w);
            self.cum_burned.insert(h, b);
            self.cum_calls.insert(h, c);
            scanned = h;
        }
    }

    /// Every live node's finalized block, and one older one, are the
    /// canonical ones.
    fn agree(&mut self, members: &[Member], finalized: &HashMap<usize, u64>) {
        let (scanned, first) = {
            let w = self.world.lock().unwrap();
            (w.chain.scanned, w.chain.first)
        };
        if scanned == 0 {
            return;
        }
        for m in members {
            let Some(&f) = finalized.get(&m.id) else {
                continue;
            };
            let top = f.min(scanned);
            if top < first {
                continue;
            }
            let older = first + self.rng.below(top - first + 1);
            for h in [top, older] {
                let Some(b) = Self::block(&m.rpc, h) else {
                    continue;
                };
                let hash = b["hash"].as_str().unwrap_or_default();
                let root = b["stateRoot"].as_str().unwrap_or_default();
                let mut w = self.world.lock().unwrap();
                let Some((want, want_root)) = w.chain.blocks.get(&h).cloned() else {
                    continue;
                };
                if hash != want || root != want_root {
                    let what = format!(
                        "SAFETY: {} (#{}) holds block {h} {hash} (state {root}); the finalized chain has {want} (state {want_root})",
                        m.label, m.generation
                    );
                    w.violate(what);
                }
            }
        }
    }

    /// Balances conserve between this check and the last, at heights the
    /// scanner has read, on one node; the counter counts its calls.
    fn conserve(&mut self, members: &[Member]) {
        let (scanned, accounts, counter) = {
            let w = self.world.lock().unwrap();
            let mut accounts: Vec<String> = self.accounts.clone();
            accounts.extend(w.chain.touched.iter().cloned());
            accounts.sort();
            accounts.dedup();
            (w.chain.scanned, accounts, w.counter.clone())
        };
        if scanned == 0 {
            return;
        }
        let Some(m) = members
            .iter()
            .find(|m| Self::block(&m.rpc, scanned).is_some())
        else {
            return;
        };
        let sum = |h: u64| -> Option<u128> {
            let mut total = 0u128;
            for a in &accounts {
                let v =
                    rpc::call(&m.rpc, "eth_getBalance", &json!([a, tag(h)]), RPC_TIMEOUT).ok()?;
                total += quantity(&v)?;
            }
            Some(total)
        };
        if let Some((prev, _)) = self.last_balance
            && prev < scanned
            && let (Some(before), Some(after)) = (sum(prev), sum(scanned))
        {
            let burned = self.cum_burned.get(&scanned).copied().unwrap_or(0)
                - self.cum_burned.get(&prev).copied().unwrap_or(0);
            self.balance_checks += 1;
            if before.checked_sub(burned) != Some(after) {
                self.violate(format!(
                    "balances do not conserve from block {prev} to {scanned} on {}: {before} before, {burned} burned between, {after} after (off by {})",
                    m.label,
                    i128::try_from(after).unwrap_or(i128::MAX)
                        - i128::try_from(before).unwrap_or(0)
                        + i128::try_from(burned).unwrap_or(0)
                ));
            }
        }
        if let Some(c) = counter {
            let calls = self.cum_calls.get(&scanned).copied().unwrap_or(0);
            if let Ok(v) = rpc::call(
                &m.rpc,
                "eth_getStorageAt",
                &json!([c, "0x0", tag(scanned)]),
                RPC_TIMEOUT,
            ) {
                let stored = quantity(&v).unwrap_or(0);
                if stored != u128::from(calls) {
                    self.violate(format!(
                        "the counter holds {stored} at block {scanned} on {}, but {calls} calls to it succeeded",
                        m.label
                    ));
                }
            }
        }
        self.last_balance = Some((scanned, Instant::now()));
    }

    /// The key set behind the newest threshold certificates, and the
    /// validator set.
    fn keys(&mut self, members: &[Member]) {
        let scanned = self.world.lock().unwrap().chain.scanned;
        let Some(m) = members
            .iter()
            .find(|m| Self::block(&m.rpc, scanned).is_some())
        else {
            return;
        };
        for h in (scanned.saturating_sub(8)..=scanned).rev() {
            let Ok(p) = rpc::call(
                &m.rpc,
                "solo_getFinalityProof",
                &json!([tag(h)]),
                RPC_TIMEOUT,
            ) else {
                continue;
            };
            if let Some(id) = q64(&p["keyId"]) {
                // Its group key, from the handoff into it.
                let key = id.checked_sub(1).and_then(|from| {
                    rpc::call(&m.rpc, "solo_getRotation", &json!([tag(from)]), RPC_TIMEOUT)
                        .ok()
                        .and_then(|r| r["key"].as_str().map(str::to_owned))
                });
                let mut w = self.world.lock().unwrap();
                if key.is_some() {
                    w.trust_key = key;
                }
                if let std::collections::btree_map::Entry::Vacant(e) = w.chain.key_ids.entry(id) {
                    e.insert(h);
                    w.log(format!("threshold key set {id} certifies block {h}"));
                }
                break;
            }
        }
        if let Ok(u) = rpc::call(&m.rpc, "solo_upgradeStatus", &json!([]), RPC_TIMEOUT) {
            let set: Vec<String> = u["validators"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|v| v["id"].as_str().map(str::to_owned))
                .collect();
            let mut w = self.world.lock().unwrap();
            if !set.is_empty() && set != w.chain.set {
                let n = set.len();
                w.chain.set = set;
                w.log(format!("validator set now has {n} members"));
            }
        }
    }

    /// Counters do not fall within a process; nothing dropped; no
    /// equivocation; the metrics agree with the status.
    fn telemetry(&mut self, m: &Member) {
        let watch = self.watches.entry(m.id).or_default();
        if watch
            .last_metrics
            .is_some_and(|t| t.elapsed() < Duration::from_secs(15))
        {
            return;
        }
        watch.last_metrics = Some(Instant::now());
        let Ok(text) = rpc::get(&m.rpc, "/metrics", RPC_TIMEOUT) else {
            return;
        };
        if !self.same(m) {
            return;
        }
        let Ok(samples) = solo_metrics::parse(&text) else {
            self.violate(format!("{}: /metrics does not parse", m.label));
            return;
        };
        let mut problems = Vec::new();
        let watch = self.watches.get_mut(&m.id).unwrap();
        if watch.generation != m.generation {
            return;
        }
        for s in &samples {
            let key = format!(
                "{}{{{}}}",
                s.name,
                s.labels
                    .iter()
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect::<Vec<_>>()
                    .join(",")
            );
            // Counters, and the counts of histograms (whose `_sum` exists).
            let counter = s.name.ends_with("_total")
                || s.name.strip_suffix("_count").is_some_and(|base| {
                    let sum = format!("{base}_sum");
                    samples.iter().any(|x| x.name == sum)
                });
            if counter {
                if let Some(&was) = watch.counters.get(&key)
                    && s.value < was
                {
                    problems.push(format!("counter {key} fell from {was} to {}", s.value));
                }
                watch.counters.insert(key.clone(), s.value);
            }
            if s.name == "solo_emitted_dropped_total" && s.value > 0.0 {
                problems.push(format!("{key} = {}", s.value));
            }
            if s.name == "solo_emitted_counter_total"
                && s.label("name") == Some("equivocations")
                && s.value > 0.0
            {
                problems.push(format!("equivocations recorded: {}", s.value));
            }
            if !s.value.is_finite() || s.value < 0.0 && !s.name.contains("seconds") {
                problems.push(format!("{key} = {}", s.value));
            }
        }
        let get = |name: &str| samples.iter().find(|s| s.name == name).map(|s| s.value);
        if let (Some(fin), Some(head)) = (
            get("solo_chain_finalized_height"),
            get("ethereum_blockchain_height"),
        ) && fin > head
        {
            problems.push(format!("finalized height {fin} above the head {head}"));
        }
        if let (Some(fin), Some(exec)) = (
            get("solo_blocks_finalized_total"),
            get("solo_blocks_executed_total"),
        ) && fin > exec
        {
            problems.push(format!("{fin} blocks finalized but {exec} executed"));
        }
        let faults: f64 = samples
            .iter()
            .filter(|s| s.name == "solo_kernel_faults_total")
            .map(|s| s.value)
            .sum();
        if faults > 0.0 {
            let which: Vec<String> = samples
                .iter()
                .filter(|s| s.name == "solo_kernel_faults_total" && s.value > 0.0)
                .map(|s| format!("{:?} = {}", s.labels, s.value))
                .collect();
            self.world.lock().unwrap().warn(format!(
                "{}: kernel faults {}",
                m.label,
                which.join(", ")
            ));
        }
        for p in problems {
            self.violate(format!("{} (#{}) telemetry: {p}", m.label, m.generation));
        }
    }

    /// Memory and open files of the node's process.
    #[allow(clippy::naive_bytecount)]
    fn resources(&mut self, m: &Member) {
        let Some(pid) = m.pid else { return };
        let watch = self.watches.entry(m.id).or_default();
        if watch
            .last_resources
            .is_some_and(|t| t.elapsed() < Duration::from_secs(30))
        {
            return;
        }
        watch.last_resources = Some(Instant::now());
        let rss = Command::new("ps")
            .args(["-o", "rss=", "-p", &pid.to_string()])
            .output()
            .ok()
            .and_then(|o| {
                String::from_utf8_lossy(&o.stdout)
                    .trim()
                    .parse::<u64>()
                    .ok()
            });
        let fds = Command::new("lsof")
            .args(["-n", "-P", "-p", &pid.to_string()])
            .output()
            .ok()
            .map(|o| o.stdout.iter().filter(|b| **b == b'\n').count() as u64);
        let (Some(rss), Some(fds)) = (rss, fds) else {
            return;
        };
        watch.rss_max = watch.rss_max.max(rss);
        watch.fd_max = watch.fd_max.max(fds);
        if m.started.elapsed() < WARM {
            return;
        }
        let rss_base = *watch.rss_base.get_or_insert(rss);
        let fd_base = *watch.fd_base.get_or_insert(fds);
        let label = format!("{} (#{}, pid {pid})", m.label, m.generation);
        if rss > rss_base * RSS_GROWTH && rss > rss_base + RSS_SLACK {
            self.violate(format!(
                "{label} memory grew from {rss_base} KiB once warm to {rss} KiB"
            ));
        }
        if fds > fd_base + FD_SLACK {
            self.violate(format!(
                "{label} open files grew from {fd_base} once warm to {fds}"
            ));
        }
    }

    pub fn summaries(&self) -> Vec<NodeSummary> {
        let w = self.world.lock().unwrap();
        w.members
            .iter()
            .map(|m| {
                let watch = self.watches.get(&m.id);
                NodeSummary {
                    label: m.label.clone(),
                    generations: m.generation,
                    finalized: watch.map_or(0, |w| w.finalized),
                    rss_base_kb: watch.and_then(|w| w.rss_base),
                    rss_max_kb: watch.map_or(0, |w| w.rss_max),
                    fd_base: watch.and_then(|w| w.fd_base),
                    fd_max: watch.map_or(0, |w| w.fd_max),
                    latency_max_ms: watch.map_or(0, |w| w.latency_max.as_millis()),
                }
            })
            .collect()
    }
}
