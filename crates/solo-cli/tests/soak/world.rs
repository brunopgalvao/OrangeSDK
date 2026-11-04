//! What the scheduler, the load generator and the checker share: the
//! nodes as the scheduler last left them, the expectations of the moment,
//! the fault timeline and the violations found.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// What a node is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// A genesis validator.
    Validator,
    /// A keyed node outside the genesis set, which may join it by staking.
    Standby,
    /// A node without a key.
    Observer,
}

/// One node as the others see it.
#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)]
pub struct Member {
    /// Its id in the soak (and in the proxy table).
    pub id: usize,
    /// Its role.
    pub role: Role,
    /// `v0`, `s0`, `o0`, …
    pub label: String,
    /// JSON-RPC address.
    pub rpc: String,
    /// Its process, while it runs.
    pub pid: Option<u32>,
    /// How many times it was started.
    pub generation: u32,
    /// Stopped with SIGSTOP.
    pub frozen: bool,
    /// Under a fault that may slow it (slow links, a partition, a freeze).
    pub impaired: bool,
    /// When its current process started.
    pub started: Instant,
    /// When it last started or was thawed: frozen time is no silence.
    pub resumed: Instant,
    /// Whether its current process started from an empty data directory.
    pub fresh: bool,
    /// Whether it syncs its state from peers on this start.
    pub syncs: bool,
    /// Removed from the run for good.
    pub retired: bool,
}

impl Member {
    /// Running and not frozen: it should answer.
    pub fn live(&self) -> bool {
        self.pid.is_some() && !self.frozen && !self.retired
    }
}

/// What the checker expects of finality right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// No fault, or faults a quorum survives: finality keeps advancing.
    Live,
    /// Faults a quorum may not survive: no expectation until they heal.
    Severe,
}

/// The canonical chain as the checker has read it.
#[derive(Debug, Default)]
pub struct Chain {
    /// Finalized blocks by height: (hash, state root).
    pub blocks: BTreeMap<u64, (String, String)>,
    /// Every height up to this one is in `blocks` (or before the first read).
    pub scanned: u64,
    /// The first height read.
    pub first: u64,
    /// Transactions included, by hash: (height, succeeded).
    pub included: HashMap<String, (u64, bool)>,
    /// Logs of included transactions to the staking address: hash to topics.
    pub staking_logs: HashMap<String, Vec<String>>,
    /// Wei burned by blocks above `first`, up to `scanned`.
    pub burned: u128,
    /// Successful calls to the counter contract up to `scanned`.
    pub counter_calls: u64,
    /// Every address a scanned transaction touched.
    pub touched: BTreeSet<String>,
    /// Key set ids seen on finality proofs, with the first height.
    pub key_ids: BTreeMap<u64, u64>,
    /// The validator set, as the latest `solo_upgradeStatus` names it.
    pub set: Vec<String>,
}

/// Everything shared.
pub struct World {
    pub start: Instant,
    pub members: Vec<Member>,
    pub mode: Mode,
    /// When the mode last changed.
    pub since: Instant,
    pub timeline: Vec<String>,
    pub violations: Vec<String>,
    pub warnings: Vec<String>,
    /// When any node last restarted (a pool lost).
    pub last_restart: Option<Instant>,
    /// When a fault last ended.
    pub last_heal: Instant,
    pub chain: Chain,
    /// The group keys of the active key sets seen, by id.
    pub key_sets: std::collections::BTreeMap<u64, String>,
    /// The counter contract, once deployed.
    pub counter: Option<String>,
    /// Stops the helper threads.
    pub done: bool,
}

pub type Shared = Arc<Mutex<World>>;

impl World {
    pub fn new() -> World {
        let now = Instant::now();
        World {
            start: now,
            members: Vec::new(),
            mode: Mode::Live,
            since: now,
            timeline: Vec::new(),
            violations: Vec::new(),
            warnings: Vec::new(),
            last_restart: None,
            last_heal: now,
            chain: Chain::default(),
            key_sets: std::collections::BTreeMap::new(),
            counter: None,
            done: false,
        }
    }

    /// What a joiner trusts (`--trust-key <id>:<key>`, spec 22 §7.5): the
    /// key set before the newest one seen, as an operator who looked it up
    /// a while ago would hold, so that every state sync follows handoffs
    /// from it; within the chain's unbonding period, it reaches every
    /// snapshot served meanwhile.
    pub fn trust_key(&self) -> Option<String> {
        let mut newest = self.key_sets.iter().rev();
        let (id, key) = newest.nth(1).or_else(|| self.key_sets.iter().next_back())?;
        Some(format!("{id}:{key}"))
    }

    /// Seconds since the start, for the timeline.
    pub fn t(&self) -> f64 {
        self.start.elapsed().as_secs_f64()
    }

    /// Notes `what` in the timeline (and on stderr).
    pub fn log(&mut self, what: impl Into<String>) {
        let line = format!("[{:8.1}s] {}", self.t(), what.into());
        eprintln!("soak {line}");
        self.timeline.push(line);
    }

    /// Records a violation once.
    pub fn violate(&mut self, what: impl Into<String>) {
        let what = what.into();
        if !self.violations.iter().any(|v| v.ends_with(&what)) {
            let line = format!("[{:8.1}s] {what}", self.t());
            eprintln!("soak VIOLATION {line}");
            self.timeline.push(format!("VIOLATION {line}"));
            self.violations.push(line);
        }
    }

    /// Records a warning once.
    pub fn warn(&mut self, what: impl Into<String>) {
        let what = what.into();
        if !self.warnings.iter().any(|v| v.ends_with(&what)) {
            let line = format!("[{:8.1}s] {what}", self.t());
            eprintln!("soak warning {line}");
            self.warnings.push(line);
        }
    }

    pub fn set_mode(&mut self, mode: Mode) {
        if self.mode != mode {
            self.mode = mode;
            self.since = Instant::now();
        }
    }
}
