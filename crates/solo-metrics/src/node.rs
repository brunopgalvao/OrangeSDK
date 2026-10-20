//! The node's metric schema (spec 11 §4) and [`NodeMetrics`], the recorder
//! the node, its transport and the HTTP endpoints share.

use std::collections::BTreeMap;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::registry::{Desc, Kind, Registry};

/// The release these metrics come from, as `solo_build_info` and `/status` report it.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Bucket bounds of `solo_kernel_call_duration_seconds`, in seconds.
pub const LATENCY_BUCKETS: &[f64] = &[
    0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

/// Longest name a kernel or module may give an emitted metric, in bytes.
pub const MAX_EMITTED_NAME: usize = 64;

/// Most series each emitted family holds per origin; later names from that
/// origin are dropped.
pub const MAX_EMITTED_SERIES: usize = 256;

/// The kernel entrypoints of spec 06 section 3, in its order: the
/// `entrypoint` values whose fault series exist from the moment the node opens.
pub const ENTRYPOINTS: [&str; 10] = [
    "kernel_init",
    "kernel_driver_step",
    "kernel_driver_state",
    "kernel_migrate",
    "kernel_version",
    "kernel_stf_validate_tx",
    "kernel_stf_build_block",
    "kernel_stf_execute_block",
    "kernel_stf_finalize_block",
    "kernel_query",
];

/// `status` label values of `solo_kernel_faults_total`: every termination
/// but halt (spec 01 section 6).
pub const FAULT_STATUSES: [&str; 6] = [
    "out_of_gas",
    "trap",
    "memory_fault",
    "invalid_jump",
    "host_error",
    "step_limit",
];

/// `reason` label values of `solo_emitted_dropped_total` (spec 11 section 5).
pub const DROP_REASONS: [&str; 4] = ["name", "kind", "negative", "cardinality"];

/// `level` label values of `solo_kernel_logs_total`, indexed by the
/// `log_emit` level; any other level is `other`.
pub const LOG_LEVELS: [&str; 5] = ["error", "warn", "info", "debug", "trace"];

const fn desc(
    name: &'static str,
    kind: Kind,
    labels: &'static [&'static str],
    help: &'static str,
) -> Desc {
    Desc {
        name,
        help,
        kind,
        labels,
        buckets: &[],
    }
}

/// `ethereum_blockchain_height` (EIP-2159).
pub const HEAD: Desc = desc(
    "ethereum_blockchain_height",
    Kind::Gauge,
    &[],
    "The current height of the canonical chain: the last block this node executed (EIP-2159).",
);
/// `ethereum_best_known_block_number` (EIP-2159).
pub const BEST_KNOWN: Desc = desc(
    "ethereum_best_known_block_number",
    Kind::Gauge,
    &[],
    "The estimated highest block available (EIP-2159); the head, since the node does not know a sync target.",
);
/// `ethereum_peer_count` (EIP-2159).
pub const PEERS: Desc = desc(
    "ethereum_peer_count",
    Kind::Gauge,
    &[],
    "The current number of peers connected (EIP-2159); absent on a node without a peer-to-peer transport.",
);
/// `solo_chain_finalized_height`.
pub const FINALIZED: Desc = desc(
    "solo_chain_finalized_height",
    Kind::Gauge,
    &[],
    "The last height this node finalized.",
);
/// `solo_chain_head_age_seconds`.
pub const HEAD_AGE: Desc = desc(
    "solo_chain_head_age_seconds",
    Kind::Gauge,
    &[],
    "Seconds since the head last advanced, or since the node started if it has executed no block.",
);
/// `solo_chain_id`.
pub const CHAIN_ID: Desc = desc(
    "solo_chain_id",
    Kind::Gauge,
    &[],
    "The chain id the kernel reports.",
);
/// `solo_blocks_executed_total`.
pub const BLOCKS_EXECUTED: Desc = desc(
    "solo_blocks_executed_total",
    Kind::Counter,
    &[],
    "Blocks this node executed.",
);
/// `solo_blocks_finalized_total`.
pub const BLOCKS_FINALIZED: Desc = desc(
    "solo_blocks_finalized_total",
    Kind::Counter,
    &[],
    "Blocks this node finalized.",
);
/// `solo_block_transactions_total`.
pub const BLOCK_TRANSACTIONS: Desc = desc(
    "solo_block_transactions_total",
    Kind::Counter,
    &[],
    "Transactions in the blocks this node executed.",
);
/// `solo_block_gas_used_total`.
pub const BLOCK_GAS: Desc = desc(
    "solo_block_gas_used_total",
    Kind::Counter,
    &[],
    "Gas used by the blocks this node executed, as their execution summaries report it.",
);
/// `solo_mempool_transactions`.
pub const MEMPOOL_TRANSACTIONS: Desc = desc(
    "solo_mempool_transactions",
    Kind::Gauge,
    &[],
    "Transactions waiting in the mempool.",
);
/// `solo_mempool_bytes`.
pub const MEMPOOL_BYTES: Desc = desc(
    "solo_mempool_bytes",
    Kind::Gauge,
    &[],
    "Raw bytes of the transactions waiting in the mempool.",
);
/// `solo_driver_timers`.
pub const DRIVER_TIMERS: Desc = desc(
    "solo_driver_timers",
    Kind::Gauge,
    &[],
    "Timers the consensus driver has armed.",
);
/// `solo_kernel_call_duration_seconds`.
pub const KERNEL_CALL_SECONDS: Desc = Desc {
    buckets: LATENCY_BUCKETS,
    ..desc(
        "solo_kernel_call_duration_seconds",
        Kind::Histogram,
        &["entrypoint"],
        "Wall-clock time of each kernel entrypoint call; its _count is the number of calls.",
    )
};
/// `solo_kernel_gas_used_total`.
pub const KERNEL_GAS: Desc = desc(
    "solo_kernel_gas_used_total",
    Kind::Counter,
    &["entrypoint"],
    "VM gas the kernel consumed, by entrypoint.",
);
/// `solo_kernel_faults_total`.
pub const KERNEL_FAULTS: Desc = desc(
    "solo_kernel_faults_total",
    Kind::Counter,
    &["entrypoint", "status"],
    "Kernel calls that ended in anything but halt (spec 06 section 6); driver faults have a kernel_driver_ entrypoint.",
);
/// `solo_kernel_logs_total`.
pub const KERNEL_LOGS: Desc = desc(
    "solo_kernel_logs_total",
    Kind::Counter,
    &["level"],
    "Lines the kernel and its modules wrote with log_emit, by level.",
);
/// `solo_emitted_counter_total`.
pub const EMITTED_COUNTER: Desc = desc(
    "solo_emitted_counter_total",
    Kind::Counter,
    &["origin", "name"],
    "Counters the kernel, its driver and sandboxed modules emit (metric_emit kind 0, Effect::Metric).",
);
/// `solo_emitted_gauge`.
pub const EMITTED_GAUGE: Desc = desc(
    "solo_emitted_gauge",
    Kind::Gauge,
    &["origin", "name"],
    "Gauges the kernel and sandboxed modules emit (metric_emit kind 1).",
);
/// `solo_emitted_dropped_total`.
pub const EMITTED_DROPPED: Desc = desc(
    "solo_emitted_dropped_total",
    Kind::Counter,
    &["reason"],
    "Emitted metrics the node discarded: bad name, unknown kind, negative counter step, or too many series.",
);
/// `solo_p2p_bytes_total`.
pub const P2P_BYTES: Desc = desc(
    "solo_p2p_bytes_total",
    Kind::Counter,
    &["direction"],
    "Bytes the peer-to-peer transport read and wrote.",
);
/// `solo_p2p_frames_total`.
pub const P2P_FRAMES: Desc = desc(
    "solo_p2p_frames_total",
    Kind::Counter,
    &["direction", "kind"],
    "Frames the peer-to-peer transport received and queued for sending, by frame kind.",
);
/// `solo_upgrade_blocked`.
pub const UPGRADE_BLOCKED: Desc = desc(
    "solo_upgrade_blocked",
    Kind::Gauge,
    &[],
    "1 while the pending kernel upgrade cannot be enacted by this host (spec 13 section 7.2), else 0.",
);
/// `solo_upgrade_missing_gates`.
pub const UPGRADE_MISSING_GATES: Desc = desc(
    "solo_upgrade_missing_gates",
    Kind::Gauge,
    &[],
    "Feature gates the chain has locked in that this host release does not support (spec 13 section 7.2).",
);
/// `solo_build_info`.
pub const BUILD_INFO: Desc = desc(
    "solo_build_info",
    Kind::Gauge,
    &["version"],
    "Always 1; the label names the release.",
);
/// `solo_node_start_time_seconds`.
pub const START_TIME: Desc = desc(
    "solo_node_start_time_seconds",
    Kind::Gauge,
    &[],
    "Unix time at which the node opened, in seconds.",
);

/// Every family the node exports, in the order spec 11 §4 lists them.
pub const ALL: &[Desc] = &[
    HEAD,
    BEST_KNOWN,
    PEERS,
    FINALIZED,
    HEAD_AGE,
    CHAIN_ID,
    BLOCKS_EXECUTED,
    BLOCKS_FINALIZED,
    BLOCK_TRANSACTIONS,
    BLOCK_GAS,
    MEMPOOL_TRANSACTIONS,
    MEMPOOL_BYTES,
    DRIVER_TIMERS,
    KERNEL_CALL_SECONDS,
    KERNEL_GAS,
    KERNEL_FAULTS,
    KERNEL_LOGS,
    EMITTED_COUNTER,
    EMITTED_GAUGE,
    EMITTED_DROPPED,
    P2P_BYTES,
    P2P_FRAMES,
    UPGRADE_BLOCKED,
    UPGRADE_MISSING_GATES,
    BUILD_INFO,
    START_TIME,
];

/// Every sample name the node exports: what alert rules and dashboards may
/// reference.
#[must_use]
pub fn exported_names() -> Vec<String> {
    ALL.iter().flat_map(Desc::sample_names).collect()
}

/// Who emitted a metric (the `origin` label).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Origin {
    /// The consensus driver, through `Effect::Metric`.
    Driver,
    /// A privileged instance (the kernel), through `metric_emit`.
    Kernel,
    /// A sandboxed instance (a kernel module or contract), through `metric_emit`.
    Sandboxed,
}

impl Origin {
    /// The label value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Origin::Driver => "driver",
            Origin::Kernel => "kernel",
            Origin::Sandboxed => "sandboxed",
        }
    }
}

/// A direction of peer-to-peer traffic (the `direction` label).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Direction {
    /// Received.
    In,
    /// Sent.
    Out,
}

impl Direction {
    /// The label value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Direction::In => "in",
            Direction::Out => "out",
        }
    }
}

/// Traffic a transport counted since it last handed it to
/// [`NodeMetrics::p2p`]; kept by the transport because frames are queued
/// where the node is out of reach.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Traffic {
    bytes: BTreeMap<Direction, u64>,
    frames: BTreeMap<(Direction, &'static str), u64>,
}

impl Traffic {
    /// Counts `n` bytes.
    pub fn bytes(&mut self, direction: Direction, n: usize) {
        *self.bytes.entry(direction).or_default() += n as u64;
    }

    /// Counts one frame of `kind`.
    pub fn frame(&mut self, direction: Direction, kind: &'static str) {
        *self.frames.entry((direction, kind)).or_default() += 1;
    }
}

/// A snapshot of the node for `GET /status` (spec 11 §6).
#[derive(Debug, Clone, PartialEq)]
pub struct Status {
    /// Release, as [`VERSION`].
    pub version: String,
    /// Chain id from the kernel.
    pub chain_id: u64,
    /// Last executed height.
    pub head: u64,
    /// Seconds since the head last advanced.
    pub head_age_seconds: f64,
    /// Last finalized height.
    pub finalized: u64,
    /// Whether the node runs a peer-to-peer transport.
    pub p2p: bool,
    /// Peers that completed the handshake; 0 without a transport.
    pub peers: u64,
    /// Transactions in the mempool.
    pub mempool: u64,
    /// Seconds since the node opened.
    pub uptime_seconds: f64,
    /// The validator id, for a node with a consensus key.
    pub validator: Option<[u8; 32]>,
    /// Why the pending kernel upgrade cannot be enacted by this host, while
    /// it cannot (spec 13 §7.2).
    pub upgrade_alert: Option<String>,
    /// The locked-in feature gates this host does not support, one bit per
    /// gate (spec 13 §7.2).
    pub missing_gates: u64,
}

/// The node's metrics: a [`Registry`] over [`ALL`] plus the little state
/// the time-based gauges need.
#[derive(Debug, Clone)]
pub struct NodeMetrics {
    registry: Registry,
    opened: Instant,
    head_changed: Instant,
    head: u64,
    finalized: u64,
    logs_seen: usize,
    chain_id: Option<u64>,
    /// Series of each emitted family (by name) per origin, for the
    /// per-origin cardinality limit.
    emitted_series: BTreeMap<(&'static str, Origin), usize>,
}

impl Default for NodeMetrics {
    fn default() -> NodeMetrics {
        NodeMetrics::new()
    }
}

#[allow(clippy::cast_precision_loss)]
fn float(n: u64) -> f64 {
    n as f64
}

/// Validates an emitted metric name: 1 to [`MAX_EMITTED_NAME`] bytes of
/// ASCII letters, digits, `_`, `.`, `:` and `-`.
#[must_use]
pub fn emitted_name(name: &[u8]) -> Option<&str> {
    let ok = (1..=MAX_EMITTED_NAME).contains(&name.len())
        && name
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(b));
    // Every accepted byte is ASCII, so the conversion cannot fail.
    ok.then(|| std::str::from_utf8(name).unwrap_or_default())
}

impl NodeMetrics {
    /// Metrics for a node opening now: every family registered, the chain
    /// gauges and the fault and drop counters at zero, `solo_build_info` and
    /// the start time set.
    #[must_use]
    pub fn new() -> NodeMetrics {
        let mut registry = Registry::new();
        for d in ALL {
            registry.register(d);
        }
        for d in [
            &HEAD,
            &BEST_KNOWN,
            &FINALIZED,
            &HEAD_AGE,
            &BLOCKS_EXECUTED,
            &BLOCKS_FINALIZED,
            &BLOCK_TRANSACTIONS,
            &BLOCK_GAS,
            &MEMPOOL_TRANSACTIONS,
            &MEMPOOL_BYTES,
            &DRIVER_TIMERS,
            &UPGRADE_BLOCKED,
            &UPGRADE_MISSING_GATES,
        ] {
            registry.set(d, &[], 0.0);
        }
        // Series that alerts read with `increase()` exist at zero from the
        // start, so that their first event is a step Prometheus can see.
        for entrypoint in ENTRYPOINTS {
            for status in FAULT_STATUSES {
                registry.set(&KERNEL_FAULTS, &[entrypoint, status], 0.0);
            }
        }
        for reason in DROP_REASONS {
            registry.set(&EMITTED_DROPPED, &[reason], 0.0);
        }
        registry.set(&BUILD_INFO, &[VERSION], 1.0);
        let unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        registry.set(&START_TIME, &[], unix.as_secs_f64());
        let now = Instant::now();
        NodeMetrics {
            registry,
            opened: now,
            head_changed: now,
            head: 0,
            finalized: 0,
            logs_seen: 0,
            chain_id: None,
            emitted_series: BTreeMap::new(),
        }
    }

    /// The underlying registry, for reading values.
    #[must_use]
    pub fn registry(&self) -> &Registry {
        &self.registry
    }

    /// Records one kernel entrypoint call: its duration, the gas it used,
    /// and the fault label if it ended in anything but halt.
    pub fn kernel_call(
        &mut self,
        entrypoint: &str,
        elapsed: Duration,
        gas_used: u64,
        fault: Option<&str>,
    ) {
        self.registry
            .observe(&KERNEL_CALL_SECONDS, &[entrypoint], elapsed.as_secs_f64());
        self.registry
            .inc(&KERNEL_GAS, &[entrypoint], float(gas_used));
        if let Some(status) = fault {
            self.registry
                .inc(&KERNEL_FAULTS, &[entrypoint, status], 1.0);
        }
    }

    /// Counts the `(level, line)` entries of `logs` past those already
    /// counted; the node passes the executor's whole log every time.
    pub fn kernel_logs(&mut self, logs: &[(u32, Vec<u8>)]) {
        for (level, _) in logs.get(self.logs_seen..).unwrap_or_default() {
            let label = LOG_LEVELS.get(*level as usize).copied().unwrap_or("other");
            self.registry.inc(&KERNEL_LOGS, &[label], 1.0);
        }
        self.logs_seen = logs.len();
    }

    fn drop_emitted(&mut self, reason: &str) {
        self.registry.inc(&EMITTED_DROPPED, &[reason], 1.0);
    }

    /// Records an emitted metric (spec 11 §5): kind 0 adds a non-negative
    /// step to a counter, kind 1 sets a gauge; anything else, a bad name,
    /// or a new name past [`MAX_EMITTED_SERIES`] for its origin is dropped
    /// and counted. Each origin has its own limit, so sandboxed instances
    /// cannot crowd out the kernel's and the driver's series.
    pub fn emitted(&mut self, origin: Origin, name: &[u8], value: i64, kind: u32) {
        let Some(name) = emitted_name(name) else {
            return self.drop_emitted("name");
        };
        let family = match kind {
            0 if value < 0 => return self.drop_emitted("negative"),
            0 => &EMITTED_COUNTER,
            1 => &EMITTED_GAUGE,
            _ => return self.drop_emitted("kind"),
        };
        let labels = [origin.as_str(), name];
        if !self.registry.contains(family, &labels) {
            let series = self
                .emitted_series
                .entry((family.name, origin))
                .or_default();
            if *series >= MAX_EMITTED_SERIES {
                return self.drop_emitted("cardinality");
            }
            *series += 1;
        }
        #[allow(clippy::cast_precision_loss)]
        let value = value as f64;
        if kind == 0 {
            self.registry.inc(family, &labels, value);
        } else {
            self.registry.set(family, &labels, value);
        }
    }

    /// Records `Effect::Metric`: a counter step from the driver.
    pub fn driver_metric(&mut self, name: &[u8], value: i64) {
        self.emitted(Origin::Driver, name, value, 0);
    }

    /// Records an executed block.
    pub fn block_executed(&mut self, height: u64, transactions: u32, gas_used: u64) {
        self.registry.inc(&BLOCKS_EXECUTED, &[], 1.0);
        self.registry
            .inc(&BLOCK_TRANSACTIONS, &[], f64::from(transactions));
        self.registry.inc(&BLOCK_GAS, &[], float(gas_used));
        self.head = height;
        self.head_changed = Instant::now();
        self.registry.set(&HEAD, &[], float(height));
        self.registry.set(&BEST_KNOWN, &[], float(height));
    }

    /// Records a finalized block.
    pub fn block_finalized(&mut self, height: u64) {
        self.registry.inc(&BLOCKS_FINALIZED, &[], 1.0);
        self.finalized = height;
        self.registry.set(&FINALIZED, &[], float(height));
    }

    /// Records the transport's view: the peer count and the traffic it
    /// counted since the last call, which this drains.
    pub fn p2p(&mut self, peers: usize, traffic: &mut Traffic) {
        self.registry.set(&PEERS, &[], float(peers as u64));
        for (direction, n) in std::mem::take(&mut traffic.bytes) {
            self.registry
                .inc(&P2P_BYTES, &[direction.as_str()], float(n));
        }
        for ((direction, kind), n) in std::mem::take(&mut traffic.frames) {
            self.registry
                .inc(&P2P_FRAMES, &[direction.as_str(), kind], float(n));
        }
    }

    /// Records the chain id the kernel reported. It is kept for the node's
    /// life (spec 11 section 2), so later scrapes need not ask the kernel.
    pub fn set_chain_id(&mut self, id: u64) {
        self.chain_id = Some(id);
        self.registry.set(&CHAIN_ID, &[], float(id));
    }

    /// The chain id, once the kernel has reported it.
    #[must_use]
    pub fn chain_id(&self) -> Option<u64> {
        self.chain_id
    }

    /// Sets the gauges read from the node at scrape time.
    pub fn refresh(&mut self, mempool_transactions: usize, mempool_bytes: usize, timers: usize) {
        self.registry.set(
            &MEMPOOL_TRANSACTIONS,
            &[],
            float(mempool_transactions as u64),
        );
        self.registry
            .set(&MEMPOOL_BYTES, &[], float(mempool_bytes as u64));
        self.registry.set(&DRIVER_TIMERS, &[], float(timers as u64));
        let age = self.head_age_seconds();
        self.registry.set(&HEAD_AGE, &[], age);
    }

    /// Sets the upgrade gauges: whether the pending kernel upgrade cannot be
    /// enacted, and the locked-in gates this host does not support (one bit
    /// per gate).
    pub fn upgrade(&mut self, blocked: bool, missing_gates: u64) {
        self.registry
            .set(&UPGRADE_BLOCKED, &[], f64::from(u8::from(blocked)));
        self.registry.set(
            &UPGRADE_MISSING_GATES,
            &[],
            f64::from(missing_gates.count_ones()),
        );
    }

    /// Last executed height.
    #[must_use]
    pub fn head(&self) -> u64 {
        self.head
    }

    /// Last finalized height.
    #[must_use]
    pub fn finalized(&self) -> u64 {
        self.finalized
    }

    /// Seconds since the head last advanced (or since the node opened).
    #[must_use]
    pub fn head_age_seconds(&self) -> f64 {
        self.head_changed.elapsed().as_secs_f64()
    }

    /// Seconds since the node opened.
    #[must_use]
    pub fn uptime_seconds(&self) -> f64 {
        self.opened.elapsed().as_secs_f64()
    }

    /// The peer count, once a transport reported one.
    #[must_use]
    pub fn peers(&self) -> Option<u64> {
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        self.registry.value(&PEERS, &[]).map(|p| p as u64)
    }

    /// The text exposition of every family.
    #[must_use]
    pub fn render(&self) -> String {
        self.registry.render()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::parse;

    #[test]
    fn desc_builds_plain_families() {
        // The constants evaluate `desc` at compile time; this runs it.
        assert_eq!(
            desc("x_total", Kind::Counter, &["a"], "Help."),
            Desc {
                name: "x_total",
                help: "Help.",
                kind: Kind::Counter,
                labels: &["a"],
                buckets: &[],
            }
        );
    }

    #[test]
    fn schema_is_valid_and_complete() {
        let mut names: Vec<&str> = ALL.iter().map(|d| d.name).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), ALL.len(), "duplicate family names");
        for d in ALL {
            Registry::new().register(d);
            if d.kind == Kind::Counter {
                assert!(d.name.ends_with("_total"), "{}", d.name);
            } else {
                assert!(!d.name.ends_with("_total"), "{}", d.name);
            }
            assert!(d.name.starts_with("solo_") || d.name.starts_with("ethereum_"));
            assert!(!d.help.contains('\n'));
        }
        assert!(exported_names().contains(&"solo_kernel_call_duration_seconds_bucket".to_owned()));
        assert!(exported_names().contains(&"ethereum_peer_count".to_owned()));
    }

    #[test]
    fn records_chain_kernel_and_transport() {
        let mut m = NodeMetrics::default();
        let r = |m: &NodeMetrics, d: &Desc, labels: &[&str]| m.registry().value(d, labels);
        assert_eq!(r(&m, &HEAD, &[]), Some(0.0));
        assert_eq!(r(&m, &BUILD_INFO, &[VERSION]), Some(1.0));
        assert!(r(&m, &START_TIME, &[]).unwrap() > 1.7e9);
        assert_eq!(m.peers(), None);
        m.block_executed(3, 2, 42_000);
        m.block_finalized(3);
        assert_eq!((m.head(), m.finalized()), (3, 3));
        assert_eq!(r(&m, &BEST_KNOWN, &[]), Some(3.0));
        assert_eq!(r(&m, &BLOCK_TRANSACTIONS, &[]), Some(2.0));
        assert_eq!(r(&m, &BLOCK_GAS, &[]), Some(42_000.0));
        assert_eq!(r(&m, &BLOCKS_FINALIZED, &[]), Some(1.0));
        m.kernel_call("kernel_query", Duration::from_millis(2), 500, None);
        m.kernel_call(
            "kernel_driver_step",
            Duration::from_secs(20),
            7,
            Some("out_of_gas"),
        );
        assert_eq!(
            m.registry()
                .histogram(&KERNEL_CALL_SECONDS, &["kernel_query"]),
            Some((1, 0.002))
        );
        assert_eq!(r(&m, &KERNEL_GAS, &["kernel_query"]), Some(500.0));
        assert_eq!(
            r(&m, &KERNEL_FAULTS, &["kernel_driver_step", "out_of_gas"]),
            Some(1.0)
        );
        assert_eq!(
            m.registry().series(&KERNEL_FAULTS),
            ENTRYPOINTS.len() * FAULT_STATUSES.len()
        );
        let line = |level: u32| (level, b"line".to_vec());
        m.kernel_logs(&[line(0), line(2)]);
        m.kernel_logs(&[line(0), line(2), line(9), line(4)]);
        m.kernel_logs(&[]);
        assert_eq!(r(&m, &KERNEL_LOGS, &["error"]), Some(1.0));
        assert_eq!(r(&m, &KERNEL_LOGS, &["info"]), Some(1.0));
        assert_eq!(r(&m, &KERNEL_LOGS, &["other"]), Some(1.0));
        assert_eq!(r(&m, &KERNEL_LOGS, &["trace"]), Some(1.0));
        let mut t = Traffic::default();
        t.bytes(Direction::In, 10);
        t.bytes(Direction::Out, 4);
        t.bytes(Direction::Out, 1);
        t.frame(Direction::In, "hello");
        t.frame(Direction::Out, "message");
        t.frame(Direction::Out, "message");
        m.p2p(2, &mut t);
        assert_eq!(t, Traffic::default());
        m.p2p(3, &mut t);
        assert_eq!(m.peers(), Some(3));
        assert_eq!(r(&m, &P2P_BYTES, &["out"]), Some(5.0));
        assert_eq!(r(&m, &P2P_FRAMES, &["out", "message"]), Some(2.0));
        assert_eq!(r(&m, &P2P_FRAMES, &["in", "hello"]), Some(1.0));
        assert_eq!((m.chain_id(), r(&m, &CHAIN_ID, &[])), (None, None));
        m.set_chain_id(1337);
        m.refresh(4, 400, 2);
        assert_eq!(m.chain_id(), Some(1337));
        assert_eq!(r(&m, &CHAIN_ID, &[]), Some(1337.0));
        assert_eq!(r(&m, &MEMPOOL_BYTES, &[]), Some(400.0));
        assert_eq!(r(&m, &DRIVER_TIMERS, &[]), Some(2.0));
        assert!(r(&m, &HEAD_AGE, &[]).unwrap() >= 0.0);
        assert!(m.uptime_seconds() >= m.head_age_seconds());
        let samples = parse(&m.render()).unwrap();
        assert!(samples.iter().any(
            |s| s.name == "ethereum_blockchain_height" && (s.value - 3.0).abs() < f64::EPSILON
        ));
        assert!(format!("{:?}", m.clone()).contains("NodeMetrics"));
    }

    #[test]
    fn emitted_metrics_are_bounded() {
        let mut m = NodeMetrics::new();
        let r = |m: &NodeMetrics, d: &Desc, labels: &[&str]| m.registry().value(d, labels);
        m.driver_metric(b"blocks", 1);
        m.driver_metric(b"blocks", 2);
        m.emitted(Origin::Kernel, b"blocks", 5, 0);
        m.emitted(Origin::Sandboxed, b"pool.depth", -4, 1);
        assert_eq!(r(&m, &EMITTED_COUNTER, &["driver", "blocks"]), Some(3.0));
        assert_eq!(r(&m, &EMITTED_COUNTER, &["kernel", "blocks"]), Some(5.0));
        assert_eq!(
            r(&m, &EMITTED_GAUGE, &["sandboxed", "pool.depth"]),
            Some(-4.0)
        );
        m.emitted(Origin::Kernel, b"", 1, 0);
        m.emitted(Origin::Kernel, b"bad name", 1, 0);
        m.emitted(Origin::Kernel, &[b'a'; MAX_EMITTED_NAME + 1], 1, 0);
        m.emitted(Origin::Kernel, b"x", -1, 0);
        m.emitted(Origin::Kernel, b"x", 1, 2);
        assert_eq!(r(&m, &EMITTED_DROPPED, &["name"]), Some(3.0));
        assert_eq!(r(&m, &EMITTED_DROPPED, &["negative"]), Some(1.0));
        assert_eq!(r(&m, &EMITTED_DROPPED, &["kind"]), Some(1.0));
        // `pool.depth` already holds one series of the gauge family.
        for i in 1..MAX_EMITTED_SERIES {
            m.emitted(Origin::Sandboxed, format!("g{i}").as_bytes(), 1, 1);
        }
        // The family is full: a new name is dropped, a known one still updates.
        m.emitted(Origin::Sandboxed, b"one-more", 1, 1);
        m.emitted(Origin::Sandboxed, b"g1", 9, 1);
        assert_eq!(r(&m, &EMITTED_DROPPED, &["cardinality"]), Some(1.0));
        assert_eq!(r(&m, &EMITTED_GAUGE, &["sandboxed", "g1"]), Some(9.0));
        // The limit is per origin: sandboxed instances that fill a family
        // leave the kernel and the driver their own room in it.
        for i in 0..=MAX_EMITTED_SERIES {
            m.emitted(Origin::Sandboxed, format!("spam{i}").as_bytes(), 1, 0);
        }
        assert_eq!(r(&m, &EMITTED_DROPPED, &["cardinality"]), Some(2.0));
        m.driver_metric(b"late", 1);
        m.emitted(Origin::Kernel, b"txs", 5, 0);
        m.emitted(Origin::Kernel, b"depth", 3, 1);
        assert_eq!(r(&m, &EMITTED_COUNTER, &["driver", "late"]), Some(1.0));
        assert_eq!(r(&m, &EMITTED_COUNTER, &["kernel", "txs"]), Some(5.0));
        assert_eq!(r(&m, &EMITTED_GAUGE, &["kernel", "depth"]), Some(3.0));
        assert_eq!(r(&m, &EMITTED_DROPPED, &["cardinality"]), Some(2.0));
        assert_eq!(emitted_name(b"a:b-c_d.e9"), Some("a:b-c_d.e9"));
        assert_eq!(emitted_name("é".as_bytes()), None);
        assert_eq!(Origin::Kernel.as_str(), "kernel");
        assert_eq!(Direction::In.as_str(), "in");
    }

    #[test]
    fn fault_and_drop_series_exist_from_the_start() {
        let samples = parse(&NodeMetrics::new().render()).unwrap();
        let faults: Vec<_> = samples
            .iter()
            .filter(|s| s.name == KERNEL_FAULTS.name)
            .collect();
        assert_eq!(faults.len(), ENTRYPOINTS.len() * FAULT_STATUSES.len());
        assert!(faults.iter().all(|s| s.value == 0.0));
        for reason in DROP_REASONS {
            assert!(samples.iter().any(|s| s.name == EMITTED_DROPPED.name
                && s.label("reason") == Some(reason)
                && s.value == 0.0));
        }
    }

    #[test]
    fn upgrade_gauges_start_at_zero_and_follow_the_node() {
        let mut m = NodeMetrics::new();
        let read = |m: &NodeMetrics, d: &Desc| m.registry().value(d, &[]);
        assert_eq!(read(&m, &UPGRADE_BLOCKED), Some(0.0));
        assert_eq!(read(&m, &UPGRADE_MISSING_GATES), Some(0.0));
        m.upgrade(true, 0b1001);
        assert_eq!(read(&m, &UPGRADE_BLOCKED), Some(1.0));
        assert_eq!(read(&m, &UPGRADE_MISSING_GATES), Some(2.0));
        assert!(m.render().contains("\nsolo_upgrade_blocked 1\n"));
        m.upgrade(false, 0);
        assert_eq!(read(&m, &UPGRADE_BLOCKED), Some(0.0));
        assert_eq!(read(&m, &UPGRADE_MISSING_GATES), Some(0.0));
    }

    #[test]
    fn status_is_plain_data() {
        let s = Status {
            version: VERSION.to_owned(),
            chain_id: 1,
            head: 2,
            head_age_seconds: 0.5,
            finalized: 2,
            p2p: false,
            peers: 0,
            mempool: 0,
            uptime_seconds: 1.0,
            validator: None,
            upgrade_alert: None,
            missing_gates: 0,
        };
        assert_eq!(s.clone(), s);
        assert!(format!("{s:?}").contains("chain_id"));
    }
}
