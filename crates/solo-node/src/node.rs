//! The node: kernel lifecycle, the driver loop, mempool and queries.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::rc::Rc;

use solo_abi::chain::{
    BlockHeader, CallRequest, CallResult as CallOutcome, Evidence, StorageQuery,
};
use solo_abi::codec::Seq;
use solo_abi::fees::FeeStatus;
use solo_abi::types::{
    self, Ahead, Block, Effect, ExecContext, ExecuteArgs, ExecuteResult, FinalizeArgs, Genesis,
    Input, QueryArgs, QueryResult, ValidateArgs, ValidateResult, exports,
};
use solo_abi::{Decode, Encode};
use solo_host::hash::keccak256;
use solo_host::{Backend, CallResult, Executor, Flags, LoadError, ModuleCache, Overlay, Storage};
use solo_vm::host::Capability;
use solo_vm::status::Termination;

use crate::extension::{NodeExtension, NodeServices, Outbound, validator_id};
use crate::mempool::{Mempool, PoolError, PoolLimits, PoolTx, rejection};
use crate::state::{ChainState, StoreConfig};
use crate::store::DriverStore;
use crate::upgrade::{GatedExtension, Upgrades};

/// How to open a node.
#[derive(Clone)]
pub struct NodeConfig {
    /// Clock at start, in milliseconds.
    pub now_ms: u64,
    /// Consensus key; a node without one follows the chain but never votes.
    pub key: Option<k256::ecdsa::SigningKey>,
    /// Node-local persisted data from a previous run (`persist_*`).
    pub persisted: BTreeMap<Vec<u8>, Vec<u8>>,
    /// Gas budget per kernel call once running; `kernel_init` always gets [`KERNEL_GAS`].
    pub kernel_gas: i64,
    /// Gas budget per `kernel_query` call; see [`QUERY_GAS`].
    pub query_gas: i64,
    /// How many of the latest executed blocks' states the node keeps to
    /// serve historical queries and proofs; see [`STATE_HISTORY`] and
    /// [`ARCHIVE`].
    pub state_history: usize,
    /// Key writes of history the node keeps per block of `state_history`;
    /// see [`HISTORY_KEYS_PER_BLOCK`].
    pub history_keys_per_block: usize,
    /// Where the chain state lives (spec 22): in memory, or on disk in a
    /// directory a later node resumes from.
    pub store: StoreConfig,
    /// Whether the host's heavy work runs on threads of its own, off the
    /// loop that steps the driver (spec 22 §7.4, spec 15 §6.4): the
    /// snapshot exports of a serving node and the DKG computations of the
    /// threshold keystore. A node that answers peers in real time wants
    /// it, so that consensus is not held up; off, the default, the work
    /// runs inside the step that asks for it, which makes every run of a
    /// simulated network the same.
    pub background: bool,
}

impl Default for NodeConfig {
    fn default() -> NodeConfig {
        NodeConfig {
            now_ms: 0,
            key: None,
            persisted: BTreeMap::new(),
            kernel_gas: KERNEL_GAS,
            query_gas: QUERY_GAS,
            state_history: STATE_HISTORY,
            history_keys_per_block: HISTORY_KEYS_PER_BLOCK,
            store: StoreConfig::Memory,
            background: false,
        }
    }
}

/// Gas allowed to each kernel entrypoint call. Kernel work is bounded by the
/// block limits it enforces, so this is a safety net, not a budget.
pub const KERNEL_GAS: i64 = 1 << 40;

/// The kernel gas a block of the reference kernel can take at most (spec 19
/// §5): the precompile budget, 2^34, plus 256 kernel gas per EVM gas of the
/// block gas limit, plus room for what every block and transaction costs
/// besides. A node whose kernel gas is below it can fail to execute a valid
/// block and stall; [`KERNEL_GAS`] is far above.
pub const BLOCK_KERNEL_GAS: i64 = 1 << 35;

/// How many of the most recently executed blocks a node keeps the state of
/// by default (spec 20 §5): the values every key held after each, to serve
/// queries at those heights ([`Node::query_at`]), and the state trie behind
/// each header's root, to prove entries against it
/// ([`Node::state_proof_at`]). Both keep only what each block changed: the
/// old values of the keys it wrote, and the trie nodes on their paths. The
/// window is shorter when its blocks write more than
/// [`HISTORY_KEYS_PER_BLOCK`] keys each on average.
pub const STATE_HISTORY: usize = 1024;

/// A [`NodeConfig::state_history`] that keeps the state of every block,
/// however many keys they write.
pub const ARCHIVE: usize = usize::MAX;

/// How many finalized heights below its finalized head a node whose chain
/// state is on disk keeps the driver's tables for, by default (spec 22
/// §8.1): what a peer that fell behind by up to that much syncs from it.
/// Below that, and below the latest snapshot record's height, the tables
/// are pruned; a peer further behind joins from a snapshot.
pub const DRIVER_RETENTION: u64 = 1024;

/// Every how many finalized heights the driver's tables are pruned: often
/// enough that they stay within a few dozen heights of the retention, and
/// rarely enough that the pass over them costs nothing per block.
pub const PRUNE_EVERY: u64 = 64;

/// Key writes of history a node keeps per block of its window, by default
/// (spec 20 §5.1). A node keeps at most `state_history` times this many:
/// when the blocks of its window wrote more committed keys than that in
/// all, it drops the oldest of them until the rest fit, so blocks that
/// write heavily cannot make history outgrow its memory. Each key write
/// kept costs its old value and the trie nodes on its path, about 1 to
/// 1.5 KB (measured 2026-10-21 over 200 000 entries: 1.4 KB at 1 500
/// writes per block, 1.0 KB at 6 000), so the default window holds at most
/// about 0.5 to 0.75 GB of history, while blocks that write fewer keys
/// keep all of their 1 024.
pub const HISTORY_KEYS_PER_BLOCK: usize = 512;

/// Gas allowed to each `kernel_query` call (spec 06 §6), unless
/// [`Node::kernel_gas`] is lower. Queries run on the thread that drives
/// consensus and an RPC caller chooses what they compute (`eth_call` runs
/// any code), so this budget is what bounds how long one query holds the
/// node. 2^26 is about three million EVM gas of plain opcodes or about a
/// thousand `KECCAK256`s on the reference interpreter: 0.3 s to 3 s at load
/// averages of 50 to 100 on the 12-core machine it was measured on
/// (2026-10-20). Deploying the 2 KiB test contract takes about a million;
/// ordinary calls take less.
pub const QUERY_GAS: i64 = 1 << 26;

/// The kernel's storage namespace. Privileged instances use bare keys, so
/// this value is only passed through.
const KERNEL_NAMESPACE: [u8; 32] = [0; 32];

/// Why the node could not proceed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum NodeError {
    /// The kernel module failed to load.
    Load(LoadError),
    /// A kernel entrypoint did not halt normally.
    Kernel {
        export: &'static str,
        status: Termination,
    },
    /// A kernel entrypoint returned bytes that do not decode as its result type.
    Decode(&'static str),
    /// A kernel switch could not complete (spec 06 §7); the node has halted.
    Upgrade(String),
    /// A query named a height whose state the node does not keep: pruned,
    /// below `oldest`, or not executed yet (spec 20 §5).
    StateUnavailable { height: u64, oldest: u64 },
    /// The node-local store refused a write (spec 06 §4.2), nothing the
    /// driver did since the last successful write having been sent; or the
    /// chain store refused one (spec 22), nothing of the block being on disk.
    Store(String),
}

impl fmt::Display for NodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NodeError::Load(e) => write!(f, "kernel failed to load: {e:?}"),
            NodeError::Kernel { export, status } => write!(f, "{export} ended with {status:?}"),
            NodeError::Decode(export) => write!(f, "{export} returned an undecodable result"),
            NodeError::Upgrade(why) => write!(f, "kernel upgrade halted the node: {why}"),
            NodeError::StateUnavailable { height, oldest } => write!(
                f,
                "state of block {height} is not available: the node keeps the state from block {oldest}"
            ),
            NodeError::Store(why) => write!(f, "{why}"),
        }
    }
}

impl std::error::Error for NodeError {}

impl NodeError {
    /// Whether a kernel call ran out of its gas budget.
    #[must_use]
    pub fn is_out_of_gas(&self) -> bool {
        matches!(
            self,
            NodeError::Kernel {
                status: Termination::OutOfGas,
                ..
            }
        )
    }
}

/// Why a transaction was not admitted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubmitError {
    /// The kernel rejected it with this reason code (`solo_abi::chain::reason`).
    Rejected(u32),
    /// The node failed while asking the kernel.
    Node(NodeError),
    /// The kernel accepted it but the mempool's policy refused it (spec 14).
    Pool(PoolError),
}

/// A running node.
pub struct Node {
    pub(crate) exec: Executor<ChainState>,
    pub(crate) kernel: [u8; 32],
    services: Rc<RefCell<NodeServices>>,
    pool: Mempool,
    /// Blocks executed, in order, as `(height, block hash)`.
    pub executed: Vec<(u64, [u8; 32])>,
    /// Heights finalized, in order.
    pub finalized: Vec<u64>,
    /// Metrics the driver emitted.
    pub metrics: Vec<(Vec<u8>, i64)>,
    /// The last state the driver asked to persist.
    pub persisted_driver_state: Option<Vec<u8>>,
    /// Gas budget for each kernel call; see [`KERNEL_GAS`].
    pub kernel_gas: i64,
    /// Gas budget for each kernel query, capped by `kernel_gas`; see [`QUERY_GAS`].
    pub query_gas: i64,
    /// Raw transactions admitted since the last [`Node::take_tx_gossip`],
    /// for the transport to forward to peers.
    tx_gossip: Vec<Vec<u8>>,
    /// How many executed blocks' states to keep; see [`STATE_HISTORY`]. A
    /// change applies from the next executed block.
    pub state_history: usize,
    /// Key writes of history to keep per block of `state_history`; see
    /// [`HISTORY_KEYS_PER_BLOCK`]. A change applies from the next executed
    /// block.
    pub history_keys_per_block: usize,
    /// Finalized heights below the head whose driver tables a node on disk
    /// keeps; see [`DRIVER_RETENTION`]. An archive node, or one whose chain
    /// state is in memory and whose restart replays its finalized blocks
    /// from these tables (spec 08 §7), keeps them all.
    pub driver_retention: u64,
    /// The executed height the node opened at: 0 from genesis, the store's
    /// head on a resume (spec 22 §5). Finalized at least that far.
    pub(crate) opened_at: u64,
    /// The fee market as the kernel last reported it (spec 23 §7): the
    /// parameters in force, the next block's base fee and the reward pool,
    /// read at open and after every executed block.
    fees: FeeStatus,
    /// Telemetry (spec 11); consensus-ignored.
    pub(crate) telemetry: solo_metrics::NodeMetrics,
    /// Kernel switchover and feature-gate state (`crate::upgrade`).
    pub(crate) upgrades: Upgrades,
    /// Where the driver's node-local data goes between steps, if anywhere.
    store: Option<DriverStore>,
    /// The snapshots this node serves to peers that sync from it (spec 22
    /// §7.4), once [`Node::serve_snapshots`] turned it on.
    server: Option<crate::statesync::SnapshotServer>,
    /// The host's half of block catch-up (spec 09 §6a).
    catch_up: crate::catchup::CatchUp,
    /// See [`NodeConfig::background`].
    background: bool,
    /// The snapshot export running off the node loop, if one is.
    export_job: Option<crate::worker::ExportJob>,
    /// While set, a background export waits before it starts (tests).
    hold_exports: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl Node {
    /// Loads a kernel module and runs its `kernel_init` with `genesis`.
    ///
    /// # Errors
    /// [`NodeError::Load`] if the module is invalid; [`NodeError::Kernel`] if init fails.
    pub fn new(kernel_module: &[u8], genesis: &Genesis, now_ms: u64) -> Result<Node, NodeError> {
        Node::open(
            kernel_module,
            genesis,
            NodeConfig {
                now_ms,
                ..NodeConfig::default()
            },
        )
    }

    /// Loads a kernel with a key and persisted data, then runs `kernel_init`,
    /// or, over a disk store a previous run sealed, resumes from its head
    /// with the kernel that wrote it (spec 22 §5): no block is executed
    /// again, and the store's history serves queries and proofs as before.
    ///
    /// # Errors
    /// As [`Node::new`]; [`NodeError::Store`] when the store cannot be
    /// opened; [`NodeError::Upgrade`] when the store was last written by a
    /// kernel that is neither `kernel_module` nor an upgrade in chain state.
    pub fn open(
        kernel_module: &[u8],
        genesis: &Genesis,
        config: NodeConfig,
    ) -> Result<Node, NodeError> {
        let opening = std::time::Instant::now();
        let services = Rc::new(RefCell::new(NodeServices {
            now_ms: config.now_ms,
            key: config.key,
            persisted: config.persisted,
            ..NodeServices::default()
        }));
        services
            .borrow_mut()
            .keystore
            .set_background(config.background);
        let state = ChainState::open(&config.store)?;
        let fresh = state.is_fresh();
        let mut exec = Executor::new(ModuleCache::default(), state);
        let active_gates = Rc::new(Cell::new(0));
        exec.set_extension(Box::new(GatedExtension::new(
            NodeExtension::new(Rc::clone(&services)),
            Rc::clone(&active_gates),
        )));
        let kernel = exec
            .load(kernel_module, Capability::Privileged)
            .map_err(NodeError::Load)?;
        let mut node = Node {
            exec,
            kernel,
            services,
            pool: Mempool::default(),
            executed: Vec::new(),
            finalized: Vec::new(),
            metrics: Vec::new(),
            persisted_driver_state: None,
            kernel_gas: KERNEL_GAS,
            query_gas: config.query_gas,
            tx_gossip: Vec::new(),
            state_history: config.state_history.max(1),
            history_keys_per_block: config.history_keys_per_block,
            driver_retention: DRIVER_RETENTION,
            opened_at: 0,
            fees: FeeStatus::default(),
            telemetry: solo_metrics::NodeMetrics::new(),
            upgrades: Upgrades::new(active_gates),
            store: None,
            server: None,
            catch_up: crate::catchup::CatchUp::default(),
            background: config.background,
            export_job: None,
            hold_exports: std::sync::Arc::default(),
        };
        if fresh {
            node.call_unit(exports::INIT, &genesis.to_bytes())?;
            // The trie behind the root the genesis header carries: the kernel
            // asks for it last, before it stores the header (spec 20 §3.1).
            let committed = node.services.borrow_mut().commitments.pop();
            // The kernel's version and gates are known before the first block:
            // the query spec 13 §7.1 makes after every block, once at open and
            // under the kernel budget like every host read of it. A kernel that
            // does not serve it reads as the default (spec 06 §7.2), so the node
            // opens and its telemetry reports version 0 (spec 11 §4).
            node.upgrades.status = Some(node.upgrade_status().unwrap_or_default());
            // The genesis state is version 0; each executed block seals its height.
            node.exec.state_mut().base_mut().set_kernel(kernel);
            node.exec.state_mut().base_mut().seal_genesis(committed)?;
            node.refresh_fees()?;
        } else {
            node.resume()?;
        }
        node.kernel_gas = config.kernel_gas;
        node.telemetry.opened_in(opening.elapsed().as_secs_f64());
        Ok(node)
    }

    /// Takes the node up where its store left it: the kernel that last wrote
    /// the store (the genesis kernel, or an upgrade whose code chain state
    /// holds, spec 13 §6), the gates active for the next block, a pending
    /// upgrade prepared again, and the head as finalized.
    fn resume(&mut self) -> Result<(), NodeError> {
        let stored = self.exec.state().base().kernel();
        self.take_up(stored)
    }

    /// Takes the node up at the store's head with `kernel`, the kernel that
    /// wrote it, if the store names one other than the module loaded.
    fn take_up(&mut self, kernel: Option<[u8; 32]>) -> Result<(), NodeError> {
        let head = self.exec.state().base().head();
        self.opened_at = head;
        // The loaded kernel's view of the upgrade state serves to find the
        // gates the kernel that wrote the store imports.
        let status = self.upgrade_status().unwrap_or_default();
        let gates = status.gates.active_at(head + 1) & self.upgrades.features;
        self.upgrades.active.set(gates);
        if let Some(stored) = kernel.filter(|k| *k != self.kernel) {
            // A kernel that cannot serve the query, like code that does not
            // hash to the stored kernel, leaves nothing to compile.
            let code = self
                .query(solo_upgrade::query::CODE, &stored)
                .ok()
                .and_then(|r| Vec::<u8>::from_bytes(&r.body).ok())
                .unwrap_or_default();
            self.compile(&code, &stored, gates).map_err(|why| {
                NodeError::Upgrade(format!(
                    "the store was last written by a kernel that is neither the one given nor an upgrade in chain state: {why}"
                ))
            })?;
            self.kernel = stored;
            self.exec.state_mut().base_mut().set_kernel(stored);
        }
        // The fee market as the state at the head has it (spec 23 §7), for
        // admission, the pool's take and the price of a gate signal, which
        // the bookkeeping below prepares, before the next block executes.
        self.refresh_fees()?;
        self.after_executed(head)
    }

    /// Loads a verified snapshot (spec 22 §7) into a node opened fresh over
    /// a disk store, before it starts: the state becomes the snapshot's, the
    /// kernel the one the chain had enacted by then, and the driver finds
    /// the finalized head in the block log when it starts and syncs forward
    /// from there. The caller verifies the snapshot first.
    ///
    /// # Errors
    /// [`NodeError::Store`] unless the node holds the genesis alone on disk;
    /// [`NodeError::Upgrade`] when the enacted kernel's code is not in the
    /// snapshot's state.
    pub fn import_snapshot(&mut self, snapshot: &solo_store::Snapshot) -> Result<(), NodeError> {
        let state = self.exec.state_mut().base_mut();
        let ChainState::Disk(store) = state else {
            return Err(NodeError::Store(
                "a snapshot loads into a chain store on disk".to_owned(),
            ));
        };
        snapshot
            .import(store)
            .map_err(|e| NodeError::Store(e.to_string()))?;
        // The kernel the chain ran at the snapshot: the latest enacted
        // upgrade's, if any, whose code is in the state just loaded.
        let status = self.upgrade_status().unwrap_or_default();
        let enacted = status.enacted.map(|e| e.code_hash);
        self.take_up(enacted)?;
        self.exec.state_mut().base_mut().flush()?;
        Ok(())
    }

    /// Prunes the driver's tables below what consensus can still need once
    /// `finalized` is final (spec 22 §8.1): `driver_retention` heights
    /// below it, and never at or above the latest snapshot record's height,
    /// so that the latest snapshot exports and a node joining from it syncs
    /// from this one. Only a node whose chain state is on disk and that is
    /// no archive prunes: a restart over its stores executes nothing again,
    /// while one in memory replays its finalized blocks from these tables.
    /// The journal on disk sheds them at its next compaction; until then a
    /// restart reads them back, and the next pass prunes them again.
    fn prune_tables(&mut self, finalized: u64) {
        let Some(store) = self.chain_store() else {
            return;
        };
        if self.state_history == ARCHIVE {
            return;
        }
        let latest = store
            .get(solo_abi::chain::keys::SNAPSHOT_LATEST)
            .and_then(|e| u64::from_bytes(&e).ok())
            .and_then(|e| store.get(&solo_store::snapshot::record_key(e)))
            .and_then(|r| solo_abi::chain::SnapshotRecord::from_bytes(&r).ok())
            .map_or(0, |r| r.height);
        let cutoff = finalized.saturating_sub(self.driver_retention).min(latest);
        if cutoff != 0 {
            crate::store::prune_tables(&mut self.services.borrow_mut().persisted, cutoff);
        }
    }

    /// Exports the snapshot of `epoch` (the latest, for `None`) from this
    /// node's chain store and driver tables to the file `out` (spec 22 §7.1).
    ///
    /// # Errors
    /// [`NodeError::Store`] when the state is not on disk, and
    /// [`solo_store::SnapshotError`]'s reasons as a store error otherwise.
    pub fn export_snapshot(
        &self,
        epoch: Option<u64>,
        out: &std::path::Path,
    ) -> Result<solo_store::Snapshot, NodeError> {
        let store = self.chain_store().ok_or_else(|| {
            NodeError::Store("a snapshot exports from a chain store on disk".to_owned())
        })?;
        let tables = self.persisted();
        solo_store::Snapshot::export(store, &tables, epoch, out)
            .map_err(|e| NodeError::Store(e.to_string()))
    }

    /// Serves snapshots to peers that sync from this node (spec 22 §7.4):
    /// those already under `snapshots/` beside the chain store, and from now
    /// on the snapshot of every newer epoch the chain records, exported
    /// once a certificate covers it; split and paged within `limits`.
    ///
    /// # Errors
    /// [`NodeError::Store`] when the chain state is not on disk or the
    /// directory cannot be made.
    pub fn serve_snapshots(
        &mut self,
        limits: crate::statesync::ServeLimits,
    ) -> Result<(), NodeError> {
        let store = self.chain_store().ok_or_else(|| {
            NodeError::Store("snapshots are served from a chain store on disk".to_owned())
        })?;
        let dir = store.path().with_file_name("snapshots");
        let server = crate::statesync::SnapshotServer::open(&dir, limits)
            .map_err(|e| NodeError::Store(e.to_string()))?;
        self.server = Some(server);
        self.serve_latest();
        Ok(())
    }

    /// What a state sync into this node, opened fresh over a disk store,
    /// needs (spec 22 §7.4): the chain id, the genesis hash its own
    /// `kernel_init` stored, `trust`, and `statesync/` beside the chain
    /// store to work in.
    ///
    /// # Errors
    /// [`NodeError::Store`] when the chain state is not on disk; what the
    /// chain id query reports.
    pub fn sync_config(
        &mut self,
        trust: solo_store::Trust,
    ) -> Result<crate::statesync::SyncConfig, NodeError> {
        let dir = self
            .chain_store()
            .ok_or_else(|| {
                NodeError::Store("a state sync loads into a chain store on disk".to_owned())
            })?
            .path()
            .with_file_name("statesync");
        let genesis_key = [solo_abi::chain::keys::BLOCK_NUMBER, &0u64.to_be_bytes()[..]].concat();
        Ok(crate::statesync::SyncConfig {
            chain_id: self.chain_id()?,
            trust,
            genesis_hash: self.state_get(&genesis_key),
            dir,
        })
    }

    /// The snapshots this node serves, if it serves any.
    #[must_use]
    pub fn snapshot_server(&self) -> Option<&crate::statesync::SnapshotServer> {
        self.server.as_ref()
    }

    /// The answer to a peer's state-sync request (spec 22 §7.4, the
    /// payload of a `SyncRequest` frame, spec 09 §2).
    #[must_use]
    pub fn answer_sync(&self, payload: &[u8]) -> Vec<u8> {
        match &self.server {
            Some(server) => server.answer(payload),
            None => crate::statesync::answer_unserved(payload),
        }
    }

    /// Exports the latest recorded epoch's snapshot for serving, when this
    /// node serves, finalized a block since it last looked, and serves an
    /// older epoch or none. An export that fails, as it does until a
    /// certificate covers the record, is tried again after the next
    /// finalized block (spec 22 §7.4).
    fn serve_latest(&mut self) {
        self.take_export();
        if self.export_job.is_some() {
            return;
        }
        let finalized = self.finalized.len();
        let latest = self
            .chain_store()
            .and_then(|s| s.get(solo_abi::chain::keys::SNAPSHOT_LATEST))
            .and_then(|e| u64::from_bytes(&e).ok());
        let Some(server) = self.server.as_mut() else {
            return;
        };
        if server.checked == finalized {
            return;
        }
        server.checked = finalized;
        let Some(epoch) = latest.filter(|e| server.newest().is_none_or(|n| n < *e)) else {
            return;
        };
        let path = server.path_for(epoch);
        let store = self
            .chain_store()
            .expect("a serving node's state is on disk");
        let Ok(export) =
            solo_store::Snapshot::prepare_export(store, &self.persisted(), Some(epoch), &path)
        else {
            return;
        };
        if self.background {
            // The entries, the expensive part, are walked off the node loop
            // from the store as it is now (spec 22 §7.4).
            let hold = std::sync::Arc::clone(&self.hold_exports);
            self.export_job = Some(crate::worker::ExportJob::start(export, hold));
        } else {
            let exported = export.run(
                solo_store::ExportLimits::default(),
                &std::sync::atomic::AtomicBool::default(),
            );
            self.serve(exported);
        }
    }

    /// Takes up the background export once it has ended.
    fn take_export(&mut self) {
        if self
            .export_job
            .as_ref()
            .is_some_and(crate::worker::ExportJob::finished)
        {
            let job = self.export_job.take().expect("checked");
            self.serve(job.join());
        }
    }

    /// Serves an exported snapshot. A file just exported reads; if it did
    /// not, or the export failed, the next record is exported in its place.
    fn serve(&mut self, exported: Result<solo_store::Snapshot, solo_store::SnapshotError>) {
        let server = self.server.as_mut();
        let _ = exported.map(|snapshot| server.map(|s| s.add(snapshot)));
    }

    /// How many DKG computations the keystore is running off the node loop.
    #[must_use]
    pub fn keystore_busy(&self) -> usize {
        self.services.borrow().keystore.busy()
    }

    /// Holds the keystore's background computations before they start
    /// while `hold` is set (tests that need one to keep running); only in
    /// builds with the `fault-injection` feature.
    #[cfg(feature = "fault-injection")]
    pub fn hold_keystore(&self, hold: bool) {
        self.services.borrow().keystore.hold(hold);
    }

    /// The epoch of the snapshot being exported off the node loop, if one is.
    #[must_use]
    pub fn exporting(&self) -> Option<u64> {
        self.export_job
            .as_ref()
            .map(crate::worker::ExportJob::epoch)
    }

    /// Holds background exports before they start while `hold` is set
    /// (tests that need an export to keep running); only in builds with
    /// the `fault-injection` feature.
    #[cfg(feature = "fault-injection")]
    pub fn hold_exports(&self, hold: bool) {
        self.hold_exports
            .store(hold, std::sync::atomic::Ordering::Relaxed);
    }

    /// The snapshot record of `epoch`, or of the latest completed epoch for
    /// `None` (spec 22 §6); `None` before the chain recorded one.
    ///
    /// # Errors
    /// See [`NodeError`].
    pub fn snapshot_record(
        &mut self,
        epoch: Option<u64>,
    ) -> Result<Option<solo_abi::chain::SnapshotRecord>, NodeError> {
        let params = epoch.map(|e| e.to_bytes()).unwrap_or_default();
        self.query_decoded(solo_abi::chain::query::SNAPSHOT, &params)
    }

    /// Turns the host's half of block catch-up (spec 09 §6a) on, as it is
    /// by default, or off: off, the driver's sync requests and their
    /// answers pass between it and the wire untouched, and an answer that
    /// comes back after the driver entered another view is lost.
    pub fn set_catch_up(&mut self, on: bool) {
        self.catch_up.set(on);
    }

    /// How many sync requests the host lets be on the wire at once now
    /// (spec 09 §6a): one, more while answers come back quickly.
    #[must_use]
    pub fn catch_up_depth(&self) -> usize {
        self.catch_up.depth()
    }

    /// Hands an answer from the wire to the request it answers (spec 06
    /// §4.1): one to a request of the host's catch-up (spec 09 §6a) waits
    /// for the driver's request for those blocks, any other goes to the
    /// driver as `Response`.
    ///
    /// # Errors
    /// See [`NodeError`].
    pub fn response(&mut self, request_id: u64, payload: Vec<u8>) -> Result<(), NodeError> {
        let now = self.now_ms();
        let mut out = Vec::new();
        let routed = self
            .catch_up
            .on_response(request_id, payload, now, &mut out);
        self.services.borrow_mut().outbound.extend(out);
        match routed {
            Some(input) => self.step(input),
            None => Ok(()),
        }
    }

    /// The highest height the host saw finalized: what it opened at, or
    /// the last `FinalizeBlock`.
    fn host_finalized(&self) -> u64 {
        self.finalized.last().copied().unwrap_or(self.opened_at)
    }

    /// Runs the kernel, and every module it invokes, on `backend` from the
    /// next call on; the interpreter by default. Both backends produce the
    /// same results and gas (spec 07 §4.1); the native one runs faster.
    pub fn set_backend(&mut self, backend: Backend) {
        self.exec.set_backend(backend);
    }

    fn call_raw(&mut self, export: &'static str, input: &[u8]) -> Result<CallResult, NodeError> {
        self.call_with(export, input, self.kernel_gas)
    }

    fn call_with(
        &mut self,
        export: &'static str,
        input: &[u8],
        gas: i64,
    ) -> Result<CallResult, NodeError> {
        let kernel = self.kernel;
        self.services.borrow_mut().commitments.clear();
        let started = std::time::Instant::now();
        let r = self.exec.call_export(
            &kernel,
            export,
            KERNEL_NAMESPACE,
            input,
            gas,
            Capability::Privileged,
            Flags::default(),
        );
        crate::telemetry::record_call(&mut self.telemetry, &mut self.exec, export, started, &r);
        if r.status == Termination::Halt {
            Ok(r)
        } else {
            Err(NodeError::Kernel {
                export,
                status: r.status,
            })
        }
    }

    fn call_decoded<T: Decode>(
        &mut self,
        export: &'static str,
        input: &[u8],
    ) -> Result<T, NodeError> {
        let r = self.call_raw(export, input)?;
        T::from_bytes(&r.output)
            .ok()
            .ok_or(NodeError::Decode(export))
    }

    fn call_unit(&mut self, export: &'static str, input: &[u8]) -> Result<(), NodeError> {
        self.call_raw(export, input).map(|_| ())
    }

    /// Current node time in milliseconds.
    #[must_use]
    pub fn now_ms(&self) -> u64 {
        self.services.borrow().now_ms
    }

    /// Pending timers as `(timer id, deadline)`.
    #[must_use]
    pub fn timers(&self) -> Vec<(u64, u64)> {
        self.services
            .borrow()
            .timers
            .iter()
            .map(|(k, v)| (*k, *v))
            .collect()
    }

    /// Messages waiting for the transport, drained.
    pub fn take_outbound(&mut self) -> Vec<Outbound> {
        std::mem::take(&mut self.services.borrow_mut().outbound)
    }

    /// Raw transactions that became pending since the last call, for peers;
    /// queued ones stay local until they are executable (spec 14 §6).
    pub fn take_tx_gossip(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.tx_gossip)
    }

    /// The fee market as of the last executed block (spec 23 §7): the
    /// parameters in force, the base fee of the next block, which admission
    /// and the pool's take apply, and the reward pool. A kernel that does
    /// not serve the `fees` query reads as a market that is off at a zero
    /// base fee.
    #[must_use]
    pub fn fee_status(&self) -> &FeeStatus {
        &self.fees
    }

    /// Reads the fee market from the kernel; see [`Node::fee_status`]. A
    /// read the host makes for itself: it runs under the kernel budget, not
    /// the cap `--query-gas` puts on what clients ask for.
    pub(crate) fn refresh_fees(&mut self) -> Result<(), NodeError> {
        let cap = std::mem::replace(&mut self.query_gas, i64::MAX);
        let fees = self.query_decoded(solo_abi::fees::query::FEES, &[]);
        self.query_gas = cap;
        self.fees = fees?.unwrap_or_default();
        Ok(())
    }

    /// This node's validator id, if it has a consensus key.
    #[must_use]
    pub fn validator_id(&self) -> Option<[u8; 32]> {
        self.services.borrow().key.as_ref().map(validator_id)
    }

    /// The consensus key, for reopening the node.
    #[must_use]
    pub fn services_key(&self) -> Option<k256::ecdsa::SigningKey> {
        self.services.borrow().key.clone()
    }

    /// A copy of the node-local persisted data, to reopen the node with.
    #[must_use]
    pub fn persisted(&self) -> BTreeMap<Vec<u8>, Vec<u8>> {
        self.services.borrow().persisted.clone()
    }

    /// Delivers a network message from `peer`.
    ///
    /// # Errors
    /// See [`NodeError`].
    pub fn deliver(
        &mut self,
        peer: [u8; 32],
        topic: u16,
        payload: Vec<u8>,
    ) -> Result<(), NodeError> {
        // A peer that speaks is one catch-up may ask (spec 09 §6a).
        self.catch_up.heard(peer, self.now_ms());
        self.step(Input::NetworkMessage {
            peer,
            topic,
            payload,
        })
    }

    /// The mempool.
    #[must_use]
    pub fn mempool(&self) -> &Mempool {
        &self.pool
    }

    /// Changes the mempool's limits; they apply to the next insertion.
    pub fn set_mempool_limits(&mut self, limits: PoolLimits) {
        self.pool.limits = limits;
    }

    /// The nonce of `address`'s next transaction counting the mempool's
    /// pending ones: the account nonce plus that many (`eth_getTransactionCount`
    /// at `pending`).
    ///
    /// # Errors
    /// See [`NodeError`].
    pub fn pending_nonce(&mut self, address: &types::Address) -> Result<u64, NodeError> {
        match self.pool.pending_nonce(address) {
            Some(nonce) => Ok(nonce),
            None => Ok(self.account(address)?.nonce),
        }
    }

    /// Starts the driver, optionally resuming from persisted state.
    ///
    /// # Errors
    /// See [`NodeError`].
    pub fn start(&mut self, resumed_state: Option<Vec<u8>>) -> Result<(), NodeError> {
        let now_ms = self.now_ms();
        self.step(Input::Started {
            now_ms,
            resumed_state,
        })
    }

    /// Delivers one input to the driver and applies every resulting effect,
    /// including the follow-up inputs they produce, until the node is quiet.
    /// A step is the host's own work: the reads it makes of the kernel on
    /// the way (the upgrade status and code, a signal's nonce) run under the
    /// kernel budget, not the cap [`Node::query_gas`] puts on what clients
    /// ask between steps.
    ///
    /// # Errors
    /// See [`NodeError`].
    pub fn step(&mut self, input: Input) -> Result<(), NodeError> {
        let cap = std::mem::replace(&mut self.query_gas, i64::MAX);
        let stepped = self.step_capless(input);
        self.query_gas = cap;
        // A block the store refused is a block the driver believes executed:
        // the node stops here, to be restarted over the store, which holds
        // the block before (spec 22 §4). What the step queued for peers goes
        // too: its driver state never reached the driver store, so a
        // restarted node could sign otherwise in a view it signed in here.
        if let Err(e @ NodeError::Store(_)) = &stepped {
            self.upgrades.halt(e.clone());
            self.take_outbound();
        }
        stepped
    }

    fn step_capless(&mut self, input: Input) -> Result<(), NodeError> {
        self.upgrade_halted()?;
        let mut queue = VecDeque::from([input]);
        while let Some(input) = queue.pop_front() {
            let effects: Seq<Effect> =
                self.call_decoded(exports::DRIVER_STEP, &input.to_bytes())?;
            for effect in effects.0 {
                if let Some(follow_up) = self.apply_effect(effect)? {
                    queue.push_back(follow_up);
                }
            }
            self.switch_kernel_if_due(&mut queue)?;
        }
        self.catch_up.settle(self.host_finalized());
        self.collect_persist_writes();
        self.send_gate_signal();
        self.serve_latest();
        Ok(())
    }

    /// Hands the `persist_set` writes of the step to the store, or drops
    /// them when the node keeps nothing on disk.
    fn collect_persist_writes(&mut self) {
        let writes = std::mem::take(&mut self.services.borrow_mut().persist_writes);
        if let Some(store) = &mut self.store {
            store.pending.extend(writes);
        }
    }

    /// Keeps the driver's node-local data in `store` from now on: every
    /// `persist_set` and the latest `PersistState`, written by
    /// [`Node::sync_store`]. The node was opened with the tables the store
    /// loaded and started with its state (spec 06 §4.2, spec 08 §7).
    pub fn attach_store(&mut self, store: DriverStore) {
        self.store = Some(store);
    }

    /// The attached store, if any.
    #[must_use]
    pub fn store(&self) -> Option<&DriverStore> {
        self.store.as_ref()
    }

    /// Writes what the driver persisted since the last call to the store,
    /// synced to disk; nothing without a store. The transport calls this
    /// before it sends anything, so what a peer sees is on disk first.
    ///
    /// # Errors
    /// [`NodeError::Store`] when the disk refuses; the next call writes the
    /// same again.
    pub fn sync_store(&mut self) -> Result<(), NodeError> {
        let Some(store) = &mut self.store else {
            return Ok(());
        };
        let services = self.services.borrow();
        store
            .sync(self.persisted_driver_state.as_deref(), &services.persisted)
            .map_err(|e| NodeError::Store(format!("driver store: {e}")))
    }

    /// Applies one driver effect as the host would, returning any follow-up
    /// input it produces. `step` calls this for every effect the kernel emits;
    /// tooling and tests can inject effects directly.
    ///
    /// # Errors
    /// See [`NodeError`].
    pub fn apply_effect(&mut self, effect: Effect) -> Result<Option<Input>, NodeError> {
        Ok(match effect {
            Effect::SetTimer {
                timer_id,
                deadline_ms,
            } => {
                self.services
                    .borrow_mut()
                    .timers
                    .insert(timer_id, deadline_ms);
                None
            }
            Effect::CancelTimer { timer_id } => {
                self.services.borrow_mut().timers.remove(&timer_id);
                None
            }
            Effect::ExecuteBlock { block } => self.execute_or_hold(block)?,
            Effect::FinalizeBlock {
                height,
                certificate,
            } => {
                let args = FinalizeArgs {
                    height,
                    certificate,
                }
                .to_bytes();
                self.call_unit(exports::FINALIZE_BLOCK, &args)?;
                self.exec.state_mut().base_mut().flush()?;
                self.finalized.push(height);
                if height.is_multiple_of(PRUNE_EVERY) {
                    self.prune_tables(height);
                }
                self.telemetry.block_finalized(height);
                None
            }
            Effect::PersistState { state } => {
                self.persisted_driver_state = Some(state);
                None
            }
            Effect::MempoolTake {
                max_bytes,
                max_gas,
                skip,
            } => {
                let base_fee = u128::from(self.fees.base_fee);
                let txs = self
                    .pool
                    .take(max_bytes as usize, max_gas, &skip.0, base_fee);
                Some(Input::MempoolContents { txs: Seq(txs) })
            }
            Effect::MempoolReject { tx_hash, .. } => {
                self.pool.remove(&tx_hash);
                None
            }
            Effect::Metric { name, value } => {
                self.telemetry.driver_metric(&name, value);
                self.metrics.push((name, value));
                None
            }
            // Admission is implicit in `submit`.
            Effect::MempoolAdmit { .. } => None,
            Effect::Send {
                peer,
                topic,
                payload,
            } => self.outbound(Outbound::Send {
                peer,
                topic,
                payload,
            }),
            Effect::Broadcast { topic, payload } => {
                self.outbound(Outbound::Broadcast { topic, payload })
            }
            Effect::Disseminate { blob_id, payload } => {
                self.outbound(Outbound::Disseminate { blob_id, payload })
            }
            Effect::Request {
                peer,
                request_id,
                payload,
            } => {
                let now = self.now_ms();
                let mut out = Vec::new();
                let answer = self
                    .catch_up
                    .on_request(peer, request_id, payload, now, &mut out);
                self.services.borrow_mut().outbound.extend(out);
                answer
            }
            Effect::Respond {
                request_id,
                payload,
            } => self.outbound(Outbound::Respond {
                request_id,
                payload,
            }),
            Effect::PeerScore { peer, delta } => self.outbound(Outbound::PeerScore { peer, delta }),
        })
    }

    fn outbound(&mut self, message: Outbound) -> Option<Input> {
        self.services.borrow_mut().outbound.push(message);
        None
    }

    fn context_for(header: &BlockHeader) -> ExecContext {
        ExecContext {
            height: header.height,
            slot: header.height,
            timestamp_ms: header.timestamp_ms,
            proposer: [0; 32],
            parent_hash: header.parent_hash,
            prev_randao: [0; 32],
            fee_params: Vec::new(),
            fork_schedule_id: 0,
            exec_lag_k: 0,
        }
    }

    pub(crate) fn execute_block(&mut self, block: Block) -> Result<Input, NodeError> {
        let header = BlockHeader::from_bytes(&block.header)
            .map_err(|_| NodeError::Decode("block header"))?;
        let context = Self::context_for(&header);
        let height = header.height;
        // Whatever the block carried is no longer pending, wherever it came from,
        // including what the kernel left out of the executed block (a transaction
        // an earlier block already recorded).
        let carried: Vec<[u8; 32]> = block.txs.0.iter().map(|raw| keccak256(raw)).collect();
        let args = ExecuteArgs { block, context }.to_bytes();
        let result: ExecuteResult = self.call_decoded(exports::EXECUTE_BLOCK, &args)?;
        // Keep the trie behind the root the block returned, which the header
        // carries: the kernel may write more after it asks for the root (the
        // reference kernel stores the header itself), so no later state
        // proves against it.
        let captured = std::mem::take(&mut self.services.borrow_mut().commitments);
        let kept = captured
            .into_iter()
            .rev()
            .find(|trie| trie.root() == result.state_root);
        // The block, its history and its trie reach the store together
        // (spec 22 §4); then the window: the last `state_history` blocks,
        // fewer when they wrote more keys than its budget (spec 20 §5.1). A
        // height's trie goes with its values.
        let history = self.state_history.max(1);
        let base = self.exec.state_mut().base_mut();
        base.seal(height, kept)?;
        if history != ARCHIVE {
            let by_blocks = (height + 1).saturating_sub(history as u64);
            let budget = history.saturating_mul(self.history_keys_per_block);
            base.prune(by_blocks.max(base.oldest_within(budget)))?;
        }
        let stored = self
            .block_by_number(height)?
            .ok_or(NodeError::Decode("stored header"))?;
        let block_hash = solo_eth::header::block_hash(&stored, keccak256);
        for hash in &carried {
            self.pool.remove(hash);
        }
        // The next block's base fee follows from this one (spec 23 §3).
        self.refresh_fees()?;
        self.reset_pool()?;
        self.executed.push((height, block_hash));
        let summary = &result.summary;
        self.telemetry
            .block_executed(height, summary.tx_count, summary.gas_used);
        Ok(Input::BlockExecuted {
            height,
            block_hash,
            state_root: result.state_root,
            result: result.summary,
        })
    }

    /// Advances time and fires every timer that is due, in deadline order.
    ///
    /// # Errors
    /// See [`NodeError`].
    pub fn tick(&mut self, now_ms: u64) -> Result<(), NodeError> {
        {
            let mut services = self.services.borrow_mut();
            services.now_ms = now_ms;
            // What the keystore computed in the background meanwhile.
            services.keystore.drain();
        }
        loop {
            let due = {
                let s = self.services.borrow();
                s.timers
                    .iter()
                    .filter(|(_, d)| **d <= now_ms)
                    .min_by_key(|(_, d)| **d)
                    .map(|(id, _)| *id)
            };
            let Some(timer_id) = due else { break };
            self.services.borrow_mut().timers.remove(&timer_id);
            self.step(Input::TimerFired { timer_id, now_ms })?;
        }
        let mut out = Vec::new();
        let moot = self.catch_up.poll(now_ms, self.host_finalized(), &mut out);
        self.services.borrow_mut().outbound.extend(out);
        match moot {
            Some(input) => self.step(input),
            None => Ok(()),
        }
    }

    /// Brings the mempool up to the state the last block left (spec 14 §5)
    /// and hands the transactions that became pending to gossip.
    fn reset_pool(&mut self) -> Result<(), NodeError> {
        for sender in self.pool.senders() {
            let account = self.account(&sender)?;
            self.pool.reset(&sender, account);
            let promoted = self.pool.announce(&sender);
            self.tx_gossip.extend(promoted);
        }
        Ok(())
    }

    /// Asks the kernel whether `raw` is valid for the next block, with
    /// `ahead` held ahead of it by the mempool (spec 06 §5.1).
    fn validate(&mut self, raw: &[u8], ahead: Ahead) -> Result<ValidateResult, SubmitError> {
        let next = self.block_number().map_err(SubmitError::Node)? + 1;
        let args = ValidateArgs {
            tx: raw.to_vec(),
            context: ExecContext {
                height: next,
                slot: next,
                ..ExecContext::default()
            },
            ahead,
        };
        self.call_decoded(exports::VALIDATE_TX, &args.to_bytes())
            .map_err(SubmitError::Node)
    }

    /// Validates a raw transaction with the kernel and admits it to the
    /// mempool (spec 14 §2). A transaction whose nonce is ahead of its
    /// sender's account validates as if the pool's transactions before it
    /// had run; it waits as queued until the nonces between are filled.
    /// Submitting a transaction the pool holds changes nothing.
    ///
    /// # Errors
    /// [`SubmitError::Rejected`] with the kernel's reason,
    /// [`SubmitError::Pool`] when the pool's policy refuses it, or a node
    /// error.
    pub fn submit(&mut self, raw: &[u8]) -> Result<[u8; 32], SubmitError> {
        let hash = keccak256(raw);
        if self.pool.get(&hash).is_none() {
            self.admit(raw)?;
        }
        self.step(Input::TxArrived {
            tx_hash: hash,
            size: u32::try_from(raw.len()).unwrap_or(u32::MAX),
        })
        .map_err(SubmitError::Node)?;
        Ok(hash)
    }

    fn admit(&mut self, raw: &[u8]) -> Result<(), SubmitError> {
        let Some(mut tx) = PoolTx::parse(raw) else {
            let result = self.validate(raw, Ahead::default())?;
            return Err(SubmitError::Rejected(rejection(&result)));
        };
        let sender = tx.sender;
        let account = match self.pool.account(&sender) {
            Some(account) => account.clone(),
            None => self.account(&sender).map_err(SubmitError::Node)?,
        };
        self.pool.check(&tx).map_err(SubmitError::Pool)?;
        let ahead = self.pool.ahead(&sender, account.nonce, tx.nonce);
        match self.validate(raw, ahead)? {
            ValidateResult::Valid { priority, .. } => tx.priority = priority,
            ValidateResult::Invalid { reason } => return Err(SubmitError::Rejected(reason)),
        }
        self.pool.insert(tx, account).map_err(SubmitError::Pool)?;
        let announced = self.pool.announce(&sender);
        self.tx_gossip.extend(announced);
        Ok(())
    }

    /// Runs a kernel query within [`Node::query_gas`].
    ///
    /// # Errors
    /// See [`NodeError`]; a query that exhausts its budget is a
    /// [`NodeError::Kernel`] for which [`NodeError::is_out_of_gas`] holds.
    pub fn query(&mut self, method: &str, params: &[u8]) -> Result<QueryResult, NodeError> {
        self.query_at(method, params, None)
    }

    /// Runs a kernel query within [`Node::query_gas`] over the state as it
    /// was right after block `at` executed, or the current state for `None`
    /// or the last executed height (spec 06 §6, spec 20 §5).
    ///
    /// # Errors
    /// As [`Node::query`]; [`NodeError::StateUnavailable`] when the node no
    /// longer keeps, or never had, the state of block `at`.
    pub fn query_at(
        &mut self,
        method: &str,
        params: &[u8],
        at: Option<u64>,
    ) -> Result<QueryResult, NodeError> {
        let base = self.exec.state_mut().base_mut();
        let view = at.filter(|h| base.versions().is_none_or(|(_, latest)| *h != latest));
        base.set_view(view)
            .map_err(|_| NodeError::StateUnavailable {
                height: at.unwrap_or_default(),
                oldest: self.oldest_state(),
            })?;
        let args = QueryArgs {
            method: method.as_bytes().to_vec(),
            params: params.to_vec(),
            at,
        };
        let gas = self.query_gas.min(self.kernel_gas);
        // A query changes nothing (spec 06 §6): whatever the kernel writes,
        // such as the precompile module of spec 19 §3.2, goes into a layer
        // dropped afterwards, so chain state and the kernel gas of the next
        // block never depend on which queries this node served.
        self.exec.state_mut().push();
        let r = self.call_with(exports::QUERY, &args.to_bytes(), gas);
        self.exec.state_mut().discard();
        // The view only ever has a layer above it, so the base saw no writes.
        let _ = self.exec.state_mut().base_mut().set_view(None);
        let r = r?;
        QueryResult::from_bytes(&r.output)
            .ok()
            .ok_or(NodeError::Decode(exports::QUERY))
    }

    /// The state commitment (spec 10) of the genesis state, which the
    /// genesis header carries (spec 20 §3.1).
    #[must_use]
    pub fn genesis_state_root(&self) -> [u8; 32] {
        self.exec.state().base().genesis_root().unwrap_or_default()
    }

    /// The chain's name (spec 20 §3.4) from the genesis parameters in its
    /// state, empty for a chain without one.
    #[must_use]
    pub fn chain_name(&self) -> String {
        self.state_get(b"meta/params")
            .and_then(|b| solo_abi::chain::GenesisParams::from_bytes(&b).ok())
            .map(|p| String::from_utf8_lossy(&p.name).into_owned())
            .unwrap_or_default()
    }

    /// The genesis hash its handshakes name (spec 09 §3): what the chain
    /// state holds at `bnum/` ‖ 0 (spec 22 §7.3), zero when it holds no
    /// 32-byte hash there.
    #[must_use]
    pub fn genesis_hash(&self) -> [u8; 32] {
        let key = [solo_abi::chain::keys::BLOCK_NUMBER, &0u64.to_be_bytes()[..]].concat();
        self.state_get(&key)
            .and_then(|hash| hash.try_into().ok())
            .unwrap_or_default()
    }

    /// The oldest height whose state the node keeps (spec 20 §5): queries
    /// and proofs reach back to it, and no further.
    #[must_use]
    pub fn oldest_state(&self) -> u64 {
        self.exec
            .state()
            .base()
            .versions()
            .map_or(0, |(oldest, _)| oldest)
    }

    fn query_decoded<T: Decode>(
        &mut self,
        method: &str,
        params: &[u8],
    ) -> Result<Option<T>, NodeError> {
        self.query_decoded_at(method, params, None)
    }

    fn query_decoded_at<T: Decode>(
        &mut self,
        method: &str,
        params: &[u8],
        at: Option<u64>,
    ) -> Result<Option<T>, NodeError> {
        let r = self.query_at(method, params, at)?;
        if r.status != 0 {
            return Ok(None);
        }
        T::from_bytes(&r.body)
            .ok()
            .map(Some)
            .ok_or(NodeError::Decode("query"))
    }

    /// Chain id from the kernel.
    ///
    /// # Errors
    /// See [`NodeError`].
    pub fn chain_id(&mut self) -> Result<u64, NodeError> {
        Ok(self
            .query_decoded(solo_abi::chain::query::CHAIN_ID, &[])?
            .unwrap_or(0))
    }

    /// Last executed height.
    ///
    /// # Errors
    /// See [`NodeError`].
    pub fn block_number(&mut self) -> Result<u64, NodeError> {
        Ok(self
            .query_decoded(solo_abi::chain::query::BLOCK_NUMBER, &[])?
            .unwrap_or(0))
    }

    /// An account.
    ///
    /// # Errors
    /// See [`NodeError`].
    pub fn account(
        &mut self,
        address: &types::Address,
    ) -> Result<solo_abi::chain::Account, NodeError> {
        self.account_at(address, None)
    }

    /// An account as it was after block `at` (see [`Node::query_at`]).
    ///
    /// # Errors
    /// See [`Node::query_at`].
    pub fn account_at(
        &mut self,
        address: &types::Address,
        at: Option<u64>,
    ) -> Result<solo_abi::chain::Account, NodeError> {
        Ok(self
            .query_decoded_at(solo_abi::chain::query::ACCOUNT, address, at)?
            .unwrap_or_default())
    }

    /// A block header by height.
    ///
    /// # Errors
    /// See [`NodeError`].
    pub fn block_by_number(&mut self, height: u64) -> Result<Option<BlockHeader>, NodeError> {
        self.query_decoded(solo_abi::chain::query::BLOCK_BY_NUMBER, &height.to_bytes())
    }

    /// A block header by hash.
    ///
    /// # Errors
    /// See [`NodeError`].
    pub fn block_by_hash(&mut self, hash: &[u8; 32]) -> Result<Option<BlockHeader>, NodeError> {
        self.query_decoded(solo_abi::chain::query::BLOCK_BY_HASH, hash)
    }

    /// A receipt by transaction hash.
    ///
    /// # Errors
    /// See [`NodeError`].
    pub fn receipt(
        &mut self,
        hash: &[u8; 32],
    ) -> Result<Option<solo_abi::chain::Receipt>, NodeError> {
        self.query_decoded(solo_abi::chain::query::RECEIPT, hash)
    }

    /// The raw transaction by hash.
    ///
    /// # Errors
    /// See [`NodeError`].
    pub fn transaction(&mut self, hash: &[u8; 32]) -> Result<Option<Vec<u8>>, NodeError> {
        self.query_decoded(solo_abi::chain::query::TRANSACTION, hash)
    }

    /// Contract code at `address`; empty for an account without code.
    ///
    /// # Errors
    /// See [`NodeError`].
    pub fn code(&mut self, address: &types::Address) -> Result<Vec<u8>, NodeError> {
        self.code_at(address, None)
    }

    /// Contract code as it was after block `at` (see [`Node::query_at`]).
    ///
    /// # Errors
    /// See [`Node::query_at`].
    pub fn code_at(
        &mut self,
        address: &types::Address,
        at: Option<u64>,
    ) -> Result<Vec<u8>, NodeError> {
        Ok(self
            .query_decoded_at(solo_abi::chain::query::CODE, address, at)?
            .unwrap_or_default())
    }

    /// The value of storage slot `slot` of `address`; zero if never written.
    ///
    /// # Errors
    /// See [`NodeError`].
    pub fn storage(
        &mut self,
        address: &types::Address,
        slot: &types::Hash,
    ) -> Result<types::Hash, NodeError> {
        self.storage_at(address, slot, None)
    }

    /// A storage slot as it was after block `at` (see [`Node::query_at`]).
    ///
    /// # Errors
    /// See [`Node::query_at`].
    pub fn storage_at(
        &mut self,
        address: &types::Address,
        slot: &types::Hash,
        at: Option<u64>,
    ) -> Result<types::Hash, NodeError> {
        let params = StorageQuery {
            address: *address,
            slot: *slot,
        };
        Ok(self
            .query_decoded_at(solo_abi::chain::query::STORAGE, &params.to_bytes(), at)?
            .unwrap_or_default())
    }

    /// Executes a message against the latest state and discards its effects
    /// (`eth_call`, `eth_estimateGas`). A `gas` of zero means the kernel's cap.
    ///
    /// # Errors
    /// See [`NodeError`]; [`NodeError::Decode`] if the kernel does not answer
    /// the call query.
    pub fn call(&mut self, request: &CallRequest) -> Result<CallOutcome, NodeError> {
        self.call_at(request, None)
    }

    /// Executes a message against the state after block `at`, in that
    /// block's context (see [`Node::query_at`]).
    ///
    /// # Errors
    /// As [`Node::call`] and [`Node::query_at`].
    pub fn call_at(
        &mut self,
        request: &CallRequest,
        at: Option<u64>,
    ) -> Result<CallOutcome, NodeError> {
        self.query_decoded_at(solo_abi::chain::query::CALL, &request.to_bytes(), at)?
            .ok_or(NodeError::Decode(solo_abi::chain::query::CALL))
    }

    /// Equivocation evidence recorded in chain state, from index `first`, at
    /// most [`EVIDENCE_PAGE`](solo_abi::chain::consensus::EVIDENCE_PAGE)
    /// records; empty if the kernel does not serve the query.
    ///
    /// # Errors
    /// See [`NodeError`].
    pub fn evidence(&mut self, first: u64) -> Result<Vec<Evidence>, NodeError> {
        let r = self.query(solo_abi::chain::query::EVIDENCE, &first.to_bytes())?;
        Ok(Seq::<Evidence>::from_bytes(&r.body).unwrap_or_default().0)
    }

    /// The driver state as last persisted, decoded; `None` before the first
    /// step or for a kernel whose driver state is not the reference driver's.
    #[must_use]
    pub fn simplex_state(&self) -> Option<solo_abi::chain::SimplexState> {
        self.persisted_driver_state
            .as_deref()
            .and_then(|b| solo_abi::chain::SimplexState::from_bytes(b).ok())
    }

    /// Last finalized height.
    ///
    /// # Errors
    /// See [`NodeError`].
    pub fn finalized_height(&mut self) -> Result<u64, NodeError> {
        Ok(self
            .query_decoded(solo_abi::chain::query::FINALIZED, &[])?
            .unwrap_or(0))
    }

    /// The kernel's exported driver state.
    ///
    /// # Errors
    /// See [`NodeError`].
    pub fn driver_state(&mut self) -> Result<Vec<u8>, NodeError> {
        self.call_raw(exports::DRIVER_STATE, &[]).map(|r| r.output)
    }

    /// The chain state as the kernel left it after its last call.
    #[must_use]
    pub fn state(&self) -> &Overlay<ChainState> {
        self.exec.state()
    }

    /// The chain store on disk, if the node keeps its state there.
    #[must_use]
    pub fn chain_store(&self) -> Option<&solo_store::DiskStore> {
        self.exec.state().base().disk()
    }

    /// Injects `fault` into the chain store's next write (tests of crash
    /// recovery, spec 22 §4); nothing happens to a node in memory. Only in
    /// builds with the `fault-injection` feature, which this crate's tests
    /// turn on; a release build has no way to drop a block's write.
    #[cfg(feature = "fault-injection")]
    pub fn inject_store_fault(&mut self, fault: solo_store::Fault) {
        self.exec.state_mut().base_mut().inject(fault);
    }

    /// Lets go of the chain store, keeping an empty state in memory: for a
    /// simulator that reopens the same store in another node.
    pub(crate) fn release_store(&mut self) {
        *self.exec.state_mut().base_mut() = ChainState::Memory(Box::default());
    }

    /// The state commitment (spec 10) of the current chain state: what
    /// `storage_commit` would return to a kernel call starting now.
    ///
    /// No block header carries this root when the kernel writes after it
    /// asks for the root, as the reference kernel does when it stores the
    /// header: a header's root is [`Node::state_proof_at`]'s.
    #[must_use]
    pub fn state_root(&self) -> [u8; 32] {
        // Between kernel calls no overlay layer is open: the base is the state.
        self.exec.state().base().state_trie().root()
    }

    /// The proof for `key` against [`Node::state_root`] (spec 10 §5).
    #[must_use]
    pub fn state_proof(&self, key: &[u8]) -> solo_trie::Proof {
        self.exec.state().base().state_trie().prove(key)
    }

    /// The proof for `key` against the root that executing block `height`
    /// returned, which is the `state_root` of that block's header for the
    /// reference kernel (spec 06 §5, spec 10 §5), or the genesis state for
    /// height 0. `None` unless this node executed that block, or started
    /// from genesis, and keeps its state (from [`Node::oldest_state`] on).
    #[must_use]
    pub fn state_proof_at(&self, height: u64, key: &[u8]) -> Option<solo_trie::Proof> {
        self.exec
            .state()
            .base()
            .trie_at(height)
            .map(|trie| trie.prove(key))
    }

    /// Log lines emitted by the kernel.
    #[must_use]
    pub fn logs(&self) -> &[(u32, Vec<u8>)] {
        self.exec.logs()
    }

    /// A raw value of the kernel's storage, by the key the kernel uses, for
    /// tooling and tests that check the kernel's state layout.
    #[must_use]
    pub fn state_get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.exec.state().get(key)
    }

    /// Every raw entry of the kernel's storage under `prefix`, in key order.
    #[must_use]
    pub fn state_scan(&self, prefix: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
        self.exec.state().scan(prefix)
    }
}
