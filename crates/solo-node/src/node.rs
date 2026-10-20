//! The node: kernel lifecycle, the driver loop, mempool and queries.

use std::cell::RefCell;
use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::rc::Rc;

use solo_abi::chain::BlockHeader;
use solo_abi::codec::Seq;
use solo_abi::types::{
    self, Block, Effect, ExecContext, ExecuteArgs, ExecuteResult, FinalizeArgs, Genesis, Input,
    QueryArgs, QueryResult, ValidateArgs, ValidateResult, exports,
};
use solo_abi::{Decode, Encode};
use solo_host::hash::keccak256;
use solo_host::{CallResult, Executor, Flags, LoadError, MemStorage, ModuleCache, Overlay};
use solo_vm::host::Capability;
use solo_vm::status::Termination;

use crate::extension::{NodeExtension, NodeServices, Outbound, validator_id};

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
}

impl Default for NodeConfig {
    fn default() -> NodeConfig {
        NodeConfig {
            now_ms: 0,
            key: None,
            persisted: BTreeMap::new(),
            kernel_gas: KERNEL_GAS,
        }
    }
}

/// Gas allowed to each kernel entrypoint call. Kernel work is bounded by the
/// block limits it enforces, so this is a safety net, not a budget.
pub const KERNEL_GAS: i64 = 1 << 40;

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
}

impl fmt::Display for NodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NodeError::Load(e) => write!(f, "kernel failed to load: {e:?}"),
            NodeError::Kernel { export, status } => write!(f, "{export} ended with {status:?}"),
            NodeError::Decode(export) => write!(f, "{export} returned an undecodable result"),
        }
    }
}

impl std::error::Error for NodeError {}

/// Why a transaction was not admitted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubmitError {
    /// The kernel rejected it with this reason code (`solo_abi::chain::reason`).
    Rejected(u32),
    /// The node failed while asking the kernel.
    Node(NodeError),
}

/// A transaction waiting in the mempool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pending {
    /// `keccak256` of the raw bytes.
    pub hash: [u8; 32],
    /// Raw transaction.
    pub raw: Vec<u8>,
    /// Ordering priority from validation.
    pub priority: u64,
}

/// A running node.
pub struct Node {
    exec: Executor<MemStorage>,
    kernel: [u8; 32],
    services: Rc<RefCell<NodeServices>>,
    mempool: Vec<Pending>,
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
    /// Raw transactions admitted since the last [`Node::take_tx_gossip`],
    /// for the transport to forward to peers.
    tx_gossip: Vec<Vec<u8>>,
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

    /// Loads a kernel with a key and persisted data, then runs `kernel_init`.
    ///
    /// # Errors
    /// As [`Node::new`].
    pub fn open(
        kernel_module: &[u8],
        genesis: &Genesis,
        config: NodeConfig,
    ) -> Result<Node, NodeError> {
        let services = Rc::new(RefCell::new(NodeServices {
            now_ms: config.now_ms,
            key: config.key,
            persisted: config.persisted,
            ..NodeServices::default()
        }));
        let mut exec = Executor::new(ModuleCache::default(), MemStorage::default());
        exec.set_extension(Box::new(NodeExtension::new(Rc::clone(&services))));
        let kernel = exec
            .load(kernel_module, Capability::Privileged)
            .map_err(NodeError::Load)?;
        let mut node = Node {
            exec,
            kernel,
            services,
            mempool: Vec::new(),
            executed: Vec::new(),
            finalized: Vec::new(),
            metrics: Vec::new(),
            persisted_driver_state: None,
            kernel_gas: KERNEL_GAS,
            tx_gossip: Vec::new(),
        };
        node.call_unit(exports::INIT, &genesis.to_bytes())?;
        node.kernel_gas = config.kernel_gas;
        Ok(node)
    }

    fn call_raw(&mut self, export: &'static str, input: &[u8]) -> Result<CallResult, NodeError> {
        let kernel = self.kernel;
        let r = self.exec.call_export(
            &kernel,
            export,
            KERNEL_NAMESPACE,
            input,
            self.kernel_gas,
            Capability::Privileged,
            Flags::default(),
        );
        if r.status == Termination::Halt {
            Ok(r)
        } else {
            Err(NodeError::Kernel {
                export,
                status: r.status,
            })
        }
    }

    fn call<T: Decode>(&mut self, export: &'static str, input: &[u8]) -> Result<T, NodeError> {
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

    /// Raw transactions admitted since the last call, for peers.
    pub fn take_tx_gossip(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.tx_gossip)
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
        self.step(Input::NetworkMessage {
            peer,
            topic,
            payload,
        })
    }

    /// The mempool contents.
    #[must_use]
    pub fn mempool(&self) -> &[Pending] {
        &self.mempool
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
    ///
    /// # Errors
    /// See [`NodeError`].
    pub fn step(&mut self, input: Input) -> Result<(), NodeError> {
        let mut queue = VecDeque::from([input]);
        while let Some(input) = queue.pop_front() {
            let effects: Seq<Effect> = self.call(exports::DRIVER_STEP, &input.to_bytes())?;
            for effect in effects.0 {
                if let Some(follow_up) = self.apply_effect(effect)? {
                    queue.push_back(follow_up);
                }
            }
        }
        Ok(())
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
            Effect::ExecuteBlock { block } => Some(self.execute_block(block)?),
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
                self.finalized.push(height);
                None
            }
            Effect::PersistState { state } => {
                self.persisted_driver_state = Some(state);
                None
            }
            Effect::MempoolTake { max_bytes, .. } => {
                let mut taken = Vec::new();
                let mut bytes = 0usize;
                self.mempool.sort_by_key(|p| core::cmp::Reverse(p.priority));
                let mut rest = Vec::new();
                for p in self.mempool.drain(..) {
                    if bytes + p.raw.len() <= max_bytes as usize {
                        bytes += p.raw.len();
                        taken.push(p.raw);
                    } else {
                        rest.push(p);
                    }
                }
                self.mempool = rest;
                Some(Input::MempoolContents { txs: Seq(taken) })
            }
            Effect::MempoolReject { tx_hash, .. } => {
                self.mempool.retain(|p| p.hash != tx_hash);
                None
            }
            Effect::Metric { name, value } => {
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
            } => self.outbound(Outbound::Request {
                peer,
                request_id,
                payload,
            }),
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

    fn execute_block(&mut self, block: Block) -> Result<Input, NodeError> {
        let header = BlockHeader::from_bytes(&block.header)
            .map_err(|_| NodeError::Decode("block header"))?;
        let context = Self::context_for(&header);
        let height = header.height;
        let args = ExecuteArgs { block, context }.to_bytes();
        let result: ExecuteResult = self.call(exports::EXECUTE_BLOCK, &args)?;
        let stored = self
            .block_by_number(height)?
            .ok_or(NodeError::Decode("stored header"))?;
        let block_hash = keccak256(&stored.to_bytes());
        // Whatever the block carried is no longer pending, wherever it came from.
        self.mempool
            .retain(|p| !stored.tx_hashes.0.contains(&p.hash));
        self.executed.push((height, block_hash));
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
        self.services.borrow_mut().now_ms = now_ms;
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
        Ok(())
    }

    /// Validates a raw transaction with the kernel and admits it to the mempool.
    ///
    /// # Errors
    /// [`SubmitError::Rejected`] with the kernel's reason, or a node error.
    pub fn submit(&mut self, raw: &[u8]) -> Result<[u8; 32], SubmitError> {
        let hash = keccak256(raw);
        let next = self.block_number().map_err(SubmitError::Node)? + 1;
        let context = ExecContext {
            height: next,
            slot: next,
            ..ExecContext::default()
        };
        let args = ValidateArgs {
            tx: raw.to_vec(),
            context,
        };
        let result: ValidateResult = self
            .call(exports::VALIDATE_TX, &args.to_bytes())
            .map_err(SubmitError::Node)?;
        match result {
            ValidateResult::Valid { priority, .. } => {
                if !self.mempool.iter().any(|p| p.hash == hash) {
                    self.mempool.push(Pending {
                        hash,
                        raw: raw.to_vec(),
                        priority,
                    });
                    self.tx_gossip.push(raw.to_vec());
                }
                self.step(Input::TxArrived {
                    tx_hash: hash,
                    size: u32::try_from(raw.len()).unwrap_or(u32::MAX),
                })
                .map_err(SubmitError::Node)?;
                Ok(hash)
            }
            ValidateResult::Invalid { reason } => Err(SubmitError::Rejected(reason)),
        }
    }

    /// Runs a kernel query.
    ///
    /// # Errors
    /// See [`NodeError`].
    pub fn query(&mut self, method: &str, params: &[u8]) -> Result<QueryResult, NodeError> {
        let args = QueryArgs {
            method: method.as_bytes().to_vec(),
            params: params.to_vec(),
            at: None,
        };
        self.call(exports::QUERY, &args.to_bytes())
    }

    fn query_decoded<T: Decode>(
        &mut self,
        method: &str,
        params: &[u8],
    ) -> Result<Option<T>, NodeError> {
        let r = self.query(method, params)?;
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
        Ok(self
            .query_decoded(solo_abi::chain::query::ACCOUNT, address)?
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
    pub fn state(&self) -> &Overlay<MemStorage> {
        self.exec.state()
    }

    /// The state commitment (spec 10) of the current chain state: what
    /// `storage_commit` would return to a kernel call starting now.
    #[must_use]
    pub fn state_root(&self) -> [u8; 32] {
        self.exec.state().commitment()
    }

    /// The proof for `key` against [`Node::state_root`] (spec 10 §5).
    #[must_use]
    pub fn state_proof(&self, key: &[u8]) -> solo_trie::Proof {
        self.exec.state().state_trie().prove(key)
    }

    /// Log lines emitted by the kernel.
    #[must_use]
    pub fn logs(&self) -> &[(u32, Vec<u8>)] {
        self.exec.logs()
    }
}
