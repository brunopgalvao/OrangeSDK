//! An in-process network of nodes with a virtual clock: broadcast and
//! point-to-point delivery after a fixed latency, transaction gossip, and
//! nodes that can be crashed and revived. The consensus tests and the
//! conformance tooling drive drivers through this rather than sockets.

use std::collections::{BTreeMap, VecDeque};

use k256::ecdsa::SigningKey;
use solo_abi::chain::{Validator, ValidatorSet};
use solo_abi::codec::Seq;
use solo_abi::types::{Genesis, Input};

use crate::extension::{Outbound, validator_id};
use crate::node::{Node, NodeConfig, NodeError, SubmitError};
use crate::state::StoreConfig;
use crate::statesync::{StateSync, SyncEvent};

/// What travels between two nodes.
#[derive(Debug, Clone)]
enum Wire {
    Message {
        from: [u8; 32],
        topic: u16,
        payload: Vec<u8>,
    },
    Request {
        from: usize,
        request_id: u64,
        payload: Vec<u8>,
    },
    Response {
        request_id: u64,
        payload: Vec<u8>,
    },
    /// A state-sync request or answer (spec 09 §6): the host's, never the
    /// driver's.
    SyncRequest {
        from: usize,
        request_id: u64,
        payload: Vec<u8>,
    },
    SyncResponse {
        from: usize,
        request_id: u64,
        payload: Vec<u8>,
    },
}

/// What may happen to a state-sync answer on its way: given the index of
/// the node that answered, it may change the payload, and drops the answer
/// by returning `false`. Tests make lying and silent peers with it.
pub type SyncFilter = Box<dyn FnMut(usize, &mut Vec<u8>) -> bool>;

/// A message in flight.
#[derive(Debug, Clone)]
struct InFlight {
    due_ms: u64,
    to: usize,
    wire: Wire,
}

/// The simulated network.
pub struct Sim {
    /// The nodes; validators first, in validator-set order, then observers.
    pub nodes: Vec<Node>,
    ids: Vec<[u8; 32]>,
    alive: Vec<bool>,
    /// Where each node keeps its chain state; a node revived over a disk
    /// store resumes from it.
    stores: Vec<StoreConfig>,
    /// Virtual clock in milliseconds.
    pub now_ms: u64,
    /// Delivery latency applied to every message.
    pub latency_ms: u64,
    /// Extra delay of every answer to a driver's request, on top of
    /// `latency_ms`: a peer slow to serve the blocks a node catches up with
    /// (spec 09 §6a), as a loaded machine is.
    pub response_delay_ms: u64,
    queue: VecDeque<InFlight>,
    gossip: VecDeque<(u64, usize, Vec<u8>)>,
    /// Messages delivered so far.
    pub delivered: u64,
    /// Requests a node is serving: `(node, local id)` to `(requester, its id)`.
    serving: BTreeMap<(usize, u64), (usize, u64)>,
    next_local_id: u64,
    /// The node joining from its peers' snapshots, and its state sync.
    joining: Option<(usize, StateSync)>,
    /// What the state sync reported, in order.
    pub sync_events: Vec<SyncEvent>,
    sync_filter: Option<SyncFilter>,
}

impl Sim {
    /// The validator set of `keys`, in order.
    #[must_use]
    pub fn validator_set(keys: &[SigningKey]) -> ValidatorSet {
        ValidatorSet {
            validators: Seq(keys
                .iter()
                .map(|k| Validator {
                    id: validator_id(k),
                    weight: 1,
                })
                .collect()),
        }
    }

    /// Opens one node per key plus `observers` keyless nodes, each from
    /// `template` with its own key, and starts them. `genesis.validators`
    /// should list the keys' ids.
    ///
    /// # Errors
    /// Whatever opening or starting a node reports.
    pub fn new(
        kernel: &[u8],
        genesis: &Genesis,
        keys: &[SigningKey],
        observers: usize,
        template: &NodeConfig,
        latency_ms: u64,
    ) -> Result<Sim, NodeError> {
        Sim::with_stores(kernel, genesis, keys, observers, template, latency_ms, &[])
    }

    /// [`Sim::new`] with the chain state of node `i` kept where `stores[i]`
    /// says (in memory for a node `stores` does not name): a node with a
    /// disk store that crashes and is revived resumes from it, as a
    /// restarted validator does (spec 22 §5).
    ///
    /// # Errors
    /// Whatever opening or starting a node reports.
    pub fn with_stores(
        kernel: &[u8],
        genesis: &Genesis,
        keys: &[SigningKey],
        observers: usize,
        template: &NodeConfig,
        latency_ms: u64,
        stores: &[StoreConfig],
    ) -> Result<Sim, NodeError> {
        let mut nodes = Vec::new();
        let mut ids = Vec::new();
        let mut configs = Vec::new();
        for i in 0..keys.len() + observers {
            let key = keys.get(i).cloned();
            ids.push(key.as_ref().map_or([0xEE; 32], validator_id));
            let store = stores.get(i).cloned().unwrap_or_default();
            let config = NodeConfig {
                key,
                store: store.clone(),
                ..template.clone()
            };
            configs.push(store);
            nodes.push(Self::open_started(kernel, genesis, config, None)?);
        }
        let alive = vec![true; nodes.len()];
        let mut sim = Sim {
            nodes,
            ids,
            alive,
            stores: configs,
            now_ms: template.now_ms,
            latency_ms,
            response_delay_ms: 0,
            queue: VecDeque::new(),
            gossip: VecDeque::new(),
            delivered: 0,
            serving: BTreeMap::new(),
            next_local_id: 0,
            joining: None,
            sync_events: Vec::new(),
            sync_filter: None,
        };
        sim.collect();
        Ok(sim)
    }

    fn open_started(
        kernel: &[u8],
        genesis: &Genesis,
        config: NodeConfig,
        resumed: Option<Vec<u8>>,
    ) -> Result<Node, NodeError> {
        let mut node = Node::open(kernel, genesis, config)?;
        node.start(resumed)?;
        Ok(node)
    }

    /// Stops a node: it neither ticks nor receives until revived.
    pub fn crash(&mut self, index: usize) {
        self.alive[index] = false;
    }

    /// Restarts a crashed node from its persisted state, with the same key.
    ///
    /// # Errors
    /// Whatever reopening the node reports.
    pub fn revive(
        &mut self,
        index: usize,
        kernel: &[u8],
        genesis: &Genesis,
    ) -> Result<(), NodeError> {
        self.restart(index, kernel, genesis, true)
    }

    /// Restarts a crashed node with the same key but nothing it persisted,
    /// like a validator reinstalled from scratch: it starts in view 1 at genesis.
    ///
    /// # Errors
    /// Whatever reopening the node reports.
    pub fn revive_from_scratch(
        &mut self,
        index: usize,
        kernel: &[u8],
        genesis: &Genesis,
    ) -> Result<(), NodeError> {
        self.restart(index, kernel, genesis, false)
    }

    /// Replaces node `index` by one that starts from `snapshot` (spec 22 §7)
    /// in a fresh disk store at `dir`, with the same key and nothing else
    /// of what the old node had: a validator reinstalled from a snapshot.
    ///
    /// # Errors
    /// Whatever opening, importing into or starting the node reports.
    pub fn revive_from_snapshot(
        &mut self,
        index: usize,
        kernel: &[u8],
        genesis: &Genesis,
        snapshot: &solo_store::Snapshot,
        dir: std::path::PathBuf,
    ) -> Result<(), NodeError> {
        let old = &self.nodes[index];
        let config = NodeConfig {
            now_ms: self.now_ms,
            key: old.services_key(),
            kernel_gas: old.kernel_gas,
            query_gas: old.query_gas,
            state_history: old.state_history,
            history_keys_per_block: old.history_keys_per_block,
            store: StoreConfig::Disk(dir.clone()),
            ..NodeConfig::default()
        };
        self.stores[index] = StoreConfig::Disk(dir);
        self.nodes[index].release_store();
        let mut node = Node::open(kernel, genesis, config)?;
        node.import_snapshot(snapshot)?;
        node.start(None)?;
        self.nodes[index] = node;
        self.alive[index] = true;
        self.collect();
        Ok(())
    }

    /// Replaces node `index` by one that joins from its peers' snapshots
    /// (spec 22 §7.4) in a fresh disk store at `dir`, with the same key and
    /// nothing else of what the old node had: it takes no part in the
    /// network until its state sync has fetched, verified and imported a
    /// snapshot, then starts and syncs blocks as any node does. The sync
    /// works in `dir/statesync`. [`Sim::advance`] reports a sync that fails.
    ///
    /// # Errors
    /// Whatever opening the node or its sync directory reports.
    pub fn join_from_peers(
        &mut self,
        index: usize,
        kernel: &[u8],
        genesis: &Genesis,
        dir: std::path::PathBuf,
        trust: solo_store::Trust,
    ) -> Result<(), NodeError> {
        let old = &self.nodes[index];
        let config = NodeConfig {
            now_ms: self.now_ms,
            key: old.services_key(),
            kernel_gas: old.kernel_gas,
            query_gas: old.query_gas,
            state_history: old.state_history,
            history_keys_per_block: old.history_keys_per_block,
            store: StoreConfig::Disk(dir.clone()),
            ..NodeConfig::default()
        };
        self.stores[index] = StoreConfig::Disk(dir);
        self.nodes[index].release_store();
        let mut node = Node::open(kernel, genesis, config)?;
        let sync = StateSync::new(node.sync_config(trust)?)
            .map_err(|e| NodeError::Store(e.to_string()))?;
        self.nodes[index] = node;
        self.alive[index] = false;
        self.joining = Some((index, sync));
        Ok(())
    }

    /// The state sync of the node joining from its peers, while it runs.
    #[must_use]
    pub fn joining(&self) -> Option<&StateSync> {
        self.joining.as_ref().map(|(_, sync)| sync)
    }

    /// Passes every state-sync answer through `filter` from now on.
    pub fn filter_sync(&mut self, filter: SyncFilter) {
        self.sync_filter = Some(filter);
    }

    /// Moves the joining node's state sync on: hands it the peers that are
    /// up and queues its requests; once it holds a snapshot, imports it and
    /// starts the node.
    fn step_sync(&mut self) -> Result<(), NodeError> {
        let Some((index, sync)) = self.joining.as_mut() else {
            return Ok(());
        };
        let index = *index;
        let connected: Vec<[u8; 32]> = (0..self.nodes.len())
            .filter(|i| *i != index && self.alive[*i])
            .map(|i| self.ids[i])
            .collect();
        let requests = sync.poll(self.now_ms, &connected);
        self.sync_events.extend(sync.take_events());
        if let Some(why) = sync.failed() {
            return Err(NodeError::Store(format!("state sync: {why}")));
        }
        if let Some(snapshot) = sync.done().cloned() {
            self.joining = None;
            crate::statesync::finish(&mut self.nodes[index], &snapshot)?;
            self.alive[index] = true;
            self.collect();
            return Ok(());
        }
        for (peer, request_id, payload) in requests {
            let to = self.index_of(&peer).expect("a connected node");
            self.enqueue(
                to,
                Wire::SyncRequest {
                    from: index,
                    request_id,
                    payload,
                },
            );
        }
        Ok(())
    }

    fn restart(
        &mut self,
        index: usize,
        kernel: &[u8],
        genesis: &Genesis,
        keep: bool,
    ) -> Result<(), NodeError> {
        let old = &self.nodes[index];
        let key = self.ids[index];
        let (persisted, resumed) = if keep {
            (old.persisted(), old.persisted_driver_state.clone())
        } else {
            (BTreeMap::new(), None)
        };
        let config = NodeConfig {
            now_ms: self.now_ms,
            key: old.services_key(),
            persisted,
            kernel_gas: old.kernel_gas,
            query_gas: old.query_gas,
            state_history: old.state_history,
            history_keys_per_block: old.history_keys_per_block,
            store: self.stores[index].clone(),
            background: false,
        };
        // A disk store is held by one node at a time: the old one lets go
        // before the new one opens it.
        self.nodes[index].release_store();
        self.nodes[index] = Self::open_started(kernel, genesis, config, resumed)?;
        self.ids[index] = key;
        self.alive[index] = true;
        self.collect();
        Ok(())
    }

    /// Submits a transaction to node `index`; it reaches the others by gossip.
    ///
    /// # Errors
    /// As [`Node::submit`].
    pub fn submit(&mut self, index: usize, raw: &[u8]) -> Result<[u8; 32], SubmitError> {
        let hash = self.nodes[index].submit(raw)?;
        self.collect();
        Ok(hash)
    }

    /// Moves every node's outbound traffic into the queue.
    fn collect(&mut self) {
        for i in 0..self.nodes.len() {
            if !self.alive[i] {
                continue;
            }
            let from = self.ids[i];
            for message in self.nodes[i].take_outbound() {
                match message {
                    Outbound::Broadcast { topic, payload } => {
                        for to in 0..self.nodes.len() {
                            if to != i {
                                self.enqueue(
                                    to,
                                    Wire::Message {
                                        from,
                                        topic,
                                        payload: payload.clone(),
                                    },
                                );
                            }
                        }
                    }
                    Outbound::Send {
                        peer,
                        topic,
                        payload,
                    } => {
                        if let Some(to) = self.index_of(&peer) {
                            self.enqueue(
                                to,
                                Wire::Message {
                                    from,
                                    topic,
                                    payload,
                                },
                            );
                        }
                    }
                    Outbound::Request {
                        peer,
                        request_id,
                        payload,
                    } => {
                        if let Some(to) = self.index_of(&peer) {
                            self.enqueue(
                                to,
                                Wire::Request {
                                    from: i,
                                    request_id,
                                    payload,
                                },
                            );
                        }
                    }
                    Outbound::Respond {
                        request_id,
                        payload,
                    } => {
                        if let Some((to, their_id)) = self.serving.remove(&(i, request_id)) {
                            self.queue.push_back(InFlight {
                                due_ms: self.now_ms + self.latency_ms + self.response_delay_ms,
                                to,
                                wire: Wire::Response {
                                    request_id: their_id,
                                    payload,
                                },
                            });
                        }
                    }
                    Outbound::Disseminate { .. } | Outbound::PeerScore { .. } => {}
                }
            }
            for raw in self.nodes[i].take_tx_gossip() {
                for to in 0..self.nodes.len() {
                    if to != i {
                        self.gossip
                            .push_back((self.now_ms + self.latency_ms, to, raw.clone()));
                    }
                }
            }
        }
    }

    fn index_of(&self, peer: &[u8; 32]) -> Option<usize> {
        self.ids.iter().position(|id| id == peer)
    }

    fn enqueue(&mut self, to: usize, wire: Wire) {
        self.queue.push_back(InFlight {
            due_ms: self.now_ms + self.latency_ms,
            to,
            wire,
        });
    }

    fn deliver(&mut self, to: usize, wire: Wire) -> Result<(), NodeError> {
        let input = match wire {
            Wire::SyncRequest {
                from,
                request_id,
                payload,
            } => {
                let mut answer = self.nodes[to].answer_sync(&payload);
                if self.sync_filter.as_mut().is_none_or(|f| f(to, &mut answer)) {
                    self.enqueue(
                        from,
                        Wire::SyncResponse {
                            from: to,
                            request_id,
                            payload: answer,
                        },
                    );
                }
                return Ok(());
            }
            Wire::SyncResponse {
                from,
                request_id,
                payload,
            } => {
                let (now, peer) = (self.now_ms, self.ids[from]);
                if let Some((_, sync)) = self.joining.as_mut() {
                    sync.on_response(peer, request_id, &payload, now);
                }
                return Ok(());
            }
            Wire::Message {
                from,
                topic,
                payload,
            } => return self.nodes[to].deliver(from, topic, payload),
            Wire::Request {
                from,
                request_id,
                payload,
            } => {
                self.next_local_id += 1;
                self.serving
                    .insert((to, self.next_local_id), (from, request_id));
                Input::Request {
                    peer: self.ids[from],
                    request_id: self.next_local_id,
                    payload,
                }
            }
            Wire::Response {
                request_id,
                payload,
            } => return self.nodes[to].response(request_id, payload),
        };
        self.nodes[to].step(input)
    }

    /// Advances the clock by `ms` in 10 ms steps, ticking nodes and
    /// delivering due messages. Messages to a crashed node are dropped.
    ///
    /// # Errors
    /// The first node error.
    pub fn advance(&mut self, ms: u64) -> Result<(), NodeError> {
        let end = self.now_ms + ms;
        while self.now_ms < end {
            self.now_ms = (self.now_ms + 10).min(end);
            let due: Vec<InFlight> = {
                let mut due = Vec::new();
                let mut rest = VecDeque::new();
                for m in self.queue.drain(..) {
                    if m.due_ms <= self.now_ms {
                        due.push(m);
                    } else {
                        rest.push_back(m);
                    }
                }
                self.queue = rest;
                due
            };
            for m in due {
                let to_joining = self.joining.as_ref().is_some_and(|(i, _)| *i == m.to);
                if to_joining && matches!(m.wire, Wire::SyncResponse { .. }) {
                    self.deliver(m.to, m.wire)?;
                } else if self.alive[m.to] {
                    self.nodes[m.to].tick(self.now_ms)?;
                    self.deliver(m.to, m.wire)?;
                    self.delivered += 1;
                }
            }
            self.step_sync()?;
            let mut rest = VecDeque::new();
            for (due_ms, to, raw) in self.gossip.drain(..) {
                if due_ms <= self.now_ms {
                    if self.alive[to] {
                        // A peer's rejection is not our error: it may already hold the transaction.
                        let _ = self.nodes[to].submit(&raw);
                    }
                } else {
                    rest.push_back((due_ms, to, raw));
                }
            }
            self.gossip = rest;
            for i in 0..self.nodes.len() {
                if self.alive[i] {
                    self.nodes[i].tick(self.now_ms)?;
                }
            }
            self.collect();
        }
        Ok(())
    }

    /// Advances until `done` holds or `max_ms` have passed; returns whether it held.
    ///
    /// # Errors
    /// As [`Sim::advance`].
    pub fn run_until(
        &mut self,
        max_ms: u64,
        mut done: impl FnMut(&mut Sim) -> bool,
    ) -> Result<bool, NodeError> {
        self.run_until_dyn(max_ms, &mut done)
    }

    /// One non-generic body, so every caller shares it.
    fn run_until_dyn(
        &mut self,
        max_ms: u64,
        done: &mut dyn FnMut(&mut Sim) -> bool,
    ) -> Result<bool, NodeError> {
        let end = self.now_ms + max_ms;
        while self.now_ms < end {
            if done(self) {
                return Ok(true);
            }
            self.advance(10)?;
        }
        Ok(done(self))
    }

    /// Finalized height of every node.
    ///
    /// # Errors
    /// The first query error.
    pub fn finalized_heights(&mut self) -> Result<Vec<u64>, NodeError> {
        self.nodes.iter_mut().map(Node::finalized_height).collect()
    }
}
