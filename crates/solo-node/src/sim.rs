//! An in-process network of nodes with a virtual clock: broadcast and
//! point-to-point delivery after a fixed latency, transaction gossip, and
//! nodes that can be crashed and revived. The consensus tests and the
//! conformance tooling drive drivers through this rather than sockets.

use std::collections::VecDeque;

use k256::ecdsa::SigningKey;
use solo_abi::chain::{Validator, ValidatorSet};
use solo_abi::codec::Seq;
use solo_abi::types::Genesis;

use crate::extension::{Outbound, validator_id};
use crate::node::{Node, NodeConfig, NodeError, SubmitError};

/// A message in flight.
#[derive(Debug, Clone)]
struct InFlight {
    due_ms: u64,
    from: [u8; 32],
    to: usize,
    topic: u16,
    payload: Vec<u8>,
}

/// The simulated network.
pub struct Sim {
    /// The nodes; validators first, in validator-set order, then observers.
    pub nodes: Vec<Node>,
    ids: Vec<[u8; 32]>,
    alive: Vec<bool>,
    /// Virtual clock in milliseconds.
    pub now_ms: u64,
    /// Delivery latency applied to every message.
    pub latency_ms: u64,
    queue: VecDeque<InFlight>,
    gossip: VecDeque<(u64, usize, Vec<u8>)>,
    /// Messages delivered so far.
    pub delivered: u64,
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
        let mut nodes = Vec::new();
        let mut ids = Vec::new();
        for i in 0..keys.len() + observers {
            let key = keys.get(i).cloned();
            ids.push(key.as_ref().map_or([0xEE; 32], validator_id));
            let config = NodeConfig {
                key,
                ..template.clone()
            };
            nodes.push(Self::open_started(kernel, genesis, config, None)?);
        }
        let alive = vec![true; nodes.len()];
        let mut sim = Sim {
            nodes,
            ids,
            alive,
            now_ms: template.now_ms,
            latency_ms,
            queue: VecDeque::new(),
            gossip: VecDeque::new(),
            delivered: 0,
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
        let old = &self.nodes[index];
        let key = self.ids[index];
        let config = NodeConfig {
            now_ms: self.now_ms,
            key: old.services_key(),
            persisted: old.persisted(),
            kernel_gas: old.kernel_gas,
        };
        let resumed = old.persisted_driver_state.clone();
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
                                self.enqueue(from, to, topic, payload.clone());
                            }
                        }
                    }
                    Outbound::Send {
                        peer,
                        topic,
                        payload,
                    } => {
                        if let Some(to) = self.ids.iter().position(|id| *id == peer) {
                            self.enqueue(from, to, topic, payload);
                        }
                    }
                    Outbound::Disseminate { .. }
                    | Outbound::Request { .. }
                    | Outbound::Respond { .. }
                    | Outbound::PeerScore { .. } => {}
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

    fn enqueue(&mut self, from: [u8; 32], to: usize, topic: u16, payload: Vec<u8>) {
        self.queue.push_back(InFlight {
            due_ms: self.now_ms + self.latency_ms,
            from,
            to,
            topic,
            payload,
        });
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
                if self.alive[m.to] {
                    self.nodes[m.to].tick(self.now_ms)?;
                    self.nodes[m.to].deliver(m.from, m.topic, m.payload)?;
                    self.delivered += 1;
                }
            }
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
