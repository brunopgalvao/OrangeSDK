//! What the node's thread keeps for the WebSocket (spec 20 §8.7): the open
//! sockets, their subscriptions, and the notifications sent after each
//! turn's requests. `eth_subscribe` and `eth_unsubscribe` are served here,
//! every other method by [`Rpc`] as over HTTP.

use std::collections::{BTreeMap, BTreeSet};
use std::hash::{BuildHasher, RandomState};
use std::sync::Arc;
use std::time::{Duration, Instant};

use orange_host::hash::keccak256;
use serde_json::{Value, json};

use crate::Rpc;
use crate::filter::Filter;
use crate::hex::data;
use crate::http::wait_while;
use crate::methods::{RpcError, param_str};
use crate::ws::{self, Socket, opcode};

/// How often the pool is looked at for `newPendingTransactions` (spec 20
/// §8.7.3).
pub const PENDING_MS: u64 = 200;

/// Most blocks announced in one turn (spec 20 §8.7.3).
pub const BLOCKS_PER_TURN: u64 = 16;

/// What a subscription announces.
enum Kind {
    Heads,
    Logs(Filter),
    Pending,
}

struct Subscription {
    kind: Kind,
    /// The first height not yet announced.
    next: u64,
}

/// One open socket and its subscriptions, by id.
struct Open {
    socket: Arc<Socket>,
    subscriptions: BTreeMap<String, Subscription>,
}

/// The sockets the node's thread serves.
pub(crate) struct Subscriptions {
    sockets: BTreeMap<u64, Open>,
    next_socket: u64,
    /// Most subscriptions one socket holds.
    max: usize,
    /// Random per server, so that ids cannot be guessed.
    seed: u64,
    count: u64,
    /// The pool's hashes when it was last looked at, and when, while any
    /// socket subscribes to `newPendingTransactions`.
    pool: Option<(BTreeSet<[u8; 32]>, Instant)>,
}

/// The pool's transaction hashes.
fn pool_hashes(rpc: &Rpc) -> BTreeSet<[u8; 32]> {
    rpc.node().mempool().iter().map(|tx| tx.hash).collect()
}

/// A notification of `result` under `id`, as a text frame.
fn notification(id: &str, result: &Value) -> Vec<u8> {
    let message = json!({
        "jsonrpc": "2.0",
        "method": "eth_subscription",
        "params": { "subscription": id, "result": result },
    });
    ws::encode(opcode::TEXT, message.to_string().as_bytes())
}

impl Subscriptions {
    pub(crate) fn new(max: usize) -> Subscriptions {
        Subscriptions {
            sockets: BTreeMap::new(),
            next_socket: 0,
            max,
            seed: RandomState::new().hash_one(1u8),
            count: 0,
            pool: None,
        }
    }

    /// Sockets open.
    pub(crate) fn len(&self) -> usize {
        self.sockets.len()
    }

    /// Opens `socket`; its id.
    pub(crate) fn open(&mut self, socket: Arc<Socket>) -> u64 {
        self.next_socket += 1;
        let open = Open {
            socket,
            subscriptions: BTreeMap::new(),
        };
        self.sockets.insert(self.next_socket, open);
        self.next_socket
    }

    /// Answers one message of socket `id`, a JSON-RPC body, on the socket.
    pub(crate) fn message(&mut self, rpc: &mut Rpc, id: u64, body: &str) {
        let answer = rpc.handle_body_with(body, &mut |rpc, method, params| match method {
            "eth_subscribe" => Some(self.subscribe(rpc, id, params)),
            "eth_unsubscribe" => Some(self.unsubscribe(id, params)),
            _ => None,
        });
        if let Some(open) = self.sockets.get(&id) {
            open.socket
                .send(ws::encode(opcode::TEXT, answer.to_string().as_bytes()));
        }
    }

    fn subscribe(&mut self, rpc: &mut Rpc, id: u64, params: &[Value]) -> Result<Value, RpcError> {
        let kind = match param_str(params, 0)? {
            "newHeads" => Kind::Heads,
            "logs" => {
                let filter = match params.get(1) {
                    None | Some(Value::Null) => Filter::parse(Some(&json!({})))?,
                    given => Filter::parse(given)?,
                };
                Kind::Logs(filter)
            }
            "newPendingTransactions" if params.get(1).and_then(Value::as_bool) == Some(true) => {
                return Err(RpcError::invalid_params(
                    "full pending transactions are not served",
                ));
            }
            "newPendingTransactions" => Kind::Pending,
            other => {
                return Err(RpcError::invalid_params(format!(
                    "unsupported subscription kind: {other}"
                )));
            }
        };
        let max = self.max;
        let held = self.sockets.get(&id).map_or(0, |o| o.subscriptions.len());
        if held >= max {
            return Err(RpcError::server(format!(
                "too many subscriptions on this connection, the limit is {max}"
            )));
        }
        let next = rpc.block_number()? + 1;
        if matches!(kind, Kind::Pending) && self.pool.is_none() {
            self.pool = Some((pool_hashes(rpc), Instant::now()));
        }
        self.count += 1;
        let mut preimage = self.seed.to_be_bytes().to_vec();
        preimage.extend_from_slice(&self.count.to_be_bytes());
        let sub = data(&keccak256(&preimage)[..16]);
        if let Some(open) = self.sockets.get_mut(&id) {
            open.subscriptions
                .insert(sub.clone(), Subscription { kind, next });
        }
        Ok(json!(sub))
    }

    fn unsubscribe(&mut self, id: u64, params: &[Value]) -> Result<Value, RpcError> {
        let sub = param_str(params, 0)?;
        let removed = self
            .sockets
            .get_mut(&id)
            .and_then(|o| o.subscriptions.remove(sub));
        Ok(json!(removed.is_some()))
    }

    /// Forgets the sockets that closed, and with them their subscriptions.
    pub(crate) fn sweep(&mut self) {
        self.sockets.retain(|_, o| o.socket.is_alive());
    }

    /// Waits, at most `wait`, for what is queued on the sockets to be
    /// written, then closes them all.
    pub(crate) fn close_all(&mut self, wait: Duration) {
        let sockets = &self.sockets;
        wait_while(wait, || {
            sockets
                .values()
                .any(|o| o.socket.is_alive() && o.socket.queued() > 0)
        });
        for open in self.sockets.values() {
            open.socket.close();
        }
        self.sockets.clear();
    }

    /// Sends what the subscriptions announce since the last turn: the
    /// blocks executed since, at most [`BLOCKS_PER_TURN`] of them, and the
    /// pool's new transactions once [`PENDING_MS`] has passed since it was
    /// last looked at.
    pub(crate) fn notify(&mut self, rpc: &mut Rpc) {
        self.sweep();
        let subs = || self.sockets.values().flat_map(|o| o.subscriptions.values());
        let pending = subs().any(|s| matches!(s.kind, Kind::Pending));
        let first = subs()
            .filter(|s| !matches!(s.kind, Kind::Pending))
            .map(|s| s.next)
            .min();
        if !pending {
            self.pool = None;
        }
        if let Some(first) = first {
            self.blocks(rpc, first);
        }
        self.pending(rpc);
    }

    /// Announces the blocks from `first` to the head, at most
    /// [`BLOCKS_PER_TURN`] of them.
    fn blocks(&mut self, rpc: &mut Rpc, first: u64) {
        let Ok(head) = rpc.block_number() else { return };
        let last = head.min(first.saturating_add(BLOCKS_PER_TURN - 1));
        for height in first..=last {
            let due = |s: &&Subscription| s.next <= height;
            let subs = || self.sockets.values().flat_map(|o| o.subscriptions.values());
            let heads = subs().filter(due).any(|s| matches!(s.kind, Kind::Heads));
            let filters: Vec<Filter> = subs()
                .filter(due)
                .filter_map(|s| match &s.kind {
                    Kind::Logs(f) => Some(f.clone()),
                    _ => None,
                })
                .collect();
            let head = heads
                .then(|| rpc.head_json(height).ok().flatten())
                .flatten();
            let logs = if filters.is_empty() {
                Vec::new()
            } else {
                let keep = |log: &_| filters.iter().any(|f| f.matches(log));
                rpc.block_logs(height, &keep).unwrap_or_default()
            };
            for open in self.sockets.values_mut() {
                for (id, sub) in open
                    .subscriptions
                    .iter_mut()
                    .filter(|(_, s)| s.next <= height)
                {
                    sub.next = height + 1;
                    match &sub.kind {
                        Kind::Heads => {
                            if let Some(head) = &head {
                                open.socket.send(notification(id, head));
                            }
                        }
                        Kind::Logs(filter) => {
                            for (_, view) in logs.iter().filter(|(log, _)| filter.matches(log)) {
                                open.socket.send(notification(id, view));
                            }
                        }
                        Kind::Pending => {}
                    }
                }
            }
        }
    }

    /// Announces the transactions the pool holds that it did not when it
    /// was last looked at, once [`PENDING_MS`] has passed since.
    fn pending(&mut self, rpc: &Rpc) {
        let Some((seen, at)) = &self.pool else { return };
        if at.elapsed() < Duration::from_millis(PENDING_MS) {
            return;
        }
        let now = pool_hashes(rpc);
        let new: Vec<Value> = now.difference(seen).map(|h| json!(data(h))).collect();
        for open in self.sockets.values() {
            let pending = open
                .subscriptions
                .iter()
                .filter(|(_, s)| matches!(s.kind, Kind::Pending));
            for (id, _) in pending {
                for hash in &new {
                    open.socket.send(notification(id, hash));
                }
            }
        }
        self.pool = Some((now, Instant::now()));
    }
}
