//! The load: value transfers between the soak's accounts and calls to a
//! counter contract it deploys, sent to random live nodes, each
//! transaction followed until a finalized block carries it. A transaction
//! a node accepted must reach a block or still sit in a live node's pool
//! (spec 14: nothing drops a transaction that stays valid and affordable);
//! one gone from every pool is excused only when a node restarted since
//! it was accepted (a pool lives in memory), and is sent again.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use k256::ecdsa::SigningKey;
use serde_json::json;
use solo_fuzz::Rng;
use solo_host::hash::keccak256;
use solo_rlp::{encode_bytes, encode_list, encode_uint};

use crate::rpc::{self, Fail};
use crate::world::{Mode, Shared};

/// The gas price of every load transaction: far above the base fee floor
/// (1 gwei), so a base fee the load pushes up never strands one.
pub const GAS_PRICE: u128 = 50_000_000_000;

/// Transactions a sender keeps in flight.
const IN_FLIGHT: usize = 4;

/// How old a sender's oldest open transaction may get on a live network
/// before the pools are searched for it.
const LOOK_AFTER: Duration = Duration::from_secs(45);

/// How long a transaction may sit in a live node's pool, on a network that
/// has been live all that time, before it counts as stuck.
const STUCK_AFTER: Duration = Duration::from_secs(150);

/// The counter contract's runtime: `sstore(0, sload(0) + 1)`.
const RUNTIME: [u8; 10] = [0x60, 0x01, 0x60, 0x00, 0x54, 0x01, 0x60, 0x00, 0x55, 0x00];

/// Its init code: copies the runtime and returns it.
fn init_code() -> Vec<u8> {
    let mut code = vec![
        0x60, 10, 0x60, 12, 0x60, 0x00, 0x39, 0x60, 10, 0x60, 0x00, 0xf3,
    ];
    code.extend_from_slice(&RUNTIME);
    code
}

/// A legacy EIP-155 transaction; `to` none creates a contract.
#[allow(clippy::too_many_arguments)]
pub fn legacy(
    key: &SigningKey,
    chain_id: u64,
    nonce: u64,
    gas_price: u128,
    gas: u64,
    to: Option<[u8; 20]>,
    value: u128,
    data: &[u8],
) -> Vec<u8> {
    let fields = |out: &mut Vec<u8>| {
        encode_uint(u128::from(nonce), out);
        encode_uint(gas_price, out);
        encode_uint(u128::from(gas), out);
        encode_bytes(to.as_ref().map_or(&[][..], |t| &t[..]), out);
        encode_uint(value, out);
        encode_bytes(data, out);
    };
    let mut unsigned = Vec::new();
    fields(&mut unsigned);
    encode_uint(u128::from(chain_id), &mut unsigned);
    encode_uint(0, &mut unsigned);
    encode_uint(0, &mut unsigned);
    let mut list = Vec::new();
    encode_list(&unsigned, &mut list);
    let sig = solo_node::sign_recoverable(key, &keccak256(&list)).unwrap();
    let strip = |b: &[u8]| b[b.iter().take_while(|x| **x == 0).count()..].to_vec();
    let mut signed = Vec::new();
    fields(&mut signed);
    encode_uint(
        u128::from(chain_id) * 2 + 35 + u128::from(sig[64]),
        &mut signed,
    );
    encode_bytes(&strip(&sig[..32]), &mut signed);
    encode_bytes(&strip(&sig[32..64]), &mut signed);
    let mut out = Vec::new();
    encode_list(&signed, &mut out);
    out
}

pub fn address(key: &SigningKey) -> [u8; 20] {
    solo_cli::client::address(key)
}

/// The soak's load accounts.
pub fn keys(seed: u64, n: usize) -> Vec<SigningKey> {
    (0..n as u64)
        .map(|i| {
            let d = keccak256(
                &[
                    b"soak load".as_slice(),
                    &seed.to_be_bytes(),
                    &i.to_be_bytes(),
                ]
                .concat(),
            );
            SigningKey::from_slice(&d).unwrap()
        })
        .collect()
}

/// The addresses transfers go to; nobody holds their keys.
pub fn recipients(seed: u64, n: usize) -> Vec<[u8; 20]> {
    (0..n as u64)
        .map(|i| {
            let d =
                keccak256(&[b"soak to".as_slice(), &seed.to_be_bytes(), &i.to_be_bytes()].concat());
            d[12..].try_into().unwrap()
        })
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Deploy,
    Transfer,
    Call,
}

struct Tx {
    nonce: u64,
    hash: String,
    raw: String,
    kind: Kind,
    /// When a node first accepted it.
    accepted: Option<Instant>,
    /// When the pools last held it, as far as the soak looked.
    held_since: Option<Instant>,
}

struct Sender {
    key: SigningKey,
    address: String,
    next: u64,
    open: VecDeque<Tx>,
}

/// What the load did, for the summary.
#[derive(Debug, Default, Clone)]
pub struct Stats {
    pub sent: u64,
    pub included: u64,
    pub failed: u64,
    pub lost: u64,
    pub refused: u64,
    pub retried: u64,
}

pub struct Load {
    world: Shared,
    chain_id: u64,
    senders: Vec<Sender>,
    to: Vec<[u8; 20]>,
    rng: Rng,
    pub stats: Stats,
    last_look: Instant,
}

fn h256(raw: &[u8]) -> String {
    rpc::hex(&keccak256(raw))
}

impl Load {
    pub fn new(
        world: Shared,
        chain_id: u64,
        keys: Vec<SigningKey>,
        to: Vec<[u8; 20]>,
        seed: u64,
    ) -> Load {
        let senders = keys
            .into_iter()
            .map(|key| Sender {
                address: rpc::hex(&address(&key)),
                key,
                next: 0,
                open: VecDeque::new(),
            })
            .collect();
        Load {
            world,
            chain_id,
            senders,
            to,
            rng: Rng::new(seed ^ 0x10ad),
            stats: Stats::default(),
            last_look: Instant::now(),
        }
    }

    /// The live nodes' RPC addresses that have run a while.
    fn targets(&self) -> Vec<(usize, String)> {
        let w = self.world.lock().unwrap();
        w.members
            .iter()
            .filter(|m| m.live() && m.started.elapsed() > Duration::from_secs(3))
            .map(|m| (m.id, m.rpc.clone()))
            .collect()
    }

    /// One turn: retires what was included, sends what is due, looks
    /// after old transactions. `generate` adds new transactions.
    pub fn turn(&mut self, generate: bool) {
        self.settle();
        let targets = self.targets();
        if targets.is_empty() {
            return;
        }
        if generate {
            self.generate();
        }
        // Send everything not yet accepted anywhere, to one node each.
        for s in 0..self.senders.len() {
            for t in 0..self.senders[s].open.len() {
                if self.senders[s].open[t].accepted.is_some() {
                    continue;
                }
                let (_, rpc_addr) = self.rng.pick(&targets).clone();
                self.submit(s, t, &rpc_addr);
            }
        }
        if self.last_look.elapsed() > Duration::from_secs(5) {
            self.last_look = Instant::now();
            self.look_after(&targets);
        }
    }

    /// Drops the transactions a scanned block carries.
    fn settle(&mut self) {
        let mut w = self.world.lock().unwrap();
        for s in &mut self.senders {
            while let Some(tx) = s.open.front() {
                let Some(&(height, ok)) = w.chain.included.get(&tx.hash) else {
                    break;
                };
                let tx = s.open.pop_front().unwrap();
                self.stats.included += 1;
                if !ok {
                    self.stats.failed += 1;
                    let what = format!(
                        "{:?} {} of {} (nonce {}) failed in block {height}",
                        tx.kind, tx.hash, s.address, tx.nonce
                    );
                    w.violate(what);
                }
            }
        }
    }

    fn generate(&mut self) {
        let counter = self.world.lock().unwrap().counter.clone();
        for _ in 0..2 {
            let s = self.rng.index(self.senders.len());
            if self.senders[s].open.len() >= IN_FLIGHT {
                continue;
            }
            let sender = &mut self.senders[s];
            // The first sender's first transaction deploys the counter;
            // calls follow once a block carries it.
            let (kind, to, value, data, gas) = if s == 0 && sender.next == 0 {
                (Kind::Deploy, None, 0, init_code(), 200_000)
            } else if let Some(c) = counter.as_ref().filter(|_| self.rng.chance(1, 3)) {
                let c: [u8; 20] = solo_rpc::methods::parse_hex(c).unwrap().try_into().unwrap();
                (Kind::Call, Some(c), 0, Vec::new(), 100_000)
            } else {
                let to = *self.rng.pick(&self.to);
                let value = u128::from(1 + self.rng.below(1_000_000)) * 1_000_000_000;
                (Kind::Transfer, Some(to), value, Vec::new(), 21_000)
            };
            let raw = legacy(
                &sender.key,
                self.chain_id,
                sender.next,
                GAS_PRICE,
                gas,
                to,
                value,
                &data,
            );
            sender.open.push_back(Tx {
                nonce: sender.next,
                hash: h256(&raw),
                raw: rpc::hex(&raw),
                kind,
                accepted: None,
                held_since: None,
            });
            sender.next += 1;
        }
    }

    fn submit(&mut self, s: usize, t: usize, rpc_addr: &str) {
        let raw = self.senders[s].open[t].raw.clone();
        let hash = self.senders[s].open[t].hash.clone();
        match rpc::call(
            rpc_addr,
            "eth_sendRawTransaction",
            &json!([raw]),
            Duration::from_secs(10),
        ) {
            Ok(v) => {
                if v.as_str() != Some(hash.as_str()) {
                    self.world
                        .lock()
                        .unwrap()
                        .violate(format!("{rpc_addr} answered {v} for transaction {hash}"));
                }
                let tx = &mut self.senders[s].open[t];
                tx.accepted = Some(Instant::now());
                self.stats.sent += 1;
            }
            // Down, frozen, still starting: another node next turn.
            Err(Fail::Transport(_)) => {}
            Err(Fail::Node(e)) => {
                self.stats.refused += 1;
                let tx = &self.senders[s].open[t];
                if e.contains("txpool is full") {
                    self.world
                        .lock()
                        .unwrap()
                        .warn(format!("{rpc_addr}: txpool is full"));
                } else if e.contains("nonce too low") {
                    // Included already; the scanner will see it. A nonce
                    // the soak never sent cannot be too low otherwise.
                    let w = &mut self.world.lock().unwrap();
                    if !w.chain.included.contains_key(&tx.hash) {
                        w.warn(format!(
                            "{rpc_addr} says nonce too low for {} (nonce {}) before a scanned block carries it",
                            tx.hash, tx.nonce
                        ));
                    }
                    let tx = &mut self.senders[s].open[t];
                    tx.accepted.get_or_insert_with(Instant::now);
                } else {
                    self.world.lock().unwrap().violate(format!(
                        "{rpc_addr} refused {:?} {} (nonce {}): {e}",
                        tx.kind, tx.hash, tx.nonce
                    ));
                    let tx = &mut self.senders[s].open[t];
                    tx.accepted.get_or_insert_with(Instant::now);
                }
            }
        }
    }

    /// Looks for every sender's oldest open transaction in the pools once
    /// it is old on a live network.
    fn look_after(&mut self, targets: &[(usize, String)]) {
        let (live_for, last_restart) = {
            let w = self.world.lock().unwrap();
            let live_for = if w.mode == Mode::Live {
                w.since.elapsed().min(w.last_heal.elapsed())
            } else {
                Duration::ZERO
            };
            (live_for, w.last_restart)
        };
        if live_for < Duration::from_secs(20) {
            for s in &mut self.senders {
                for t in &mut s.open {
                    t.held_since = None;
                }
            }
            return;
        }
        for s in 0..self.senders.len() {
            let Some(head) = self.senders[s].open.front() else {
                continue;
            };
            let Some(accepted) = head.accepted else {
                continue;
            };
            if accepted.elapsed() < LOOK_AFTER {
                continue;
            }
            let hash = head.hash.clone();
            let mut holders = Vec::new();
            let mut answered = 0;
            let mut in_block = false;
            for (id, rpc_addr) in targets {
                match rpc::call(
                    rpc_addr,
                    "eth_getTransactionByHash",
                    &json!([hash]),
                    Duration::from_secs(10),
                ) {
                    Ok(v) if v.is_null() => answered += 1,
                    Ok(v) => {
                        answered += 1;
                        if v["blockNumber"].is_null() {
                            holders.push(*id);
                        } else {
                            in_block = true;
                        }
                    }
                    Err(_) => {}
                }
            }
            if in_block || answered == 0 {
                continue;
            }
            let labels: Vec<String> = {
                let w = self.world.lock().unwrap();
                holders
                    .iter()
                    .map(|id| w.members[*id].label.clone())
                    .collect()
            };
            let sender = &mut self.senders[s];
            if holders.is_empty() {
                // Gone from every pool: lost with a restarted node's pool,
                // or dropped, which nothing should do to it.
                let excused = last_restart.is_some_and(|r| r > accepted);
                let mut w = self.world.lock().unwrap();
                if excused {
                    w.log(format!(
                        "transactions of {} from nonce {} lost with a restart; sent again",
                        sender.address, sender.open[0].nonce
                    ));
                } else {
                    w.violate(format!(
                        "transaction {hash} of {} (nonce {}) accepted {:.0}s ago is in no pool and no block, and no node restarted since",
                        sender.address,
                        sender.open[0].nonce,
                        accepted.elapsed().as_secs_f64()
                    ));
                }
                drop(w);
                self.stats.lost += 1;
                for t in &mut sender.open {
                    t.accepted = None;
                    t.held_since = None;
                }
                self.stats.retried += 1;
            } else {
                let head = &mut sender.open[0];
                let since = *head.held_since.get_or_insert_with(Instant::now);
                if since.elapsed() > STUCK_AFTER {
                    self.world.lock().unwrap().violate(format!(
                        "transaction {hash} of {} (nonce {}) has sat in the pool of {} for {:.0}s on a live network without reaching a block",
                        sender.address,
                        head.nonce,
                        labels.join(", "),
                        since.elapsed().as_secs_f64()
                    ));
                }
            }
        }
    }

    /// Transactions not yet in a scanned block.
    pub fn open(&self) -> usize {
        self.senders.iter().map(|s| s.open.len()).sum()
    }

    /// The oldest open transactions, for a report.
    pub fn describe_open(&self) -> String {
        self.senders
            .iter()
            .filter_map(|s| {
                s.open.front().map(|t| {
                    format!(
                        "{} nonce {} {} {:?}, accepted {:?} s ago",
                        s.address,
                        t.nonce,
                        t.hash,
                        t.kind,
                        t.accepted.map(|a| a.elapsed().as_secs())
                    )
                })
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}
