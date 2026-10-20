//! The mempool (spec 14): per-sender queues ordered by nonce, the pending
//! (executable) and queued (gapped) split, replacement by price bump, limits
//! with eviction, and the block-ordered take.
//!
//! The pool is policy, not validity: the node admits a transaction only once
//! the kernel's `kernel_stf_validate_tx` accepts it against the sender's
//! account as it will be after what the pool holds ahead of it (spec 06
//! §5.1), and the kernel checks every transaction again when it executes a
//! block. This module holds no kernel; [`Node`](crate::Node) asks the kernel
//! and tells the pool.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BinaryHeap, HashMap, HashSet};
use std::fmt;

use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use solo_abi::chain::{Account, reason};
use solo_abi::types::{Ahead, ValidateResult};
use solo_host::hash::keccak256;

/// An account address.
pub type Address = [u8; 20];

/// Most transactions the pool holds ([`PoolLimits::max_txs`]).
pub const MAX_TXS: usize = 8192;
/// Most queued (not yet executable) transactions ([`PoolLimits::max_queued`]).
pub const MAX_QUEUED: usize = 1024;
/// Most transactions of one sender ([`PoolLimits::per_sender`]).
pub const PER_SENDER: usize = 256;
/// Most bytes of raw transactions the pool holds ([`PoolLimits::max_bytes`]).
pub const MAX_BYTES: usize = 64 << 20;
/// Most bytes of one raw transaction ([`PoolLimits::max_tx_bytes`]): geth's
/// `txMaxSize`, well under the reference driver's take of 1 MiB, so that
/// every pending transaction fits a block.
pub const MAX_TX_BYTES: usize = 128 << 10;
/// The least increase, in percent, of both fee fields that lets a transaction
/// replace one with the same sender and nonce: geth's default price bump.
pub const PRICE_BUMP: u128 = 10;

/// The pool's capacity (spec 14 §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolLimits {
    /// Most transactions in all.
    pub max_txs: usize,
    /// Most queued transactions.
    pub max_queued: usize,
    /// Most transactions of one sender.
    pub per_sender: usize,
    /// Most bytes of raw transactions in all.
    pub max_bytes: usize,
    /// Most bytes of one raw transaction.
    pub max_tx_bytes: usize,
}

impl Default for PoolLimits {
    fn default() -> PoolLimits {
        PoolLimits {
            max_txs: MAX_TXS,
            max_queued: MAX_QUEUED,
            per_sender: PER_SENDER,
            max_bytes: MAX_BYTES,
            max_tx_bytes: MAX_TX_BYTES,
        }
    }
}

/// Why the pool refused a transaction the kernel accepted. The texts are
/// geth's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoolError {
    /// The pool holds a transaction with the same sender and nonce, and this
    /// one does not raise both fee fields by [`PRICE_BUMP`] percent.
    Underpriced,
    /// The pool is at a limit and nothing cheaper can make room.
    Full,
    /// The raw transaction is longer than [`PoolLimits::max_tx_bytes`].
    Oversized,
    /// A replacement whose cost, with the sender's other pending
    /// transactions, exceeds the sender's balance.
    Overdraft,
}

impl fmt::Display for PoolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            PoolError::Underpriced => "replacement transaction underpriced",
            PoolError::Full => "txpool is full",
            PoolError::Oversized => "oversized data",
            PoolError::Overdraft => "insufficient funds for gas * price + value",
        })
    }
}

impl std::error::Error for PoolError {}

/// A transaction in the pool, with the fields the pool orders it by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolTx {
    /// `keccak256` of the raw bytes.
    pub hash: [u8; 32],
    /// Raw transaction.
    pub raw: Vec<u8>,
    /// Recovered sender.
    pub sender: Address,
    /// Nonce.
    pub nonce: u64,
    /// Most it pays per gas: the gas price, or the maximum fee per gas.
    pub fee_cap: u128,
    /// Most it tips per gas: the gas price, or the maximum priority fee.
    pub tip_cap: u128,
    /// Gas limit.
    pub gas: u64,
    /// Value plus the gas limit at the fee cap: the most it can cost.
    pub cost: u128,
    /// Ordering priority, as the kernel's validation reported it.
    pub priority: u64,
    /// Order of arrival, which breaks priority ties.
    arrival: u64,
    /// Whether it was handed out for gossip.
    announced: bool,
}

impl PoolTx {
    /// The pool's fields of a raw Ethereum transaction; `None` if it does not
    /// decode, its signature does not recover, or its cost overflows. The
    /// kernel says why such a transaction is invalid.
    #[must_use]
    pub fn parse(raw: &[u8]) -> Option<PoolTx> {
        let tx = solo_eth::decode(raw).ok()?;
        let sig = tx.signature();
        let signature = Signature::from_slice(&sig[..64]).ok()?;
        let id = RecoveryId::from_byte(sig[64])?;
        let digest = keccak256(&tx.signing_payload);
        let key = VerifyingKey::recover_from_prehash(&digest, &signature, id).ok()?;
        let point = key.to_encoded_point(false);
        let mut sender = [0u8; 20];
        sender.copy_from_slice(&keccak256(&point.as_bytes()[1..])[12..]);
        Some(PoolTx {
            hash: keccak256(raw),
            raw: raw.to_vec(),
            sender,
            nonce: tx.nonce,
            fee_cap: tx.gas_price,
            tip_cap: tx.priority_fee.unwrap_or(tx.gas_price),
            gas: tx.gas_limit,
            cost: tx.max_cost()?,
            priority: 0,
            arrival: 0,
            announced: false,
        })
    }

    /// Whether `self` may replace `old`: both fee fields at least
    /// [`PRICE_BUMP`] percent higher, rounding the threshold down as geth does.
    #[must_use]
    pub fn bumps(&self, old: &PoolTx) -> bool {
        // fee × (100 + bump) / 100, without the overflow of the product.
        let bump = |fee: u128| fee / 100 * PRICE_BUMP + fee % 100 * PRICE_BUMP / 100;
        let threshold = |fee: u128| fee.saturating_add(bump(fee));
        self.fee_cap >= threshold(old.fee_cap) && self.tip_cap >= threshold(old.tip_cap)
    }
}

/// The reason code of a validation result the pool could not use: the
/// kernel's, or [`reason::MALFORMED`] for a transaction the kernel accepts but
/// the pool cannot read.
#[must_use]
pub fn rejection(result: &ValidateResult) -> u32 {
    match result {
        ValidateResult::Invalid { reason } => *reason,
        ValidateResult::Valid { .. } => reason::MALFORMED,
    }
}

/// What an insertion did besides adding the transaction.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Inserted {
    /// The transaction it replaced, with the same sender and nonce.
    pub replaced: Option<[u8; 32]>,
    /// Queued transactions evicted to make room.
    pub evicted: Vec<[u8; 32]>,
    /// The sender's transaction dropped because the newcomer, filling a gap,
    /// made it pending without the balance to cover it.
    pub unfunded: Option<[u8; 32]>,
}

/// One sender's transactions, by nonce, and its account as of the last block.
#[derive(Debug, Clone)]
struct Queue {
    account: Account,
    txs: BTreeMap<u64, PoolTx>,
}

impl Queue {
    /// The nonce after the run of transactions contiguous from the account's.
    fn pending_end(&self) -> u64 {
        let mut next = self.account.nonce;
        while self.txs.contains_key(&next) {
            next += 1;
        }
        next
    }

    fn pending_len(&self) -> usize {
        self.txs
            .range(self.account.nonce..self.pending_end())
            .count()
    }

    fn is_pending(&self, nonce: u64) -> bool {
        (self.account.nonce..self.pending_end()).contains(&nonce)
    }

    /// The pending transactions, in nonce order.
    fn pending(&self) -> impl Iterator<Item = &PoolTx> {
        self.txs
            .range(self.account.nonce..self.pending_end())
            .map(|(_, tx)| tx)
    }

    /// The first pending transaction whose cost, with those before it,
    /// exceeds the balance.
    fn first_unfunded(&self) -> Option<&PoolTx> {
        let mut spent = 0u128;
        self.pending().find(|tx| {
            spent = spent.saturating_add(tx.cost);
            spent > self.account.balance
        })
    }
}

/// The mempool.
#[derive(Debug, Clone, Default)]
pub struct Mempool {
    queues: BTreeMap<Address, Queue>,
    index: HashMap<[u8; 32], (Address, u64)>,
    bytes: usize,
    arrivals: u64,
    /// Capacity; see [`PoolLimits`].
    pub limits: PoolLimits,
}

impl Mempool {
    /// An empty pool with these limits.
    #[must_use]
    pub fn new(limits: PoolLimits) -> Mempool {
        Mempool {
            limits,
            ..Mempool::default()
        }
    }

    /// Transactions held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.index.len()
    }

    /// Whether the pool is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.index.is_empty()
    }

    /// Bytes of raw transactions held.
    #[must_use]
    pub fn bytes(&self) -> usize {
        self.bytes
    }

    /// A transaction by hash.
    #[must_use]
    pub fn get(&self, hash: &[u8; 32]) -> Option<&PoolTx> {
        let (sender, nonce) = self.index.get(hash)?;
        self.queues.get(sender)?.txs.get(nonce)
    }

    /// Every transaction, by sender, then nonce.
    pub fn iter(&self) -> impl Iterator<Item = &PoolTx> {
        self.queues.values().flat_map(|q| q.txs.values())
    }

    /// Senders with transactions in the pool.
    #[must_use]
    pub fn senders(&self) -> Vec<Address> {
        self.queues.keys().copied().collect()
    }

    /// The account the pool holds for `sender`, as of the last block or its
    /// first transaction since.
    #[must_use]
    pub fn account(&self, sender: &Address) -> Option<&Account> {
        self.queues.get(sender).map(|q| &q.account)
    }

    /// The nonce `sender`'s next transaction would take once the pool's
    /// pending ones run; `None` without transactions in the pool.
    #[must_use]
    pub fn pending_nonce(&self, sender: &Address) -> Option<u64> {
        self.queues.get(sender).map(Queue::pending_end)
    }

    /// Whether `tx` is pending: its sender's transactions from the account
    /// nonce up to it are all in the pool.
    #[must_use]
    pub fn is_pending(&self, tx: &PoolTx) -> bool {
        self.queues
            .get(&tx.sender)
            .is_some_and(|q| q.is_pending(tx.nonce))
    }

    /// Pending and queued counts.
    #[must_use]
    pub fn status(&self) -> (usize, usize) {
        let pending = self.queues.values().map(Queue::pending_len).sum();
        (pending, self.len() - pending)
    }

    /// What the pool holds ahead of a transaction of `sender` with `nonce`,
    /// when the sender's account nonce is `state_nonce` (spec 06 §5.1): the
    /// nonces between, and the summed cost of the pool's transactions among
    /// them. Zero for a nonce at or below the account's.
    #[must_use]
    pub fn ahead(&self, sender: &Address, state_nonce: u64, nonce: u64) -> Ahead {
        if nonce <= state_nonce {
            return Ahead::default();
        }
        let reserved = self.queues.get(sender).map_or(0, |q| {
            q.txs
                .range(state_nonce..nonce)
                .fold(0u128, |sum, (_, tx)| sum.saturating_add(tx.cost))
        });
        Ahead {
            nonces: nonce - state_nonce,
            reserved,
        }
    }

    /// The checks of a newcomer that need no kernel (spec 14 §2): its size,
    /// and for a replacement the price bump and that the sender's pending
    /// transactions stay funded with it in place of the one it replaces
    /// (geth's overdraft check).
    ///
    /// # Errors
    /// [`PoolError::Oversized`], [`PoolError::Underpriced`] or
    /// [`PoolError::Overdraft`].
    pub fn check(&self, tx: &PoolTx) -> Result<(), PoolError> {
        if tx.raw.len() > self.limits.max_tx_bytes {
            return Err(PoolError::Oversized);
        }
        let Some(queue) = self.queues.get(&tx.sender) else {
            return Ok(());
        };
        let Some(old) = queue.txs.get(&tx.nonce) else {
            return Ok(());
        };
        if !tx.bumps(old) {
            return Err(PoolError::Underpriced);
        }
        let others = queue
            .pending()
            .filter(|t| t.nonce != tx.nonce)
            .fold(0u128, |sum, t| sum.saturating_add(t.cost));
        let overdrawn = others.saturating_add(tx.cost) > queue.account.balance;
        if queue.is_pending(tx.nonce) && overdrawn {
            return Err(PoolError::Overdraft);
        }
        Ok(())
    }

    /// Adds a transaction the kernel accepted. `account` is its sender's
    /// account as the node read it, used when the pool holds nothing of that
    /// sender yet. A transaction already held changes nothing.
    ///
    /// A newcomer that fills a gap makes the transactions behind it pending;
    /// the first of them its sender's balance cannot cover, with those
    /// before it, is dropped, and the rest are queued behind the new gap.
    ///
    /// # Errors
    /// See [`Mempool::check`]; [`PoolError::Full`] when a limit holds and no
    /// cheaper queued transaction can be evicted to make room.
    pub fn insert(&mut self, mut tx: PoolTx, account: Account) -> Result<Inserted, PoolError> {
        if self.index.contains_key(&tx.hash) {
            return Ok(Inserted::default());
        }
        self.check(&tx)?;
        let (sender, nonce, priority) = (tx.sender, tx.nonce, tx.priority);
        let held = self.queues.get(&sender).map(|q| &q.txs);
        let replacing = held.is_some_and(|txs| txs.contains_key(&nonce));
        if !replacing && held.map_or(0, BTreeMap::len) >= self.limits.per_sender {
            return Err(PoolError::Full);
        }
        tx.arrival = self.arrivals;
        self.arrivals += 1;
        self.queues.entry(sender).or_insert(Queue {
            account,
            txs: BTreeMap::new(),
        });
        let replaced = self.put(tx);
        if let Some(victims) = self.plan_eviction(&sender, nonce, priority) {
            for victim in &victims {
                self.remove(victim);
            }
            let unfunded = self.drop_unfunded_behind(&sender, nonce);
            return Ok(Inserted {
                replaced: replaced.map(|old| old.hash),
                evicted: victims,
                unfunded,
            });
        }
        match replaced {
            Some(old) => self.put(old),
            None => self.take_out(&sender, nonce),
        };
        Err(PoolError::Full)
    }

    /// Stores `tx` in its sender's queue, which exists, returning the one it
    /// displaced.
    fn put(&mut self, tx: PoolTx) -> Option<PoolTx> {
        let (sender, nonce, hash, len) = (tx.sender, tx.nonce, tx.hash, tx.raw.len());
        let queue = self.queues.get_mut(&sender)?;
        let old = queue.txs.insert(nonce, tx);
        if let Some(old) = &old {
            self.index.remove(&old.hash);
            self.bytes -= old.raw.len();
        }
        self.index.insert(hash, (sender, nonce));
        self.bytes += len;
        old
    }

    /// Removes the transaction of `sender` with `nonce`, and the sender's
    /// queue once empty.
    fn take_out(&mut self, sender: &Address, nonce: u64) -> Option<PoolTx> {
        let queue = self.queues.get_mut(sender)?;
        let tx = queue.txs.remove(&nonce)?;
        if queue.txs.is_empty() {
            self.queues.remove(sender);
        }
        self.index.remove(&tx.hash);
        self.bytes -= tx.raw.len();
        Some(tx)
    }

    /// The queued transactions to evict so that the pool, holding the
    /// transaction of `sender` with `nonce` just put in, is within its
    /// limits: the cheapest first, the latest among equals. A pending
    /// newcomer may evict any queued transaction, a queued one only cheaper
    /// ones. `None` if no such set exists.
    fn plan_eviction(&self, sender: &Address, nonce: u64, priority: u64) -> Option<Vec<[u8; 32]>> {
        let limits = self.limits;
        let (_, mut queued) = self.status();
        let (mut count, mut bytes) = (self.len(), self.bytes);
        let over = |count: usize, bytes: usize, queued: usize| {
            count > limits.max_txs || bytes > limits.max_bytes || queued > limits.max_queued
        };
        if !over(count, bytes, queued) {
            return Some(Vec::new());
        }
        let newcomer_pending = self.queues.get(sender)?.is_pending(nonce);
        let mut candidates: Vec<&PoolTx> = self
            .queues
            .values()
            .flat_map(|q| q.txs.values().filter(|tx| !q.is_pending(tx.nonce)))
            .filter(|tx| (tx.sender, tx.nonce) != (*sender, nonce))
            .filter(|tx| newcomer_pending || tx.priority < priority)
            .collect();
        candidates.sort_by_key(|tx| (tx.priority, Reverse(tx.arrival)));
        let mut victims = Vec::new();
        for tx in candidates {
            if !over(count, bytes, queued) {
                break;
            }
            count -= 1;
            bytes -= tx.raw.len();
            queued -= 1;
            victims.push(tx.hash);
        }
        (!over(count, bytes, queued)).then_some(victims)
    }

    /// Drops `sender`'s first unfunded pending transaction if its nonce is
    /// above `nonce`, the newcomer's.
    fn drop_unfunded_behind(&mut self, sender: &Address, nonce: u64) -> Option<[u8; 32]> {
        let behind = self.queues.get(sender)?.first_unfunded()?.nonce;
        (behind > nonce)
            .then(|| self.take_out(sender, behind))
            .flatten()
            .map(|tx| tx.hash)
    }

    /// Removes a transaction by hash. Its sender's later transactions stay,
    /// queued behind the gap.
    pub fn remove(&mut self, hash: &[u8; 32]) -> Option<PoolTx> {
        let (sender, nonce) = *self.index.get(hash)?;
        self.take_out(&sender, nonce)
    }

    /// Brings `sender`'s queue up to its account after a block (spec 14 §5):
    /// drops the transactions whose nonce the account has passed, the first
    /// pending one whose cost, with those before it, exceeds the balance,
    /// and every queued one that alone exceeds it. A sender whose code hash
    /// changed loses every transaction: the reference kernel's transactions
    /// cannot set code at a sender's address (it decodes no EIP-7702
    /// transaction), so the kernel accepted them for an account in a state
    /// that cannot recur. Returns the hashes dropped.
    pub fn reset(&mut self, sender: &Address, account: Account) -> Vec<[u8; 32]> {
        let Some(queue) = self.queues.get_mut(sender) else {
            return Vec::new();
        };
        if queue.account == account {
            return Vec::new();
        }
        let code_changed = queue.account.code_hash != account.code_hash;
        queue.account = account;
        let pending_end = queue.pending_end();
        let mut spent = 0u128;
        let mut unfunded = false;
        let mut drop = Vec::new();
        let balance = queue.account.balance;
        for tx in queue.txs.values() {
            let stale = tx.nonce < queue.account.nonce;
            // Behind an unfunded transaction, the rest wait as queued ones do.
            let pending = !unfunded && !stale && tx.nonce < pending_end;
            spent = spent.saturating_add(if pending { tx.cost } else { 0 });
            let over = if pending { spent } else { tx.cost } > balance;
            unfunded |= pending && over;
            if code_changed || stale || over {
                drop.push(tx.nonce);
            }
        }
        drop.iter()
            .filter_map(|nonce| self.take_out(sender, *nonce))
            .map(|tx| tx.hash)
            .collect()
    }

    /// `sender`'s pending transactions not yet handed out for gossip, marked
    /// as handed out: only executable transactions travel (spec 14 §6).
    pub fn announce(&mut self, sender: &Address) -> Vec<Vec<u8>> {
        let Some(queue) = self.queues.get_mut(sender) else {
            return Vec::new();
        };
        let end = queue.pending_end();
        queue
            .txs
            .range_mut(queue.account.nonce..end)
            .filter(|(_, tx)| !tx.announced)
            .map(|(_, tx)| {
                tx.announced = true;
                tx.raw.clone()
            })
            .collect()
    }

    /// Pending transactions in an order a block can execute, within
    /// `max_bytes` and `max_gas` (spec 14 §3): each sender's by nonce, the
    /// senders interleaved by priority, then arrival. A sender whose next
    /// transaction does not fit, or whose balance would not cover it after
    /// the ones before it, contributes nothing more. A transaction in `skip`
    /// counts as already taken: it is left out and uses none of the budget,
    /// but its cost counts against its sender's balance and the sender's
    /// later transactions may follow it. The pool keeps what it hands out
    /// until a block includes it.
    #[must_use]
    pub fn take(&self, max_bytes: usize, max_gas: u64, skip: &[[u8; 32]]) -> Vec<Vec<u8>> {
        let skip: HashSet<&[u8; 32]> = skip.iter().collect();
        let runs: Vec<(Vec<&PoolTx>, u128)> = self
            .queues
            .values()
            .map(|q| {
                let run = q.txs.range(q.account.nonce..q.pending_end());
                (run.map(|(_, tx)| tx).collect(), q.account.balance)
            })
            .collect();
        let mut heap = BinaryHeap::new();
        let push = |heap: &mut BinaryHeap<_>, run: usize, at: usize| {
            if let Some(tx) = runs[run].0.get(at) {
                heap.push((tx.priority, Reverse(tx.arrival), run, at));
            }
        };
        for run in 0..runs.len() {
            push(&mut heap, run, 0);
        }
        let mut spent = vec![0u128; runs.len()];
        let (mut bytes, mut gas) = (0usize, 0u64);
        let mut taken = Vec::new();
        while let Some((_, _, run, at)) = heap.pop() {
            let tx = runs[run].0[at];
            let cost = spent[run].saturating_add(tx.cost);
            let skipped = skip.contains(&tx.hash);
            let (len, used) = if skipped {
                (0, 0)
            } else {
                (tx.raw.len(), tx.gas)
            };
            if bytes + len > max_bytes || gas + used > max_gas || cost > runs[run].1 {
                continue;
            }
            bytes += len;
            gas += used;
            spent[run] = cost;
            if !skipped {
                taken.push(tx.raw.clone());
            }
            push(&mut heap, run, at + 1);
        }
        taken
    }
}

#[cfg(test)]
mod tests;
