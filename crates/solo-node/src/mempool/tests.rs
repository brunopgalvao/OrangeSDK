//! The pool's state machine on its own: pending and queued, promotion,
//! replacement, limits and eviction, the block-ordered take, the reset after
//! a block, and invariants under random operations.

use super::*;
use proptest::prelude::*;

const GAS: u64 = 21_000;

/// A pool transaction of sender `[sender; 20]` paying `fee` on both fee
/// fields, `size` raw bytes long.
fn sized(sender: u8, nonce: u64, fee: u128, size: usize) -> PoolTx {
    let mut raw = vec![sender];
    raw.extend_from_slice(&nonce.to_le_bytes());
    raw.extend_from_slice(&fee.to_le_bytes());
    raw.resize(raw.len().max(size), 0xAA);
    PoolTx {
        hash: keccak256(&raw),
        raw,
        sender: [sender; 20],
        nonce,
        fee_cap: fee,
        tip_cap: fee,
        gas: GAS,
        cost: u128::from(GAS).saturating_mul(fee),
        authorities: Vec::new(),
        priority: u64::try_from(fee).unwrap_or(u64::MAX),
        arrival: 0,
        announced: false,
    }
}

fn tx(sender: u8, nonce: u64, fee: u128) -> PoolTx {
    sized(sender, nonce, fee, 0)
}

fn rich(nonce: u64) -> Account {
    Account {
        nonce,
        balance: u128::MAX,
        code_hash: [0; 32],
    }
}

fn funded(nonce: u64, balance: u128) -> Account {
    Account {
        nonce,
        balance,
        code_hash: [0; 32],
    }
}

fn add(pool: &mut Mempool, tx: &PoolTx) -> Result<Inserted, PoolError> {
    pool.insert(tx.clone(), rich(0))
}

fn nonces(pool: &Mempool, raws: &[Vec<u8>]) -> Vec<(u8, u64)> {
    raws.iter()
        .map(|raw| {
            let tx = pool.get(&keccak256(raw)).unwrap();
            (tx.sender[0], tx.nonce)
        })
        .collect()
}

#[test]
fn defaults_and_texts() {
    let limits = PoolLimits::default();
    assert_eq!(
        (
            limits.max_txs,
            limits.max_queued,
            limits.per_sender,
            limits.max_bytes,
            limits.max_tx_bytes
        ),
        (MAX_TXS, MAX_QUEUED, PER_SENDER, MAX_BYTES, 131_072)
    );
    assert_eq!(Mempool::new(limits).limits, limits);
    assert_eq!(
        PoolError::Underpriced.to_string(),
        "replacement transaction underpriced"
    );
    assert_eq!(PoolError::Full.to_string(), "txpool is full");
    assert_eq!(PoolError::Oversized.to_string(), "oversized data");
    assert_eq!(
        PoolError::Overdraft.to_string(),
        "insufficient funds for gas * price + value"
    );
    assert_eq!(
        PoolError::InflightLimit.to_string(),
        "in-flight transaction limit reached for delegated accounts"
    );
    assert_eq!(
        PoolError::AuthorityReserved.to_string(),
        "authority already reserved"
    );
    let invalid = ValidateResult::Invalid { reason: 4 };
    assert_eq!(rejection(&invalid), 4);
    let valid = ValidateResult::Valid {
        priority: 1,
        reserved_fee: 2,
    };
    assert_eq!(rejection(&valid), reason::MALFORMED);
}

#[test]
fn gaps_queue_and_fills_promote() {
    let mut pool = Mempool::default();
    assert!(pool.is_empty());
    assert_eq!(pool.pending_nonce(&[1; 20]), None);
    assert!(pool.announce(&[1; 20]).is_empty());
    let (t0, t1, t2) = (tx(1, 0, 5), tx(1, 1, 5), tx(1, 2, 5));
    add(&mut pool, &t0).unwrap();
    assert_eq!(pool.announce(&[1; 20]), vec![t0.raw.clone()]);
    add(&mut pool, &t2).unwrap();
    assert_eq!(
        (pool.status(), pool.pending_nonce(&[1; 20])),
        ((1, 1), Some(1))
    );
    assert!(pool.is_pending(&t0) && !pool.is_pending(&t2));
    assert!(pool.announce(&[1; 20]).is_empty(), "queued stays local");
    add(&mut pool, &t1).unwrap();
    assert_eq!(
        (pool.status(), pool.pending_nonce(&[1; 20])),
        ((3, 0), Some(3))
    );
    assert_eq!(
        pool.announce(&[1; 20]),
        vec![t1.raw.clone(), t2.raw.clone()]
    );
    assert!(pool.announce(&[1; 20]).is_empty());
    assert_eq!(pool.len(), 3);
    assert_eq!(pool.bytes(), 3 * t0.raw.len());
    assert_eq!(pool.senders(), vec![[1; 20]]);
    assert_eq!(pool.account(&[1; 20]), Some(&rich(0)));
    assert_eq!(pool.iter().map(|t| t.nonce).collect::<Vec<_>>(), [0, 1, 2]);
    assert!(!pool.is_pending(&tx(9, 0, 1)), "unknown sender");
    // Holding a transaction already is not an error and changes nothing.
    assert_eq!(add(&mut pool, &t1), Ok(Inserted::default()));
    assert_eq!(pool.len(), 3);
    // Removing the middle one demotes the one behind it.
    assert_eq!(pool.remove(&t1.hash).map(|t| t.nonce), Some(1));
    assert_eq!(pool.remove(&t1.hash), None);
    assert_eq!(pool.status(), (1, 1));
    pool.remove(&t0.hash);
    pool.remove(&t2.hash);
    assert!(pool.is_empty() && pool.senders().is_empty());
    assert_eq!(pool.bytes(), 0);
    assert_eq!(pool.get(&t0.hash), None);
}

#[test]
fn ahead_sums_the_pools_earlier_costs() {
    let mut pool = Mempool::default();
    let (t0, t2) = (tx(1, 0, 3), tx(1, 2, 7));
    add(&mut pool, &t0).unwrap();
    add(&mut pool, &t2).unwrap();
    let ahead = |nonces, reserved| Ahead { nonces, reserved };
    assert_eq!(pool.ahead(&[1; 20], 0, 0), Ahead::default());
    assert_eq!(pool.ahead(&[1; 20], 4, 2), Ahead::default());
    assert_eq!(pool.ahead(&[1; 20], 0, 1), ahead(1, t0.cost));
    assert_eq!(pool.ahead(&[1; 20], 0, 3), ahead(3, t0.cost + t2.cost));
    assert_eq!(pool.ahead(&[2; 20], 3, 5), ahead(2, 0));
    // The sum saturates rather than wraps.
    let mut huge = tx(3, 0, 1);
    huge.cost = u128::MAX;
    add(&mut pool, &huge).unwrap();
    add(&mut pool, &tx(3, 1, 1)).unwrap();
    assert_eq!(pool.ahead(&[3; 20], 0, 2).reserved, u128::MAX);
}

#[test]
fn replacement_needs_a_ten_percent_bump_on_both_fees() {
    let mut pool = Mempool::default();
    let old = tx(1, 0, 100);
    add(&mut pool, &old).unwrap();
    pool.announce(&[1; 20]);
    for (fee_cap, tip_cap) in [(109, 110), (110, 109), (300, 100)] {
        let mut new = tx(1, 0, fee_cap);
        new.tip_cap = tip_cap;
        assert_eq!(pool.check(&new), Err(PoolError::Underpriced));
        assert_eq!(add(&mut pool, &new), Err(PoolError::Underpriced));
    }
    let new = tx(1, 0, 110);
    let inserted = add(&mut pool, &new).unwrap();
    assert_eq!(inserted.replaced, Some(old.hash));
    assert!(inserted.evicted.is_empty());
    assert_eq!(pool.len(), 1);
    assert_eq!(pool.get(&old.hash), None);
    assert_eq!(pool.get(&new.hash).unwrap().fee_cap, 110);
    assert_eq!(
        pool.announce(&[1; 20]),
        vec![new.raw.clone()],
        "the replacement travels"
    );
    // geth rounds the threshold down: 15 needs 16, not 16.5.
    assert!(tx(1, 0, 16).bumps(&tx(1, 0, 15)));
    assert!(!tx(1, 0, 15).bumps(&tx(1, 0, 15)));
    // At the top of the range the threshold saturates.
    assert!(tx(1, 0, u128::MAX).bumps(&tx(1, 0, u128::MAX)));
}

#[test]
fn per_sender_limit() {
    let mut pool = Mempool::new(PoolLimits {
        per_sender: 2,
        ..PoolLimits::default()
    });
    add(&mut pool, &tx(1, 0, 1)).unwrap();
    add(&mut pool, &tx(1, 1, 1)).unwrap();
    assert_eq!(add(&mut pool, &tx(1, 2, 1)), Err(PoolError::Full));
    assert!(add(&mut pool, &tx(1, 1, 2)).unwrap().replaced.is_some());
    add(&mut pool, &tx(2, 0, 1)).unwrap();
    assert_eq!(pool.len(), 3);
}

#[test]
fn a_full_pool_evicts_its_cheapest_queued_transactions() {
    let mut pool = Mempool::new(PoolLimits {
        max_txs: 3,
        ..PoolLimits::default()
    });
    let (pending, cheap, dear) = (tx(1, 0, 1), tx(2, 5, 10), tx(3, 5, 20));
    for t in [&pending, &cheap, &dear] {
        add(&mut pool, t).unwrap();
    }
    // A pending newcomer evicts the cheapest queued one, whatever it pays.
    let newcomer = tx(4, 0, 1);
    assert_eq!(add(&mut pool, &newcomer).unwrap().evicted, vec![cheap.hash]);
    // A queued newcomer evicts only a cheaper queued one.
    assert_eq!(add(&mut pool, &tx(5, 5, 15)), Err(PoolError::Full));
    assert_eq!(pool.len(), 3);
    assert_eq!(pool.senders(), vec![[1; 20], [3; 20], [4; 20]]);
    let richer = tx(5, 5, 30);
    assert_eq!(add(&mut pool, &richer).unwrap().evicted, vec![dear.hash]);
    // With nothing queued left to evict but the newcomer's own slot, a
    // pending newcomer is refused too.
    pool.remove(&richer.hash);
    add(&mut pool, &tx(6, 0, 1)).unwrap();
    assert_eq!(add(&mut pool, &tx(7, 0, 100)), Err(PoolError::Full));
    // Among equals the latest goes first.
    let mut pool = Mempool::new(PoolLimits {
        max_txs: 2,
        ..PoolLimits::default()
    });
    let (first, second) = (tx(1, 3, 5), tx(2, 3, 5));
    add(&mut pool, &first).unwrap();
    add(&mut pool, &second).unwrap();
    assert_eq!(
        add(&mut pool, &tx(3, 0, 1)).unwrap().evicted,
        vec![second.hash]
    );
}

#[test]
fn a_refused_replacement_restores_the_original() {
    let mut pool = Mempool::new(PoolLimits {
        max_bytes: 100,
        ..PoolLimits::default()
    });
    let old = sized(1, 0, 10, 60);
    add(&mut pool, &old).unwrap();
    let bigger = sized(1, 0, 20, 101);
    assert_eq!(add(&mut pool, &bigger), Err(PoolError::Full));
    assert_eq!(pool.get(&old.hash), Some(&old));
    assert_eq!(pool.bytes(), 60);
    assert_eq!(pool.len(), 1);
}

#[test]
fn queued_limit() {
    let mut pool = Mempool::new(PoolLimits {
        max_queued: 1,
        ..PoolLimits::default()
    });
    let queued = tx(1, 3, 5);
    add(&mut pool, &queued).unwrap();
    assert_eq!(add(&mut pool, &tx(2, 3, 1)), Err(PoolError::Full));
    assert_eq!(
        add(&mut pool, &tx(2, 3, 9)).unwrap().evicted,
        vec![queued.hash]
    );
    // Pending transactions do not count against it.
    add(&mut pool, &tx(3, 0, 1)).unwrap();
    assert_eq!(pool.status(), (1, 1));
}

#[test]
fn take_orders_by_nonce_within_and_priority_across_senders() {
    let mut pool = Mempool::default();
    let txs = [
        tx(1, 0, 1),
        tx(1, 1, 100),
        tx(2, 0, 50),
        tx(3, 1, 1000),
        tx(4, 0, 50),
    ];
    for t in &txs {
        add(&mut pool, t).unwrap();
    }
    let all = pool.take(usize::MAX, u64::MAX, &[], 0);
    // Sender 3 is queued; 2 and 4 tie and go in arrival order; 1's second
    // transaction, the dearest, waits for its first, the cheapest.
    assert_eq!(nonces(&pool, &all), [(2, 0), (4, 0), (1, 0), (1, 1)]);
    assert_eq!(pool.len(), 5, "taking keeps them");
    // Gas: two transactions' worth.
    let two = pool.take(usize::MAX, 2 * GAS, &[], 0);
    assert_eq!(nonces(&pool, &two), [(2, 0), (4, 0)]);
    // Bytes: a sender whose next transaction does not fit drops out, the
    // others continue.
    let len = txs[0].raw.len();
    let mut pool = Mempool::default();
    add(&mut pool, &sized(1, 0, 9, 3 * len)).unwrap();
    add(&mut pool, &tx(2, 0, 1)).unwrap();
    add(&mut pool, &tx(2, 1, 1)).unwrap();
    assert_eq!(
        nonces(&pool, &pool.take(2 * len, u64::MAX, &[], 0)),
        [(2, 0), (2, 1)]
    );
    assert!(pool.take(0, u64::MAX, &[], 0).is_empty());
}

#[test]
fn take_stops_a_sender_its_balance_cannot_cover() {
    let mut pool = Mempool::default();
    let t0 = tx(1, 0, 10);
    pool.insert(t0.clone(), funded(0, t0.cost + t0.cost / 2))
        .unwrap();
    pool.insert(tx(1, 1, 10), rich(0)).unwrap();
    pool.insert(tx(2, 0, 1), rich(0)).unwrap();
    assert_eq!(
        nonces(&pool, &pool.take(usize::MAX, u64::MAX, &[], 0)),
        [(1, 0), (2, 0)]
    );
}

#[test]
fn take_skips_what_an_unexecuted_block_carries() {
    let mut pool = Mempool::default();
    let (a0, a1, b0) = (tx(1, 0, 30), tx(1, 1, 20), tx(2, 0, 10));
    for t in [&a0, &a1, &b0] {
        add(&mut pool, t).unwrap();
    }
    // One transaction's budget: without the skip it goes to a0 again.
    assert_eq!(nonces(&pool, &pool.take(usize::MAX, GAS, &[], 0)), [(1, 0)]);
    assert_eq!(
        nonces(&pool, &pool.take(usize::MAX, GAS, &[a0.hash], 0)),
        [(1, 1)]
    );
    assert_eq!(
        nonces(
            &pool,
            &pool.take(usize::MAX, 2 * GAS, &[a0.hash, a1.hash], 0)
        ),
        [(2, 0)]
    );
    // A skipped transaction still spends its sender's balance.
    let mut pool = Mempool::default();
    pool.insert(a0.clone(), funded(0, a0.cost + a1.cost - 1))
        .unwrap();
    pool.insert(a1.clone(), rich(0)).unwrap();
    assert!(pool.take(usize::MAX, u64::MAX, &[a0.hash], 0).is_empty());
}

#[test]
fn take_leaves_out_senders_priced_below_the_base_fee() {
    let mut pool = Mempool::default();
    let (a0, a1, b0, c0) = (tx(1, 0, 5), tx(1, 1, 50), tx(2, 0, 10), tx(3, 0, 20));
    for t in [&a0, &a1, &b0, &c0] {
        add(&mut pool, t).unwrap();
    }
    // Under a base fee of 10, sender 1's first transaction cannot run, so its
    // dearer second one waits behind it; the pool keeps all of them for a
    // block whose base fee is lower.
    assert_eq!(
        nonces(&pool, &pool.take(usize::MAX, u64::MAX, &[], 10)),
        [(3, 0), (2, 0)]
    );
    assert_eq!(
        nonces(&pool, &pool.take(usize::MAX, u64::MAX, &[], 11)),
        [(3, 0)]
    );
    assert_eq!(
        nonces(&pool, &pool.take(usize::MAX, u64::MAX, &[], 5)),
        [(3, 0), (2, 0), (1, 0), (1, 1)]
    );
    assert_eq!(pool.len(), 4);
    // A transaction an unexecuted block carries is skipped whatever its
    // price: the block that carries it decides, and the one behind it is
    // taken (in its sender's turn, which the skipped one's tip sets: none
    // under a base fee of 10, tied with sender 2's and ahead by arrival).
    assert_eq!(
        nonces(&pool, &pool.take(usize::MAX, u64::MAX, &[a0.hash], 10)),
        [(3, 0), (1, 1), (2, 0)]
    );
}

#[test]
fn take_orders_by_the_tip_under_the_base_fee_of_the_take() {
    // Admitted under a base fee of 0, a legacy transaction at 30 reported
    // the higher priority; a dynamic-fee one with a fee cap of 100 and a tip
    // cap of 20, the lower.
    let mut pool = Mempool::default();
    let legacy = tx(1, 0, 30);
    let dynamic = PoolTx {
        fee_cap: 100,
        ..tx(2, 0, 20)
    };
    add(&mut pool, &legacy).unwrap();
    add(&mut pool, &dynamic).unwrap();
    assert_eq!((legacy.priority, dynamic.priority), (30, 20));
    assert_eq!(
        nonces(&pool, &pool.take(usize::MAX, u64::MAX, &[], 0)),
        [(1, 0), (2, 0)]
    );
    // Under a base fee of 15 the legacy one tips 15 and the dynamic-fee one
    // still 20: the take orders by the tips paid now, not those at
    // admission.
    assert_eq!((legacy.tip_at(15), dynamic.tip_at(15)), (15, 20));
    assert_eq!(
        nonces(&pool, &pool.take(usize::MAX, u64::MAX, &[], 15)),
        [(2, 0), (1, 0)]
    );
    // Equal tips go by arrival; below the base fee there is no tip.
    assert_eq!((legacy.tip_at(10), dynamic.tip_at(10)), (20, 20));
    assert_eq!(
        nonces(&pool, &pool.take(usize::MAX, u64::MAX, &[], 10)),
        [(1, 0), (2, 0)]
    );
    assert_eq!(legacy.tip_at(31), 0);
}

#[test]
fn a_transaction_too_large_for_a_block_is_refused() {
    let mut pool = Mempool::default();
    let at_cap = sized(1, 0, 1, MAX_TX_BYTES);
    assert_eq!(add(&mut pool, &at_cap).map(|i| i.replaced), Ok(None));
    let over = sized(1, 1, 1, MAX_TX_BYTES + 1);
    assert_eq!(pool.check(&over), Err(PoolError::Oversized));
    assert_eq!(add(&mut pool, &over), Err(PoolError::Oversized));
    assert_eq!(pool.len(), 1);
}

#[test]
fn a_replacement_must_leave_the_pending_run_funded() {
    let mut pool = Mempool::default();
    let unit = tx(1, 0, 10).cost;
    let account = funded(0, 3 * unit);
    let run: Vec<PoolTx> = (0..3).map(|n| tx(1, n, 10)).collect();
    for t in &run {
        pool.insert(t.clone(), account.clone()).unwrap();
    }
    let far = tx(1, 5, 10);
    pool.insert(far.clone(), account.clone()).unwrap();
    // Dearer on its own nonce: the balance no longer covers the run.
    let mut dear = tx(1, 0, 11);
    dear.cost = unit + 1;
    assert_eq!(add(&mut pool, &dear), Err(PoolError::Overdraft));
    assert_eq!(pool.get(&run[0].hash), Some(&run[0]));
    // Within the balance it may replace.
    dear.cost = unit;
    assert_eq!(add(&mut pool, &dear).unwrap().replaced, Some(run[0].hash));
    // A queued transaction is not part of the run.
    let mut queued = tx(1, 5, 11);
    queued.cost = 3 * unit;
    assert_eq!(add(&mut pool, &queued).unwrap().replaced, Some(far.hash));
}

#[test]
fn a_gap_fill_drops_the_first_follower_left_unfunded() {
    let mut pool = Mempool::default();
    let unit = tx(1, 0, 10).cost;
    let account = funded(0, 2 * unit + unit / 2);
    let txs: Vec<PoolTx> = (0..4).map(|n| tx(1, n, 10)).collect();
    for n in [0, 2, 3] {
        let inserted = pool.insert(txs[n].clone(), account.clone()).unwrap();
        assert_eq!(inserted.unfunded, None);
    }
    // Nonce 1 makes 2 and 3 pending; the balance covers 0 and 1 only.
    let inserted = pool.insert(txs[1].clone(), account).unwrap();
    assert_eq!(inserted.unfunded, Some(txs[2].hash));
    assert_eq!(pool.status(), (2, 1));
    // A newcomer that is itself unfunded is the kernel's to refuse.
    let mut pool = Mempool::default();
    let inserted = pool.insert(txs[0].clone(), funded(0, 0)).unwrap();
    assert_eq!(inserted.unfunded, None);
}

#[test]
fn reset_follows_the_account() {
    let mut pool = Mempool::default();
    assert!(pool.reset(&[1; 20], rich(0)).is_empty(), "unknown sender");
    let txs: Vec<PoolTx> = (0..4).map(|n| tx(1, n, 10)).collect();
    let far = tx(1, 9, 10);
    let costly = tx(1, 8, 1000);
    for t in txs.iter().chain([&far, &costly]) {
        add(&mut pool, t).unwrap();
    }
    assert!(pool.reset(&[1; 20], rich(0)).is_empty(), "unchanged");
    // Two included: their nonces are stale. The balance covers one of the
    // two pending ones left and the far queued one, not the costly one.
    let cost = txs[0].cost;
    let dropped = pool.reset(&[1; 20], funded(2, cost + cost / 2));
    assert_eq!(
        dropped,
        vec![txs[0].hash, txs[1].hash, txs[3].hash, costly.hash]
    );
    assert_eq!(pool.status(), (1, 1));
    assert_eq!(pool.pending_nonce(&[1; 20]), Some(3));
    assert_eq!(pool.account(&[1; 20]), Some(&funded(2, cost + cost / 2)));
    // A delegation appearing at the sender keeps what it has: a delegated
    // account still sends.
    let delegated = Account {
        code_hash: [7; 32],
        ..funded(2, u128::MAX)
    };
    assert!(pool.reset(&[1; 20], delegated).is_empty());
    assert_eq!(pool.status(), (1, 1));
}

#[test]
fn delegated_senders_and_authorities_are_limited_as_geth_limits_them() {
    let mut pool = Mempool::default();
    let delegated = Account {
        code_hash: [7; 32],
        ..rich(0)
    };
    // A delegated sender: the first transaction enters, a second with
    // another nonce does not, a replacement does.
    pool.insert(tx(1, 0, 10), delegated.clone()).unwrap();
    assert_eq!(pool.check(&tx(1, 1, 10)), Err(PoolError::InflightLimit));
    assert_eq!(
        pool.insert(tx(1, 1, 10), delegated),
        Err(PoolError::InflightLimit)
    );
    assert!(pool.insert(tx(1, 0, 20), rich(0)).is_ok());
    // A set-code transaction naming sender 2 as authority makes sender 2
    // delegated for the pool, until it leaves.
    let set_code = PoolTx {
        authorities: vec![[2; 20]],
        ..tx(3, 0, 10)
    };
    add(&mut pool, &set_code).unwrap();
    add(&mut pool, &tx(2, 0, 10)).unwrap();
    assert_eq!(add(&mut pool, &tx(2, 1, 10)), Err(PoolError::InflightLimit));
    // Replacing the set-code transaction with one naming nobody frees sender 2.
    add(&mut pool, &tx(3, 0, 20)).unwrap();
    add(&mut pool, &tx(2, 1, 10)).unwrap();
    // Sender 2 now holds two: a set-code transaction naming it is refused.
    let naming_two = PoolTx {
        authorities: vec![[2; 20], [9; 20]],
        ..tx(4, 0, 10)
    };
    assert_eq!(
        add(&mut pool, &naming_two),
        Err(PoolError::AuthorityReserved)
    );
    // An authority with one transaction may be named, which limits it to
    // that one. Sender 5 has no code, so only the naming holds it: removing
    // the set-code transaction (which names it twice) frees it.
    add(&mut pool, &tx(5, 0, 10)).unwrap();
    let naming_one = PoolTx {
        authorities: vec![[5; 20], [5; 20]],
        ..tx(4, 0, 10)
    };
    add(&mut pool, &naming_one).unwrap();
    assert_eq!(add(&mut pool, &tx(5, 1, 10)), Err(PoolError::InflightLimit));
    assert!(pool.remove(&naming_one.hash).is_some());
    add(&mut pool, &tx(5, 1, 10)).unwrap();
    // The delegated sender stays limited by its code.
    assert_eq!(add(&mut pool, &tx(1, 1, 20)), Err(PoolError::InflightLimit));
}

#[test]
fn a_take_leaves_out_senders_that_an_authorization_ahead_names() {
    let everything =
        |pool: &Mempool, skip: &[[u8; 32]]| nonces(pool, &pool.take(usize::MAX, u64::MAX, skip, 0));
    // Sender 3's set-code transaction names sender 2 and comes first in the
    // order (same priority, earlier arrival): its authorization can move
    // 2's nonce, so 2's transaction is left out. Sender 1 is not named.
    let mut pool = Mempool::default();
    let set_code = PoolTx {
        authorities: vec![[2; 20]],
        ..tx(3, 0, 10)
    };
    add(&mut pool, &set_code).unwrap();
    add(&mut pool, &tx(2, 0, 10)).unwrap();
    add(&mut pool, &tx(1, 0, 10)).unwrap();
    assert_eq!(everything(&pool, &[]), [(3, 0), (1, 0)]);
    // Ahead of it, 2's transaction runs first, and then the authorization
    // is stale: both are taken.
    let mut pool = Mempool::default();
    add(&mut pool, &set_code).unwrap();
    add(&mut pool, &tx(2, 0, 20)).unwrap();
    assert_eq!(everything(&pool, &[]), [(2, 0), (3, 0)]);
    // A set-code transaction in `skip` runs before anything taken, whatever
    // its priority: 2 is left out. A skipped hash the pool does not hold
    // names nobody.
    assert!(everything(&pool, &[set_code.hash]).is_empty());
    assert_eq!(everything(&pool, &[[9; 32]]), [(2, 0), (3, 0)]);
}

#[test]
fn parse_reads_a_signed_transaction() {
    use k256::ecdsa::SigningKey;
    use solo_rlp::{encode_bytes, encode_list, encode_uint};
    let key = SigningKey::from_slice(&[1; 32]).unwrap();
    let point = key.verifying_key().to_encoded_point(false);
    let address: Address = keccak256(&point.as_bytes()[1..])[12..].try_into().unwrap();
    let sign = |gas_price: u128| {
        let fields = solo_eth::legacy_unsigned(7, gas_price, GAS, Some([2; 20]), 5, &[]);
        let mut payload = Vec::new();
        encode_list(&fields, &mut payload);
        let (sig, id) = key.sign_prehash_recoverable(&keccak256(&payload)).unwrap();
        let mut signed = fields.clone();
        encode_uint(27 + u128::from(id.to_byte()), &mut signed);
        encode_bytes(&sig.r().to_bytes(), &mut signed);
        encode_bytes(&sig.s().to_bytes(), &mut signed);
        let mut raw = Vec::new();
        encode_list(&signed, &mut raw);
        raw
    };
    let raw = sign(3);
    let tx = PoolTx::parse(&raw).unwrap();
    assert_eq!(
        (tx.hash, tx.sender, tx.nonce, tx.fee_cap, tx.tip_cap, tx.gas),
        (keccak256(&raw), address, 7, 3, 3, GAS)
    );
    assert_eq!((tx.cost, tx.priority), (3 * u128::from(GAS) + 5, 0));
    assert_eq!(PoolTx::parse(&[0xC0]), None, "does not decode");
    assert_eq!(PoolTx::parse(&sign(u128::MAX)), None, "cost overflows");
}

#[derive(Debug, Clone)]
enum Op {
    Insert { sender: u8, nonce: u64, fee: u128 },
    Remove(usize),
    Advance { sender: u8, by: u64 },
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        4 => (0u8..4, 0u64..6, 1u128..40).prop_map(|(sender, nonce, fee)| Op::Insert { sender, nonce, fee }),
        1 => any::<usize>().prop_map(Op::Remove),
        1 => (0u8..4, 0u64..3).prop_map(|(sender, by)| Op::Advance { sender, by }),
    ]
}

/// What holds after every operation: the index and byte count agree with
/// the queues, no queue is empty, the size limit holds, and a take is a
/// valid block order.
fn check(pool: &Mempool) {
    let txs: Vec<&PoolTx> = pool.iter().collect();
    assert_eq!(txs.len(), pool.len());
    assert_eq!(txs.iter().map(|t| t.raw.len()).sum::<usize>(), pool.bytes());
    for t in &txs {
        assert_eq!(pool.get(&t.hash), Some(*t));
    }
    for sender in pool.senders() {
        assert!(pool.iter().any(|t| t.sender == sender));
    }
    // Removals can demote pending transactions past the queued limit, which
    // binds insertions only; the total never grows past its limit.
    assert!(pool.len() <= pool.limits.max_txs);
    let mut next: BTreeMap<Address, u64> = BTreeMap::new();
    for raw in pool.take(usize::MAX, u64::MAX, &[], 0) {
        let t = pool.get(&keccak256(&raw)).unwrap();
        let expected = next
            .entry(t.sender)
            .or_insert_with(|| pool.account(&t.sender).unwrap().nonce);
        assert_eq!(t.nonce, *expected, "nonce order within a sender");
        *expected += 1;
        assert!(pool.is_pending(t));
    }
}

proptest! {
    #[test]
    fn invariants_hold(ops in prop::collection::vec(op(), 1..60)) {
        let mut pool = Mempool::new(PoolLimits { max_txs: 10, max_queued: 4, per_sender: 5, max_bytes: usize::MAX, max_tx_bytes: usize::MAX });
        let mut nonce_of = [0u64; 4];
        for op in ops {
            match op {
                Op::Insert { sender, nonce, fee } => {
                    let state = nonce_of[sender as usize];
                    let _ = pool.insert(tx(sender, state + nonce, fee), rich(state));
                }
                Op::Remove(i) => {
                    let hashes: Vec<[u8; 32]> = pool.iter().map(|t| t.hash).collect();
                    if !hashes.is_empty() {
                        pool.remove(&hashes[i % hashes.len()]);
                    }
                }
                Op::Advance { sender, by } => {
                    nonce_of[sender as usize] += by;
                    pool.reset(&[sender; 20], rich(nonce_of[sender as usize]));
                }
            }
            check(&pool);
        }
    }
}

#[test]
fn authorities_come_from_the_authorization_signatures() {
    use k256::ecdsa::SigningKey;
    let key = SigningKey::from_slice(&[1; 32]).unwrap();
    let point = key.verifying_key().to_encoded_point(false);
    let address: Address = keccak256(&point.as_bytes()[1..])[12..].try_into().unwrap();
    let mut auth = solo_eth::Authorization {
        chain_id: [0; 32],
        address: [9; 20],
        nonce: 3,
        y_parity: 0,
        r: [0; 32],
        s: [0; 32],
    };
    let (sig, id) = key
        .sign_prehash_recoverable(&keccak256(&auth.signing_payload()))
        .unwrap();
    // EIP-7702 takes the low-s form; normalizing s flips the parity.
    let normalized = sig.normalize_s();
    auth.y_parity = id.to_byte() ^ u8::from(normalized.is_some());
    let sig = normalized.unwrap_or(sig);
    auth.r = sig.r().to_bytes().into();
    auth.s = sig.s().to_bytes().into();
    assert_eq!(authority(&auth), Some(address));
    // A parity other than 0 or 1 names no one, and the pool ignores it.
    let unsigned = solo_eth::Authorization {
        y_parity: 2,
        ..auth
    };
    assert_eq!(authority(&unsigned), None);
}
