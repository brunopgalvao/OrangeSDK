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
            limits.max_bytes
        ),
        (MAX_TXS, MAX_QUEUED, PER_SENDER, MAX_BYTES)
    );
    assert_eq!(Mempool::new(limits).limits, limits);
    assert_eq!(
        PoolError::Underpriced.to_string(),
        "replacement transaction underpriced"
    );
    assert_eq!(PoolError::Full.to_string(), "txpool is full");
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
        assert_eq!(pool.check_replacement(&new), Err(PoolError::Underpriced));
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
    let all = pool.take(usize::MAX, u64::MAX);
    // Sender 3 is queued; 2 and 4 tie and go in arrival order; 1's second
    // transaction, the dearest, waits for its first, the cheapest.
    assert_eq!(nonces(&pool, &all), [(2, 0), (4, 0), (1, 0), (1, 1)]);
    assert_eq!(pool.len(), 5, "taking keeps them");
    // Gas: two transactions' worth.
    let two = pool.take(usize::MAX, 2 * GAS);
    assert_eq!(nonces(&pool, &two), [(2, 0), (4, 0)]);
    // Bytes: a sender whose next transaction does not fit drops out, the
    // others continue.
    let len = txs[0].raw.len();
    let mut pool = Mempool::default();
    add(&mut pool, &sized(1, 0, 9, 3 * len)).unwrap();
    add(&mut pool, &tx(2, 0, 1)).unwrap();
    add(&mut pool, &tx(2, 1, 1)).unwrap();
    assert_eq!(
        nonces(&pool, &pool.take(2 * len, u64::MAX)),
        [(2, 0), (2, 1)]
    );
    assert!(pool.take(0, u64::MAX).is_empty());
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
        nonces(&pool, &pool.take(usize::MAX, u64::MAX)),
        [(1, 0), (2, 0)]
    );
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
    // Code appearing at the sender drops all it has.
    let coded = Account {
        code_hash: [7; 32],
        ..funded(2, u128::MAX)
    };
    assert_eq!(pool.reset(&[1; 20], coded), vec![txs[2].hash, far.hash]);
    assert!(pool.is_empty());
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
    for raw in pool.take(usize::MAX, u64::MAX) {
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
        let mut pool = Mempool::new(PoolLimits { max_txs: 10, max_queued: 4, per_sender: 5, max_bytes: usize::MAX });
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
