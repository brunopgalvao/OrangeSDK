//! The mempool through a node running the reference kernel (spec 14):
//! several transactions of one sender in one block, nonce gaps that queue
//! and promote, replacement, limits, gossip of executable transactions only,
//! and the pool following the state a block leaves.

use std::sync::OnceLock;

use k256::ecdsa::SigningKey;
use orange_abi::Encode;
use orange_abi::chain::{Allocation, BlockHeader, GenesisParams, reason};
use orange_abi::codec::Seq;
use orange_abi::types::{Block, Effect, Genesis, Input};
use orange_host::hash::keccak256;
use orange_node::{MAX_TX_BYTES, Node, NodeConfig, PoolError, PoolLimits, Sim, SubmitError};
use orange_recompile::{Input as Elf, Options, recompile};
use orange_rlp::{encode_bytes, encode_list, encode_uint};

const KERNEL: &[u8] = include_bytes!("fixtures/kernel.elf");
const CHAIN_ID: u64 = 1337;
const SLOT_MS: u64 = 400;
const START_MS: u64 = 1_000;
const GWEI: u128 = 1_000_000_000;
const ETHER: u128 = GWEI * GWEI;
const BOB: [u8; 20] = [0xB0; 20];

fn kernel_module() -> &'static [u8] {
    static MODULE: OnceLock<Vec<u8>> = OnceLock::new();
    MODULE.get_or_init(|| recompile(&Elf::load(KERNEL).unwrap(), &Options::default()).unwrap())
}

struct Wallet {
    key: SigningKey,
    address: [u8; 20],
}

impl Wallet {
    fn new(seed: u8) -> Wallet {
        let key = SigningKey::from_slice(&[seed; 32]).unwrap();
        let point = key.verifying_key().to_encoded_point(false);
        let address = keccak256(&point.as_bytes()[1..])[12..].try_into().unwrap();
        Wallet { key, address }
    }

    /// An EIP-155 legacy transfer of `value` to [`BOB`] at `gas_price`.
    fn transfer(&self, nonce: u64, value: u128, gas_price: u128) -> Vec<u8> {
        self.call(nonce, value, gas_price, 21_000, &[])
    }

    /// An EIP-155 legacy call to [`BOB`] with a gas limit and data.
    fn call(&self, nonce: u64, value: u128, gas_price: u128, gas: u64, data: &[u8]) -> Vec<u8> {
        let fields = orange_eth::legacy_unsigned(nonce, gas_price, gas, Some(BOB), value, data);
        let mut unsigned = fields.clone();
        encode_uint(u128::from(CHAIN_ID), &mut unsigned);
        encode_uint(0, &mut unsigned);
        encode_uint(0, &mut unsigned);
        let mut payload = Vec::new();
        encode_list(&unsigned, &mut payload);
        let (sig, id) = self
            .key
            .sign_prehash_recoverable(&keccak256(&payload))
            .unwrap();
        let mut signed = fields;
        encode_uint(
            u128::from(CHAIN_ID * 2 + 35 + u64::from(id.to_byte())),
            &mut signed,
        );
        // RLP integers carry no leading zeros.
        for half in [sig.r().to_bytes(), sig.s().to_bytes()] {
            let first = half.iter().position(|b| *b != 0).unwrap_or(half.len());
            encode_bytes(&half[first..], &mut signed);
        }
        let mut raw = Vec::new();
        encode_list(&signed, &mut raw);
        raw
    }
}

/// A transfer's cost at `gas_price`: the most the pool reserves for it.
fn cost(value: u128, gas_price: u128) -> u128 {
    value + 21_000 * gas_price
}

fn node_key() -> SigningKey {
    SigningKey::from_slice(&[0x42; 32]).unwrap()
}

/// A single-validator chain where each wallet holds its balance.
fn node(accounts: &[(&Wallet, u128)]) -> Node {
    let params = GenesisParams {
        slot_ms: SLOT_MS,
        max_txs: 16,
        allocations: Seq(accounts
            .iter()
            .map(|(wallet, balance)| Allocation {
                address: wallet.address,
                balance: *balance,
                ..Allocation::default()
            })
            .collect()),
        ..GenesisParams::default()
    };
    let genesis = Genesis {
        chain_id: CHAIN_ID,
        fee_schedule: vec![],
        modules: Seq(vec![]),
        params: params.to_bytes(),
        validators: Sim::validator_set(&[node_key()]).to_bytes(),
    };
    let config = NodeConfig {
        now_ms: START_MS,
        key: Some(node_key()),
        ..NodeConfig::default()
    };
    let mut node = Node::open(kernel_module(), &genesis, config).unwrap();
    node.start(None).unwrap();
    node
}

/// Fires the next slot's proposal: the block it makes executes and
/// finalizes at once on a single validator.
fn slot(node: &mut Node) {
    let height = node.block_number().unwrap();
    node.tick(START_MS + (height + 1) * SLOT_MS).unwrap();
    assert_eq!(node.block_number().unwrap(), height + 1);
}

/// Executes a block of `txs` as if another validator had proposed it.
fn execute_foreign(node: &mut Node, txs: &[&Vec<u8>]) {
    let height = node.block_number().unwrap() + 1;
    let header = BlockHeader {
        height,
        timestamp_ms: START_MS + height,
        ..BlockHeader::default()
    };
    let block = Block {
        header: header.to_bytes(),
        txs: Seq(txs.iter().map(|raw| (*raw).clone()).collect()),
        participation: vec![],
    };
    let executed = node.apply_effect(Effect::ExecuteBlock { block }).unwrap();
    assert!(matches!(executed, Some(Input::BlockExecuted { .. })));
}

fn tx_hashes(node: &mut Node, height: u64) -> Vec<[u8; 32]> {
    node.block_by_number(height).unwrap().unwrap().tx_hashes.0
}

#[test]
fn one_sender_fills_a_block_in_nonce_order() {
    let alice = Wallet::new(1);
    let mut node = node(&[(&alice, 100 * ETHER)]);
    assert_eq!(node.pending_nonce(&alice.address).unwrap(), 0);
    let txs: Vec<Vec<u8>> = (0..10).map(|n| alice.transfer(n, ETHER, GWEI)).collect();
    for raw in &txs {
        node.submit(raw).unwrap();
    }
    assert_eq!(node.pending_nonce(&alice.address).unwrap(), 10);
    assert_eq!(node.account(&alice.address).unwrap().nonce, 0);
    assert_eq!(node.mempool().status(), (10, 0));
    assert_eq!(node.take_tx_gossip(), txs, "all executable, all gossiped");
    slot(&mut node);
    let hashes: Vec<[u8; 32]> = txs.iter().map(|raw| keccak256(raw)).collect();
    assert_eq!(tx_hashes(&mut node, 1), hashes);
    for (index, hash) in hashes.iter().enumerate() {
        let receipt = node.receipt(hash).unwrap().unwrap();
        assert_eq!((receipt.status, receipt.index as usize), (1, index));
    }
    assert_eq!(node.account(&alice.address).unwrap().nonce, 10);
    assert_eq!(node.account(&BOB).unwrap().balance, 10 * ETHER);
    assert!(node.mempool().is_empty());
    assert_eq!(node.pending_nonce(&alice.address).unwrap(), 10);
}

#[test]
fn a_gap_queues_until_it_fills() {
    let alice = Wallet::new(1);
    let mut node = node(&[(&alice, 100 * ETHER)]);
    let txs: Vec<Vec<u8>> = (0..4).map(|n| alice.transfer(n, ETHER, GWEI)).collect();
    node.submit(&txs[0]).unwrap();
    node.submit(&txs[2]).unwrap();
    node.submit(&txs[3]).unwrap();
    assert_eq!(node.mempool().status(), (1, 2));
    assert_eq!(node.pending_nonce(&alice.address).unwrap(), 1);
    assert_eq!(
        node.take_tx_gossip(),
        vec![txs[0].clone()],
        "queued stays local"
    );
    // The block takes the executable one; the gapped ones wait.
    slot(&mut node);
    assert_eq!(tx_hashes(&mut node, 1), vec![keccak256(&txs[0])]);
    assert_eq!(node.mempool().status(), (0, 2));
    // Filling the gap promotes them all, and gossips them.
    node.submit(&txs[1]).unwrap();
    assert_eq!(node.mempool().status(), (3, 0));
    assert_eq!(node.take_tx_gossip(), txs[1..].to_vec());
    slot(&mut node);
    let rest: Vec<[u8; 32]> = txs[1..].iter().map(|raw| keccak256(raw)).collect();
    assert_eq!(tx_hashes(&mut node, 2), rest);
    assert!(node.mempool().is_empty());
}

#[test]
fn replacement_needs_the_price_bump() {
    let alice = Wallet::new(1);
    let mut node = node(&[(&alice, 100 * ETHER)]);
    let first = alice.transfer(0, ETHER, 10 * GWEI);
    node.submit(&first).unwrap();
    assert_eq!(
        node.submit(&alice.transfer(0, 2 * ETHER, 10 * GWEI + GWEI / 2)),
        Err(SubmitError::Pool(PoolError::Underpriced))
    );
    let second = alice.transfer(0, 2 * ETHER, 11 * GWEI);
    node.submit(&second).unwrap();
    assert_eq!(node.mempool().len(), 1);
    assert!(node.mempool().get(&keccak256(&first)).is_none());
    assert_eq!(node.take_tx_gossip(), vec![first, second.clone()]);
    slot(&mut node);
    assert_eq!(tx_hashes(&mut node, 1), vec![keccak256(&second)]);
    assert_eq!(node.account(&BOB).unwrap().balance, 2 * ETHER);
}

#[test]
fn later_nonces_validate_against_what_the_earlier_ones_leave() {
    let alice = Wallet::new(1);
    let mut node = node(&[(&alice, cost(ETHER, GWEI) * 2)]);
    node.submit(&alice.transfer(0, ETHER, GWEI)).unwrap();
    node.submit(&alice.transfer(1, ETHER, GWEI)).unwrap();
    assert_eq!(
        node.submit(&alice.transfer(2, 1, GWEI)),
        Err(SubmitError::Rejected(reason::INSUFFICIENT_FUNDS))
    );
    // A queued transaction reserves what the pool holds before it.
    assert_eq!(
        node.submit(&alice.transfer(5, 1, GWEI)),
        Err(SubmitError::Rejected(reason::INSUFFICIENT_FUNDS))
    );
    slot(&mut node);
    assert_eq!(node.account(&alice.address).unwrap().nonce, 2);
    assert_eq!(node.account(&alice.address).unwrap().balance, 0);
}

#[test]
fn limits_evict_queued_transactions() {
    let (alice, carol) = (Wallet::new(1), Wallet::new(3));
    let mut node = node(&[(&alice, 100 * ETHER), (&carol, 100 * ETHER)]);
    node.set_mempool_limits(PoolLimits {
        max_txs: 2,
        ..PoolLimits::default()
    });
    let queued = alice.transfer(3, ETHER, GWEI);
    node.submit(&queued).unwrap();
    node.submit(&alice.transfer(0, ETHER, GWEI)).unwrap();
    // Full: an executable newcomer pushes out the queued one.
    node.submit(&carol.transfer(0, ETHER, GWEI)).unwrap();
    assert!(node.mempool().get(&keccak256(&queued)).is_none());
    assert_eq!(node.mempool().status(), (2, 0));
    // Nothing queued is left to evict.
    assert_eq!(
        node.submit(&carol.transfer(1, ETHER, GWEI)),
        Err(SubmitError::Pool(PoolError::Full))
    );
}

#[test]
fn a_transaction_no_block_can_carry_is_refused() {
    // Larger than the per-transaction cap, it would sit pending for ever:
    // no take could return it, and no block would spend its sender's funds.
    let alice = Wallet::new(1);
    let mut node = node(&[(&alice, 10 * ETHER)]);
    let big = alice.call(0, 0, GWEI, 16_000_000, &vec![0; MAX_TX_BYTES]);
    assert!(big.len() > MAX_TX_BYTES);
    assert_eq!(
        node.submit(&big),
        Err(SubmitError::Pool(PoolError::Oversized))
    );
    assert!(node.mempool().is_empty());
    assert!(node.take_tx_gossip().is_empty());
}

#[test]
fn an_oversized_transaction_is_refused_before_it_is_read() {
    // Reading a transaction recovers its signatures, so the size is checked
    // first: bytes no transaction decodes from are refused for their size,
    // not handed to the kernel to find malformed.
    let alice = Wallet::new(1);
    let mut node = node(&[(&alice, 10 * ETHER)]);
    let junk = vec![0x04; MAX_TX_BYTES + 1];
    assert_eq!(
        node.submit(&junk),
        Err(SubmitError::Pool(PoolError::Oversized))
    );
    assert_eq!(
        node.submit(&junk[..100]),
        Err(SubmitError::Rejected(reason::MALFORMED))
    );
}

#[test]
fn replacements_and_gap_fills_keep_the_pending_run_funded() {
    let alice = Wallet::new(1);
    let mut node = node(&[(&alice, 10 * ETHER)]);
    let run: Vec<Vec<u8>> = (0..4).map(|n| alice.transfer(n, ETHER, GWEI)).collect();
    for raw in &run {
        node.submit(raw).unwrap();
    }
    // Alone the 9 ETH replacement is funded; with nonces 1 to 3 behind it,
    // it is not (geth's overdraft check).
    assert_eq!(
        node.submit(&alice.transfer(0, 9 * ETHER, 2 * GWEI)),
        Err(SubmitError::Pool(PoolError::Overdraft))
    );
    node.submit(&alice.transfer(0, ETHER, 2 * GWEI)).unwrap();
    assert_eq!(node.mempool().status(), (4, 0));
    // Nonce 5 is funded behind the run, and so is nonce 4 on its own; with
    // both, the balance covers nonce 4 only, and nonce 5 goes.
    let left = 10 * ETHER - 4 * cost(ETHER, GWEI) - 21_000 * GWEI;
    let five = alice.transfer(5, left - cost(0, GWEI), GWEI);
    node.submit(&five).unwrap();
    assert_eq!(node.mempool().status(), (4, 1));
    node.submit(&alice.transfer(4, 1, GWEI)).unwrap();
    assert!(node.mempool().get(&keccak256(&five)).is_none());
    assert_eq!(node.mempool().status(), (5, 0));
}

#[test]
fn a_foreign_block_resets_the_pool() {
    let alice = Wallet::new(1);
    let mut node = node(&[(&alice, 10 * ETHER)]);
    let ours: Vec<Vec<u8>> = (0..2).map(|n| alice.transfer(n, ETHER, GWEI)).collect();
    let queued = alice.transfer(3, 5 * ETHER, GWEI);
    for raw in ours.iter().chain([&queued]) {
        node.submit(raw).unwrap();
    }
    node.take_tx_gossip();
    // Another validator's block spends nonce 0 on another transaction, which
    // leaves the funds for nonce 1 and two small transfers at 1 wei, not for
    // the queued one.
    let spare = 2 * cost(1, 1);
    let theirs = alice.transfer(
        0,
        10 * ETHER - cost(0, GWEI) - cost(ETHER, GWEI) - spare,
        GWEI,
    );
    execute_foreign(&mut node, &[&theirs]);
    assert_eq!(node.account(&alice.address).unwrap().nonce, 1);
    assert!(
        node.mempool().get(&keccak256(&ours[0])).is_none(),
        "stale nonce"
    );
    assert!(
        node.mempool().get(&keccak256(&ours[1])).is_some(),
        "still funded"
    );
    assert!(
        node.mempool().get(&keccak256(&queued)).is_none(),
        "unfunded"
    );
    assert!(
        node.take_tx_gossip().is_empty(),
        "nonce 1 was gossiped already"
    );
    // A block that leaves a queued transaction executable gossips it.
    let late = alice.transfer(3, 1, 1);
    node.submit(&late).unwrap();
    assert!(node.take_tx_gossip().is_empty());
    execute_foreign(&mut node, &[&ours[1], &alice.transfer(2, 1, 1)]);
    assert!(node.mempool().get(&keccak256(&ours[1])).is_none());
    assert_eq!(node.take_tx_gossip(), vec![late.clone()]);
    assert_eq!(node.mempool().status(), (1, 0));
    assert_eq!(node.pending_nonce(&alice.address).unwrap(), 4);
}

/// A three-validator network over `latency_ms` where each wallet holds 100
/// ETH and a block holds up to 64 transactions.
fn network(wallets: &[Wallet], latency_ms: u64) -> Sim {
    let keys: Vec<SigningKey> = (1..=3)
        .map(|i| SigningKey::from_slice(&[0x10 + i; 32]).unwrap())
        .collect();
    let params = GenesisParams {
        slot_ms: SLOT_MS,
        max_txs: 64,
        allocations: Seq(wallets
            .iter()
            .map(|w| Allocation {
                address: w.address,
                balance: 100 * ETHER,
                ..Allocation::default()
            })
            .collect()),
        ..GenesisParams::default()
    };
    let genesis = Genesis {
        chain_id: CHAIN_ID,
        fee_schedule: vec![],
        modules: Seq(vec![]),
        params: params.to_bytes(),
        validators: Sim::validator_set(&keys).to_bytes(),
    };
    let config = NodeConfig {
        now_ms: START_MS,
        ..NodeConfig::default()
    };
    Sim::new(kernel_module(), &genesis, &keys, 0, &config, latency_ms).unwrap()
}

#[test]
fn a_block_on_an_unexecuted_parent_takes_new_transactions() {
    // Blocks execute on finalization, so with real latency a leader builds on
    // a parent it has not executed and its pool still holds the parent's
    // transactions. Ten of these fill a block's gas; if the take handed the
    // parent's ones out again, every other block would be empty.
    let wallets: Vec<Wallet> = (1..=4).map(Wallet::new).collect();
    let mut sim = network(&wallets, 150);
    let txs: Vec<Vec<u8>> = wallets
        .iter()
        .flat_map(|w| (0..10).map(move |n| w.call(n, 1, GWEI, 3_000_000, &[])))
        .collect();
    for raw in &txs {
        sim.submit(0, raw).unwrap();
    }
    let hashes: Vec<[u8; 32]> = txs.iter().map(|raw| keccak256(raw)).collect();
    let landed = sim
        .run_until(60 * SLOT_MS, |s| {
            hashes
                .iter()
                .all(|hash| s.nodes[0].receipt(hash).unwrap().is_some())
        })
        .unwrap();
    assert!(landed, "{:?}", sim.finalized_heights().unwrap());
    let node = &mut sim.nodes[0];
    let head = node.block_number().unwrap();
    let counts: Vec<usize> = (1..=head).map(|h| tx_hashes(node, h).len()).collect();
    let first = counts.iter().position(|&n| n > 0).unwrap();
    let last = counts.iter().rposition(|&n| n > 0).unwrap();
    assert_eq!(counts[first..=last], [10, 10, 10, 10], "{counts:?}");
}

#[test]
fn nonces_sent_backwards_reach_every_validator_and_land() {
    let keys: Vec<SigningKey> = (1..=3)
        .map(|i| SigningKey::from_slice(&[0x10 + i; 32]).unwrap())
        .collect();
    let alice = Wallet::new(1);
    let params = GenesisParams {
        slot_ms: SLOT_MS,
        max_txs: 8,
        allocations: Seq(vec![Allocation {
            address: alice.address,
            balance: 100 * ETHER,
            ..Allocation::default()
        }]),
        ..GenesisParams::default()
    };
    let genesis = Genesis {
        chain_id: CHAIN_ID,
        fee_schedule: vec![],
        modules: Seq(vec![]),
        params: params.to_bytes(),
        validators: Sim::validator_set(&keys).to_bytes(),
    };
    let config = NodeConfig {
        now_ms: START_MS,
        ..NodeConfig::default()
    };
    let mut sim = Sim::new(kernel_module(), &genesis, &keys, 0, &config, 25).unwrap();
    let txs: Vec<Vec<u8>> = (0..3).map(|n| alice.transfer(n, ETHER, GWEI)).collect();
    // Only the submitting node holds the gapped ones until nonce 0 arrives.
    for raw in txs[1..].iter().rev() {
        sim.submit(2, raw).unwrap();
    }
    sim.advance(10 * 25).unwrap();
    assert_eq!(sim.nodes[2].mempool().status(), (0, 2));
    assert!(sim.nodes[0].mempool().is_empty() && sim.nodes[1].mempool().is_empty());
    sim.submit(2, &txs[0]).unwrap();
    let hashes: Vec<[u8; 32]> = txs.iter().map(|raw| keccak256(raw)).collect();
    let landed = sim
        .run_until(20 * SLOT_MS, |s| {
            s.nodes.iter_mut().all(|n| {
                hashes
                    .iter()
                    .all(|hash| n.receipt(hash).unwrap().is_some_and(|r| r.status == 1))
            })
        })
        .unwrap();
    assert!(landed, "{:?}", sim.finalized_heights().unwrap());
    for node in &mut sim.nodes {
        assert_eq!(node.account(&BOB).unwrap().balance, 3 * ETHER);
        assert!(node.mempool().is_empty());
    }
}
