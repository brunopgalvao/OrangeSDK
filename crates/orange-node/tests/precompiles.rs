//! Blocks full of the costliest precompile calls (spec 19 §5), on a node
//! whose kernel gas is exactly [`BLOCK_KERNEL_GAS`]: before feature gate 2
//! the point evaluations run in the guest until the block's precompile
//! budget is spent and then halt out of gas; once the gate is active they
//! run on the host and all succeed. Either way every block executes within
//! the kernel gas and finalizes, and the chain goes on.

mod support;

use orange_abi::Encode;
use orange_abi::chain::{Allocation, CallRequest, GenesisParams, Receipt, call_status};
use orange_abi::codec::Seq;
use orange_abi::types::Genesis;
use orange_host::Backend;
use orange_host::hash::{keccak256, sha256};
use orange_node::{BLOCK_KERNEL_GAS, Node, NodeConfig, Sim};
use support::{CHAIN_ID, ETHER, SLOT_MS, alice, governed, keys, v1};

/// The contract that calls the point-evaluation precompile.
const CALLER: [u8; 20] = [0xC0; 20];
/// Calls per transaction, each with `CALL_GAS`.
const CALLS: usize = 240;
const CALL_GAS: u32 = 60_000;
/// Two fit a block with room for the validator's signal transaction.
const TX_GAS: u64 = 14_900_000;
/// The precompile budget of spec 19 §5.
const BUDGET: u64 = 1 << 34;

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// The EIP-4844 point evaluation with a real proof.
fn kzg() -> Vec<u8> {
    let commitment = hex(
        "8f59a8d2a1a625a17f3fea0fe5eb8c896db3764f3185481bc22f91b4aaffcca25f26936857bc3a7c2539ea8ec3a952b7",
    );
    let mut versioned = sha256(&commitment);
    versioned[0] = 1;
    [
        versioned.to_vec(),
        hex("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000"),
        hex("1522a4a7f34e1ea350ae07c29c96c7e79655aa926122e95fe69fcbd932ca49e9"),
        commitment,
        hex("a62ad71d14c5719385c0686f1871430475bf3a00f0aa3f7b8dd99a9abc2160744faf0070725e00b60ad9a026a15b1a8c"),
    ]
    .concat()
}

/// Copies the calldata to memory, `STATICCALL`s 0x0a with it `CALLS` times
/// with `CALL_GAS` each, and adds the number that succeeded to slot 0.
fn caller() -> Vec<u8> {
    let [_, g2, g1, g0] = CALL_GAS.to_be_bytes();
    let mut code = vec![0x36, 0x5F, 0x5F, 0x37, 0x5F];
    for _ in 0..CALLS {
        code.extend_from_slice(&[
            0x5F, 0x5F, 0x36, 0x5F, 0x60, 0x0A, 0x62, g2, g1, g0, 0xFA, 0x01,
        ]);
    }
    // SSTORE(0, SLOAD(0) + count)
    code.extend_from_slice(&[0x5F, 0x54, 0x01, 0x5F, 0x55, 0x00]);
    code
}

fn genesis() -> Genesis {
    let params = GenesisParams {
        slot_ms: SLOT_MS,
        max_txs: 8,
        allocations: Seq(vec![
            Allocation {
                address: alice().address,
                balance: 100 * ETHER,
                ..Allocation::default()
            },
            Allocation {
                address: CALLER,
                nonce: 1,
                code: caller(),
                ..Allocation::default()
            },
        ]),
        upgrades: governed(1, 2),
        ..GenesisParams::default()
    };
    Genesis {
        chain_id: CHAIN_ID,
        fee_schedule: vec![],
        modules: Seq(vec![]),
        params: params.to_bytes(),
        validators: Sim::validator_set(&keys(1)).to_bytes(),
    }
}

/// The kernel gas `kernel_stf_execute_block` has used so far.
fn execute_gas(node: &mut Node) -> u64 {
    node.metrics_text()
        .lines()
        .find(|l| {
            l.starts_with("orange_kernel_gas_used_total") && l.contains("kernel_stf_execute_block")
        })
        .and_then(|l| l.rsplit(' ').next())
        .map_or(0, |n| n.parse().unwrap())
}

/// Ticks one slot; the kernel gas of each block executed in it.
fn tick(node: &mut Node, blocks: &mut Vec<u64>) {
    let (before, gas) = (node.executed.len(), execute_gas(node));
    let t = node.now_ms() + SLOT_MS;
    node.tick(t).unwrap();
    if node.executed.len() == before + 1 {
        blocks.push(execute_gas(node) - gas);
    }
}

/// Submits two transactions full of calls and runs until both have receipts;
/// the receipts and the number of calls that succeeded since `before`.
fn fill(node: &mut Node, nonce: u64, blocks: &mut Vec<u64>) -> (Vec<Receipt>, u64) {
    let before = node.storage(&CALLER, &[0; 32]).unwrap();
    let hashes: Vec<_> = (nonce..nonce + 2)
        .map(|n| {
            node.submit(&alice().tx(n, CALLER, 0, TX_GAS, &kzg()))
                .unwrap()
        })
        .collect();
    for _ in 0..10 {
        if hashes.iter().all(|h| node.receipt(h).unwrap().is_some()) {
            break;
        }
        tick(node, blocks);
    }
    let receipts: Vec<Receipt> = hashes
        .iter()
        .map(|h| node.receipt(h).unwrap().unwrap())
        .collect();
    let after = node.storage(&CALLER, &[0; 32]).unwrap();
    let count = |w: [u8; 32]| u64::from_be_bytes(w[24..].try_into().unwrap());
    (receipts, count(after) - count(before))
}

#[test]
fn blocks_of_point_evaluations_execute_within_the_kernel_gas() {
    let config = NodeConfig {
        now_ms: 1_000,
        key: Some(keys(1)[0].clone()),
        kernel_gas: BLOCK_KERNEL_GAS,
        ..NodeConfig::default()
    };
    let mut node = Node::open(v1(), &genesis(), config).unwrap();
    node.set_backend(Backend::Native);
    node.start(None).unwrap();
    let mut blocks = Vec::new();
    tick(&mut node, &mut blocks);
    assert_eq!(node.upgrades().active() >> 2 & 1, 0);

    // Before gate 2: both transactions run in the same block; the guest's
    // point evaluations stop at the budget.
    let (receipts, passed) = fill(&mut node, 0, &mut blocks);
    assert_eq!(receipts[0].height, receipts[1].height);
    assert!(
        receipts
            .iter()
            .all(|r| r.status == 1 && r.gas_used > 12_000_000)
    );
    assert!((100..400).contains(&passed), "{passed} passed in the guest");
    let heaviest = *blocks.iter().max().unwrap();
    assert!(
        heaviest > BUDGET / 2 && heaviest < BUDGET + 256 * 30_000_000,
        "{heaviest}"
    );
    // Spec 19 §5.1 states this block's kernel gas.
    assert_eq!(heaviest, 17_113_678_145);

    // Once gate 2 is active, the module is in state and every call succeeds.
    for _ in 0..40 {
        if node.upgrades().active() >> 2 & 1 == 1 {
            break;
        }
        tick(&mut node, &mut blocks);
    }
    assert_eq!(
        node.upgrades().active() >> 2 & 1,
        1,
        "gate 2 never activated"
    );
    let module = include_bytes!("../../../guest/kernel/precompiles.orange");
    let key = [&b"code/"[..], &keccak256(module)].concat();
    let nonce = node.account(&alice().address).unwrap().nonce;
    let before_gate = blocks.len();
    let (receipts, passed) = fill(&mut node, nonce, &mut blocks);
    assert!(receipts.iter().all(|r| r.status == 1));
    assert_eq!(passed, 2 * CALLS as u64);
    assert_eq!(node.state_get(&key).as_deref(), Some(&module[..]));
    let heaviest = *blocks.iter().max().unwrap();
    assert!(heaviest < BLOCK_KERNEL_GAS as u64, "{heaviest}");
    // Spec 19 §5.1: the heaviest block once gate 2 is active.
    assert_eq!(*blocks[before_gate..].iter().max().unwrap(), 56_782_486);

    // Every block was finalized, and the chain goes on.
    let height = node.executed.last().unwrap().0;
    support::run_until(&mut node, 10, &mut |n| {
        n.finalized.last().is_some_and(|h| *h > height)
    });
    println!("kernel gas per block: {blocks:?}");
}

/// A call query served once gate 2 is active, before any block has installed
/// the module, writes nothing (spec 06 §6, spec 19 §3.2): the node that
/// served it holds the same state as one that did not, and both spend the
/// same kernel gas on the next block, which installs the module on both.
#[test]
fn a_call_query_at_the_gate_leaves_no_trace() {
    let open = || {
        let config = NodeConfig {
            now_ms: 1_000,
            key: Some(keys(1)[0].clone()),
            ..NodeConfig::default()
        };
        let mut node = Node::open(v1(), &genesis(), config).unwrap();
        node.start(None).unwrap();
        node
    };
    let (mut a, mut b) = (open(), open());
    let (mut gas_a, mut gas_b) = (Vec::new(), Vec::new());
    for _ in 0..40 {
        if a.upgrades().active() >> 2 & 1 == 1 {
            break;
        }
        tick(&mut a, &mut gas_a);
        tick(&mut b, &mut gas_b);
    }
    assert_eq!(a.upgrades().active() >> 2 & 1, 1, "gate 2 never activated");
    assert_eq!(b.upgrades().active(), a.upgrades().active());
    let module = include_bytes!("../../../guest/kernel/precompiles.orange");
    let key = [&b"code/"[..], &keccak256(module)].concat();
    assert!(a.state_get(&key).is_none());
    let root = a.state_root();

    let outcome = a
        .call(&CallRequest {
            from: alice().address,
            to: Some([0xEE; 20]),
            ..CallRequest::default()
        })
        .unwrap();
    assert_eq!(outcome.status, call_status::SUCCESS);
    assert!(a.state_get(&key).is_none());
    assert_eq!(a.state_root(), root);

    let (height_a, height_b) = (a.executed.len(), b.executed.len());
    while a.executed.len() == height_a {
        tick(&mut a, &mut gas_a);
    }
    while b.executed.len() == height_b {
        tick(&mut b, &mut gas_b);
    }
    assert_eq!(gas_a.last(), gas_b.last());
    assert_eq!(a.state_root(), b.state_root());
    assert_eq!(a.state_get(&key).as_deref(), Some(&module[..]));
}
