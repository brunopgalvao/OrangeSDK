//! Chain state on disk (spec 22): a node resumes from its store in constant
//! time with the same state, history and proofs it had; a crash inside a
//! block's write leaves the block before and the driver finalizes it again;
//! a restart between a block's write and the driver's takes the block from
//! the log; a kernel switch survives a restart; and a validator of a
//! simulated network restarts from its store while the others keep
//! finalizing.

mod support;

use std::collections::BTreeMap;
use std::path::Path;

use solo_abi::chain::{Account, BlockHeader, UpgradeParams};
use solo_host::Storage;
use solo_host::hash::keccak256;
use solo_node::{Node, NodeConfig, NodeError, Sim, StoreConfig};
use solo_scratch::Scratch;
use solo_store::Fault;
use solo_upgrade::Action;
use support::{
    ETHER, SLOT_MS, Wallet, alice, genesis, governance, governed, include, keys, run_until,
    stage_actions, tiny_kernel, v1, v2,
};

fn scratch(name: &str) -> Scratch {
    Scratch::new("node-store", name)
}

/// A single validator's configuration over `dir`, keeping four heights.
fn config(dir: &Path) -> NodeConfig {
    NodeConfig {
        key: Some(keys(1)[0].clone()),
        now_ms: 1_000,
        state_history: 4,
        store: StoreConfig::Disk(dir.to_path_buf()),
        ..NodeConfig::default()
    }
}

/// What a client could ask the node about every kept height: accounts,
/// the header, and the proof of Bob's account against it.
type Answers = BTreeMap<u64, (Account, Account, Option<BlockHeader>, Vec<u8>, [u8; 32])>;

fn answers(node: &mut Node, bob: &[u8; 20]) -> Answers {
    let head = node.block_number().unwrap();
    let key = [b"acct/".as_slice(), bob].concat();
    (node.oldest_state()..=head)
        .map(|h| {
            let proof = node.state_proof_at(h, &key).unwrap().encode();
            let root = if h == 0 {
                node.genesis_state_root()
            } else {
                node.block_by_number(h).unwrap().unwrap().state_root
            };
            (
                h,
                (
                    node.account_at(bob, Some(h)).unwrap(),
                    node.account_at(&alice().address, Some(h)).unwrap(),
                    node.block_by_number(h).unwrap(),
                    proof,
                    root,
                ),
            )
        })
        .collect()
}

/// The node reopened over the same directory with the driver data it had.
fn reopen(dir: &Path, kernel: &[u8], persisted: BTreeMap<Vec<u8>, Vec<u8>>, now_ms: u64) -> Node {
    let config = NodeConfig {
        persisted,
        now_ms,
        ..config(dir)
    };
    Node::open(
        kernel,
        &genesis(&keys(1), UpgradeParams::default(), 10),
        config,
    )
    .unwrap()
}

#[test]
fn a_node_resumes_from_its_store_with_the_same_state_history_and_proofs() {
    let dir = scratch("resume");
    let genesis = genesis(&keys(1), UpgradeParams::default(), 10);
    let mut node = Node::open(v1(), &genesis, config(&dir)).unwrap();
    assert!(node.chain_store().is_some());
    node.start(None).unwrap();
    let bob = Wallet::new(0x42);
    for nonce in 0..6u64 {
        include(
            &mut node,
            &alice().tx(nonce, bob.address, ETHER, 21_000, &[]),
        );
    }
    let head = node.block_number().unwrap();
    assert_eq!(node.oldest_state(), head - 3);
    let before = answers(&mut node, &bob.address);
    let (root, genesis_root) = (node.state_root(), node.genesis_state_root());
    // The flat state and the window's key writes, as the store holds them.
    let accounts = node.state().base().scan(b"acct/");
    let history = node.state().base().history_keys();
    assert!(accounts.len() >= 2 && history > 0, "{history}");
    let stats = node.chain_store().unwrap().stats();
    assert!(stats.write_bytes > 0 && stats.versions == 4, "{stats:?}");
    let (persisted, resumed, now) = (
        node.persisted(),
        node.persisted_driver_state.clone(),
        node.now_ms(),
    );
    drop(node);
    // Reopened: the head, the state and the history are there before the
    // driver starts, and starting it executes nothing again.
    let started = std::time::Instant::now();
    let mut again = reopen(&dir, v1(), persisted, now);
    let opened_in = started.elapsed();
    assert!(again.executed.is_empty() && again.finalized.is_empty());
    assert_eq!(again.block_number().unwrap(), head);
    assert_eq!(again.state_root(), root);
    assert_eq!(again.genesis_state_root(), genesis_root);
    assert_eq!(again.oldest_state(), head - 3);
    assert_eq!(again.kernel_hash(), keccak256(v1()));
    assert_eq!(again.chain_store().unwrap().stats().versions, 4);
    assert_eq!(again.state().base().scan(b"acct/"), accounts);
    assert_eq!(again.state().base().history_keys(), history);
    // Its status reports the height it took up, before the driver starts
    // and before it finalizes anything new.
    let reported = again.status().unwrap();
    assert_eq!((reported.head, reported.finalized), (head, head));
    again.start(resumed).unwrap();
    assert!(again.executed.is_empty(), "{:?}", again.executed);
    assert_eq!(again.finalized_height().unwrap(), head);
    assert_eq!(answers(&mut again, &bob.address), before);
    eprintln!("reopened in {opened_in:?}");
    // The chain goes on from there, the window moving with it.
    include(&mut again, &alice().tx(6, bob.address, ETHER, 21_000, &[]));
    let later = again.block_number().unwrap();
    assert!(later > head);
    assert_eq!(again.account(&bob.address).unwrap().balance, 7 * ETHER);
    assert_eq!(again.oldest_state(), later - 3);
    assert!(again.state_proof_at(later, b"meta/chain_id").is_some());
    assert!(again.state_proof_at(later - 4, b"meta/chain_id").is_none());
    assert_eq!(again.executed.len(), usize::try_from(later - head).unwrap());
}

#[test]
fn a_crash_inside_a_block_write_leaves_the_block_before() {
    let dir = scratch("crash-inside");
    let genesis = genesis(&keys(1), UpgradeParams::default(), 10);
    let mut node = Node::open(v1(), &genesis, config(&dir)).unwrap();
    node.start(None).unwrap();
    let bob = Wallet::new(0x43);
    for nonce in 0..2u64 {
        include(
            &mut node,
            &alice().tx(nonce, bob.address, ETHER, 21_000, &[]),
        );
    }
    let head = node.block_number().unwrap();
    // The driver's data as its store would hold it after the last good step.
    let (persisted, resumed, now) = (
        node.persisted(),
        node.persisted_driver_state.clone(),
        node.now_ms(),
    );
    // The next block's write fails as a crash in the middle of it would:
    // the step reports it, and the node is halted from then on.
    let third = alice().tx(2, bob.address, ETHER, 21_000, &[]);
    node.submit(&third).unwrap();
    node.inject_store_fault(Fault::DropNextCommit);
    let mut failed = None;
    for _ in 0..10 {
        let t = node.now_ms() + SLOT_MS;
        if let Err(e) = node.tick(t) {
            failed = Some(e);
            break;
        }
        // A transport would have synced and sent these.
        node.take_outbound();
    }
    let failed = failed.expect("the block's write fails");
    assert!(
        matches!(&failed, NodeError::Store(why) if why.contains("injected fault")),
        "{failed}"
    );
    assert_eq!(node.tick(node.now_ms() + SLOT_MS), Err(failed));
    // Nothing the failed step signed leaves the node: its driver state never
    // reached the disk, so a restart could sign otherwise in the same view.
    assert!(node.take_outbound().is_empty());
    drop(node);
    // Reopened: the state of the block before; the driver finalizes the
    // block again and the transaction lands.
    let mut again = reopen(&dir, v1(), persisted, now);
    assert_eq!(again.block_number().unwrap(), head);
    assert_eq!(again.account(&bob.address).unwrap().balance, 2 * ETHER);
    again.start(resumed).unwrap();
    assert!(again.executed.is_empty());
    again.submit(&third).unwrap();
    run_until(&mut again, 20, &mut |n| {
        n.receipt(&keccak256(&third)).unwrap().is_some()
    });
    assert_eq!(again.account(&bob.address).unwrap().balance, 3 * ETHER);
    assert!(again.block_number().unwrap() > head);
    assert!(
        again
            .metrics
            .iter()
            .all(|(name, _)| name != b"equivocations")
    );
}

#[test]
fn a_restart_between_the_block_and_the_driver_takes_the_block_from_the_log() {
    let dir = scratch("crash-between");
    let genesis = genesis(&keys(1), UpgradeParams::default(), 10);
    let mut node = Node::open(v1(), &genesis, config(&dir)).unwrap();
    node.start(None).unwrap();
    let bob = Wallet::new(0x44);
    for nonce in 0..2u64 {
        include(
            &mut node,
            &alice().tx(nonce, bob.address, ETHER, 21_000, &[]),
        );
    }
    let head = node.block_number().unwrap();
    let (persisted, resumed, now) = (
        node.persisted(),
        node.persisted_driver_state.clone(),
        node.now_ms(),
    );
    // One more block reaches the chain store; the driver's data does not.
    include(&mut node, &alice().tx(2, bob.address, ETHER, 21_000, &[]));
    let executed = node.block_number().unwrap();
    assert!(executed > head);
    drop(node);
    let mut again = reopen(&dir, v1(), persisted, now);
    assert_eq!(again.block_number().unwrap(), executed);
    again.start(resumed).unwrap();
    // The block is finalized by the log, not executed again, and the chain
    // goes on above it.
    assert!(again.executed.is_empty());
    assert_eq!(again.finalized_height().unwrap(), executed);
    assert_eq!(again.simplex_state().unwrap().finalized_height, executed);
    assert_eq!(again.simplex_state().unwrap().tip_height, executed);
    include(&mut again, &alice().tx(3, bob.address, ETHER, 21_000, &[]));
    assert!(again.block_number().unwrap() > executed);
    assert_eq!(again.account(&bob.address).unwrap().balance, 4 * ETHER);
    assert!(
        again
            .metrics
            .iter()
            .all(|(name, _)| name != b"equivocations")
    );
}

#[test]
fn a_kernel_switch_survives_a_restart() {
    let dir = scratch("switch");
    let genesis = genesis(&keys(1), governed(2, 0), 8);
    let config = NodeConfig {
        state_history: 1_024,
        ..config(&dir)
    };
    let mut node = Node::open(v1(), &genesis, config.clone()).unwrap();
    node.start(None).unwrap();
    let gov = governance();
    let mut nonce = 0;
    for action in stage_actions(v2()) {
        assert_eq!(include(&mut node, &gov.action(nonce, &action)).status, 1);
        nonce += 1;
    }
    let activation = node.block_number().unwrap() + 4;
    let proposal = Action::Propose {
        code_hash: keccak256(v2()),
        activation_height: activation,
        required_gates: 0,
    };
    assert_eq!(include(&mut node, &gov.action(nonce, &proposal)).status, 1);
    // Stopped with the upgrade pending: the restarted node prepares it
    // again and switches at the height.
    let stop = |node: &Node| {
        (
            node.persisted(),
            node.persisted_driver_state.clone(),
            node.now_ms(),
        )
    };
    let (persisted, resumed, now) = stop(&node);
    drop(node);
    let mut node = Node::open(
        v1(),
        &genesis,
        NodeConfig {
            persisted,
            now_ms: now,
            ..config.clone()
        },
    )
    .unwrap();
    assert_eq!(node.upgrades().prepared, Some(keccak256(v2())));
    node.start(resumed).unwrap();
    run_until(&mut node, 30, &mut |n| {
        n.block_number().unwrap() > activation + 1
    });
    assert_eq!(node.kernel_version().unwrap(), 2);
    assert_eq!(node.upgrades().switches.len(), 1);
    let switched_at = node.block_number().unwrap();
    // Stopped after the switch and restarted with the genesis kernel on the
    // command line: the store names the kernel that wrote it, whose code
    // chain state holds, and the node runs it.
    let (persisted, resumed, now) = stop(&node);
    drop(node);
    let mut node = Node::open(
        v1(),
        &genesis,
        NodeConfig {
            persisted: persisted.clone(),
            now_ms: now,
            ..config.clone()
        },
    )
    .unwrap();
    assert_eq!(node.kernel_hash(), keccak256(v2()));
    assert_eq!(node.kernel_version().unwrap(), 2);
    assert!(node.upgrades().switches.is_empty());
    assert_eq!(node.block_number().unwrap(), switched_at);
    node.start(resumed.clone()).unwrap();
    run_until(&mut node, 10, &mut |n| {
        n.block_number().unwrap() > switched_at
    });
    assert_eq!(node.kernel_version().unwrap(), 2);
    drop(node);
    // A kernel that is neither the one on the command line nor an upgrade
    // in chain state cannot have written the store.
    let other = tiny_kernel(&3u32.to_le_bytes(), false, None);
    let err = Node::open(
        &other,
        &genesis,
        NodeConfig {
            persisted,
            now_ms: now,
            ..config
        },
    )
    .err()
    .unwrap();
    assert!(
        matches!(&err, NodeError::Upgrade(why) if why.contains("neither")),
        "{err}"
    );
}

#[test]
fn a_validator_restarts_from_its_store_while_the_others_keep_finalizing() {
    let dir = scratch("sim");
    let validators = keys(4);
    let genesis = genesis(&validators, UpgradeParams::default(), 10);
    let template = NodeConfig {
        now_ms: 10_000,
        state_history: 64,
        ..NodeConfig::default()
    };
    let stores = [
        StoreConfig::Memory,
        StoreConfig::Memory,
        StoreConfig::Memory,
        StoreConfig::Disk(dir.to_path_buf()),
    ];
    let mut sim = Sim::with_stores(v1(), &genesis, &validators, 0, &template, 20, &stores).unwrap();
    let bob = Wallet::new(0x45);
    sim.submit(0, &alice().tx(0, bob.address, ETHER, 21_000, &[]))
        .unwrap();
    assert!(
        sim.run_until(20 * SLOT_MS, |s| s.nodes[3].finalized.len() >= 3
            && s.nodes[3].account(&bob.address).unwrap().balance == ETHER)
            .unwrap()
    );
    let stopped_at = sim.nodes[3].block_number().unwrap();
    let key = [b"acct/".as_slice(), &bob.address].concat();
    let proof_before = sim.nodes[3].state_proof_at(stopped_at, &key).unwrap();
    sim.crash(3);
    assert!(
        sim.run_until(20 * SLOT_MS, |s| s.nodes[0].finalized.len() >= 8)
            .unwrap()
    );
    // Revived from its store: at the height it stopped, nothing executed
    // again, the proof it had still there; then it syncs forward and signs.
    sim.revive(3, v1(), &genesis).unwrap();
    assert_eq!(sim.nodes[3].block_number().unwrap(), stopped_at);
    assert!(sim.nodes[3].executed.is_empty());
    assert_eq!(
        sim.nodes[3].state_proof_at(stopped_at, &key),
        Some(proof_before.clone())
    );
    let target = sim.nodes[0].finalized_height().unwrap() + 4;
    let caught_up = sim
        .run_until(30 * SLOT_MS, |s| {
            s.finalized_heights().unwrap().iter().all(|h| *h >= target)
        })
        .unwrap();
    assert!(caught_up, "{:?}", sim.finalized_heights().unwrap());
    let height = sim.nodes[3].finalized_height().unwrap();
    for i in 0..3 {
        assert_eq!(
            sim.nodes[i].block_by_number(height).unwrap(),
            sim.nodes[3].block_by_number(height).unwrap(),
            "node {i}"
        );
    }
    assert!(sim.nodes[3].executed.len() >= 4);
    assert!(sim.nodes[3].validator_id().is_some());
    assert_eq!(
        sim.nodes[3].state_proof_at(stopped_at, &key),
        Some(proof_before)
    );
    // Revived a second time, further on, it resumes from the later head.
    let later = sim.nodes[3].block_number().unwrap();
    sim.crash(3);
    sim.revive(3, v1(), &genesis).unwrap();
    assert_eq!(sim.nodes[3].block_number().unwrap(), later);
    assert!(sim.nodes[3].executed.is_empty());
    assert!(
        sim.nodes
            .iter()
            .all(|n| n.metrics.iter().all(|(name, _)| name != b"equivocations"))
    );
}
