//! Governed kernel upgrades end to end (spec 06 §7, spec 13): the reference
//! kernel uploads, proposes and cancels a new kernel through transactions to
//! the upgrade address; the host prepares it ahead of time and switches at
//! exactly the activation height, on one node and across four validators,
//! keeping chain state, finality and the driver's state; a validator that
//! crashes across the activation height catches up through it; and a switch
//! that cannot complete halts the node.

mod support;

use solo_abi::chain::{BlockHeader, Receipt, SimplexState, reason};
use solo_abi::types::{Block, Effect, Genesis, MigrateArgs};
use solo_abi::{Decode, Encode};
use solo_host::hash::keccak256;
use solo_node::{Node, NodeConfig, NodeError, Sim, SubmitError, Switch};
use solo_upgrade::action::{cancelled_log, proposed_log};
use solo_upgrade::{Action, EnactedUpgrade, UPGRADE_ADDRESS, gate, query};
use solo_vm::host::Capability;
use solo_vm::status::Termination;
use support::{
    SLOT_MS, STAGE_GAS, Wallet, alice, genesis, governance, governed, include, keys, run_until,
    stage_actions, tiny_kernel, v1, v2,
};

const ETHER: u128 = support::ETHER;

fn start(genesis: &Genesis) -> Node {
    let config = NodeConfig {
        now_ms: 1_000,
        key: Some(keys(1)[0].clone()),
        ..NodeConfig::default()
    };
    let mut node = Node::open(v1(), genesis, config).unwrap();
    node.start(None).unwrap();
    node
}

/// Stages `code` from the governance account starting at `nonce`; returns the next nonce.
fn upload(node: &mut Node, code: &[u8], mut nonce: u64) -> u64 {
    for action in stage_actions(code) {
        let receipt = include(node, &governance().action(nonce, &action));
        assert_eq!(receipt.status, 1, "chunk {nonce}");
        nonce += 1;
    }
    nonce
}

fn propose(code_hash: [u8; 32], activation_height: u64) -> Action {
    Action::Propose {
        code_hash,
        activation_height,
        required_gates: 0,
    }
}

fn driver_view(node: &Node) -> u64 {
    SimplexState::from_bytes(node.persisted_driver_state.as_ref().unwrap())
        .unwrap()
        .view
}

#[test]
#[allow(clippy::too_many_lines)]
fn a_node_switches_kernels_at_the_activation_height() {
    let mut node = start(&genesis(&keys(1), governed(2, 0), 8));
    let (gov, alice, bob) = (governance(), alice(), Wallet::new(2));
    assert_eq!(node.kernel_version().unwrap(), 1);
    assert_eq!(node.kernel_hash(), keccak256(v1()));
    assert_eq!(node.upgrade_status().unwrap().version, 1);
    // State the upgrade must carry over.
    assert_eq!(
        include(&mut node, &alice.tx(0, bob.address, 5 * ETHER, 21_000, &[])).status,
        1
    );
    let code = v2();
    let code_hash = keccak256(code);
    let stages = stage_actions(code);
    assert!(stages.len() > 10);
    // Admission turns away a transaction to the upgrade address that cannot
    // run, before the nonce and balance checks; and one signed without a
    // chain id, which could have been replayed from another chain.
    let rejected = Err(SubmitError::Rejected(reason::SYSTEM_ACTION));
    for raw in [
        alice.action(1, &stages[0]),
        alice.action(7, &stages[0]),
        Wallet::new(9).action(0, &stages[0]),
        gov.unprotected_tx(0, UPGRADE_ADDRESS, STAGE_GAS, &stages[0].encode()),
        gov.tx(0, UPGRADE_ADDRESS, 1, STAGE_GAS, &stages[0].encode()),
        gov.tx(0, UPGRADE_ADDRESS, 0, STAGE_GAS, b"not an action"),
        gov.action(0, &Action::Signal { features: 1 }),
    ] {
        assert_eq!(node.submit(&raw), rejected);
    }
    let mut nonce = upload(&mut node, code, 0);
    // Too soon, no block after it, or code never staged: the proposal
    // reverts, gas and nonce spent.
    let next = node.block_number().unwrap() + 1;
    for action in [
        propose(code_hash, next + 1),
        propose(code_hash, u64::MAX),
        propose([9; 32], next + 50),
    ] {
        let receipt = include(&mut node, &gov.action(nonce, &action));
        assert_eq!((receipt.status, receipt.logs.0.len()), (0, 0));
        nonce += 1;
    }
    assert_eq!(node.upgrade_status().unwrap().pending, None);
    // A proposal the host validates and compiles at once.
    let h = node.block_number().unwrap() + 20;
    let receipt = include(&mut node, &gov.action(nonce, &propose(code_hash, h)));
    nonce += 1;
    assert_eq!(receipt.status, 1);
    assert_eq!(receipt.logs.0, vec![proposed_log(&code_hash, h, 0)]);
    let pending = node.upgrade_status().unwrap().pending.unwrap();
    assert_eq!(
        (
            pending.code_hash,
            pending.activation_height,
            pending.proposed_at
        ),
        (code_hash, h, receipt.height)
    );
    assert_eq!(
        (pending.size as usize, pending.chunks as usize),
        (code.len(), stages.len())
    );
    assert_eq!(node.upgrades().prepared, Some(code_hash));
    assert_eq!(node.upgrades().alert, None);
    // Its code is frozen, one upgrade is pending at a time, and only it can be cancelled.
    for action in [
        stages[0].clone(),
        propose(code_hash, h + 10),
        Action::Cancel { code_hash: [9; 32] },
    ] {
        assert_eq!(include(&mut node, &gov.action(nonce, &action)).status, 0);
        nonce += 1;
    }
    let receipt = include(&mut node, &gov.action(nonce, &Action::Cancel { code_hash }));
    nonce += 1;
    assert_eq!(receipt.status, 1);
    assert_eq!(receipt.logs.0, vec![cancelled_log(&code_hash)]);
    assert_eq!(node.upgrade_status().unwrap().pending, None);
    assert_eq!(node.upgrades().prepared, None);
    assert!(node.upgrades().switches.is_empty());
    // Proposed again from the chunks still staged, at the earliest height the delay allows.
    let h = node.block_number().unwrap() + 1 + 2;
    assert_eq!(
        include(&mut node, &gov.action(nonce, &propose(code_hash, h))).status,
        1
    );
    nonce += 1;
    run_until(&mut node, 20, &mut |n| n.block_number().unwrap() >= h + 2);
    // The old kernel executed and finalized `h`; the new one everything after.
    assert_eq!(
        node.upgrades().switches,
        vec![Switch {
            height: h,
            code_hash,
            from_version: 1,
            to_version: 2,
            held: 0
        }]
    );
    assert_eq!(node.kernel_hash(), code_hash);
    assert_eq!(node.kernel_version().unwrap(), 2);
    let version = node.query(query::KERNEL_VERSION, &[]).unwrap();
    assert_eq!(u32::from_bytes(&version.body), Ok(2));
    let status = node.upgrade_status().unwrap();
    assert_eq!((status.version, &status.pending), (2, &None));
    assert_eq!(
        status.enacted,
        Some(EnactedUpgrade {
            code_hash,
            height: h,
            from_version: 1,
            to_version: 2
        })
    );
    assert_eq!(node.upgrades().status.as_ref(), Some(&status));
    // The chain goes on from the same state, finalizing as before.
    let at_h = node.block_by_number(h).unwrap().unwrap();
    let after = node.block_by_number(h + 1).unwrap().unwrap();
    assert_eq!(after.parent_hash, keccak256(&at_h.to_bytes()));
    assert!(node.finalized.contains(&h) && node.finalized.contains(&(h + 2)));
    assert_eq!(
        node.finalized_height().unwrap(),
        node.block_number().unwrap()
    );
    assert_eq!(node.account(&bob.address).unwrap().balance, 5 * ETHER);
    // The new driver resumed the old one's state: its views continue past `h`.
    assert!(driver_view(&node) > h);
    let receipt: Receipt = include(&mut node, &alice.tx(1, bob.address, ETHER, 21_000, &[]));
    assert_eq!(receipt.status, 1);
    assert_eq!(node.account(&bob.address).unwrap().balance, 6 * ETHER);
    // The running kernel's code is frozen for good, and it cannot be proposed again.
    let restage = Action::Stage {
        code_hash,
        index: 0,
        chunk: vec![0xAA; 32],
    };
    let far = node.block_number().unwrap() + 50;
    for action in [
        restage,
        stages[stages.len() - 1].clone(),
        propose(code_hash, far),
    ] {
        assert_eq!(include(&mut node, &gov.action(nonce, &action)).status, 0);
        nonce += 1;
    }
    assert_eq!(node.upgrade_status().unwrap().pending, None);
    // The new kernel serves the staged code of itself, and nothing for an unknown hash.
    let code_query = node.query(query::CODE, &code_hash).unwrap();
    assert_eq!(Vec::<u8>::from_bytes(&code_query.body).unwrap(), code);
    assert_eq!(node.query(query::CODE, &[9; 32]).unwrap().status, 1);
    assert_eq!(node.query(query::CODE, &[9; 3]).unwrap().status, 2);
    assert_eq!(node.query("no_such_method", &[]).unwrap().status, 3);
    assert!(!node.resolves("secp256k1_verify", Capability::Privileged));
    assert_eq!(node.upgrades().held(), 0);
    assert_eq!(node.upgrades().halted(), None);
}

/// Runs a fresh single-validator chain that stages `code` and proposes it,
/// until the node fails; returns the error, the activation height and the node.
fn halt_at_switch(code: &[u8]) -> (NodeError, u64, Node) {
    let mut node = start(&genesis(&keys(1), governed(1, 0), 8));
    let nonce = upload(&mut node, code, 0);
    let h = node.block_number().unwrap() + 3;
    let action = propose(keccak256(code), h);
    assert_eq!(
        include(&mut node, &governance().action(nonce, &action)).status,
        1
    );
    for _ in 0..10 {
        let t = node.now_ms() + SLOT_MS;
        if let Err(e) = node.tick(t) {
            return (e, h, node);
        }
    }
    panic!("the node did not halt");
}

#[test]
fn a_switch_that_cannot_complete_halts_the_node() {
    // A migrate that traps.
    let (err, h, mut node) = halt_at_switch(&tiny_kernel(&3u32.to_le_bytes(), true, None));
    assert_eq!(
        err,
        NodeError::Kernel {
            export: "kernel_migrate",
            status: Termination::Trap
        }
    );
    // The old kernel stopped at `h`, and the node stays halted.
    assert_eq!(node.block_number().unwrap(), h);
    assert_eq!(node.kernel_hash(), keccak256(v1()));
    assert_eq!(node.upgrades().halted(), Some(&err));
    assert!(node.upgrades().switches.is_empty());
    let t = node.now_ms() + 10 * SLOT_MS;
    assert_eq!(node.tick(t), Err(err.clone()));
    assert_eq!(node.start(None), Err(err));
    // A host that ran the superseded kernel past `h` anyway would halt there too.
    let parent = node.block_by_number(h).unwrap().unwrap();
    let header = BlockHeader {
        height: h + 1,
        parent_hash: keccak256(&parent.to_bytes()),
        timestamp_ms: parent.timestamp_ms + SLOT_MS,
        ..BlockHeader::default()
    };
    let block = Block {
        header: header.to_bytes(),
        ..Block::default()
    };
    assert_eq!(
        node.apply_effect(Effect::ExecuteBlock { block }),
        Err(NodeError::Kernel {
            export: "kernel_stf_execute_block",
            status: Termination::Trap
        })
    );

    // A module this host cannot load: an alert from the moment it is proposed, then a halt.
    let (err, h, node) = halt_at_switch(b"not a module");
    let alert = node.upgrades().alert.clone().unwrap();
    assert!(alert.contains("cannot load"), "{alert}");
    assert_eq!(node.upgrades().prepared, None);
    let NodeError::Upgrade(why) = &err else {
        panic!("{err:?}")
    };
    assert!(
        why.contains(&format!("no runnable kernel at height {h}")),
        "{why}"
    );
    assert!(err.to_string().contains("kernel upgrade halted the node"));

    // A kernel whose version does not decode: an alert from the moment it is proposed, then a halt.
    let (err, h, node) = halt_at_switch(&tiny_kernel(&[3, 0], false, None));
    let alert = node.upgrades().alert.clone().unwrap();
    assert!(alert.contains("cannot read the version"), "{alert}");
    assert!(alert.contains("kernel_version"), "{alert}");
    assert_eq!(
        err,
        NodeError::Upgrade(format!("no runnable kernel at height {h}: {alert}"))
    );
}

#[test]
fn an_upgrade_that_does_not_supersede_the_running_kernel_alerts_then_halts() {
    // The running kernel itself, proposed again: its migrate would trap at
    // `h` on every node, so the host says so while governance can cancel.
    let (err, h, node) = halt_at_switch(v1());
    let alert = node.upgrades().alert.clone().unwrap();
    assert!(
        alert.contains("is version 1, which does not supersede the running version 1"),
        "{alert}"
    );
    assert_eq!(node.upgrades().prepared, None);
    assert_eq!(
        err,
        NodeError::Upgrade(format!("no runnable kernel at height {h}: {alert}"))
    );
    assert_eq!(node.kernel_hash(), keccak256(v1()));
}

#[test]
fn the_reference_migrate_accepts_only_its_predecessor_at_the_activation_height() {
    let mut node = start(&genesis(&keys(1), governed(1, 0), 8));
    let code = v2();
    let code_hash = keccak256(code);
    let nonce = upload(&mut node, code, 0);
    let h = node.block_number().unwrap() + 4;
    let receipt = include(
        &mut node,
        &governance().action(nonce, &propose(code_hash, h)),
    );
    assert_eq!(receipt.status, 1);
    run_until(&mut node, 10, &mut |n| n.block_number().unwrap() >= h - 1);
    assert_eq!(node.block_number().unwrap(), h - 1);
    assert_eq!(node.upgrades().prepared, Some(code_hash));
    let driver_state = node.driver_state().unwrap();
    let migrate = |from_version: u32| {
        MigrateArgs {
            from_version,
            driver_state: driver_state.clone(),
        }
        .to_bytes()
    };
    let trap = Err(NodeError::Kernel {
        export: "kernel_migrate",
        status: Termination::Trap,
    });
    // Before the activation height, even from its predecessor.
    assert_eq!(
        node.call_module(code_hash, "kernel_migrate", &migrate(1)),
        trap
    );
    // The old kernel executes block `h`, by hand so that no switch follows.
    let parent = node.block_by_number(h - 1).unwrap().unwrap();
    let header = BlockHeader {
        height: h,
        parent_hash: keccak256(&parent.to_bytes()),
        timestamp_ms: parent.timestamp_ms + SLOT_MS,
        ..BlockHeader::default()
    };
    let block = Block {
        header: header.to_bytes(),
        ..Block::default()
    };
    node.apply_effect(Effect::ExecuteBlock { block }).unwrap();
    assert_eq!(node.block_number().unwrap(), h);
    // At `h`, any version but the one it supersedes traps, its own included.
    for from_version in [0, 2, 3, u32::MAX] {
        assert_eq!(
            node.call_module(code_hash, "kernel_migrate", &migrate(from_version)),
            trap,
            "from {from_version}"
        );
    }
    assert_eq!(node.upgrade_status().unwrap().enacted, None);
    assert_eq!(
        node.call_module(code_hash, "kernel_migrate", &migrate(1)),
        Ok(Vec::new())
    );
    let enacted = EnactedUpgrade {
        code_hash,
        height: h,
        from_version: 1,
        to_version: 2,
    };
    let status = node.upgrade_status().unwrap();
    assert_eq!((status.pending, status.enacted), (None, Some(enacted)));
}

#[test]
fn a_cancel_in_the_activation_block_stops_the_switch() {
    let mut node = start(&genesis(&keys(1), governed(1, 0), 8));
    let tiny = tiny_kernel(&2u32.to_le_bytes(), false, None);
    let code_hash = keccak256(&tiny);
    let nonce = upload(&mut node, &tiny, 0);
    let h = node.block_number().unwrap() + 4;
    let receipt = include(
        &mut node,
        &governance().action(nonce, &propose(code_hash, h)),
    );
    assert_eq!(receipt.status, 1);
    assert_eq!(node.upgrades().prepared, Some(code_hash));
    run_until(&mut node, 10, &mut |n| n.block_number().unwrap() >= h - 1);
    let cancel = governance().action(nonce + 1, &Action::Cancel { code_hash });
    let receipt = include(&mut node, &cancel);
    assert_eq!((receipt.status, receipt.height), (1, h));
    run_until(&mut node, 10, &mut |n| n.block_number().unwrap() >= h + 2);
    assert!(node.upgrades().switches.is_empty());
    assert_eq!(node.upgrade_status().unwrap().pending, None);
    assert_eq!(node.kernel_version().unwrap(), 1);
    assert_eq!(node.upgrades().halted(), None);
}

#[test]
fn an_upgrade_needing_a_gate_that_is_not_active_lapses() {
    let mut node = start(&genesis(&keys(1), governed(1, 0), 8));
    let tiny = tiny_kernel(&2u32.to_le_bytes(), false, Some("secp256k1_verify"));
    let nonce = upload(&mut node, &tiny, 0);
    let h = node.block_number().unwrap() + 3;
    let action = Action::Propose {
        code_hash: keccak256(&tiny),
        activation_height: h,
        required_gates: 1 << gate::SECP256K1_VERIFY,
    };
    assert_eq!(
        include(&mut node, &governance().action(nonce, &action)).status,
        1
    );
    // This host could not load it before its gate is active, and says so.
    assert!(
        node.upgrades()
            .alert
            .as_ref()
            .unwrap()
            .contains("cannot load")
    );
    run_until(&mut node, 10, &mut |n| n.block_number().unwrap() >= h + 2);
    // Gates are off on this chain, so the upgrade lapsed at `h` and the old kernel goes on.
    assert!(node.upgrades().switches.is_empty());
    assert_eq!(node.upgrade_status().unwrap().pending, None);
    assert_eq!(
        (
            node.upgrades().alert.clone(),
            node.kernel_version().unwrap()
        ),
        (None, 1)
    );
}

/// Submits `raw` to node `live[0]` (gossip takes it to the others) and runs
/// the network until every live node has executed it.
fn sim_include(sim: &mut Sim, live: &[usize], raw: &[u8]) -> Receipt {
    let hash = sim.submit(live[0], raw).unwrap();
    let mut seen = vec![usize::MAX; sim.nodes.len()];
    let mut done = vec![false; sim.nodes.len()];
    let reached = sim
        .run_until(40 * SLOT_MS, |s| {
            for &i in live {
                if s.nodes[i].executed.len() != seen[i] {
                    seen[i] = s.nodes[i].executed.len();
                    done[i] = s.nodes[i].receipt(&hash).unwrap().is_some();
                }
            }
            live.iter().all(|&i| done[i])
        })
        .unwrap();
    assert!(reached, "transaction not executed everywhere");
    sim.nodes[live[0]].receipt(&hash).unwrap().unwrap()
}

/// Every node in `live` executed the same blocks, prefix-wise.
fn assert_agreement(sim: &Sim, live: &[usize]) {
    let longest = live
        .iter()
        .map(|&i| sim.nodes[i].executed.clone())
        .max_by_key(Vec::len)
        .unwrap();
    for &i in live {
        let mine = &sim.nodes[i].executed;
        assert_eq!(&longest[..mine.len()], mine.as_slice(), "node {i} diverges");
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn four_validators_switch_together_and_a_crashed_one_catches_up() {
    let validators = keys(4);
    let genesis = genesis(&validators, governed(3, 4), 16);
    let template = NodeConfig {
        now_ms: 10_000,
        ..NodeConfig::default()
    };
    let mut sim = Sim::new(v1(), &genesis, &validators, 0, &template, 30).unwrap();
    let all = [0, 1, 2, 3];
    let gov = governance();
    let code = v2();
    let code_hash = keccak256(code);
    let mut nonce = 0;
    for action in stage_actions(code) {
        assert_eq!(
            sim_include(&mut sim, &all, &gov.action(nonce, &action)).status,
            1
        );
        nonce += 1;
    }
    // Every validator's host signalled the gate it supports, epoch after epoch: it locked in.
    let book = sim.nodes[0].upgrade_status().unwrap().gates;
    assert_eq!(book.locked_in(), 1 << gate::SECP256K1_VERIFY, "{book:?}");
    let locked = book.record(gate::SECP256K1_VERIFY).cloned().unwrap();
    assert_eq!(locked.activation_height % 4, 1);
    // Activate at a height whose catch-up batch (16 blocks, spec 08) also carries the next blocks.
    let mut h = sim.nodes[0].block_number().unwrap() + 1 + 3 + 2;
    if h.is_multiple_of(16) {
        h += 1;
    }
    let receipt = sim_include(&mut sim, &all, &gov.action(nonce, &propose(code_hash, h)));
    assert_eq!(receipt.status, 1);
    for i in all {
        assert_eq!(
            sim.nodes[i].upgrades().prepared,
            Some(code_hash),
            "node {i}"
        );
    }
    // Validator 3 goes down before the activation height; the others switch without it.
    sim.crash(3);
    let live = [0, 1, 2];
    let reached = sim
        .run_until(60 * SLOT_MS, |s| {
            live.iter()
                .all(|&i| s.nodes[i].executed.last().is_some_and(|e| e.0 >= h + 3))
        })
        .unwrap();
    assert!(reached, "{:?}", sim.finalized_heights().unwrap());
    let switch = Switch {
        height: h,
        code_hash,
        from_version: 1,
        to_version: 2,
        held: 0,
    };
    for i in live {
        let node = &mut sim.nodes[i];
        assert_eq!(node.upgrades().switches.len(), 1, "node {i}");
        assert_eq!(
            Switch {
                held: 0,
                ..node.upgrades().switches[0].clone()
            },
            switch,
            "node {i}"
        );
        assert_eq!(node.kernel_version().unwrap(), 2);
        // Each new driver carried on from its node's old driver state.
        assert!(driver_view(node) > h, "node {i}");
    }
    assert_agreement(&sim, &live);
    // Restarted from genesis with the old kernel, it syncs through `h`, switches there and catches up.
    sim.revive(3, v1(), &genesis).unwrap();
    let target = sim.nodes[0].executed.last().unwrap().0;
    let reached = sim
        .run_until(120 * SLOT_MS, |s| {
            s.nodes[3].executed.last().is_some_and(|e| e.0 >= target)
        })
        .unwrap();
    assert!(reached, "{:?}", sim.finalized_heights().unwrap());
    let caught_up = &sim.nodes[3].upgrades().switches;
    assert_eq!(caught_up.len(), 1);
    assert_eq!(
        Switch {
            held: 0,
            ..caught_up[0].clone()
        },
        switch
    );
    // It had finalized blocks past `h` in the same catch-up batch: the new kernel executed them.
    assert!(caught_up[0].held > 0, "{caught_up:?}");
    assert_eq!(sim.nodes[3].kernel_hash(), code_hash);
    assert_agreement(&sim, &all);
    // The upgraded network keeps executing transactions and finalizing, every node alike.
    let bob = Wallet::new(2);
    let receipt = sim_include(
        &mut sim,
        &all,
        &alice().tx(0, bob.address, ETHER, 21_000, &[]),
    );
    assert_eq!(receipt.status, 1);
    assert!(receipt.height > h);
    for i in all {
        let node = &mut sim.nodes[i];
        assert_eq!(node.account(&bob.address).unwrap().balance, ETHER);
        // The gate, replayed by the restarted node too, is active everywhere at the same height.
        let gates = node.upgrade_status().unwrap().gates;
        assert_eq!(
            gates.record(gate::SECP256K1_VERIFY),
            Some(&locked),
            "node {i}"
        );
        assert!(
            node.resolves("secp256k1_verify", Capability::Privileged),
            "node {i}"
        );
    }
    assert_agreement(&sim, &all);
}
