//! Historical state (spec 20 §5): balances, nonces, code, storage and calls
//! at every height the node keeps, the genesis included, the error once a
//! height leaves the retention window, and an archive node that keeps all.

mod support;

use solo_abi::chain::{CallRequest, UpgradeParams, call_status};
use solo_abi::codec::Seq;
use solo_node::{ARCHIVE, Node, NodeConfig, NodeError};
use support::{ETHER, Wallet, alice, genesis, include, keys, v1};

/// Initcode `MSTORE(0, NUMBER); RETURN(0, 32)`: the block number a call sees.
const NUMBER: [u8; 7] = [0x43, 0x5F, 0x52, 0x60, 0x20, 0x5F, 0xF3];

fn node(history: usize) -> Node {
    let validators = keys(1);
    let config = NodeConfig {
        key: Some(validators[0].clone()),
        now_ms: 1_000,
        state_history: history,
        ..NodeConfig::default()
    };
    let mut node = Node::open(
        v1(),
        &genesis(&validators, UpgradeParams::default(), 10),
        config,
    )
    .unwrap();
    node.start(None).unwrap();
    node
}

fn number_call() -> CallRequest {
    CallRequest {
        to: None,
        data: NUMBER.to_vec(),
        access_list: Seq(Vec::new()),
        authorization_list: Seq(Vec::new()),
        ..CallRequest::default()
    }
}

#[test]
fn queries_answer_from_every_kept_height_and_refuse_pruned_ones() {
    let mut node = node(4);
    let bob = Wallet::new(0x42);
    let mut balances = vec![(node.block_number().unwrap(), 0u128)];
    for nonce in 0..6u64 {
        let receipt = include(
            &mut node,
            &alice().tx(nonce, bob.address, ETHER, 21_000, &[]),
        );
        balances.push((receipt.height, u128::from(nonce + 1) * ETHER));
    }
    let head = node.block_number().unwrap();
    assert_eq!(node.oldest_state(), head - 3);
    // Every kept height answers with the state right after that block.
    for (height, expected) in &balances {
        if *height < head - 3 {
            continue;
        }
        let at = Some(*height);
        assert_eq!(
            node.account_at(&bob.address, at).unwrap().balance,
            *expected,
            "{height}"
        );
        // Within a block's own state Bob's balance is exactly its transfers.
        let alice_nonce = node.account_at(&alice().address, at).unwrap().nonce;
        assert_eq!(u128::from(alice_nonce) * ETHER, *expected);
    }
    // The head, by number, is the current state.
    assert_eq!(
        node.account_at(&bob.address, Some(head)).unwrap().balance,
        6 * ETHER
    );
    // A call at a height sees that block's number.
    let at = head - 2;
    let result = node.call_at(&number_call(), Some(at)).unwrap();
    assert_eq!(result.status, call_status::SUCCESS);
    assert_eq!(result.output[24..], at.to_be_bytes());
    assert!(node.code_at(&bob.address, Some(at)).unwrap().is_empty());
    assert_eq!(
        node.storage_at(&bob.address, &[0; 32], Some(at)).unwrap(),
        [0; 32]
    );
    // Below the window, and above the head, there is no state to read.
    let pruned = node.account_at(&bob.address, Some(head - 4)).unwrap_err();
    assert_eq!(
        pruned,
        NodeError::StateUnavailable {
            height: head - 4,
            oldest: head - 3
        }
    );
    assert_eq!(
        pruned.to_string(),
        format!(
            "state of block {} is not available: the node keeps the state from block {}",
            head - 4,
            head - 3
        )
    );
    assert!(matches!(
        node.account_at(&bob.address, Some(head + 1)),
        Err(NodeError::StateUnavailable { .. })
    ));
    // A failed historical query leaves the node reading the current state.
    assert_eq!(node.account(&bob.address).unwrap().balance, 6 * ETHER);
}

#[test]
fn an_archive_node_keeps_the_genesis_state() {
    let mut node = node(ARCHIVE);
    let bob = Wallet::new(0x43);
    for nonce in 0..3u64 {
        include(
            &mut node,
            &alice().tx(nonce, bob.address, ETHER, 21_000, &[]),
        );
    }
    assert_eq!(node.oldest_state(), 0);
    assert_eq!(
        node.account_at(&alice().address, Some(0)).unwrap().balance,
        100 * ETHER
    );
    assert_eq!(node.account_at(&bob.address, Some(0)).unwrap().balance, 0);
    // Its tries reach back to the first block.
    assert!(node.state_proof_at(1, b"meta/chain_id").is_some());
}
