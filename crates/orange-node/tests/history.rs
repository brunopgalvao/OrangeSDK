//! Historical state (spec 20 §5): balances, nonces, code, storage and calls
//! at every height the node keeps, the genesis included, the error once a
//! height leaves the retention window, and an archive node that keeps all.

mod support;

use orange_abi::chain::{CallRequest, UpgradeParams, call_status};
use orange_abi::codec::Seq;
use orange_node::{ARCHIVE, Node, NodeConfig, NodeError};
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
fn an_archive_node_keeps_what_a_windowed_node_prunes() {
    let mut archive = node(ARCHIVE);
    let mut windowed = node(2);
    let bob = Wallet::new(0x43);
    let mut paid_at = Vec::new();
    for nonce in 0..3u64 {
        let transfer = alice().tx(nonce, bob.address, ETHER, 21_000, &[]);
        paid_at.push(include(&mut archive, &transfer).height);
        include(&mut windowed, &transfer);
    }
    // The same blocks; the node with a window of two kept the last two.
    let head = archive.block_number().unwrap();
    assert_eq!(windowed.block_number().unwrap(), head);
    assert_eq!(windowed.oldest_state(), head - 1);
    for height in 0..head - 1 {
        assert!(windowed.account_at(&bob.address, Some(height)).is_err());
        assert!(windowed.state_proof_at(height, b"meta/chain_id").is_none());
    }
    // The archive node keeps every height's state and trie, the genesis
    // included.
    assert_eq!(archive.oldest_state(), 0);
    for height in 0..=head {
        assert!(archive.state_proof_at(height, b"meta/chain_id").is_some());
        let transfers = paid_at.iter().filter(|h| **h <= height).count();
        assert_eq!(
            archive
                .account_at(&bob.address, Some(height))
                .unwrap()
                .balance,
            u128::try_from(transfers).unwrap() * ETHER,
            "{height}"
        );
    }
    assert_eq!(
        archive
            .account_at(&alice().address, Some(0))
            .unwrap()
            .balance,
        100 * ETHER
    );
}

#[test]
fn blocks_that_write_more_keys_than_the_budget_shorten_the_window() {
    // A window of 1 000 blocks, longer than the chain, with no key writes of
    // history allowed: whatever a block writes is over budget, so the node
    // keeps the head's state only, and its trie only.
    let mut node = node(1_000);
    node.history_keys_per_block = 0;
    let bob = Wallet::new(0x44);
    include(&mut node, &alice().tx(0, bob.address, ETHER, 21_000, &[]));
    let head = node.block_number().unwrap();
    assert_eq!(node.oldest_state(), head);
    assert_eq!(node.state().base().history_keys(), 0);
    assert_eq!(
        node.account_at(&bob.address, Some(head - 1)),
        Err(NodeError::StateUnavailable {
            height: head - 1,
            oldest: head
        })
    );
    assert!(node.state_proof_at(head - 1, b"meta/chain_id").is_none());
    assert!(node.state_proof_at(head, b"meta/chain_id").is_some());
    // One key write per block of the window, 1 000 in all: the next blocks
    // fit, and the window grows again from where it was.
    node.history_keys_per_block = 1;
    for nonce in 1..3u64 {
        include(
            &mut node,
            &alice().tx(nonce, bob.address, ETHER, 21_000, &[]),
        );
    }
    assert!(node.block_number().unwrap() > head);
    assert_eq!(node.oldest_state(), head);
    let writes = node.state().base().history_keys();
    assert!((1..=1_000).contains(&writes), "{writes}");
    assert_eq!(
        node.account_at(&bob.address, Some(head)).unwrap().balance,
        ETHER
    );
    assert!(node.state_proof_at(head, b"meta/chain_id").is_some());
}
