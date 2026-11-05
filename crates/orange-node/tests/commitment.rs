//! The state commitment through a node running the reference kernel (spec
//! 10): the root the node keeps incrementally is the trie of its state and
//! its proofs verify against it; a block header's root is the state before
//! that block's own bookkeeping, which only the tries the node keeps per
//! block prove against; and nodes that executed the same blocks in different
//! batches commit to the same roots.

use k256::ecdsa::SigningKey;
use orange_abi::Encode;
use orange_abi::chain::{Allocation, BlockHeader, GenesisParams, keys};
use orange_abi::codec::Seq;
use orange_abi::types::{Block, Effect, Genesis};
use orange_host::hash::keccak256;
use orange_host::storage::committed;
use orange_node::{Node, NodeConfig, Sim};
use orange_rlp::{encode_bytes, encode_list, encode_uint};
use orange_trie::Trie;

const KERNEL: &[u8] = include_bytes!("fixtures/kernel.elf");
const CHAIN_ID: u64 = 1337;
const SLOT_MS: u64 = 400;
const ETHER: u128 = 1_000_000_000_000_000_000;

fn kernel_module() -> Vec<u8> {
    orange_recompile::recompile(
        &orange_recompile::Input::load(KERNEL).unwrap(),
        &orange_recompile::Options::default(),
    )
    .unwrap()
}

fn address(key: &SigningKey) -> [u8; 20] {
    let point = key.verifying_key().to_encoded_point(false);
    let digest = keccak256(&point.as_bytes()[1..]);
    let mut address = [0u8; 20];
    address.copy_from_slice(&digest[12..]);
    address
}

fn genesis(validators: &[SigningKey], funded: [u8; 20]) -> Genesis {
    let params = GenesisParams {
        slot_ms: SLOT_MS,
        max_txs: 8,
        allocations: Seq(vec![Allocation {
            address: funded,
            balance: 100 * ETHER,
            ..Allocation::default()
        }]),
        ..GenesisParams::default()
    };
    Genesis {
        chain_id: CHAIN_ID,
        fee_schedule: vec![],
        modules: Seq(vec![]),
        params: params.to_bytes(),
        validators: Sim::validator_set(validators).to_bytes(),
    }
}

/// An EIP-155 legacy transfer.
fn transfer(key: &SigningKey, nonce: u64, to: [u8; 20], value: u128) -> Vec<u8> {
    let fields = |out: &mut Vec<u8>| {
        encode_uint(u128::from(nonce), out);
        encode_uint(1_000_000_000, out);
        encode_uint(21_000, out);
        encode_bytes(&to, out);
        encode_uint(value, out);
        encode_bytes(&[], out);
    };
    let mut unsigned = Vec::new();
    fields(&mut unsigned);
    encode_uint(u128::from(CHAIN_ID), &mut unsigned);
    encode_uint(0, &mut unsigned);
    encode_uint(0, &mut unsigned);
    let mut list = Vec::new();
    encode_list(&unsigned, &mut list);
    let (sig, rid) = key.sign_prehash_recoverable(&keccak256(&list)).unwrap();
    let mut signed = Vec::new();
    fields(&mut signed);
    encode_uint(
        u128::from(CHAIN_ID * 2 + 35 + u64::from(rid.to_byte())),
        &mut signed,
    );
    let strip = |b: &[u8]| -> Vec<u8> {
        let skip = b.iter().take_while(|x| **x == 0).count();
        b[skip..].to_vec()
    };
    encode_bytes(&strip(&sig.r().to_bytes()), &mut signed);
    encode_bytes(&strip(&sig.s().to_bytes()), &mut signed);
    let mut out = Vec::new();
    encode_list(&signed, &mut out);
    out
}

/// The root by definition: a fresh trie over the node's committed entries.
fn rebuilt(node: &Node) -> [u8; 32] {
    let mut trie = Trie::new();
    for (key, value) in node.state().scan(&[]) {
        if committed(&key) {
            trie.insert(&key, &value);
        }
    }
    trie.root()
}

fn account_key(address: &[u8; 20]) -> Vec<u8> {
    let mut key = keys::ACCOUNT.to_vec();
    key.extend_from_slice(address);
    key
}

/// A single validator that has made `blocks` blocks, with a transfer from
/// `alice` in every third one.
fn chain(alice: &SigningKey, blocks: u64) -> (Node, [u8; 20]) {
    let validator = SigningKey::from_slice(&[0x42; 32]).unwrap();
    let bob = address(&SigningKey::from_slice(&[2; 32]).unwrap());
    let config = NodeConfig {
        now_ms: 1_000,
        key: Some(validator.clone()),
        ..NodeConfig::default()
    };
    let mut node = Node::open(
        &kernel_module(),
        &genesis(&[validator], address(alice)),
        config,
    )
    .unwrap();
    node.start(None).unwrap();
    for height in 1..=blocks {
        if height % 3 == 1 {
            node.submit(&transfer(alice, height / 3, bob, ETHER))
                .unwrap();
        }
        node.tick(1_000 + height * SLOT_MS).unwrap();
        assert_eq!(node.block_number().unwrap(), height);
    }
    (node, bob)
}

#[test]
fn the_kept_root_is_the_trie_of_the_state_and_proves_it() {
    let alice = SigningKey::from_slice(&[1; 32]).unwrap();
    let (node, bob) = chain(&alice, 4);
    let root = node.state_root();
    assert_eq!(root, rebuilt(&node));
    // Bob's account is in the state, with the value the store holds.
    let key = account_key(&bob);
    let value = node.state().get(&key).unwrap();
    let proof = node.state_proof(&key);
    assert_eq!(
        proof.verify(keccak256, &root, &key),
        Ok(Some(keccak256(&value)))
    );
    // A never-funded account, and the node-local finalized height, are not.
    let nobody = account_key(&[0x99; 20]);
    assert_eq!(
        node.state_proof(&nobody).verify(keccak256, &root, &nobody),
        Ok(None)
    );
    assert!(node.state().get(keys::FINALIZED).is_some());
    assert_eq!(orange_host::storage::LOCAL_PREFIX, keys::LOCAL);
    assert_eq!(
        node.state_proof(keys::FINALIZED)
            .verify(keccak256, &root, keys::FINALIZED),
        Ok(None)
    );
}

fn block_key(height: u64) -> Vec<u8> {
    [keys::BLOCK, &height.to_be_bytes()].concat()
}

/// What a proof against block `height`'s header root shows for `key`.
fn proven_at(node: &mut Node, height: u64, key: &[u8]) -> Option<[u8; 32]> {
    let header = node.block_by_number(height).unwrap().unwrap();
    node.state_proof_at(height, key)
        .unwrap()
        .verify(keccak256, &header.state_root, key)
        .unwrap()
}

#[test]
fn proofs_verify_against_block_headers() {
    // The kernel asks for the root after a block's transactions and receipts
    // and before it stores the header, the block hash, the height and the
    // last hash. So the state a node holds after block h is not what header
    // h commits to: proofs against a header come from the trie the node kept
    // when the kernel asked for that root.
    let alice = SigningKey::from_slice(&[1; 32]).unwrap();
    let (mut node, bob) = chain(&alice, 5);
    let bob_key = account_key(&bob);
    let header1 = node.block_by_number(1).unwrap().unwrap();
    assert_ne!(header1.state_root, node.state_root());
    assert_eq!(
        node.state_proof(&bob_key)
            .verify(keccak256, &header1.state_root, &bob_key),
        Err(orange_trie::ProofError::RootMismatch)
    );
    // Bob was paid in blocks 1 and 4: his account as each header has it.
    let after_one = proven_at(&mut node, 1, &bob_key);
    assert!(after_one.is_some());
    assert_eq!(proven_at(&mut node, 3, &bob_key), after_one);
    let after_four = proven_at(&mut node, 4, &bob_key);
    assert_ne!(after_four, after_one);
    let now = node.state().get(&bob_key).unwrap();
    assert_eq!(after_four, Some(keccak256(&now)));
    assert_eq!(proven_at(&mut node, 5, &bob_key), after_four);
    // A block's own header is in the next header's root, not its own.
    for height in 1..5 {
        let stored = node.state().get(&block_key(height)).unwrap();
        assert_eq!(proven_at(&mut node, height, &block_key(height)), None);
        assert_eq!(
            proven_at(&mut node, height + 1, &block_key(height)),
            Some(keccak256(&stored))
        );
    }
    // The genesis state is height 0's (spec 20 §4.3): Bob is not in it.
    let genesis = node.genesis_state_root();
    assert_eq!(
        node.state_proof_at(0, &bob_key)
            .unwrap()
            .verify(keccak256, &genesis, &bob_key),
        Ok(None)
    );
    // A height the node never executed has no trie.
    assert!(node.state_proof_at(6, &bob_key).is_none());
}

#[test]
fn the_node_keeps_the_tries_of_its_latest_blocks() {
    let alice = SigningKey::from_slice(&[1; 32]).unwrap();
    let (mut node, bob) = chain(&alice, 1);
    assert_eq!(node.state_history, orange_node::STATE_HISTORY);
    node.state_history = 2;
    let after_one = node.state_root();
    for height in 2..=4 {
        node.tick(1_000 + height * SLOT_MS).unwrap();
        assert_eq!(node.block_number().unwrap(), height);
    }
    // Block 2 has no transactions, so it writes nothing before its root:
    // its header commits to the state the node held after block 1.
    let empty = node.block_by_number(2).unwrap().unwrap();
    assert!(empty.tx_hashes.0.is_empty());
    assert_eq!(empty.state_root, after_one);
    let bob_key = account_key(&bob);
    for height in 1..=2 {
        assert!(node.state_proof_at(height, &bob_key).is_none(), "{height}");
    }
    for height in 3..=4 {
        assert!(proven_at(&mut node, height, &bob_key).is_some(), "{height}");
    }
}

#[test]
fn headers_carry_the_commitment_of_the_state_they_were_built_on() {
    // The root in block h's header is storage_commit's answer during block h:
    // the state after block h-1 plus block h's own writes before the header.
    // Replaying block h on a node holding the state after h-1 reproduces it.
    let alice = SigningKey::from_slice(&[1; 32]).unwrap();
    let (mut live, _) = chain(&alice, 3);
    let validator = SigningKey::from_slice(&[0x42; 32]).unwrap();
    let mut replay = Node::open(
        &kernel_module(),
        &genesis(&[validator], address(&alice)),
        NodeConfig::default(),
    )
    .unwrap();
    for height in 1..=3 {
        let header = live.block_by_number(height).unwrap().unwrap();
        replay
            .apply_effect(Effect::ExecuteBlock {
                block: block_of(&mut live, height),
            })
            .unwrap();
        let mine = replay.block_by_number(height).unwrap().unwrap();
        assert_eq!(mine.state_root, header.state_root, "height {height}");
        assert_ne!(mine.state_root, orange_trie::EMPTY);
    }
}

/// Block `height` of `node` as an `ExecuteBlock` effect carries it.
fn block_of(node: &mut Node, height: u64) -> Block {
    let header = node.block_by_number(height).unwrap().unwrap();
    let txs = header
        .tx_hashes
        .0
        .iter()
        .map(|hash| node.transaction(hash).unwrap().unwrap())
        .collect();
    let template = BlockHeader {
        height,
        parent_hash: header.parent_hash,
        timestamp_ms: header.timestamp_ms,
        ..BlockHeader::default()
    };
    Block {
        header: template.to_bytes(),
        txs: Seq(txs),
        participation: Vec::new(),
    }
}

#[test]
fn different_batching_gives_identical_roots() {
    // A validator that finalized every block as it made it, an observer that
    // executes all blocks first and finalizes them at the end, and one that
    // finalizes each block before executing the next: the finalized height
    // they keep differs throughout, the roots never do.
    const BLOCKS: u64 = 9;
    let alice = SigningKey::from_slice(&[1; 32]).unwrap();
    let (mut live, _) = chain(&alice, BLOCKS);
    let blocks: Vec<Block> = (1..=BLOCKS).map(|h| block_of(&mut live, h)).collect();
    let validator = SigningKey::from_slice(&[0x42; 32]).unwrap();
    let observer = || {
        Node::open(
            &kernel_module(),
            &genesis(std::slice::from_ref(&validator), address(&alice)),
            NodeConfig::default(),
        )
        .unwrap()
    };
    let finalize = |height| Effect::FinalizeBlock {
        height,
        certificate: Vec::new(),
    };
    let mut batched = observer();
    for block in &blocks {
        batched
            .apply_effect(Effect::ExecuteBlock {
                block: block.clone(),
            })
            .unwrap();
    }
    assert_eq!(batched.finalized_height().unwrap(), 0);
    let mut stepped = observer();
    for (block, height) in blocks.iter().zip(1..) {
        stepped
            .apply_effect(Effect::ExecuteBlock {
                block: block.clone(),
            })
            .unwrap();
        stepped.apply_effect(finalize(height)).unwrap();
    }
    // Same blocks, so the same block hashes, which cover the header roots.
    assert_eq!(batched.executed, live.executed);
    assert_eq!(stepped.executed, live.executed);
    for height in 1..=BLOCKS {
        let root = live.block_by_number(height).unwrap().unwrap().state_root;
        assert_eq!(
            batched.block_by_number(height).unwrap().unwrap().state_root,
            root
        );
        assert_eq!(
            stepped.block_by_number(height).unwrap().unwrap().state_root,
            root
        );
    }
    // And the same current state, finalized or not.
    assert_eq!(batched.state_root(), live.state_root());
    for height in 1..=BLOCKS {
        batched.apply_effect(finalize(height)).unwrap();
    }
    assert_eq!(batched.finalized_height().unwrap(), BLOCKS);
    assert_eq!(batched.state_root(), live.state_root());
    assert_eq!(stepped.state_root(), live.state_root());
    assert_eq!(live.state_root(), rebuilt(&live));
    assert_eq!(batched.state_root(), rebuilt(&batched));
}

#[test]
fn a_synced_observer_and_the_live_validators_commit_to_the_same_state() {
    // Four validators make blocks while an observer is offline, then it syncs
    // them in batches of up to 16 and follows live. Every header root and the
    // current root agree across all five once they stand at the same height.
    let validators: Vec<SigningKey> = (1..=4u8)
        .map(|i| SigningKey::from_slice(&[0x10 + i; 32]).unwrap())
        .collect();
    let funded = SigningKey::from_slice(&[1u8; 32]).unwrap();
    let kernel = kernel_module();
    let genesis = genesis(&validators, address(&funded));
    let config = NodeConfig {
        now_ms: 1_000,
        ..NodeConfig::default()
    };
    let mut sim = Sim::new(&kernel, &genesis, &validators, 1, &config, 10).unwrap();
    sim.crash(4);
    let to = address(&validators[3]);
    sim.submit(0, &transfer(&funded, 0, to, ETHER)).unwrap();
    assert!(
        sim.run_until(60 * SLOT_MS, |s| s.nodes[0].finalized.len() >= 20)
            .unwrap(),
        "{:?}",
        sim.finalized_heights().unwrap()
    );
    sim.submit(1, &transfer(&funded, 1, to, ETHER)).unwrap();
    sim.revive(4, &kernel, &genesis).unwrap();
    let target = sim.nodes[0].executed.len() + 2;
    let level = sim
        .run_until(40 * SLOT_MS, |s| {
            let heights: Vec<usize> = s.nodes.iter().map(|n| n.executed.len()).collect();
            heights[0] >= target && heights.iter().all(|h| *h == heights[0])
        })
        .unwrap();
    assert!(
        level,
        "{:?}",
        sim.nodes
            .iter()
            .map(|n| n.executed.len())
            .collect::<Vec<_>>()
    );
    let height = sim.nodes[0].executed.len() as u64;
    for h in 1..=height {
        let root = sim.nodes[0].block_by_number(h).unwrap().unwrap().state_root;
        for node in &mut sim.nodes[1..] {
            assert_eq!(
                node.block_by_number(h).unwrap().unwrap().state_root,
                root,
                "height {h}"
            );
        }
    }
    let root = sim.nodes[0].state_root();
    for node in &sim.nodes {
        assert_eq!(node.state_root(), root);
    }
    assert_eq!(root, rebuilt(&sim.nodes[4]));
    assert_eq!(sim.nodes[4].account(&to).unwrap().balance, 2 * ETHER);
}

/// The genesis state's trie (spec 20 §3.4, spec 06 §3): the one behind the
/// root the genesis header carries, which leaves out what the kernel wrote
/// after it asked for that root; under a kernel that asks for none, the
/// state's own.
#[test]
fn the_genesis_seals_the_trie_behind_its_header_root() {
    use orange_host::Storage;
    let mut bare = orange_node::ChainState::default();
    bare.set(b"acct/a", b"1");
    bare.seal_genesis(None).unwrap();
    let root = bare.genesis_root().unwrap();
    let trie = bare.trie_at(0).unwrap();
    assert_eq!(trie.root(), root);
    let mut headed = orange_node::ChainState::default();
    headed.set(b"acct/a", b"1");
    headed.set(b"block/0", b"header");
    headed.seal_genesis(Some(trie)).unwrap();
    assert_eq!(headed.genesis_root(), Some(root));
    assert_eq!(headed.trie_at(0).unwrap().root(), root);
}
