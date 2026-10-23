//! Committee-signed state snapshots (spec 22 §6–§7): the kernel records
//! the state root at every epoch boundary; a node exports the state at that
//! root with a certificate that vouches for it, through its anchor and a
//! spec 10 proof; the file round-trips; forged snapshots are refused; a
//! fresh node imports one, serves it and syncs forward with the network;
//! and a chain with a threshold key is vouched for by a threshold
//! certificate under a trusted group key.

mod support;

use std::path::Path;

use k256::ecdsa::SigningKey;
use solo_abi::chain::consensus::{KIND_FINALIZE, signing_preimage};
use solo_abi::chain::{
    Allocation, Certificate, GenesisParams, Proposal, UpgradeParams, Validator, ValidatorSet, keys,
};
use solo_abi::codec::Seq;
use solo_abi::staking::{KeySetRecord, StakingParams, ValidatorKey, keys as skeys};
use solo_abi::types::Genesis;
use solo_abi::{Decode, Encode};
use solo_host::hash::keccak256;
use solo_node::keystore::encryption_key;
use solo_node::{
    ARCHIVE, Node, NodeConfig, NodeError, STATE_HISTORY, Sim, StoreConfig, validator_id,
};
use solo_scratch::Scratch;
use solo_store::{Entries, Snapshot, SnapshotError, Trust};
use support::{CHAIN_ID, ETHER, SLOT_MS, Wallet, alice, genesis, include, keys, v1};

fn scratch(name: &str) -> Scratch {
    Scratch::new("node-snapshot", name)
}

/// Feature-gate epochs of four blocks and no staking: snapshots every four
/// blocks, vouched for by vote certificates of the genesis set.
fn epochs_of_four() -> UpgradeParams {
    UpgradeParams {
        governance: [0; 20],
        min_delay: 0,
        epoch_blocks: 4,
    }
}

fn validator_set(validators: &[SigningKey]) -> ValidatorSet {
    Sim::validator_set(validators)
}

#[test]
fn the_kernel_records_a_snapshot_at_every_epoch_boundary() {
    let validators = keys(1);
    let config = NodeConfig {
        key: Some(validators[0].clone()),
        now_ms: 1_000,
        ..NodeConfig::default()
    };
    let mut node = Node::open(v1(), &genesis(&validators, epochs_of_four(), 10), config).unwrap();
    node.start(None).unwrap();
    assert_eq!(node.snapshot_record(None).unwrap(), None);
    let bob = Wallet::new(0x50);
    let mut roots = Vec::new();
    for nonce in 0..9u64 {
        include(
            &mut node,
            &alice().tx(nonce, bob.address, ETHER, 21_000, &[]),
        );
        let height = node.block_number().unwrap();
        roots.push((height, node.state_root()));
    }
    // The record of epoch e names the state after block 4(e + 1): the
    // commitment of the whole state as it stood when the next block began.
    let latest = node.snapshot_record(None).unwrap().unwrap();
    assert_eq!(latest.height % 4, 0);
    for (epoch, height) in [(0, 4), (1, 8)] {
        let record = node.snapshot_record(Some(epoch)).unwrap().unwrap();
        assert_eq!(record.height, height);
        let (_, root) = roots.iter().find(|(h, _)| *h == height).unwrap();
        assert_eq!(record.state_root, *root);
        let stored = node.state_get(&[keys::SNAPSHOT, &epoch.to_be_bytes()[..]].concat());
        assert_eq!(stored, Some(record.to_bytes()));
    }
    assert_eq!(node.snapshot_record(Some(7)).unwrap(), None);
    assert_eq!(
        node.state_get(keys::SNAPSHOT_LATEST),
        Some(latest.height.div_ceil(4).saturating_sub(1).to_bytes())
    );
}

/// A single validator over a disk store at `dir`, run past block 10: two blocks past the record of epoch 1, so
/// that a proposal anchors a height above it.
fn exporter(dir: &Path) -> (Node, Genesis, Wallet) {
    let validators = keys(1);
    let genesis = genesis(&validators, epochs_of_four(), 10);
    let config = NodeConfig {
        key: Some(validators[0].clone()),
        now_ms: 1_000,
        store: StoreConfig::Disk(dir.to_path_buf()),
        ..NodeConfig::default()
    };
    let mut node = Node::open(v1(), &genesis, config).unwrap();
    node.start(None).unwrap();
    let bob = Wallet::new(0x51);
    for nonce in 0..10u64 {
        include(
            &mut node,
            &alice().tx(nonce, bob.address, ETHER, 21_000, &[]),
        );
    }
    (node, genesis, bob)
}

/// The entries of `snapshot`, read from its file.
fn entries_of(snapshot: &Snapshot) -> Entries {
    snapshot.entries().unwrap().map(Result::unwrap).collect()
}

#[test]
#[allow(clippy::too_many_lines)]
fn a_snapshot_exports_verifies_round_trips_and_refuses_forgeries() {
    let dir = scratch("export");
    let (node, _, bob) = exporter(&dir);
    let trust = Trust::Genesis(validator_set(&keys(1)));
    // A node in memory has nothing to export from.
    let memory = Node::new(v1(), &genesis(&keys(1), epochs_of_four(), 10), 0).unwrap();
    assert!(matches!(
        memory.export_snapshot(None, &dir.join("memory.snap")),
        Err(NodeError::Store(_))
    ));
    // The latest epoch, and a named one.
    let path = dir.join("epoch.snap");
    let snapshot = node.export_snapshot(None, &path).unwrap();
    let first = node
        .export_snapshot(Some(0), &dir.join("first.snap"))
        .unwrap();
    assert_eq!((first.header.epoch, first.header.height), (0, 4));
    assert!(snapshot.header.height >= 8 && snapshot.header.height % 4 == 0);
    assert_eq!(snapshot.header.chain_id, CHAIN_ID);
    let entries = entries_of(&snapshot);
    assert_eq!(snapshot.header.entries, entries.len() as u64);
    assert!(snapshot.header.head_threshold.is_empty());
    snapshot.verify(CHAIN_ID, &trust).unwrap();
    first.verify(CHAIN_ID, &trust).unwrap();
    // The head is linked to the anchoring proposal by the proposals of the
    // heights between, the fewest the tables allow.
    let anchoring = Proposal::from_bytes(&snapshot.header.anchor_proposal).unwrap();
    assert_eq!(
        snapshot.header.links.0.len() as u64,
        anchoring.height - snapshot.header.height - 1
    );
    // The entries are the committed state after the record's height, which
    // holds the record of the epoch before and Bob's balance then, in path
    // order.
    let height = snapshot.header.height;
    let balance_then = u128::from(height) * ETHER;
    let account = entries
        .iter()
        .find(|(k, _)| *k == [b"acct/".as_slice(), &bob.address].concat())
        .map(|(_, v)| solo_abi::chain::Account::from_bytes(v).unwrap())
        .unwrap();
    assert_eq!(account.balance, balance_then);
    assert!(entries.iter().all(|(k, _)| !k.starts_with(b"local/")));
    assert!(
        entries
            .windows(2)
            .all(|w| keccak256(&w[0].0) < keccak256(&w[1].0))
    );
    let unknown = node
        .export_snapshot(Some(9), &dir.join("nine.snap"))
        .unwrap_err();
    assert!(
        unknown.to_string().contains("no snapshot record"),
        "{unknown}"
    );
    // The file round-trips.
    let read = Snapshot::open(&path).unwrap();
    assert_eq!(read, snapshot);
    assert_eq!(read.path(), path.as_path());
    read.verify(CHAIN_ID, &trust).unwrap();
    // Files that are not snapshots.
    let bad = dir.join("bad.snap");
    std::fs::write(&bad, b"not a snapshot").unwrap();
    assert_eq!(
        Snapshot::open(&bad),
        Err(SnapshotError::Format("wrong magic"))
    );
    let mut bytes = std::fs::read(&path).unwrap();
    bytes[8] = 9;
    std::fs::write(&bad, &bytes).unwrap();
    assert_eq!(
        Snapshot::open(&bad),
        Err(SnapshotError::Format("another format"))
    );
    let mut bytes = std::fs::read(&path).unwrap();
    bytes.truncate(40);
    std::fs::write(&bad, &bytes).unwrap();
    assert!(matches!(Snapshot::open(&bad), Err(SnapshotError::Io(_))));
    let mut bytes = std::fs::read(&path).unwrap();
    bytes[12..16].copy_from_slice(&[0, 0, 0, 0]);
    std::fs::write(&bad, &bytes).unwrap();
    assert_eq!(
        Snapshot::open(&bad),
        Err(SnapshotError::Format("the header does not decode"))
    );
    assert!(matches!(
        Snapshot::open(&dir.join("missing.snap")),
        Err(SnapshotError::Io(_))
    ));
    // A file whose entries are cut short, or run on, is found out as its
    // entries stream: they are as many as the header says, then nothing.
    let refused_file = |bytes: &[u8], why: &str| {
        std::fs::write(&bad, bytes).unwrap();
        let err = Snapshot::open(&bad)
            .unwrap()
            .verify(CHAIN_ID, &trust)
            .unwrap_err();
        assert!(err.to_string().contains(why), "{why}: {err}");
    };
    let whole = std::fs::read(&path).unwrap();
    refused_file(
        &[whole.as_slice(), &[0]].concat(),
        "bytes follow the last entry",
    );
    refused_file(&whole[..whole.len() - 3], "snapshot file: ");
    let last = &entries[entries.len() - 1];
    let cut = whole.len() - 8 - last.0.len() - last.1.len();
    refused_file(&whole[..cut], "the file ends early");
    // A file removed after it was opened cannot stream its entries.
    let gone = Snapshot::open(&path).unwrap();
    let moved = dir.join("moved.snap");
    std::fs::rename(&path, &moved).unwrap();
    assert!(matches!(gone.entries(), Err(SnapshotError::Io(_))));
    assert!(matches!(
        gone.verify(CHAIN_ID, &trust),
        Err(SnapshotError::Io(_))
    ));
    std::fs::rename(&moved, &path).unwrap();
    // Forgeries: each is refused for its own reason.
    let refused = |forge: &dyn Fn(&mut Snapshot), why: &str| {
        let mut forged = snapshot.clone();
        forge(&mut forged);
        let err = forged.verify(CHAIN_ID, &trust).unwrap_err();
        assert!(
            matches!(&err, SnapshotError::Verify(reason) if reason.contains(why)),
            "{why}: {err}"
        );
    };
    // Forged entries are written to a file of their own.
    let forged_entries = |name: &str, f: &dyn Fn(&mut Entries)| {
        let mut altered = entries.clone();
        f(&mut altered);
        let mut header = snapshot.header.clone();
        header.entries = altered.len() as u64;
        Snapshot::write(&dir.join(name), &header, altered).unwrap()
    };
    let rewrite = |forged: &mut Snapshot, made: Snapshot| *forged = made;
    refused(&|s| s.header.chain_id += 1, "another chain");
    refused(
        &|s| s.header.anchor_proposal.clear(),
        "anchoring proposal does not decode",
    );
    refused(
        &|s| {
            let mut p = Proposal::from_bytes(&s.header.anchor_proposal).unwrap();
            p.anchor_height = s.header.height;
            s.header.anchor_proposal = p.to_bytes();
        },
        "anchors no height above",
    );
    refused(
        &|s| {
            let mut c = Certificate::from_bytes(&s.header.certificate).unwrap();
            c.votes.0[0].signature.0[0] ^= 1;
            s.header.certificate = c.to_bytes();
        },
        "not a quorum of the genesis set",
    );
    refused(
        &|s| {
            let mut c = Certificate::from_bytes(&s.header.certificate).unwrap();
            c.votes.0.push(c.votes.0[0].clone());
            s.header.certificate = c.to_bytes();
        },
        "not a quorum of the genesis set",
    );
    refused(
        &|s| {
            let mut c = Certificate::from_bytes(&s.header.certificate).unwrap();
            c.kind = 1;
            s.header.certificate = c.to_bytes();
        },
        "not a quorum of the genesis set",
    );
    refused(
        &|s| {
            let mut c = Certificate::from_bytes(&s.header.certificate).unwrap();
            c.votes.0[0].validator = 5;
            s.header.certificate = c.to_bytes();
        },
        "not a quorum of the genesis set",
    );
    refused(
        &|s| s.header.certificate.clear(),
        "certificate does not decode",
    );
    refused(
        &|s| s.header.certificate = vec![2; 97],
        "is not the anchoring proposal's",
    );
    refused(&|s| s.header.record_proof.clear(), "proof does not decode");
    refused(&|s| s.header.state_root[0] ^= 1, "proof does not verify");
    refused(
        &|s| {
            rewrite(s, forged_entries("value.snap", &|l| l[0].1.push(0)));
        },
        "do not hash to the record's root",
    );
    refused(
        &|s| {
            rewrite(
                s,
                forged_entries("local.snap", &|l| l[0].0 = b"local/x".to_vec()),
            );
        },
        "node-local",
    );
    refused(
        &|s| rewrite(s, forged_entries("order.snap", &|l| l.swap(0, 1))),
        "not in path order",
    );
    refused(
        &|s| rewrite(s, forged_entries("fewer.snap", &|l| drop(l.pop()))),
        "do not hash to the record's root",
    );
    // The head: its proposal, the links that join it to the anchoring
    // proposal, its certificate.
    refused(&|s| s.header.head_proposal.clear(), "head proposal");
    refused(
        &|s| {
            let mut p = Proposal::from_bytes(&s.header.head_proposal).unwrap();
            p.timestamp_ms += 1;
            s.header.head_proposal = p.to_bytes();
        },
        "do not join the head to the anchoring proposal",
    );
    refused(
        &|s| s.header.links.0.push(s.header.head_proposal.clone()),
        "do not join the head",
    );
    refused(
        &|s| s.header.links.0.push(vec![0xFF]),
        "a link does not decode",
    );
    // Without its links the head does not reach the anchoring proposal.
    assert!(!snapshot.header.links.0.is_empty());
    refused(&|s| s.header.links.0.clear(), "do not join the head");
    refused(&|s| s.header.head_certificate.clear(), "head certificate");
    // A head certificate from a view the anchoring proposal does not reach
    // would move the importing node past the chain's views; under the
    // genesis set its votes must also hold.
    refused(
        &|s| {
            let mut c = Certificate::from_bytes(&s.header.head_certificate).unwrap();
            c.view = Proposal::from_bytes(&s.header.anchor_proposal)
                .unwrap()
                .view
                + 1;
            s.header.head_certificate = c.to_bytes();
        },
        "at or below the anchoring proposal's view",
    );
    refused(
        &|s| {
            let mut c = Certificate::from_bytes(&s.header.head_certificate).unwrap();
            c.votes.0[0].signature.0[0] ^= 1;
            s.header.head_certificate = c.to_bytes();
        },
        "the head certificate is not a quorum of the genesis set",
    );
    // A head finalized by a descendant (a suffix proposal, spec 08 §3a)
    // carries that descendant's certificate, which verifies.
    let mut descendant = snapshot.clone();
    let mut c = Certificate::from_bytes(&descendant.header.head_certificate).unwrap();
    c.hash = [7; 32];
    let digest = keccak256(&signing_preimage(KIND_FINALIZE, CHAIN_ID, c.view, &c.hash));
    let (signature, id) = keys(1)[0].sign_prehash_recoverable(&digest).unwrap();
    c.votes.0[0].signature.0[..64].copy_from_slice(&signature.to_bytes());
    c.votes.0[0].signature.0[64] = id.to_byte();
    descendant.header.head_certificate = c.to_bytes();
    descendant.verify(CHAIN_ID, &trust).unwrap();
    // A vote certificate verifies only against the genesis set, and only a
    // threshold certificate under a key.
    let other = Trust::Genesis(validator_set(&keys(2)));
    assert!(matches!(
        snapshot.verify(CHAIN_ID, &other),
        Err(SnapshotError::Verify(_))
    ));
    assert_eq!(
        snapshot.verify(CHAIN_ID, &Trust::Key([0; 96])),
        Err(SnapshotError::Verify(
            "a vote certificate needs the genesis validator set, and only a chain without staking keeps it"
        ))
    );
    for (e, text) in [
        (SnapshotError::Io("a".into()), "snapshot file: a"),
        (
            SnapshotError::Format("b"),
            "snapshot: not a snapshot file: b",
        ),
        (SnapshotError::Verify("c"), "snapshot does not verify: c"),
        (SnapshotError::Store("d".into()), "snapshot: d"),
        (
            SnapshotError::Export("e".into()),
            "snapshot: cannot export: e",
        ),
    ] {
        assert_eq!(e.to_string(), text);
    }
    drop(node);
    // Exports need the driver's tables and the store's history: a node
    // whose window no longer reaches the height has nothing to export, and
    // no kept trie for a certificate's anchor, which is looked for first.
    let validators = keys(1);
    let short = scratch("export-short");
    let config = NodeConfig {
        key: Some(validators[0].clone()),
        now_ms: 1_000,
        state_history: 1,
        store: StoreConfig::Disk(short.to_path_buf()),
        ..NodeConfig::default()
    };
    let mut short = Node::open(v1(), &genesis(&validators, epochs_of_four(), 10), config).unwrap();
    short.start(None).unwrap();
    for nonce in 0..6u64 {
        include(
            &mut short,
            &alice().tx(nonce, bob.address, ETHER, 21_000, &[]),
        );
    }
    let err = short
        .export_snapshot(None, &dir.join("short.snap"))
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("no certified proposal anchors a kept height"),
        "{err}"
    );
}

/// The finalized heights the driver's tables of `node` hold.
fn table_heights(node: &Node) -> Vec<u64> {
    node.persisted()
        .keys()
        .filter_map(|k| k.strip_prefix(b"final/"))
        .map(|h| u64::from_le_bytes(h.try_into().unwrap()))
        .collect()
}

/// A single validator in epochs of four blocks over `store`, run until it
/// has finalized block 70, with `retention` heights of driver tables.
fn pruning(store: StoreConfig, state_history: usize, retention: u64) -> Node {
    let validators = keys(1);
    let config = NodeConfig {
        key: Some(validators[0].clone()),
        now_ms: 1_000,
        state_history,
        store,
        ..NodeConfig::default()
    };
    let mut node = Node::open(v1(), &genesis(&validators, epochs_of_four(), 10), config).unwrap();
    assert_eq!(node.driver_retention, solo_node::DRIVER_RETENTION);
    node.driver_retention = retention;
    node.start(None).unwrap();
    support::run_until(&mut node, 400, &mut |n| n.finalized_height().unwrap() >= 70);
    node
}

#[test]
fn driver_tables_are_pruned_below_the_retention_and_the_latest_snapshot() {
    assert_eq!(
        (solo_node::DRIVER_RETENTION, solo_node::PRUNE_EVERY),
        (1_024, 64)
    );
    // With no retention at all, the pass at height 64 prunes below the
    // latest snapshot record's height, 60: the latest snapshot still exports
    // and verifies, its head and links still in the tables.
    let dir = scratch("prune");
    let mut node = pruning(StoreConfig::Disk(dir.to_path_buf()), STATE_HISTORY, 0);
    let heights = table_heights(&node);
    assert_eq!(heights.iter().min(), Some(&60), "{heights:?}");
    assert!(heights.contains(&70));
    let tables = node.persisted();
    assert!(
        tables
            .iter()
            .filter(|(k, _)| k.starts_with(b"prop/"))
            .all(|(_, v)| Proposal::from_bytes(v).unwrap().height >= 60)
    );
    let snapshot = node
        .export_snapshot(None, &dir.join("latest.snap"))
        .unwrap();
    assert_eq!(snapshot.header.height, 68);
    snapshot
        .verify(CHAIN_ID, &Trust::Genesis(validator_set(&keys(1))))
        .unwrap();
    // The epoch before the pass's floor is gone from the tables, so it no
    // longer exports.
    let err = node
        .export_snapshot(Some(10), &dir.join("old.snap"))
        .unwrap_err();
    assert!(err.to_string().contains("do not hold block 44"), "{err}");
    // A restart over its stores goes on from there.
    let (persisted, resumed, now) = (
        node.persisted(),
        node.persisted_driver_state.clone(),
        node.now_ms(),
    );
    let head = node.block_number().unwrap();
    drop(node);
    let mut again = Node::open(
        v1(),
        &genesis(&keys(1), epochs_of_four(), 10),
        NodeConfig {
            key: Some(keys(1)[0].clone()),
            persisted,
            now_ms: now,
            store: StoreConfig::Disk(dir.to_path_buf()),
            ..NodeConfig::default()
        },
    )
    .unwrap();
    again.start(resumed).unwrap();
    support::run_until(&mut again, 40, &mut |n| {
        n.finalized_height().unwrap() >= head + 4
    });
    // A node in memory, whose restart replays its finalized blocks from its
    // tables, and an archive node keep every height.
    let archive = scratch("prune-archive");
    for node in [
        pruning(StoreConfig::Memory, STATE_HISTORY, 0),
        pruning(StoreConfig::Disk(archive.to_path_buf()), ARCHIVE, 0),
    ] {
        assert_eq!(table_heights(&node).iter().min(), Some(&1));
    }
}

#[test]
fn a_fresh_node_imports_a_snapshot_serves_it_and_syncs_forward() {
    let dir = scratch("import-source");
    let (mut node, genesis, bob) = exporter(&dir);
    let snapshot = node
        .export_snapshot(None, &dir.join("import.snap"))
        .unwrap();
    let height = snapshot.header.height;
    let head_hash = node.block_by_number(height).unwrap().unwrap();
    let now = node.now_ms();
    drop(node);
    // Importing needs a store on disk holding the genesis alone.
    let mut memory = Node::new(v1(), &genesis, 0).unwrap();
    assert!(matches!(
        memory.import_snapshot(&snapshot),
        Err(NodeError::Store(_))
    ));
    let target = scratch("import-target");
    let config = NodeConfig {
        key: Some(keys(1)[0].clone()),
        now_ms: now,
        store: StoreConfig::Disk(target.to_path_buf()),
        ..NodeConfig::default()
    };
    let mut fresh = Node::open(v1(), &genesis, config.clone()).unwrap();
    assert_eq!(fresh.block_number().unwrap(), 0);
    fresh.import_snapshot(&snapshot).unwrap();
    assert!(matches!(
        fresh.import_snapshot(&snapshot),
        Err(NodeError::Store(_))
    ));
    // The state is the snapshot's: the head, its header, the balances, the
    // record, and the genesis root for block 0; queries below the snapshot
    // are refused as pruned.
    assert_eq!(fresh.block_number().unwrap(), height);
    assert_eq!(fresh.finalized_height().unwrap(), height);
    assert_eq!(fresh.block_by_number(height).unwrap().unwrap(), head_hash);
    assert_eq!(fresh.oldest_state(), height);
    assert_eq!(
        fresh.account(&bob.address).unwrap().balance,
        u128::from(height) * ETHER
    );
    assert_eq!(fresh.state_root(), snapshot.header.state_root);
    // The state after the epoch's last block holds the record of the epoch
    // before it; the kernel writes this epoch's in the next block.
    assert_eq!(
        fresh.snapshot_record(None).unwrap().map(|r| r.height),
        Some(height - 4)
    );
    assert!(fresh.state_proof_at(height, b"meta/chain_id").is_none());
    assert!(matches!(
        fresh.account_at(&bob.address, Some(1)),
        Err(NodeError::StateUnavailable { .. })
    ));
    // Started with no driver data, it finalizes from the snapshot's height
    // and, alone as it is the only validator, goes on producing blocks whose
    // proofs it serves.
    fresh.start(None).unwrap();
    // Alone as it is the only validator, it may already have proposed the
    // next block in the step that started it.
    let state = fresh.simplex_state().unwrap();
    assert!(state.finalized_height >= height && state.tip_height >= height);
    // Alice's nonce at the snapshot is its height: one transfer per block.
    include(
        &mut fresh,
        &alice().tx(height, bob.address, ETHER, 21_000, &[]),
    );
    let next = fresh.block_number().unwrap();
    assert!(next > height);
    // And the block after that: the tip moved to the block it proposed.
    include(
        &mut fresh,
        &alice().tx(height + 1, bob.address, ETHER, 21_000, &[]),
    );
    let later = fresh.block_number().unwrap();
    assert!(later > next);
    assert!(fresh.state_proof_at(later, b"meta/chain_id").is_some());
    assert_eq!(
        fresh
            .block_by_number(height + 1)
            .unwrap()
            .unwrap()
            .parent_hash,
        solo_eth::header::block_hash(&head_hash, keccak256)
    );
    // Reopened over the imported store, it resumes there.
    let (persisted, resumed, now) = (
        fresh.persisted(),
        fresh.persisted_driver_state.clone(),
        fresh.now_ms(),
    );
    drop(fresh);
    let mut again = Node::open(
        v1(),
        &genesis,
        NodeConfig {
            persisted,
            now_ms: now,
            ..config
        },
    )
    .unwrap();
    assert_eq!(again.block_number().unwrap(), later);
    again.start(resumed).unwrap();
    assert!(again.executed.is_empty());
}

#[test]
fn a_validator_joins_a_network_from_a_snapshot() {
    let validators = keys(4);
    let genesis = genesis(&validators, epochs_of_four(), 10);
    let template = NodeConfig {
        now_ms: 10_000,
        ..NodeConfig::default()
    };
    let source = scratch("join-source");
    let join_target = scratch("join-target");
    let stores = [StoreConfig::Disk(source.to_path_buf())];
    let mut sim = Sim::with_stores(v1(), &genesis, &validators, 0, &template, 20, &stores).unwrap();
    let bob = Wallet::new(0x52);
    sim.submit(0, &alice().tx(0, bob.address, ETHER, 21_000, &[]))
        .unwrap();
    // Validator 3 is down while the network runs through two epochs.
    sim.crash(3);
    assert!(
        sim.run_until(60 * SLOT_MS, |s| s.nodes[0].finalized_height().unwrap()
            >= 10)
            .unwrap()
    );
    let snap_file = scratch("join.snap");
    let snapshot = sim.nodes[0].export_snapshot(None, &snap_file).unwrap();
    snapshot
        .verify(CHAIN_ID, &Trust::Genesis(validator_set(&validators)))
        .unwrap();
    let height = snapshot.header.height;
    assert!(height >= 8);
    // Reinstalled from the snapshot, it serves that state at once, then
    // syncs the rest from its peers and votes again.
    sim.revive_from_snapshot(3, v1(), &genesis, &snapshot, join_target.to_path_buf())
        .unwrap();
    assert_eq!(sim.nodes[3].block_number().unwrap(), height);
    assert_eq!(sim.nodes[3].account(&bob.address).unwrap().balance, ETHER);
    let target = sim.nodes[0].finalized_height().unwrap() + 4;
    let caught_up = sim
        .run_until(60 * SLOT_MS, |s| {
            s.finalized_heights().unwrap().iter().all(|h| *h >= target)
        })
        .unwrap();
    assert!(caught_up, "{:?}", sim.finalized_heights().unwrap());
    let at = sim.nodes[3].finalized_height().unwrap();
    assert_eq!(
        sim.nodes[0].block_by_number(at).unwrap(),
        sim.nodes[3].block_by_number(at).unwrap()
    );
    assert!(sim.nodes[3].validator_id().is_some());
    assert!(
        sim.nodes
            .iter()
            .all(|n| n.metrics.iter().all(|(name, _)| name != b"equivocations"))
    );
}

/// A staking chain of `keys` in epochs of four blocks with a DKG phase per
/// block, so that a threshold key exists from epoch 1 on.
fn staking_genesis(validators: &[SigningKey]) -> Genesis {
    let params = GenesisParams {
        slot_ms: SLOT_MS,
        max_txs: 8,
        allocations: Seq(validators
            .iter()
            .map(|k| Allocation {
                address: validator_id(k)[12..].try_into().unwrap(),
                balance: 100 * ETHER,
                ..Allocation::default()
            })
            .chain([Allocation {
                address: alice().address,
                balance: 100 * ETHER,
                ..Allocation::default()
            }])
            .collect()),
        staking: StakingParams {
            epoch_blocks: 4,
            unbonding_epochs: 4,
            min_stake: 0,
            max_validators: 0,
            dkg_phase_blocks: 1,
            max_key_age: 2,
            keys: Seq(validators
                .iter()
                .map(|k| ValidatorKey {
                    id: validator_id(k),
                    dkg_key: encryption_key(k).to_vec(),
                })
                .collect()),
        },
        ..GenesisParams::default()
    };
    let set = ValidatorSet {
        validators: Seq(validators
            .iter()
            .map(|k| Validator {
                id: validator_id(k),
                weight: 1_000,
            })
            .collect()),
    };
    Genesis {
        chain_id: CHAIN_ID,
        fee_schedule: vec![],
        modules: Seq(vec![]),
        params: params.to_bytes(),
        validators: set.to_bytes(),
    }
}

#[test]
fn a_threshold_certificate_vouches_for_a_staking_chains_snapshot() {
    let validators: Vec<SigningKey> = (1..=4u8)
        .map(|i| SigningKey::from_slice(&[0x70 + i; 32]).unwrap())
        .collect();
    let genesis = staking_genesis(&validators);
    let template = NodeConfig {
        now_ms: 10_000,
        ..NodeConfig::default()
    };
    let dir = scratch("threshold");
    let stores = [StoreConfig::Disk(dir.to_path_buf())];
    let mut sim = Sim::with_stores(v1(), &genesis, &validators, 0, &template, 20, &stores).unwrap();
    // Run until a block well into the threshold key's life has a threshold
    // certificate behind a snapshot record.
    let certified = sim
        .run_until(400 * SLOT_MS, |s| {
            let node = &mut s.nodes[0];
            let tables = node.persisted();
            node.snapshot_record(None)
                .is_ok_and(|r| r.is_some_and(|r| r.height >= 12))
                && tables.keys().any(|k| k.starts_with(b"bcert/"))
                && node.finalized_height().unwrap() >= 16
        })
        .unwrap();
    assert!(certified, "{:?}", sim.finalized_heights().unwrap());
    let snap_file = scratch("threshold.snap");
    let snapshot = sim.nodes[0].export_snapshot(None, &snap_file).unwrap();
    let certificate = &snapshot.header.certificate;
    assert_eq!(certificate.len(), 97);
    let key_id = u64::from_be_bytes(certificate[1..9].try_into().unwrap());
    let record = sim.nodes[0]
        .state_get(&[skeys::KEY_SET, &key_id.to_be_bytes()].concat())
        .map(|b| KeySetRecord::from_bytes(&b).unwrap())
        .unwrap();
    let group_key: [u8; 96] = record.key_set[..96].try_into().unwrap();
    snapshot.verify(CHAIN_ID, &Trust::Key(group_key)).unwrap();
    // The wrong key, a key that is not a point, and the genesis set refuse it.
    let other = solo_bls::SecretKey::generate(&[7; 32], b"")
        .unwrap()
        .public_key()
        .to_bytes();
    assert_eq!(
        snapshot.verify(CHAIN_ID, &Trust::Key(other)),
        Err(SnapshotError::Verify(
            "the threshold certificate does not verify under the trusted key"
        ))
    );
    assert_eq!(
        snapshot.verify(CHAIN_ID, &Trust::Key([0xFF; 96])),
        Err(SnapshotError::Verify("the trusted key is not a group key"))
    );
    assert_eq!(
        snapshot.verify(CHAIN_ID, &Trust::Genesis(validator_set(&validators))),
        Err(SnapshotError::Verify(
            "a threshold certificate needs a trusted group key"
        ))
    );
    let mut forged = snapshot.clone();
    forged.header.certificate[9..17].copy_from_slice(&u64::MAX.to_be_bytes());
    assert_eq!(
        forged.verify(CHAIN_ID, &Trust::Key(group_key)),
        Err(SnapshotError::Verify(
            "the threshold certificate is not the anchoring proposal's"
        ))
    );
    let mut forged = snapshot.clone();
    forged.header.certificate[96] ^= 1;
    assert!(matches!(
        forged.verify(CHAIN_ID, &Trust::Key(group_key)),
        Err(SnapshotError::Verify(_))
    ));
    assert!(!snapshot.header.head_threshold.is_empty() || snapshot.header.height < 8);
}
