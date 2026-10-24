//! Seeded adversarial peers for the state sync (spec 22 §7.4): beside one
//! honest peer, peers that corrupt answers byte by byte, rewrite manifests
//! and pages, answer the wrong request, stay silent or come and go. The
//! joining node never panics, never bans the honest peer, and always ends
//! with the snapshot the honest peer serves, verified. And a snapshot file
//! changed anywhere never verifies. See `solo-fuzz` for the long mode.

mod support;

use std::path::Path;

use solo_abi::chain::UpgradeParams;
use solo_abi::{Decode, Encode};
use solo_fuzz::Rng;
use solo_node::statesync::{ServeLimits, StateSync, SyncEvent, SyncRequest, SyncResponse};
use solo_node::{Node, NodeConfig, Sim, StoreConfig};
use solo_scratch::Scratch;
use solo_store::Trust;
use support::{ETHER, Wallet, alice, genesis, include, keys, v1};

const SMALL: ServeLimits = ServeLimits {
    slice_entries: 8,
    chunk_bytes: 600,
};

fn chain() -> solo_abi::types::Genesis {
    genesis(
        &keys(1),
        UpgradeParams {
            governance: [0; 20],
            min_delay: 0,
            epoch_blocks: 4,
        },
        10,
    )
}

/// One validator over a disk store at `dir`, past block 15, serving its
/// snapshots in small pieces.
fn server(dir: &Path) -> Node {
    let config = NodeConfig {
        key: Some(keys(1)[0].clone()),
        now_ms: 1_000,
        store: StoreConfig::Disk(dir.to_path_buf()),
        ..NodeConfig::default()
    };
    let mut node = Node::open(v1(), &chain(), config).unwrap();
    node.start(None).unwrap();
    node.serve_snapshots(SMALL).unwrap();
    let bob = Wallet::new(0x51);
    for nonce in 0..15u64 {
        include(
            &mut node,
            &alice().tx(nonce, bob.address, ETHER, 21_000, &[]),
        );
    }
    node
}

fn joiner(dir: &Path) -> StateSync {
    let config = NodeConfig {
        now_ms: 1_000,
        store: StoreConfig::Disk(dir.to_path_buf()),
        ..NodeConfig::default()
    };
    let mut node = Node::open(v1(), &chain(), config).unwrap();
    StateSync::new(
        node.sync_config(Trust::Genesis(Sim::validator_set(&keys(1))))
            .unwrap(),
    )
    .unwrap()
}

/// A lie told about `answer` (the honest answer to `request`), or `None`
/// for silence.
fn lie(r: &mut Rng, request: &SyncRequest, answer: Vec<u8>, last: &mut Vec<u8>) -> Option<Vec<u8>> {
    let lied = match r.below(8) {
        0 => return None,
        1 => r.mutate(&answer),
        // The answer to another request.
        2 => last.clone(),
        3 => SyncResponse::Unavailable.to_bytes(),
        _ => match (request, SyncResponse::from_bytes(&answer).ok()?) {
            (_, SyncResponse::Slice { mut entries, more }) => {
                let more = if r.chance(1, 4) { !more } else { more };
                match r.below(4) {
                    0 if !entries.is_empty() => {
                        entries.remove(r.index(entries.len()));
                    }
                    1 if !entries.is_empty() => {
                        let i = r.index(entries.len());
                        entries[i].value = r.mutate(&entries[i].value);
                    }
                    2 if entries.len() > 1 => entries.swap(0, 1),
                    _ => entries.truncate(r.index(entries.len() + 1)),
                }
                SyncResponse::Slice { entries, more }.to_bytes()
            }
            (_, SyncResponse::Manifest(mut m)) => {
                match r.below(3) {
                    0 => m.depth = m.depth.wrapping_add(1),
                    1 if !m.slices.is_empty() => {
                        let i = r.index(m.slices.len());
                        m.slices[i] = m.slices[(i + 1) % m.slices.len()];
                    }
                    _ => m.header = r.mutate(&m.header),
                }
                SyncResponse::Manifest(m).to_bytes()
            }
            (_, SyncResponse::Offers(mut offers)) => {
                for o in &mut offers {
                    o.entries = o.entries.wrapping_add(r.below(3));
                    if r.chance(1, 2) {
                        o.state_root = r.array32();
                    }
                }
                SyncResponse::Offers(offers).to_bytes()
            }
            (_, SyncResponse::Unavailable) => answer.clone(),
        },
    };
    *last = answer;
    Some(lied)
}

fn case(node: &Node, r: &mut Rng) {
    let offer = node.snapshot_server().unwrap().offers()[0];
    let target = Scratch::new("node-statesync-fuzz", &format!("{:x}", r.u64()));
    let mut sync = joiner(&target);
    // Peer 0 is honest; the others lie, each its own way.
    let liars = 1 + r.index(4);
    let mut rngs: Vec<Rng> = (0..liars).map(|_| Rng::new(r.u64())).collect();
    let mut last = vec![Vec::new(); liars];
    let mut now = 0;
    let mut honest_up = true;
    for round in 0..20_000 {
        if sync.done().is_some() || sync.failed().is_some() {
            break;
        }
        // Liars stay; the honest peer drops out now and then.
        if round % 50 == 0 {
            honest_up = r.chance(4, 5);
        }
        let up: Vec<[u8; 32]> = (0..=liars)
            .filter(|i| *i > 0 || honest_up)
            .map(|i| [u8::try_from(i).unwrap(); 32])
            .collect();
        for (to, id, payload) in sync.poll(now, &up) {
            let request = SyncRequest::from_bytes(&payload).unwrap();
            let answer = node.answer_sync(&payload);
            let i = usize::from(to[0]);
            let reply = if i == 0 {
                Some(answer)
            } else {
                lie(&mut rngs[i - 1], &request, answer, &mut last[i - 1])
            };
            if let Some(reply) = reply {
                sync.on_response(to, id, &reply, now);
            }
        }
        now += 10;
    }
    let events = sync.take_events();
    for e in &events {
        if let SyncEvent::Banned { peer, why } = e {
            assert_ne!(*peer, [0; 32], "the honest peer was banned: {why}");
        }
    }
    assert!(
        sync.failed().is_none(),
        "{:?} after {events:?}",
        sync.failed()
    );
    let snapshot = sync
        .done()
        .expect("the sync completes from the honest peer");
    assert_eq!(snapshot.header.state_root, offer.state_root);
    assert_eq!(snapshot.header.entries, offer.entries);
}

/// A snapshot file changed anywhere never opens and verifies as anything
/// but itself (spec 22 §7.2).
fn tampered_file(original: &[u8], dir: &Path, r: &mut Rng) {
    let path = dir.join("tampered.snap");
    let bytes = r.mutate(original);
    std::fs::write(&path, &bytes).unwrap();
    let Ok(snapshot) = solo_store::Snapshot::open(&path) else {
        return;
    };
    let trust = Trust::Genesis(Sim::validator_set(&keys(1)));
    if snapshot.verify(support::CHAIN_ID, &trust).is_ok() {
        assert_eq!(bytes, original, "a changed snapshot file verified");
    }
}

#[test]
fn adversarial_peers_never_stop_a_sync_with_an_honest_one() {
    let source = Scratch::new("node-statesync-fuzz", "source");
    let node = server(&source);
    solo_fuzz::run("statesync-liars", 3, |r| case(&node, r));
    let files = Scratch::dir("node-statesync-fuzz", "files");
    let exported = node
        .export_snapshot(None, &files.join("good.snap"))
        .unwrap();
    let trust = Trust::Genesis(Sim::validator_set(&keys(1)));
    exported.verify(support::CHAIN_ID, &trust).unwrap();
    let original = std::fs::read(files.join("good.snap")).unwrap();
    solo_fuzz::run("snapshot-files", 150, |r| {
        tampered_file(&original, &files, r);
    });
}
