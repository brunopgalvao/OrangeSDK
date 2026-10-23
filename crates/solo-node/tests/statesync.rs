//! State sync (spec 22 §7.4): a node serves the snapshots it exports; a
//! joining node fetches one from its peers slice by slice, verifying the
//! manifest under its trust and every slice against it, bans peers that lie
//! or stay silent, resumes after a peer leaves or after a restart, refuses
//! another genesis, and joins a running network.

mod support;

use std::path::Path;

use k256::ecdsa::SigningKey;
use solo_abi::chain::{UpgradeParams, keys as ckeys};
use solo_abi::types::Genesis;
use solo_abi::{Decode, Encode};
use solo_host::hash::keccak256;
use solo_node::statesync::{
    Entry, Manifest, Offer, ServeLimits, SnapshotServer, StateSync, Summary, SyncEvent,
    SyncRequest, SyncResponse, answer_unserved, combine, depth_for, finish, slice_of,
};
use solo_node::{Node, NodeConfig, NodeError, Sim, StoreConfig};
use solo_scratch::Scratch;
use solo_store::Trust;
use support::{ETHER, SLOT_MS, Wallet, alice, genesis, include, keys, v1};

fn scratch(name: &str) -> Scratch {
    Scratch::new("node-statesync", name)
}

/// Snapshots every four blocks, vouched for by the genesis set's votes.
fn epochs_of_four() -> UpgradeParams {
    UpgradeParams {
        governance: [0; 20],
        min_delay: 0,
        epoch_blocks: 4,
    }
}

/// Small slices and pages, so that a small state makes many of both.
const SMALL: ServeLimits = ServeLimits {
    slice_entries: 8,
    chunk_bytes: 600,
};

/// A single validator over a disk store at `dir`, run past block 15, three
/// epochs, and serving its snapshots within `limits`.
fn server(dir: &Path, genesis: &Genesis, limits: ServeLimits) -> Node {
    let config = NodeConfig {
        key: Some(keys(1)[0].clone()),
        now_ms: 1_000,
        store: StoreConfig::Disk(dir.to_path_buf()),
        ..NodeConfig::default()
    };
    let mut node = Node::open(v1(), genesis, config).unwrap();
    node.start(None).unwrap();
    node.serve_snapshots(limits).unwrap();
    let bob = Wallet::new(0x51);
    for nonce in 0..15u64 {
        include(
            &mut node,
            &alice().tx(nonce, bob.address, ETHER, 21_000, &[]),
        );
    }
    node
}

fn chain() -> Genesis {
    genesis(&keys(1), epochs_of_four(), 10)
}

fn trust() -> Trust {
    Trust::Genesis(Sim::validator_set(&keys(1)))
}

/// A node opened fresh over a disk store at `dir`, and a state sync into it.
fn joiner(dir: &Path, genesis: &Genesis) -> (Node, StateSync) {
    let config = NodeConfig {
        now_ms: 1_000,
        store: StoreConfig::Disk(dir.to_path_buf()),
        ..NodeConfig::default()
    };
    let mut node = Node::open(v1(), genesis, config).unwrap();
    let sync = StateSync::new(node.sync_config(trust()).unwrap()).unwrap();
    (node, sync)
}

/// How a peer answers: the request and the honest answer in, what it sends
/// out (`None`: nothing).
type Behaviour = Box<dyn FnMut(&SyncRequest, Vec<u8>) -> Option<Vec<u8>>>;

fn honest() -> Behaviour {
    Box::new(|_, answer| Some(answer))
}

/// A peer that answers honestly except that it rewrites the answers of one
/// kind with `lie`.
fn lying(lie: impl Fn(SyncResponse) -> Vec<u8> + 'static) -> Behaviour {
    Box::new(move |request, answer| {
        let response = SyncResponse::from_bytes(&answer).unwrap();
        let lies = matches!(
            (request, &response),
            (SyncRequest::Manifest { .. }, SyncResponse::Manifest(_))
                | (SyncRequest::Slice { .. }, SyncResponse::Slice { .. })
        );
        Some(if lies { lie(response) } else { answer })
    })
}

fn peer(i: u8) -> [u8; 32] {
    [i; 32]
}

/// Runs `sync` against `peers` (all served by `node`) in 10 ms steps from
/// `now`, the peers `connected(round)` names connected, until it is done,
/// failed, or `rounds` passed. Returns the time reached and the requests
/// sent.
/// What answers a peer's requests: a node, or a server of its own.
trait Answers {
    fn answer(&self, payload: &[u8]) -> Vec<u8>;
}

impl Answers for Node {
    fn answer(&self, payload: &[u8]) -> Vec<u8> {
        self.answer_sync(payload)
    }
}

impl Answers for SnapshotServer {
    fn answer(&self, payload: &[u8]) -> Vec<u8> {
        SnapshotServer::answer(self, payload)
    }
}

fn drive(
    sync: &mut StateSync,
    node: &dyn Answers,
    peers: &mut [Behaviour],
    mut now: u64,
    rounds: usize,
    connected: &dyn Fn(usize) -> Vec<usize>,
) -> (u64, usize) {
    let mut sent = 0;
    for round in 0..rounds {
        if sync.done().is_some() || sync.failed().is_some() {
            break;
        }
        let up: Vec<[u8; 32]> = connected(round)
            .into_iter()
            .map(|i| peer(u8::try_from(i).unwrap()))
            .collect();
        for (to, id, payload) in sync.poll(now, &up) {
            sent += 1;
            let request = SyncRequest::from_bytes(&payload).unwrap();
            let index = usize::from(to[0]);
            if let Some(answer) = peers[index](&request, node.answer(&payload)) {
                sync.on_response(to, id, &answer, now);
            }
        }
        now += 10;
    }
    (now, sent)
}

fn all(n: usize) -> impl Fn(usize) -> Vec<usize> {
    move |_| (0..n).collect()
}

fn banned(events: &[SyncEvent]) -> Vec<([u8; 32], &'static str)> {
    events
        .iter()
        .filter_map(|e| match e {
            SyncEvent::Banned { peer, why } => Some((*peer, *why)),
            _ => None,
        })
        .collect()
}

#[test]
fn messages_round_trip_and_bad_ones_are_refused() {
    let requests = [
        SyncRequest::Offers,
        SyncRequest::Manifest { epoch: 3 },
        SyncRequest::Slice {
            epoch: 3,
            slice: 7,
            after: Some([9; 32]),
        },
    ];
    for r in &requests {
        assert_eq!(&SyncRequest::from_bytes(&r.to_bytes()).unwrap(), r);
    }
    let responses = [
        SyncResponse::Offers(vec![Offer {
            epoch: 1,
            height: 8,
            state_root: [2; 32],
            entries: 5,
        }]),
        SyncResponse::Manifest(Manifest {
            header: vec![1, 2],
            depth: 1,
            slices: vec![
                Summary::Empty,
                Summary::Leaf {
                    path: [1; 32],
                    value_hash: [2; 32],
                },
                Summary::Branch { hash: [3; 32] },
            ],
        }),
        SyncResponse::Slice {
            entries: vec![Entry {
                key: b"k".to_vec(),
                value: b"v".to_vec(),
            }],
            more: true,
        },
        SyncResponse::Unavailable,
    ];
    for r in &responses {
        assert_eq!(&SyncResponse::from_bytes(&r.to_bytes()).unwrap(), r);
    }
    assert!(SyncRequest::from_bytes(&[3]).is_err());
    assert!(SyncResponse::from_bytes(&[4]).is_err());
    assert!(Summary::from_bytes(&[3]).is_err());
    // A node that serves nothing offers nothing and has nothing else.
    let offers = SyncResponse::from_bytes(&answer_unserved(&SyncRequest::Offers.to_bytes()));
    assert_eq!(offers.unwrap(), SyncResponse::Offers(vec![]));
    let manifest = answer_unserved(&SyncRequest::Manifest { epoch: 0 }.to_bytes());
    assert_eq!(
        SyncResponse::from_bytes(&manifest).unwrap(),
        SyncResponse::Unavailable
    );
    assert_eq!(
        SyncResponse::from_bytes(&answer_unserved(&[9])).unwrap(),
        SyncResponse::Unavailable
    );
    // Depths and slices.
    assert_eq!(depth_for(0, 8), 0);
    assert_eq!(depth_for(8, 8), 0);
    assert_eq!(depth_for(9, 8), 1);
    assert_eq!(depth_for(u64::MAX, 1), 16);
    assert_eq!(slice_of(&[0xFF; 32], 0), 0);
    assert_eq!(slice_of(&[0b1010_0000; 32], 3), 0b101);
    assert_eq!(slice_of(&[0xFF; 32], 16), 0xFFFF);
    // Summaries combine as the trie places them: an empty pair is empty,
    // a leaf beside an empty half moves up, anything else is a branch.
    let leaf = Summary::Leaf {
        path: [0x80; 32],
        value_hash: [1; 32],
    };
    let leaf_hash = solo_trie::leaf_hash(keccak256, &[0x80; 32], &[1; 32]);
    assert_eq!(combine(&[]), solo_trie::EMPTY);
    assert_eq!(combine(&[Summary::Empty, Summary::Empty]), solo_trie::EMPTY);
    assert_eq!(combine(&[Summary::Empty, leaf]), leaf_hash);
    assert_eq!(combine(&[leaf, Summary::Empty]), leaf_hash);
    let branch = Summary::Branch { hash: [5; 32] };
    assert_eq!(
        combine(&[Summary::Empty, branch]),
        solo_trie::branch_hash(keccak256, &solo_trie::EMPTY, &[5; 32])
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn a_server_serves_the_latest_epochs_and_answers_every_request() {
    let dir = scratch("server");
    let genesis = chain();
    let mut node = server(&dir, &genesis, SMALL);
    let served = node.snapshot_server().unwrap();
    let offers = served.offers();
    // It exported the latest record once a certificate covered it, and
    // keeps two epochs.
    let latest = node
        .state_get(ckeys::SNAPSHOT_LATEST)
        .map(|b| u64::from_bytes(&b).unwrap())
        .unwrap();
    assert_eq!(served.newest(), Some(offers[0].epoch));
    assert!(offers[0].epoch + 1 >= latest, "{offers:?} {latest}");
    assert_eq!(offers.len(), 2);
    assert!(offers[0].epoch > offers[1].epoch);
    let snaps = dir.join("snapshots");
    let files = std::fs::read_dir(&snaps).unwrap().count();
    assert_eq!(files, 2);
    let ask = |r: SyncRequest| SyncResponse::from_bytes(&node.answer_sync(&r.to_bytes())).unwrap();
    assert_eq!(
        ask(SyncRequest::Offers),
        SyncResponse::Offers(offers.clone())
    );
    let SyncResponse::Manifest(manifest) = ask(SyncRequest::Manifest {
        epoch: offers[0].epoch,
    }) else {
        panic!("a manifest");
    };
    assert_eq!(combine(&manifest.slices), offers[0].state_root);
    assert_eq!(
        manifest.depth,
        depth_for(offers[0].entries, SMALL.slice_entries)
    );
    assert_eq!(
        ask(SyncRequest::Manifest { epoch: 99 }),
        SyncResponse::Unavailable
    );
    // Pages of a slice follow one another by `after`, each within the
    // limit but for its last entry, and end with `more` false.
    let slice = (0u32..)
        .zip(&manifest.slices)
        .find(|(_, s)| matches!(s, Summary::Branch { .. }))
        .unwrap()
        .0;
    let mut after = None;
    let mut pages = 0;
    let mut entries = Vec::new();
    loop {
        let SyncResponse::Slice {
            entries: page,
            more,
        } = ask(SyncRequest::Slice {
            epoch: offers[0].epoch,
            slice,
            after,
        })
        else {
            panic!("a page");
        };
        pages += 1;
        assert!(!page.is_empty());
        after = Some(keccak256(&page.last().unwrap().key));
        entries.extend(page);
        if !more {
            break;
        }
    }
    assert!(entries.len() >= 2);
    assert!(
        entries
            .iter()
            .all(|e| slice_of(&keccak256(&e.key), manifest.depth) == slice)
    );
    let _ = pages;
    let unavailable = [
        SyncRequest::Slice {
            epoch: offers[0].epoch,
            slice: u32::MAX,
            after: None,
        },
        SyncRequest::Slice {
            epoch: 99,
            slice: 0,
            after: None,
        },
    ];
    for r in unavailable {
        assert_eq!(ask(r), SyncResponse::Unavailable);
    }
    assert_eq!(
        SyncResponse::from_bytes(&node.answer_sync(&[7])).unwrap(),
        SyncResponse::Unavailable
    );
    // A file that disappears is no longer served.
    let path = served.path_for(offers[1].epoch);
    std::fs::remove_file(&path).unwrap();
    assert_eq!(
        ask(SyncRequest::Slice {
            epoch: offers[1].epoch,
            slice: 0,
            after: None
        }),
        SyncResponse::Unavailable
    );
    // Reopened, a server serves what its directory holds: a snapshot file
    // that does not read goes, anything else stays, and the newest are
    // kept.
    std::fs::write(snaps.join("broken.snap"), b"not a snapshot").unwrap();
    std::fs::write(snaps.join("notes.txt"), b"kept").unwrap();
    let again = SnapshotServer::open(&snaps, ServeLimits::default()).unwrap();
    assert_eq!(again.offers(), vec![offers[0]]);
    assert!(!snaps.join("broken.snap").exists());
    assert!(snaps.join("notes.txt").exists());
    // Unsorted entries are not served.
    let snapshot = solo_store::Snapshot::open(&served.path_for(offers[0].epoch)).unwrap();
    let mut backwards: Vec<(Vec<u8>, Vec<u8>)> =
        snapshot.entries().unwrap().map(Result::unwrap).collect();
    backwards.reverse();
    let bad =
        solo_store::Snapshot::write(&snaps.join("backwards.snap"), &snapshot.header, backwards)
            .unwrap();
    let mut third = SnapshotServer::open(&scratch("server-empty"), SMALL).unwrap();
    assert!(third.add(bad).is_err());
    assert_eq!(third.newest(), None);
    // A directory that cannot be made is named; so is serving from memory.
    let file = scratch("server-file");
    std::fs::write(&file, b"x").unwrap();
    assert!(SnapshotServer::open(&file.join("sub"), SMALL).is_err());
    // A snapshot directory that cannot be made is named.
    std::fs::remove_dir_all(&snaps).unwrap();
    std::fs::write(&snaps, b"a file").unwrap();
    assert!(matches!(
        node.serve_snapshots(SMALL),
        Err(NodeError::Store(_))
    ));
    let mut memory = Node::new(v1(), &genesis, 0).unwrap();
    assert!(matches!(
        memory.serve_snapshots(SMALL),
        Err(NodeError::Store(_))
    ));
    assert!(matches!(
        memory.sync_config(trust()),
        Err(NodeError::Store(_))
    ));
}

#[test]
fn a_node_syncs_from_its_peers_and_starts() {
    let source = scratch("honest-source");
    let genesis = chain();
    let node = server(&source, &genesis, SMALL);
    let offer = node.snapshot_server().unwrap().offers()[0];
    let target = scratch("honest-target");
    let (mut fresh, mut sync) = joiner(&target, &genesis);
    assert_eq!(sync.progress(), None);
    let mut peers = [honest(), honest(), honest()];
    let (_, sent) = drive(&mut sync, &node, &mut peers, 0, 2_000, &all(3));
    let snapshot = sync.done().expect("synced").clone();
    assert!(sync.failed().is_none());
    let (done, total) = sync.progress().unwrap_or((0, 0));
    assert_eq!((done, total), (0, 0), "a finished sync reports no progress");
    let events = sync.take_events();
    assert_eq!(events, vec![SyncEvent::Target(offer)]);
    assert!(sent > 10, "{sent}");
    assert_eq!(snapshot.header.state_root, offer.state_root);
    assert_eq!(snapshot.header.entries, offer.entries);
    // Polling a finished sync asks nothing.
    assert!(sync.poll(1_000_000, &[peer(0)]).is_empty());
    // Slices of one entry or none, as a server with tiny slices makes
    // them, are summarised as leaves and empties and verified as such.
    let tiny = ServeLimits {
        slice_entries: 1,
        chunk_bytes: 64,
    };
    let leafy = SnapshotServer::open(&source.join("snapshots"), tiny).unwrap();
    let other = scratch("honest-leaves");
    let (_, mut leaves) = joiner(&other, &genesis);
    let mut peers = [honest()];
    drive(&mut leaves, &leafy, &mut peers, 0, 5_000, &all(1));
    assert_eq!(leaves.done().unwrap().header.state_root, offer.state_root);
    finish(&mut fresh, &snapshot).unwrap();
    assert_eq!(fresh.block_number().unwrap(), offer.height);
    assert_eq!(fresh.state_root(), offer.state_root);
    assert!(!target.join("statesync").exists());
}

/// A manifest rewritten by `f`.
fn manifest_lie(f: impl Fn(&mut Manifest) + 'static) -> Behaviour {
    lying(move |response| match response {
        SyncResponse::Manifest(mut m) => {
            f(&mut m);
            SyncResponse::Manifest(m).to_bytes()
        }
        other => other.to_bytes(),
    })
}

/// A page rewritten by `f`.
fn page_lie(f: impl Fn(&mut Vec<Entry>, &mut bool) + 'static) -> Behaviour {
    lying(move |response| match response {
        SyncResponse::Slice {
            mut entries,
            mut more,
        } => {
            f(&mut entries, &mut more);
            SyncResponse::Slice { entries, more }.to_bytes()
        }
        other => other.to_bytes(),
    })
}

#[test]
#[allow(clippy::too_many_lines)]
fn lying_peers_are_banned_and_the_sync_completes_from_honest_ones() {
    let source = scratch("liars-source");
    let genesis = chain();
    let node = server(&source, &genesis, SMALL);
    let offer = node.snapshot_server().unwrap().offers()[0];
    let header = |f: fn(&mut solo_store::SnapshotHeader)| {
        manifest_lie(move |m| {
            let mut h = solo_store::SnapshotHeader::from_bytes(&m.header).unwrap();
            f(&mut h);
            m.header = h.to_bytes();
        })
    };
    let cases: Vec<(&str, Behaviour, &str)> = vec![
        (
            "garbage",
            Box::new(|_, _| Some(vec![0xFF])),
            "an answer that does not decode",
        ),
        (
            "another kind",
            lying(|_| SyncResponse::Offers(vec![]).to_bytes()),
            "an answer of another kind than asked",
        ),
        (
            "undecodable header",
            manifest_lie(|m| m.header = vec![1]),
            "a manifest whose header does not decode",
        ),
        (
            "another snapshot",
            header(|h| h.height += 1),
            "a manifest of another snapshot than offered",
        ),
        (
            "an unverified header",
            header(|h| h.links.0.clear()),
            "a snapshot header that does not verify under the node's trust",
        ),
        (
            "too deep",
            manifest_lie(|m| m.depth = 17),
            "a manifest of the wrong shape",
        ),
        (
            "too few slices",
            manifest_lie(|m| {
                m.slices.pop();
            }),
            "a manifest of the wrong shape",
        ),
        (
            "a misplaced leaf",
            manifest_lie(|m| {
                m.slices[0] = Summary::Leaf {
                    path: [0xFF; 32],
                    value_hash: [0; 32],
                };
            }),
            "a manifest with a leaf outside its slice",
        ),
        (
            "a wrong subtree",
            manifest_lie(|m| {
                let branch = m
                    .slices
                    .iter()
                    .position(|s| matches!(s, Summary::Branch { .. }))
                    .unwrap();
                m.slices[branch] = Summary::Branch { hash: [7; 32] };
            }),
            "a manifest that does not combine to the snapshot's root",
        ),
        (
            "an empty page that says more",
            page_lie(|entries, more| {
                entries.clear();
                *more = true;
            }),
            "a page with no entry that says more follow",
        ),
        (
            "a node-local entry",
            page_lie(|entries, _| entries[0].key = b"local/x".to_vec()),
            "a node-local entry",
        ),
        (
            "an entry of another slice",
            page_lie(|entries, _| {
                // A key whose path differs in the first bit: another slice
                // at any depth above 0.
                let first = keccak256(&entries[0].key)[0] >> 7;
                entries[0].key = (0u32..1_000)
                    .map(|i| format!("elsewhere/{i}").into_bytes())
                    .find(|k| keccak256(k)[0] >> 7 != first)
                    .unwrap();
            }),
            "an entry outside its slice",
        ),
        (
            "entries out of order",
            page_lie(|entries, _| {
                let first = entries[0].clone();
                entries.push(first);
            }),
            "entries out of path order",
        ),
        (
            "a changed value",
            page_lie(|entries, _| entries[0].value.push(1)),
            "a slice that does not hash to its summary",
        ),
    ];
    for (name, liar, reason) in cases {
        let target = scratch(&format!("liars-{}", name.replace(' ', "-")));
        let (_, mut sync) = joiner(&target, &genesis);
        let mut peers = [liar, honest()];
        drive(&mut sync, &node, &mut peers, 0, 3_000, &all(2));
        let snapshot = sync
            .done()
            .unwrap_or_else(|| panic!("{name}: {:?}", sync.failed()));
        assert_eq!(snapshot.header.state_root, offer.state_root, "{name}");
        let events = sync.take_events();
        let bans = banned(&events);
        assert_eq!(bans, vec![(peer(0), reason)], "{name}: {events:?}");
    }
}

#[test]
fn silent_and_departing_peers_cost_time_not_the_sync() {
    let source = scratch("silent-source");
    let genesis = chain();
    let node = server(&source, &genesis, SMALL);
    // A peer that offers but never sends a page is asked three times, each
    // time out, and then no more.
    let target = scratch("silent-target");
    let (_, mut sync) = joiner(&target, &genesis);
    let silent: Behaviour =
        Box::new(|r, answer| (!matches!(r, SyncRequest::Slice { .. })).then_some(answer));
    let mut peers = [silent, honest()];
    drive(&mut sync, &node, &mut peers, 0, 20_000, &all(2));
    assert!(sync.done().is_some(), "{:?}", sync.failed());
    let events = sync.take_events();
    assert_eq!(banned(&events), vec![(peer(0), "requests that time out")]);
    // A peer that disconnects loses its requests without a strike; the
    // sync goes on from the other and from it again once it is back.
    let target = scratch("leaving-target");
    let (_, mut sync) = joiner(&target, &genesis);
    let mut peers = [honest(), honest()];
    let flaky = |round: usize| {
        if (20..60).contains(&round) {
            vec![1]
        } else {
            vec![0, 1]
        }
    };
    drive(&mut sync, &node, &mut peers, 0, 3_000, &flaky);
    assert!(sync.done().is_some());
    assert!(banned(&sync.take_events()).is_empty());
    // With nobody left who offers the target, it waits and resumes.
    let target = scratch("alone-target");
    let (_, mut sync) = joiner(&target, &genesis);
    let mut peers = [honest()];
    let gap = |round: usize| {
        if (15..200).contains(&round) {
            vec![]
        } else {
            vec![0]
        }
    };
    drive(&mut sync, &node, &mut peers, 0, 3_000, &gap);
    assert!(sync.done().is_some());
}

#[test]
fn a_peer_that_stops_serving_the_target_hands_it_to_others() {
    let source = scratch("unavailable-source");
    let genesis = chain();
    let node = server(&source, &genesis, SMALL);
    let target = scratch("unavailable-target");
    let (_, mut sync) = joiner(&target, &genesis);
    // Peer 0 offers the snapshot, then answers every other request with
    // `Unavailable`: it is not banned, only no longer a source.
    let gone: Behaviour = Box::new(|r, answer| {
        Some(match r {
            SyncRequest::Offers => answer,
            _ => SyncResponse::Unavailable.to_bytes(),
        })
    });
    let mut peers = [gone, honest()];
    drive(&mut sync, &node, &mut peers, 0, 3_000, &all(2));
    assert!(sync.done().is_some(), "{:?}", sync.failed());
    assert!(banned(&sync.take_events()).is_empty());
    // Alone, such a peer strands the target: discovery chooses again, and
    // again, until another peer turns up.
    let target = scratch("unavailable-alone");
    let (_, mut sync) = joiner(&target, &genesis);
    let gone: Behaviour = Box::new(|r, answer| {
        Some(match r {
            SyncRequest::Offers => answer,
            _ => SyncResponse::Unavailable.to_bytes(),
        })
    });
    let mut peers = [gone, honest()];
    let later = |round: usize| if round < 300 { vec![0] } else { vec![0, 1] };
    drive(&mut sync, &node, &mut peers, 0, 3_000, &later);
    assert!(sync.done().is_some(), "{:?}", sync.failed());
    // One that stops serving pages halfway, leaving one unanswered, strands
    // the target with slices in flight: they are dropped, and the sync
    // resumes once another peer turns up.
    let target = scratch("unavailable-halfway");
    let (_, mut sync) = joiner(&target, &genesis);
    let mut pages = 0;
    let halfway: Behaviour = Box::new(move |r, answer| {
        if !matches!(r, SyncRequest::Slice { .. }) {
            return Some(answer);
        }
        pages += 1;
        match pages {
            ..=4 => Some(answer),
            n if n % 2 == 1 => None,
            _ => Some(SyncResponse::Unavailable.to_bytes()),
        }
    });
    let mut peers = [halfway, honest()];
    drive(&mut sync, &node, &mut peers, 0, 3_000, &later);
    assert!(sync.done().is_some(), "{:?}", sync.failed());
}

#[test]
fn a_restarted_sync_keeps_the_slices_it_verified() {
    let source = scratch("resume-source");
    let genesis = chain();
    let node = server(&source, &genesis, SMALL);
    let offer = node.snapshot_server().unwrap().offers()[0];
    let target = scratch("resume-target");
    let (mut fresh, mut sync) = joiner(&target, &genesis);
    let mut peers = [honest()];
    // Stop once some slices are in.
    for round in 0..2_000u64 {
        if sync.progress().is_some_and(|(done, _)| done >= 3) {
            break;
        }
        drive(&mut sync, &node, &mut peers, round * 10, 1, &all(1));
    }
    let (done, total) = sync.progress().unwrap();
    assert!(done >= 3 && done < total, "{done} of {total}");
    drop(sync);
    // A stray file in the parts directory goes; the verified slices stay.
    std::fs::write(target.join("statesync/parts/stray"), b"x").unwrap();
    let mut again = StateSync::new(fresh.sync_config(trust()).unwrap()).unwrap();
    drive(&mut again, &node, &mut peers, 0, 2_000, &all(1));
    let events = again.take_events();
    assert_eq!(events[0], SyncEvent::Target(offer));
    assert!(
        matches!(events[1], SyncEvent::Resumed { slices } if slices >= done),
        "{events:?}"
    );
    let snapshot = again.done().unwrap().clone();
    assert!(!target.join("statesync/parts/stray").exists());
    finish(&mut fresh, &snapshot).unwrap();
    assert_eq!(fresh.state_root(), offer.state_root);
}

#[test]
fn a_snapshot_of_another_genesis_stops_the_sync_after_one_slice() {
    // The same validator and chain id, another allocation: the snapshot
    // verifies under the genesis set, but its genesis block is not ours.
    let source = scratch("other-genesis-source");
    let mut other = chain();
    let mut params = solo_abi::chain::GenesisParams::from_bytes(&other.params).unwrap();
    params.allocations.0[0].balance += 1;
    other.params = params.to_bytes();
    let node = server(&source, &other, SMALL);
    let target = scratch("other-genesis-target");
    let (_, mut sync) = joiner(&target, &chain());
    let mut peers = [honest()];
    let (_, sent) = drive(&mut sync, &node, &mut peers, 0, 2_000, &all(1));
    assert_eq!(
        sync.failed(),
        Some("the snapshot is of a chain with another genesis block")
    );
    // Offers, the manifest and the genesis slice's pages only.
    assert!(sent < 10, "{sent}");
    assert!(sync.poll(0, &[peer(0)]).is_empty());
}

#[test]
fn discovery_takes_the_newest_epoch_and_drops_a_forged_one() {
    let source = scratch("discovery-source");
    let genesis = chain();
    let node = server(&source, &genesis, SMALL);
    let offers = node.snapshot_server().unwrap().offers();
    let target = scratch("discovery-target");
    let (_, mut sync) = joiner(&target, &genesis);
    // Peer 0 offers a newer epoch it cannot back, peer 1 only the older of
    // the two served, peer 2 both.
    let forged = Offer {
        epoch: offers[0].epoch + 5,
        ..offers[0]
    };
    let liar: Behaviour = Box::new(move |r, answer| {
        Some(match r {
            SyncRequest::Offers => SyncResponse::Offers(vec![forged]).to_bytes(),
            SyncRequest::Manifest { .. } => SyncResponse::Manifest(Manifest {
                header: vec![],
                depth: 0,
                slices: vec![Summary::Empty],
            })
            .to_bytes(),
            SyncRequest::Slice { .. } => answer,
        })
    });
    let older = offers[1];
    let old_only: Behaviour = Box::new(move |r, answer| {
        Some(match r {
            SyncRequest::Offers => SyncResponse::Offers(vec![older]).to_bytes(),
            _ => answer,
        })
    });
    let mut peers = [liar, old_only, honest()];
    drive(&mut sync, &node, &mut peers, 0, 3_000, &all(3));
    let events = sync.take_events();
    assert_eq!(events[0], SyncEvent::Target(forged));
    assert_eq!(
        events[1],
        SyncEvent::Banned {
            peer: peer(0),
            why: "a manifest whose header does not decode"
        }
    );
    assert_eq!(events[2], SyncEvent::Target(offers[0]));
    assert_eq!(sync.done().unwrap().header.epoch, offers[0].epoch);
    // An answer to a request never sent, or from another peer than asked,
    // changes nothing.
    sync.on_response(peer(1), 12_345, &[], 0);
    // A peer that serves nothing yet is asked again until it does.
    let target = scratch("discovery-late");
    let (_, mut sync) = joiner(&target, &genesis);
    let mut asked = 0;
    let late: Behaviour = Box::new(move |r, answer| {
        asked += usize::from(matches!(r, SyncRequest::Offers));
        Some(if asked < 3 {
            SyncResponse::Offers(vec![]).to_bytes()
        } else {
            answer
        })
    });
    let mut peers = [late];
    drive(&mut sync, &node, &mut peers, 0, 3_000, &all(1));
    assert!(sync.done().is_some(), "{:?}", sync.failed());
}

#[test]
fn a_sync_directory_that_cannot_be_used_is_reported() {
    let source = scratch("disk-source");
    let genesis = chain();
    let node = server(&source, &genesis, SMALL);
    let target = scratch("disk-target");
    let (mut fresh, _) = joiner(&target, &genesis);
    let mut config = fresh.sync_config(trust()).unwrap();
    // A file where the directory should be.
    let file = scratch("disk-file");
    std::fs::write(&file, b"x").unwrap();
    config.dir = file.join("sub");
    assert!(StateSync::new(config.clone()).is_err());
    // A parts directory removed under a running sync fails it.
    config.dir = target.join("removed");
    let mut sync = StateSync::new(config.clone()).unwrap();
    let mut peers = [honest()];
    for round in 0..2_000u64 {
        if sync.progress().is_some() {
            break;
        }
        drive(&mut sync, &node, &mut peers, round * 10, 1, &all(1));
    }
    std::fs::remove_dir_all(config.dir.join("parts")).unwrap();
    drive(&mut sync, &node, &mut peers, 100_000, 2_000, &all(1));
    assert!(sync.failed().is_some());
    // So do verified slices that vanish before they are put together.
    config.dir = target.join("vanished");
    let mut sync = StateSync::new(config.clone()).unwrap();
    for round in 0..2_000u64 {
        if sync.progress().is_some_and(|(done, _)| done >= 1) {
            break;
        }
        drive(&mut sync, &node, &mut peers, round * 10, 1, &all(1));
    }
    for part in std::fs::read_dir(config.dir.join("parts")).unwrap() {
        let path = part.unwrap().path();
        if path.extension().is_none() {
            std::fs::remove_file(path).unwrap();
        }
    }
    drive(&mut sync, &node, &mut peers, 100_000, 2_000, &all(1));
    assert!(sync.failed().is_some());
    // So does a directory where the manifest cannot be written.
    config.dir = target.join("blocked");
    let mut sync = StateSync::new(config.clone()).unwrap();
    std::fs::create_dir_all(config.dir.join("manifest")).unwrap();
    drive(&mut sync, &node, &mut peers, 0, 2_000, &all(1));
    assert!(sync.failed().is_some());
}

/// Four validators, the first three on disk serving small snapshots.
fn network(dirs: &[Scratch]) -> (Sim, Genesis, Vec<SigningKey>) {
    let validators = keys(4);
    let genesis = genesis(&validators, epochs_of_four(), 10);
    let template = NodeConfig {
        now_ms: 10_000,
        ..NodeConfig::default()
    };
    let stores: Vec<StoreConfig> = dirs
        .iter()
        .map(|d| StoreConfig::Disk(d.to_path_buf()))
        .collect();
    let mut sim = Sim::with_stores(v1(), &genesis, &validators, 0, &template, 20, &stores).unwrap();
    for i in 0..dirs.len() {
        sim.nodes[i].serve_snapshots(SMALL).unwrap();
    }
    (sim, genesis, validators)
}

#[test]
fn a_validator_joins_a_running_network_from_its_peers() {
    let dirs = [scratch("net-0"), scratch("net-1"), scratch("net-2")];
    let (mut sim, genesis, validators) = network(&dirs);
    let bob = Wallet::new(0x52);
    sim.submit(0, &alice().tx(0, bob.address, ETHER, 21_000, &[]))
        .unwrap();
    // Validator 3 is down while the network runs through a few epochs.
    sim.crash(3);
    assert!(
        sim.run_until(80 * SLOT_MS, |s| s.nodes[0].finalized_height().unwrap()
            >= 12)
            .unwrap()
    );
    // Node 1 lies about every page; the others are honest.
    sim.filter_sync(Box::new(|from, payload| {
        if from == 1
            && let Ok(SyncResponse::Slice { mut entries, more }) = SyncResponse::from_bytes(payload)
            && !entries.is_empty()
        {
            entries[0].value.push(0);
            *payload = SyncResponse::Slice { entries, more }.to_bytes();
        }
        true
    }));
    let joined = scratch("net-3");
    sim.join_from_peers(
        3,
        v1(),
        &genesis,
        joined.to_path_buf(),
        Trust::Genesis(Sim::validator_set(&validators)),
    )
    .unwrap();
    assert!(sim.joining().is_some());
    let target = sim.nodes[0].finalized_height().unwrap() + 4;
    let caught_up = sim
        .run_until(120 * SLOT_MS, |s| {
            s.joining().is_none() && s.finalized_heights().unwrap().iter().all(|h| *h >= target)
        })
        .unwrap();
    assert!(caught_up, "{:?}", sim.finalized_heights().unwrap());
    let at = sim.nodes[3].finalized_height().unwrap();
    assert_eq!(
        sim.nodes[0].block_by_number(at).unwrap(),
        sim.nodes[3].block_by_number(at).unwrap()
    );
    assert_eq!(sim.nodes[3].account(&bob.address).unwrap().balance, ETHER);
    let liar = solo_node::validator_id(&validators[1]);
    assert!(
        sim.sync_events
            .iter()
            .any(|e| matches!(e, SyncEvent::Banned { peer, .. } if *peer == liar)),
        "{:?}",
        sim.sync_events
    );
    assert!(!joined.join("statesync").exists());
}

#[test]
fn a_join_survives_its_only_server_restarting_and_reports_a_failure() {
    let dirs = [scratch("restart-0")];
    let (mut sim, genesis, validators) = network(&dirs);
    sim.crash(3);
    assert!(
        sim.run_until(80 * SLOT_MS, |s| s.nodes[0].finalized_height().unwrap()
            >= 12)
            .unwrap()
    );
    let joined = scratch("restart-3");
    let trust = Trust::Genesis(Sim::validator_set(&validators));
    sim.join_from_peers(3, v1(), &genesis, joined.to_path_buf(), trust.clone())
        .unwrap();
    // Some slices in, the only server goes down: the network halts and the
    // sync waits; the server comes back over its store and serves again.
    assert!(
        sim.run_until(60 * SLOT_MS, |s| s
            .joining()
            .and_then(StateSync::progress)
            .is_some_and(|(done, _)| done >= 2))
            .unwrap()
    );
    sim.crash(0);
    sim.advance(20 * SLOT_MS).unwrap();
    let stalled = sim.joining().and_then(StateSync::progress).unwrap();
    sim.revive(0, v1(), &genesis).unwrap();
    sim.nodes[0].serve_snapshots(SMALL).unwrap();
    let caught_up = sim
        .run_until(200 * SLOT_MS, |s| {
            s.joining().is_none() && s.nodes[3].finalized_height().unwrap() > 12
        })
        .unwrap();
    assert!(
        caught_up,
        "{stalled:?} {:?}",
        sim.finalized_heights().unwrap()
    );
    // A sync that fails, here into a node of another genesis, fails the
    // simulation's step; a sync directory that cannot be made fails the join.
    let mut other = genesis.clone();
    let mut params = solo_abi::chain::GenesisParams::from_bytes(&other.params).unwrap();
    params.allocations.0[0].balance += 1;
    other.params = params.to_bytes();
    let elsewhere = scratch("restart-other");
    sim.join_from_peers(2, v1(), &other, elsewhere.to_path_buf(), trust.clone())
        .unwrap();
    let failed = sim.run_until(60 * SLOT_MS, |_| false);
    assert!(
        matches!(&failed, Err(NodeError::Store(why)) if why.contains("another genesis")),
        "{failed:?}"
    );
    let blocked = scratch("restart-blocked");
    std::fs::create_dir_all(&*blocked).unwrap();
    std::fs::write(blocked.join("statesync"), b"a file").unwrap();
    assert!(matches!(
        sim.join_from_peers(1, v1(), &genesis, blocked.to_path_buf(), trust),
        Err(NodeError::Store(_))
    ));
}
