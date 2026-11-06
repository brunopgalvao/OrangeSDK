//! The light-client module's logic on a synthetic beacon chain in the
//! minimal preset: genesis, updates across periods and a fork, every reason
//! an update is refused, governance, deliveries with their delay, rate
//! limit, pause and replay protection in the verifier, views, and the
//! admission checks.

use std::collections::BTreeMap;

use orange_abi::bridge_in::{
    BridgeInParams, Fork, INBOX_ADDRESS, InboxLimits, LIGHT_CLIENT_ADDRESS, VERIFIER_ADDRESS,
};
use orange_abi::chain::reason;
use orange_abi::codec::Seq;
use orange_ethlc::abi::{self, Delivery, encode, word};
use orange_ethlc::beacon::{Bootstrap, Update};
use orange_ethlc::client::{self, Context, Finalized, Storage, keys};
use orange_ethlc::inbox::{self, Message};
use orange_ethlc::sync::{self, Rejection};
use orange_ethlc::testing::{Chain, Committee, EthState, Evm, Native, unhex};
use orange_ethlc::verifier;

const GOVERNANCE: [u8; 20] = [0x60; 20];
const SIZE: usize = 32;

#[derive(Default, Clone)]
struct Map(BTreeMap<Vec<u8>, Vec<u8>>);

impl Storage for Map {
    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.0.get(key).cloned()
    }

    fn set(&mut self, key: &[u8], value: Option<&[u8]>) {
        match value {
            Some(v) => self.0.insert(key.to_vec(), v.to_vec()),
            None => self.0.remove(key),
        };
    }
}

fn rejected(r: Rejection) -> Vec<u8> {
    encode(abi::UPDATE_REJECTED, &[word(r as u64)])
}

fn at(timestamp: u64) -> Context {
    Context {
        caller: [0x11; 20],
        timestamp,
    }
}

fn finalized(store: &Map) -> Finalized {
    orange_abi::Decode::from_bytes(&store.get(keys::FINALIZED).unwrap()).unwrap()
}

/// An outbox on "Ethereum" with two messages sent, and its state.
struct Outbox {
    address: [u8; 20],
    state: EthState,
    messages: Vec<Message>,
}

fn outbox() -> Outbox {
    outbox_to(&[[0x7E; 20]; 3])
}

/// An outbox that sent one message to each of `recipients`, in order.
fn outbox_to(recipients: &[[u8; 20]]) -> Outbox {
    let mut evm = Evm::new();
    let root = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../contracts/build/EthereumOutbox.bin"
    );
    let mut init = unhex(&std::fs::read_to_string(root).unwrap());
    init.extend_from_slice(&word(7));
    let address = evm.deploy([0xD0; 20], init).unwrap();
    let mut messages = Vec::new();
    let payloads = [b"one".to_vec(), vec![2; 50], b"three".to_vec()];
    for (nonce, (payload, recipient)) in payloads.into_iter().cycle().zip(recipients).enumerate() {
        let message = Message {
            nonce: nonce as u64,
            sender: [0x5E; 20],
            recipient: *recipient,
            gas_limit: 60_000,
            payload,
        };
        evm.call([0x5E; 20], address, message.send_call()).unwrap();
        messages.push(message);
    }
    Outbox {
        address,
        state: evm.state(),
        messages,
    }
}

fn params(chain: &Chain, bootstrap: &Bootstrap, outbox: [u8; 20]) -> BridgeInParams {
    BridgeInParams {
        light_client: vec![1],
        verifier: vec![2],
        config: chain.config.clone(),
        bootstrap: bootstrap.encode(),
        outbox,
        limits: InboxLimits {
            delay: 100,
            window: 1000,
            max_messages: 2,
        },
    }
}

fn submit(
    store: &mut Map,
    update: &Update,
    finality: bool,
    timestamp: u64,
) -> Result<Vec<u8>, Vec<u8>> {
    let bytes = if finality {
        update.encode_finality_update()
    } else {
        update.encode_update(SIZE)
    };
    client::call(
        &Native,
        store,
        &at(timestamp),
        &client::submit_call(&bytes, finality),
    )
}

#[test]
fn genesis_refuses_what_cannot_work() {
    let c = Native;
    let chain = Chain::minimal(32);
    let good = chain.bootstrap(8, [3; 32]);
    let mut store = Map::default();
    let mut p = params(&chain, &good, [1; 20]);
    p.config.forks = Seq(vec![]);
    assert_eq!(
        client::genesis(&c, &mut store, &p, GOVERNANCE),
        Err(Rejection::BadConfig)
    );
    for f in [
        |p: &mut BridgeInParams| p.config.sync_committee_size = 0,
        |p: &mut BridgeInParams| p.config.sync_committee_size = 12,
        |p: &mut BridgeInParams| p.config.sync_committee_size = 2048,
        |p: &mut BridgeInParams| p.config.slots_per_epoch = 0,
        |p: &mut BridgeInParams| p.config.epochs_per_period = 0,
        |p: &mut BridgeInParams| p.config.forks.0.reverse(),
    ] {
        let mut p = params(&chain, &good, [1; 20]);
        f(&mut p);
        assert_eq!(
            client::genesis(&c, &mut store, &p, GOVERNANCE),
            Err(Rejection::BadConfig)
        );
    }
    let mut p = params(&chain, &good, [1; 20]);
    p.bootstrap.truncate(100);
    assert_eq!(
        client::genesis(&c, &mut store, &p, GOVERNANCE),
        Err(Rejection::Malformed)
    );
    let mut bad = good.clone();
    bad.current_sync_committee_branch[0][0] ^= 1;
    assert_eq!(
        client::genesis(&c, &mut store, &params(&chain, &bad, [1; 20]), GOVERNANCE),
        Err(Rejection::BadBootstrap)
    );
    let mut bad = good.clone();
    bad.header.execution.gas_limit = 1;
    assert_eq!(
        client::genesis(&c, &mut store, &params(&chain, &bad, [1; 20]), GOVERNANCE),
        Err(Rejection::BadExecutionBranch)
    );
    let mut p = params(&chain, &good, [1; 20]);
    p.config.forks = Seq(vec![Fork {
        epoch: 2,
        version: [5, 0, 0, 1],
    }]);
    assert_eq!(
        client::genesis(&c, &mut store, &p, GOVERNANCE),
        Err(Rejection::UnsupportedFork)
    );
    assert!(store.0.is_empty());
    assert_eq!(
        client::genesis(&c, &mut store, &params(&chain, &good, [1; 20]), GOVERNANCE),
        Ok(())
    );
    let root: client::ExecutionRoot =
        orange_abi::Decode::from_bytes(&store.get(&keys::root(8)).unwrap()).unwrap();
    assert_eq!(
        (root.state_root, root.slot, root.usable_at),
        ([3; 32], 8, 100)
    );
}

#[test]
#[allow(clippy::too_many_lines)]
#[allow(clippy::many_single_char_names)]
fn updates_advance_the_client_and_bad_ones_are_refused() {
    let c = Native;
    let chain = Chain::minimal(32);
    let mut store = Map::default();
    client::genesis(
        &c,
        &mut store,
        &params(&chain, &chain.bootstrap(8, [3; 32]), [1; 20]),
        GOVERNANCE,
    )
    .unwrap();
    let f16 = chain.header(16, [16; 32], [0; 32]);

    // Refusals before anything is learned.
    let garbage = client::submit_call(&[1, 2, 3], false);
    assert_eq!(
        client::call(&c, &mut store, &at(0), &garbage),
        Err(rejected(Rejection::Malformed))
    );
    let few = chain.update(20, &f16, true, 21, 21);
    assert_eq!(
        submit(&mut store, &few, false, 0),
        Err(rejected(Rejection::LowParticipation))
    );
    let same_slot = chain.update(20, &f16, true, 20, 32);
    assert_eq!(
        submit(&mut store, &same_slot, false, 0),
        Err(rejected(Rejection::Slots))
    );
    let backwards = chain.update(15, &f16, true, 21, 32);
    assert_eq!(
        submit(&mut store, &backwards, false, 0),
        Err(rejected(Rejection::Slots))
    );
    // Signed in period 1, whose committee is not known yet.
    let early = chain.update(20, &f16, true, 70, 32);
    assert_eq!(
        submit(&mut store, &early, false, 0),
        Err(rejected(Rejection::WrongPeriod))
    );
    let stale = chain.update(8, &chain.header(8, [3; 32], [0; 32]), false, 9, 32);
    assert_eq!(
        submit(&mut store, &stale, true, 0),
        Err(rejected(Rejection::NotNewer))
    );
    // Attested ahead, but finalizing nothing new and teaching nothing.
    let not_final = chain.update(20, &chain.header(4, [4; 32], [0; 32]), false, 21, 32);
    assert_eq!(
        submit(&mut store, &not_final, true, 0),
        Err(rejected(Rejection::NotNewer))
    );
    let mut no_finality = chain.update(20, &f16, true, 21, 32);
    no_finality.finality_branch = [[0; 32]; 7];
    assert_eq!(
        submit(&mut store, &no_finality, false, 0),
        Err(rejected(Rejection::NoFinality))
    );
    let mut bad_signature = chain.update(20, &f16, true, 21, 32);
    bad_signature.sync_aggregate.bits[0] ^= 1;
    assert_eq!(
        submit(&mut store, &bad_signature, false, 0),
        Err(rejected(Rejection::BadSignature))
    );

    // Two thirds is enough: the next committee is learned, the header advances.
    let a = chain.update(20, &f16, true, 21, 22);
    assert_eq!(submit(&mut store, &a, false, 50), Ok(vec![]));
    assert_eq!(finalized(&store).slot, 16);
    assert_eq!(
        store.get(&keys::committee(1)),
        Some(chain.committee(1).pubkeys)
    );
    let root: client::ExecutionRoot =
        orange_abi::Decode::from_bytes(&store.get(&keys::root(16)).unwrap()).unwrap();
    assert_eq!((root.state_root, root.usable_at), ([16; 32], 150));
    assert_eq!(
        submit(&mut store, &a, false, 51),
        Err(rejected(Rejection::NotNewer))
    );

    // A next committee other than the one learned.
    let mut mismatch = chain.update(30, &chain.header(24, [24; 32], [0; 32]), true, 31, 32);
    mismatch.next_sync_committee.as_mut().unwrap().0 = Committee::new(99, SIZE).sync_committee();
    assert_eq!(
        submit(&mut store, &mismatch, false, 60),
        Err(rejected(Rejection::CommitteeMismatch))
    );
    // Signed in period 2: neither the current nor the next.
    let far = chain.update(30, &chain.header(24, [24; 32], [0; 32]), false, 130, 32);
    assert_eq!(
        submit(&mut store, &far, true, 60),
        Err(rejected(Rejection::WrongPeriod))
    );
    // Signed by the next committee in period 1 while finalizing in period 0: no rotation.
    let b0 = chain.update(66, &chain.header(40, [40; 32], [0; 32]), true, 67, 32);
    assert_eq!(submit(&mut store, &b0, false, 61), Ok(vec![]));
    assert_eq!(finalized(&store).slot, 40);
    assert!(store.get(&keys::committee(2)).is_none());

    // Finalizing in period 1 rotates, and the committee of period 2 is learned.
    let b = chain.update(70, &chain.header(66, [66; 32], [0; 32]), true, 71, 32);
    assert_eq!(submit(&mut store, &b, false, 70), Ok(vec![]));
    assert_eq!(finalized(&store).slot, 66);
    assert!(store.get(&keys::committee(0)).is_none());
    assert_eq!(
        store.get(&keys::committee(2)),
        Some(chain.committee(2).pubkeys)
    );

    // A finality update across the fork at epoch 16 rotates without a next committee.
    let f = chain.update(140, &chain.header(130, [130; 32], [0; 32]), false, 141, 32);
    let mut bad_branch = f.clone();
    bad_branch.finality_branch[2][0] ^= 1;
    assert_eq!(
        submit(&mut store, &bad_branch, true, 80),
        Err(rejected(Rejection::BadFinalityBranch))
    );
    assert_eq!(submit(&mut store, &f, true, 80), Ok(vec![]));
    assert_eq!(finalized(&store).slot, 130);
    assert!(store.get(&keys::committee(3)).is_none());
    // Then the period's update teaches the next committee again.
    let mut bad_committee =
        chain.update(150, &chain.header(145, [145; 32], [0; 32]), true, 151, 32);
    bad_committee.next_sync_committee.as_mut().unwrap().1[0][0] ^= 1;
    assert_eq!(
        submit(&mut store, &bad_committee, false, 90),
        Err(rejected(Rejection::BadCommitteeBranch))
    );
    let d = chain.update(150, &chain.header(145, [145; 32], [0; 32]), true, 151, 32);
    assert_eq!(submit(&mut store, &d, false, 90), Ok(vec![]));
    assert_eq!(
        store.get(&keys::committee(3)),
        Some(chain.committee(3).pubkeys)
    );

    // Views of the result.
    let fin = client::query(&store, &abi::FINALIZED).unwrap();
    assert_eq!(fin[..32], word(145));
    assert_eq!(fin[64..96], word(145));
    assert_eq!(fin[128..160], [145; 32]);
    let unknown = client::query(&store, &client::u64_call(abi::EXECUTION_ROOT, 9999)).unwrap();
    assert_eq!(unknown, vec![0; 128]);
    let mut high = client::u64_call(abi::EXECUTION_ROOT, 1);
    high[4] = 1;
    assert_eq!(client::query(&store, &high), Err(vec![]));
    assert_eq!(client::query(&Map::default(), &abi::PAUSED), Err(vec![]));

    // A client missing its committee cannot process anything.
    let mut broken = store.clone();
    broken.set(&keys::committee(2), None);
    let e = chain.update(160, &chain.header(155, [155; 32], [0; 32]), false, 161, 32);
    assert_eq!(
        submit(&mut broken, &e, true, 99),
        Err(rejected(Rejection::Malformed))
    );
    assert_eq!(
        client::admit(
            &broken,
            &Map::default(),
            &LIGHT_CLIENT_ADDRESS,
            0,
            &client::submit_call(&e.encode_finality_update(), true)
        ),
        Err(reason::BRIDGE_UPDATE)
    );
}

#[test]
fn an_update_from_before_the_first_fork_is_refused() {
    let c = Native;
    let mut chain = Chain::minimal(32);
    chain.config.forks = Seq(vec![Fork {
        epoch: 1,
        version: [5, 0, 0, 1],
    }]);
    let mut store = Map::default();
    client::genesis(
        &c,
        &mut store,
        &params(&chain, &chain.bootstrap(8, [3; 32]), [1; 20]),
        GOVERNANCE,
    )
    .unwrap();
    let mut early =
        Chain::minimal(32).update(20, &chain.header(4, [4; 32], [0; 32]), false, 21, 32);
    early.finalized.beacon.slot = 4;
    assert_eq!(
        submit(&mut store, &early, true, 0),
        Err(rejected(Rejection::UnsupportedFork))
    );
    assert_eq!(sync::fork_version(&chain.config, 0), None);
    assert_eq!(sync::fork_version(&chain.config, 1), Some([5, 0, 0, 1]));
}

#[test]
#[allow(clippy::too_many_lines)]
fn light_client_governance() {
    let c = Native;
    let chain = Chain::minimal(32);
    let mut store = Map::default();
    client::genesis(
        &c,
        &mut store,
        &params(&chain, &chain.bootstrap(8, [3; 32]), [1; 20]),
        GOVERNANCE,
    )
    .unwrap();
    let gov = |t: u64| Context {
        caller: GOVERNANCE,
        timestamp: t,
    };
    // The delay: governance only, exactly one word.
    assert_eq!(client::query(&store, &abi::DELAY), Ok(word(100).to_vec()));
    let set = client::u64_call(abi::SET_DELAY, 5);
    assert_eq!(
        client::call(&c, &mut store, &at(0), &set),
        Err(encode(abi::NOT_GOVERNANCE, &[]))
    );
    assert_eq!(
        client::call(&c, &mut store, &gov(0), &set[..35]),
        Err(vec![])
    );
    assert_eq!(client::call(&c, &mut store, &gov(0), &set), Ok(vec![]));
    assert_eq!(client::query(&store, &abi::DELAY), Ok(word(5).to_vec()));
    let root_of = |store: &Map, block: u64| {
        client::query(store, &client::u64_call(abi::EXECUTION_ROOT, block)).unwrap()[..32].to_vec()
    };
    assert_eq!(root_of(&store, 8), [3; 32]);
    // A new checkpoint replaces the client's state; its root waits out the delay.
    let fresh = chain.bootstrap(200, [0xEE; 32]);
    let checkpoint = abi::encode_bytes_call(abi::SET_CHECKPOINT, &fresh.encode());
    assert_eq!(
        client::call(&c, &mut store, &at(3000), &checkpoint),
        Err(encode(abi::NOT_GOVERNANCE, &[]))
    );
    assert_eq!(
        client::call(
            &c,
            &mut store,
            &gov(3000),
            &abi::encode_bytes_call(abi::SET_CHECKPOINT, &[1])
        ),
        Err(rejected(Rejection::Malformed))
    );
    assert_eq!(
        client::call(&c, &mut store, &gov(3000), &abi::SET_CHECKPOINT),
        Err(rejected(Rejection::Malformed))
    );
    let mut bad = fresh.clone();
    bad.current_sync_committee_branch[1][0] ^= 1;
    assert_eq!(
        client::call(
            &c,
            &mut store,
            &gov(3000),
            &abi::encode_bytes_call(abi::SET_CHECKPOINT, &bad.encode())
        ),
        Err(rejected(Rejection::BadBootstrap))
    );
    assert_eq!(
        client::call(&c, &mut store, &gov(3000), &checkpoint),
        Ok(vec![])
    );
    assert_eq!(finalized(&store).slot, 200);
    assert!(store.get(&keys::committee(0)).is_none());
    assert_eq!(
        store.get(&keys::committee(3)),
        Some(chain.committee(3).pubkeys)
    );
    let root: client::ExecutionRoot =
        orange_abi::Decode::from_bytes(&store.get(&keys::root(200)).unwrap()).unwrap();
    assert_eq!((root.usable_at, root.epoch), (3005, 1));
    assert_eq!(root_of(&store, 200), [0xEE; 32]);
    // Every root stored before the checkpoint is revoked: one a dishonest
    // committee got accepted can no longer prove messages (spec 18 §5.1).
    assert!(store.get(&keys::root(8)).is_some());
    assert_eq!(root_of(&store, 8), [0; 32]);
    // A second checkpoint revokes the first one's roots in turn.
    let again = chain.bootstrap(208, [0xDD; 32]);
    assert_eq!(
        client::call(
            &c,
            &mut store,
            &gov(4000),
            &abi::encode_bytes_call(abi::SET_CHECKPOINT, &again.encode())
        ),
        Ok(vec![])
    );
    assert_eq!(finalized(&store).epoch, 2);
    assert_eq!(root_of(&store, 200), [0; 32]);
    assert_eq!(root_of(&store, 208), [0xDD; 32]);
    // Without a governance account nobody governs.
    let mut ungoverned = Map::default();
    client::genesis(
        &c,
        &mut ungoverned,
        &params(&chain, &chain.bootstrap(8, [3; 32]), [1; 20]),
        [0; 20],
    )
    .unwrap();
    let nobody = Context {
        caller: [0; 20],
        timestamp: 0,
    };
    assert_eq!(
        client::call(&c, &mut ungoverned, &nobody, &set),
        Err(encode(abi::NOT_GOVERNANCE, &[]))
    );
    // Unknown calldata, short calldata, and a namespace without the client.
    assert_eq!(
        client::call(&c, &mut ungoverned, &nobody, &[1, 2, 3, 4]),
        Err(vec![])
    );
    assert_eq!(
        client::call(&c, &mut ungoverned, &nobody, &[1, 2]),
        Err(vec![])
    );
    assert_eq!(client::query(&ungoverned, &[1, 2]), Err(vec![]));
    assert_eq!(
        client::call(&c, &mut Map::default(), &nobody, &abi::DELAY),
        Err(vec![])
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn the_verifier_delivers_each_message_once() {
    let c = Native;
    let ob = outbox();
    let root = ob.state.root();
    let mut store = Map::default();
    verifier::genesis(
        &mut store,
        &params(
            &Chain::minimal(32),
            &Chain::minimal(32).bootstrap(8, root),
            ob.address,
        ),
        7,
        GOVERNANCE,
    );
    let gov = |t: u64| Context {
        caller: GOVERNANCE,
        timestamp: t,
    };
    let inbox_at = |t: u64| Context {
        caller: INBOX_ADDRESS,
        timestamp: t,
    };
    let delivery = |m: &Message| {
        let (account_proof, storage_proof) = ob.state.proof(&ob.address, &inbox::slot(&c, m.nonce));
        Delivery {
            anchor: root,
            message: m.clone(),
            account_proof,
            storage_proof,
        }
    };
    let consume = |store: &mut Map, d: &Delivery, ctx: Context| {
        verifier::call(&c, store, &ctx, &d.encode(abi::CONSUME))
    };
    let d0 = delivery(&ob.messages[0]);

    // Only the inbox consumes, with proofs of exactly the stored message.
    assert_eq!(
        consume(&mut store, &d0, at(500)),
        Err(encode(abi::NOT_INBOX, &[]))
    );
    assert_eq!(
        verifier::call(&c, &mut store, &inbox_at(500), &abi::CONSUME),
        Err(vec![])
    );
    let mut forged = d0.clone();
    forged.message.payload = b"forged".to_vec();
    assert_eq!(
        consume(&mut store, &forged, inbox_at(500)),
        Err(encode(abi::BAD_PROOF, &[]))
    );
    // A relayer cannot change the gas the sender gave the recipient.
    let mut starved = d0.clone();
    starved.message.gas_limit = 21_000;
    assert_eq!(
        consume(&mut store, &starved, inbox_at(500)),
        Err(encode(abi::BAD_PROOF, &[]))
    );
    // Only the canonical encoding counts (spec 18 §5): trailing bytes revert
    // with empty data, before anything else is checked.
    let mut trailing = d0.encode(abi::CONSUME);
    trailing.extend_from_slice(&[0; 32]);
    assert_eq!(
        verifier::call(&c, &mut store, &inbox_at(500), &trailing),
        Err(vec![])
    );
    let mut wrong_root = d0.clone();
    wrong_root.anchor = [9; 32];
    assert_eq!(
        consume(&mut store, &wrong_root, inbox_at(500)),
        Err(encode(abi::BAD_PROOF, &[]))
    );
    let mut wrong_slot = d0.clone();
    wrong_slot.storage_proof = delivery(&ob.messages[1]).storage_proof;
    assert_eq!(
        consume(&mut store, &wrong_slot, inbox_at(500)),
        Err(encode(abi::BAD_PROOF, &[]))
    );

    // Paused: nothing is consumed. Only governance pauses, with no arguments.
    assert_eq!(
        verifier::call(&c, &mut store, &at(500), &abi::PAUSE),
        Err(encode(abi::NOT_GOVERNANCE, &[]))
    );
    assert_eq!(
        verifier::call(
            &c,
            &mut store,
            &gov(500),
            &[abi::PAUSE.as_slice(), &[0]].concat()
        ),
        Err(vec![])
    );
    assert_eq!(
        verifier::call(&c, &mut store, &gov(500), &abi::PAUSE),
        Ok(vec![])
    );
    assert_eq!(verifier::query(&store, &abi::PAUSED), Ok(word(1).to_vec()));
    assert_eq!(
        consume(&mut store, &d0, inbox_at(500)),
        Err(encode(abi::PAUSED_ERROR, &[]))
    );
    assert_eq!(
        verifier::call(&c, &mut store, &gov(500), &abi::UNPAUSE),
        Ok(vec![])
    );
    assert_eq!(verifier::query(&store, &abi::PAUSED), Ok(word(0).to_vec()));

    // Delivered once; never again.
    assert_eq!(consume(&mut store, &d0, inbox_at(500)), Ok(vec![]));
    assert_eq!(
        consume(&mut store, &d0, inbox_at(501)),
        Err(encode(abi::ALREADY_DELIVERED, &[word(0)]))
    );
    assert_eq!(
        verifier::query(&store, &client::u64_call(abi::DELIVERED, 0)),
        Ok(word(1).to_vec())
    );
    assert_eq!(
        verifier::query(&store, &client::u64_call(abi::DELIVERED, 1)),
        Ok(word(0).to_vec())
    );
    let mut high = client::u64_call(abi::DELIVERED, 1);
    high[5] = 1;
    assert_eq!(verifier::query(&store, &high), Err(vec![]));

    // Two per window of 1000 s (the first window opened at 0): the third
    // waits for the next one, which opens with the first delivery after.
    assert_eq!(
        consume(&mut store, &delivery(&ob.messages[1]), inbox_at(600)),
        Ok(vec![])
    );
    let d2 = delivery(&ob.messages[2]);
    assert_eq!(
        consume(&mut store, &d2, inbox_at(999)),
        Err(encode(abi::RATE_LIMITED, &[]))
    );
    assert_eq!(consume(&mut store, &d2, inbox_at(1000)), Ok(vec![]));
    let window: verifier::Window =
        orange_abi::Decode::from_bytes(&store.get(verifier::keys::WINDOW).unwrap()).unwrap();
    assert_eq!((window.start, window.count), (1000, 1));

    // The rate limit: governance only, exactly two words.
    assert_eq!(
        verifier::query(&store, &abi::RATE_LIMIT),
        Ok([word(1000), word(2)].concat())
    );
    let set = verifier::set_rate_limit_call(10, 1);
    assert_eq!(
        verifier::call(&c, &mut store, &at(0), &set),
        Err(encode(abi::NOT_GOVERNANCE, &[]))
    );
    assert_eq!(
        verifier::call(&c, &mut store, &gov(0), &set[..67]),
        Err(vec![])
    );
    let mut dirty = set.clone();
    dirty[4] = 1;
    assert_eq!(verifier::call(&c, &mut store, &gov(0), &dirty), Err(vec![]));
    assert_eq!(verifier::call(&c, &mut store, &gov(0), &set), Ok(vec![]));
    assert_eq!(
        verifier::query(&store, &abi::RATE_LIMIT),
        Ok([word(10), word(1)].concat())
    );

    // Without a governance account nobody governs; unknown calldata and an
    // empty namespace answer nothing.
    let mut ungoverned = Map::default();
    verifier::genesis(
        &mut ungoverned,
        &params(
            &Chain::minimal(32),
            &Chain::minimal(32).bootstrap(8, root),
            ob.address,
        ),
        7,
        [0; 20],
    );
    let nobody = Context {
        caller: [0; 20],
        timestamp: 0,
    };
    assert_eq!(
        verifier::call(&c, &mut ungoverned, &nobody, &abi::PAUSE),
        Err(encode(abi::NOT_GOVERNANCE, &[]))
    );
    assert_eq!(
        verifier::call(&c, &mut ungoverned, &nobody, &[1, 2, 3, 4]),
        Err(vec![])
    );
    assert_eq!(
        verifier::call(&c, &mut ungoverned, &nobody, &[1]),
        Err(vec![])
    );
    assert_eq!(verifier::query(&ungoverned, &[1]), Err(vec![]));
    assert_eq!(
        verifier::call(&c, &mut Map::default(), &nobody, &abi::PAUSED),
        Err(vec![])
    );
}

#[test]
fn a_recipient_with_its_own_limit_is_not_crowded_out() {
    const OTHER: [u8; 20] = [0x7E; 20];
    const GATEWAY: [u8; 20] = [0x6A; 20];
    let c = Native;
    let ob = outbox_to(&[OTHER, OTHER, OTHER, GATEWAY, GATEWAY, GATEWAY]);
    let root = ob.state.root();
    let mut store = Map::default();
    let chain = Chain::minimal(32);
    verifier::genesis(
        &mut store,
        &params(&chain, &chain.bootstrap(8, root), ob.address),
        7,
        GOVERNANCE,
    );
    let ctx = |caller: [u8; 20], timestamp: u64| Context { caller, timestamp };
    let consume = |store: &mut Map, nonce: usize, timestamp: u64| {
        let m = &ob.messages[nonce];
        let (account_proof, storage_proof) = ob.state.proof(&ob.address, &inbox::slot(&c, m.nonce));
        let d = Delivery {
            anchor: root,
            message: m.clone(),
            account_proof,
            storage_proof,
        };
        verifier::call(
            &c,
            store,
            &ctx(INBOX_ADDRESS, timestamp),
            &d.encode(abi::CONSUME),
        )
    };
    let limit_of = |store: &Map, recipient: &[u8; 20]| {
        verifier::query(
            store,
            &encode(abi::RECIPIENT_LIMIT, &[abi::address_word(recipient)]),
        )
    };
    // Governance alone gives the gateway a limit of its own, of two words.
    let set = verifier::set_recipient_limit_call(&GATEWAY, 2);
    assert_eq!(
        verifier::call(&c, &mut store, &ctx(OTHER, 0), &set),
        Err(encode(abi::NOT_GOVERNANCE, &[]))
    );
    assert_eq!(
        verifier::call(&c, &mut store, &ctx(GOVERNANCE, 0), &set[..67]),
        Err(vec![])
    );
    let mut dirty = set.clone();
    dirty[4] = 1;
    assert_eq!(
        verifier::call(&c, &mut store, &ctx(GOVERNANCE, 0), &dirty),
        Err(vec![])
    );
    assert_eq!(
        verifier::call(&c, &mut store, &ctx(GOVERNANCE, 0), &set),
        Ok(vec![])
    );
    assert_eq!(limit_of(&store, &GATEWAY), Ok(word(2).to_vec()));
    assert_eq!(limit_of(&store, &OTHER), Ok(word(0).to_vec()));
    let mut short = encode(abi::RECIPIENT_LIMIT, &[abi::address_word(&GATEWAY)]);
    short.pop();
    assert_eq!(verifier::query(&store, &short), Err(vec![]));
    // Others fill the shared window of two; the gateway's messages pass, up to
    // its own two.
    assert_eq!(consume(&mut store, 0, 500), Ok(vec![]));
    assert_eq!(consume(&mut store, 1, 500), Ok(vec![]));
    let limited = Err(encode(abi::RATE_LIMITED, &[]));
    assert_eq!(consume(&mut store, 2, 500), limited);
    assert_eq!(consume(&mut store, 3, 600), Ok(vec![]));
    assert_eq!(consume(&mut store, 4, 600), Ok(vec![]));
    assert_eq!(consume(&mut store, 5, 700), limited);
    // Each window opens again with its first delivery a window after it opened.
    assert_eq!(consume(&mut store, 5, 999), limited);
    assert_eq!(consume(&mut store, 5, 1000), Ok(vec![]));
    assert_eq!(consume(&mut store, 2, 1500), Ok(vec![]));
    let shared: verifier::Window =
        orange_abi::Decode::from_bytes(&store.get(verifier::keys::WINDOW).unwrap()).unwrap();
    assert_eq!((shared.start, shared.count), (1500, 1));
    let own: verifier::RecipientLimit =
        orange_abi::Decode::from_bytes(&store.get(&verifier::keys::recipient(&GATEWAY)).unwrap())
            .unwrap();
    assert_eq!((own.max_messages, own.start, own.count), (2, 1000, 1));
    // Zero returns it to the shared window.
    let unset = verifier::set_recipient_limit_call(&GATEWAY, 0);
    assert_eq!(
        verifier::call(&c, &mut store, &ctx(GOVERNANCE, 0), &unset),
        Ok(vec![])
    );
    assert_eq!(limit_of(&store, &GATEWAY), Ok(word(0).to_vec()));
}

#[test]
#[allow(clippy::too_many_lines)]
fn admission_checks() {
    let c = Native;
    let chain = Chain::minimal(32);
    let empty = Map::default();
    let update = chain.update(20, &chain.header(16, [16; 32], [0; 32]), true, 21, 32);
    let call = client::submit_call(&update.encode_update(SIZE), false);
    // Other addresses pass; the bridge's three refuse everything without the bridge.
    assert_eq!(client::admit(&empty, &empty, &[9; 20], 5, &[]), Ok(()));
    assert_eq!(
        client::admit(&empty, &empty, &LIGHT_CLIENT_ADDRESS, 0, &call),
        Err(reason::BRIDGE_CALL)
    );
    assert_eq!(
        client::admit(&empty, &empty, &INBOX_ADDRESS, 0, &[]),
        Err(reason::BRIDGE_CALL)
    );
    assert_eq!(
        client::admit(&empty, &empty, &VERIFIER_ADDRESS, 0, &[]),
        Err(reason::BRIDGE_CALL)
    );
    let p = params(&chain, &chain.bootstrap(8, [3; 32]), [1; 20]);
    let mut light = Map::default();
    client::genesis(&c, &mut light, &p, GOVERNANCE).unwrap();
    let mut messages = Map::default();
    verifier::genesis(&mut messages, &p, 7, GOVERNANCE);
    assert_eq!(
        client::admit(&light, &messages, &LIGHT_CLIENT_ADDRESS, 1, &call),
        Err(reason::BRIDGE_CALL)
    );
    assert_eq!(
        client::admit(&light, &messages, &VERIFIER_ADDRESS, 1, &abi::PAUSE),
        Err(reason::BRIDGE_CALL)
    );
    assert_eq!(
        client::admit(&light, &messages, &VERIFIER_ADDRESS, 0, &abi::PAUSE),
        Ok(())
    );
    assert_eq!(
        client::admit(&light, &messages, &LIGHT_CLIENT_ADDRESS, 0, &call),
        Ok(())
    );
    assert_eq!(
        client::admit(&light, &messages, &LIGHT_CLIENT_ADDRESS, 0, &abi::DELAY),
        Ok(())
    );
    assert_eq!(
        client::admit(
            &light,
            &messages,
            &LIGHT_CLIENT_ADDRESS,
            0,
            &client::submit_call(&[0], true)
        ),
        Err(reason::BRIDGE_UPDATE)
    );
    let stale = chain.update(8, &chain.header(8, [3; 32], [0; 32]), false, 9, 32);
    assert_eq!(
        client::admit(
            &light,
            &messages,
            &LIGHT_CLIENT_ADDRESS,
            0,
            &client::submit_call(&stale.encode_finality_update(), true)
        ),
        Err(reason::BRIDGE_UPDATE)
    );
    // The inbox takes only canonical deliveries of messages not yet
    // delivered, and none while paused.
    let d = Delivery {
        anchor: word(8),
        message: Message {
            nonce: 0,
            sender: [1; 20],
            recipient: [2; 20],
            gas_limit: 0,
            payload: vec![],
        },
        account_proof: vec![],
        storage_proof: vec![],
    };
    let deliver = d.encode(abi::DELIVER);
    assert_eq!(
        client::admit(&light, &messages, &INBOX_ADDRESS, 0, &deliver),
        Ok(())
    );
    // Proof elements whose offsets all point at one element are refused
    // before they are copied (spec 18 §7).
    let mut aliased = Delivery {
        account_proof: vec![vec![7; 64]],
        ..d.clone()
    }
    .encode(abi::DELIVER);
    let account_at = 4 + 8 * 32 + 32;
    aliased[account_at + 31] = 2;
    aliased[account_at + 63] = 64;
    aliased.splice(account_at + 64..account_at + 64, word(64));
    aliased[4 + 7 * 32 + 31] += 32;
    assert_eq!(
        client::admit(&light, &messages, &INBOX_ADDRESS, 0, &aliased),
        Err(reason::BRIDGE_CALL)
    );
    assert_eq!(
        client::admit(
            &light,
            &messages,
            &INBOX_ADDRESS,
            0,
            &d.encode(abi::CONSUME)
        ),
        Err(reason::BRIDGE_CALL)
    );
    assert_eq!(
        client::admit(&light, &messages, &INBOX_ADDRESS, 0, &abi::DELIVER),
        Err(reason::BRIDGE_CALL)
    );
    messages.set(&verifier::keys::delivered(0), Some(&[1]));
    assert_eq!(
        client::admit(&light, &messages, &INBOX_ADDRESS, 0, &deliver),
        Err(reason::MESSAGE_DELIVERED)
    );
    messages.set(verifier::keys::PAUSED, Some(&[1]));
    assert_eq!(
        client::admit(&light, &messages, &INBOX_ADDRESS, 0, &deliver),
        Err(reason::INBOX_PAUSED)
    );
}
