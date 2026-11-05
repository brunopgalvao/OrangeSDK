//! Seeded forgeries of the threshold evidence the bridge from Ethereum
//! accepts (spec 18 §3, §5–§6): light-client updates, whose evidence is a
//! supermajority of the sync committee signing an attested header that
//! proves a finalized one, and message deliveries proven against the
//! execution state root that finalized header anchors. In every case the
//! genuine update is accepted and the genuine delivery verifies; every
//! forgery (another committee, another period or slot, fewer than two
//! thirds of the committee or more bits than signers, a swapped attested or
//! finalized header, a finalized header or execution payload that does not
//! chain to the attested state, a committee the attested state does not
//! hold, the previous period's committee after the client rotated, damaged
//! encodings, and for deliveries another root, message or proof) is
//! refused. See `orange-fuzz` for the long mode.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use orange_abi::bridge_in::{BridgeInParams, INBOX_ADDRESS, InboxLimits};
use orange_ethlc::abi::{self, Delivery, encode, word};
use orange_ethlc::beacon::{SyncAggregate, Update};
use orange_ethlc::client::{self, Context, Storage, keys};
use orange_ethlc::inbox::{self, Message};
use orange_ethlc::sync::Rejection::{
    BadCommitteeBranch, BadExecutionBranch, BadFinalityBranch, BadSignature, LowParticipation,
    Slots, WrongPeriod,
};
use orange_ethlc::sync::{self, Rejection};
use orange_ethlc::testing::{Chain, Committee, EthState, Evm, Native, unhex};
use orange_ethlc::verifier;
use orange_fuzz::{Rng, run};

const GOVERNANCE: [u8; 20] = [0x60; 20];
/// Committee size: two thirds is 22 members.
const SIZE: usize = 32;
const QUORUM: usize = 22;
/// The Orange chain id the outbox names.
const ORANGE_CHAIN_ID: u64 = 7;
const NOW: u64 = 500;

#[derive(Default, Clone, PartialEq, Eq, Debug)]
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

/// An `EthereumOutbox` on "Ethereum" that sent three messages, its state
/// then, and its state after a fourth.
struct Outbox {
    address: [u8; 20],
    state: EthState,
    later: EthState,
    messages: Vec<Message>,
}

fn outbox() -> &'static Outbox {
    static OUTBOX: OnceLock<Outbox> = OnceLock::new();
    OUTBOX.get_or_init(|| {
        let mut evm = Evm::new();
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../contracts/build/EthereumOutbox.bin"
        );
        let mut init = unhex(&std::fs::read_to_string(path).unwrap());
        init.extend_from_slice(&word(ORANGE_CHAIN_ID));
        let address = evm.deploy([0xD0; 20], init).unwrap();
        let mut messages = Vec::new();
        let mut state = None;
        for (nonce, payload) in [b"one".to_vec(), vec![2; 50], b"three".to_vec(), vec![4]]
            .into_iter()
            .enumerate()
        {
            if nonce == 3 {
                state = Some(evm.state());
            }
            let message = Message {
                nonce: nonce as u64,
                sender: [0x5E; 20],
                recipient: [0x7E; 20],
                gas_limit: 60_000,
                payload,
            };
            evm.call([0x5E; 20], address, message.send_call()).unwrap();
            messages.push(message);
        }
        Outbox {
            address,
            state: state.unwrap(),
            later: evm.state(),
            messages,
        }
    })
}

fn params(chain: &Chain, outbox: [u8; 20]) -> BridgeInParams {
    BridgeInParams {
        light_client: vec![1],
        verifier: vec![2],
        config: chain.config.clone(),
        bootstrap: chain.bootstrap(8, [3; 32]).encode(),
        outbox,
        limits: InboxLimits {
            delay: 100,
            window: 1000,
            max_messages: 10,
        },
    }
}

fn submit(store: &mut Map, update: &Update, finality: bool) -> Result<Vec<u8>, Vec<u8>> {
    let bytes = if finality {
        update.encode_finality_update()
    } else {
        update.encode_update(SIZE)
    };
    submit_bytes(store, &bytes, finality)
}

fn submit_bytes(store: &mut Map, bytes: &[u8], finality: bool) -> Result<Vec<u8>, Vec<u8>> {
    client::call(
        &Native,
        store,
        &Context {
            caller: [0x11; 20],
            timestamp: NOW,
        },
        &client::submit_call(bytes, finality),
    )
}

fn rejected(r: Rejection) -> Vec<u8> {
    encode(abi::UPDATE_REJECTED, &[word(r as u64)])
}

/// A slot in `lo..hi`.
fn slot(r: &mut Rng, lo: u64, hi: u64) -> u64 {
    lo + r.below(hi - lo)
}

/// The signature of the first `signers` of `committee` over `update`'s
/// attested header in its signature slot.
fn signed_by(
    chain: &Chain,
    update: &Update,
    committee: &Committee,
    signers: usize,
) -> SyncAggregate {
    let root = sync::signing_root(
        &Native,
        &chain.config,
        &update.attested.beacon.root(&Native),
        update.signature_slot,
    )
    .unwrap();
    committee.sign(signers, &root)
}

/// The checks every forged update goes through on a copy of `store`.
struct Forger<'a> {
    store: &'a Map,
    genuine: &'a Map,
}

impl Forger<'_> {
    /// `update` is refused, for a reason in `reasons` if any are given.
    fn refused(&self, update: &Update, reasons: &[Rejection], class: &str) {
        for finality in [false, true] {
            if finality && update.next_sync_committee.is_some() {
                continue;
            }
            let outcome = submit(&mut self.store.clone(), update, finality);
            let Err(data) = outcome else {
                panic!("{class}: a forged update was accepted");
            };
            assert!(
                reasons.is_empty() || reasons.iter().any(|r| rejected(*r) == data),
                "{class}: refused with {data:02x?}"
            );
        }
    }

    /// Whatever `bytes` does, it does no more than the genuine update:
    /// every key it leaves is as before or as the genuine update left it.
    fn no_more(&self, bytes: &[u8], finality: bool) {
        let mut store = self.store.clone();
        if submit_bytes(&mut store, bytes, finality).is_err() {
            return;
        }
        let keys: Vec<&Vec<u8>> = store.0.keys().chain(self.genuine.0.keys()).collect();
        for k in keys {
            let after = store.get(k);
            assert!(
                after == self.store.get(k) || after == self.genuine.get(k),
                "a damaged update wrote {k:02x?}"
            );
        }
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn forged_updates_and_deliveries_are_refused() {
    let c = Native;
    let chain = Chain::minimal(u32::try_from(SIZE).unwrap());
    let ob = outbox();
    let root = ob.state.root();
    run("ethlc-forged-evidence", 6, |r| {
        let mut store = Map::default();
        client::genesis(&c, &mut store, &params(&chain, ob.address), GOVERNANCE).unwrap();

        // A genuine update in period 0 finalizing the outbox's state and
        // teaching period 1's committee.
        let finalized = slot(r, 9, 48);
        let attested = slot(r, finalized, 62);
        let signature_slot = slot(r, attested + 1, 64);
        let signers = QUORUM + r.index(SIZE - QUORUM + 1);
        let header = chain.header(finalized, root, r.array32());
        let update = chain.update(attested, &header, true, signature_slot, signers);
        let mut genuine = store.clone();
        assert_eq!(submit(&mut genuine, &update, false), Ok(vec![]));
        let check = Forger {
            store: &store,
            genuine: &genuine,
        };
        // Another committee: the next period's, or one nobody knows.
        for other in [chain.committee(1), Committee::new(99, SIZE)] {
            let mut forged = update.clone();
            forged.sync_aggregate = signed_by(&chain, &forged, &other, signers);
            check.refused(&forged, &[BadSignature], "another committee");
        }
        // Below two thirds, honestly marked or with more bits than signers.
        let few = QUORUM - 1 - r.index(QUORUM - 1);
        let mut forged = update.clone();
        forged.sync_aggregate = signed_by(&chain, &forged, &chain.committee(0), few);
        check.refused(&forged, &[LowParticipation], "minority");
        forged
            .sync_aggregate
            .bits
            .clone_from(&update.sync_aggregate.bits);
        check.refused(&forged, &[BadSignature], "minority with forged bits");
        let mut forged = update.clone();
        let extra = r.index(SIZE);
        forged.sync_aggregate.bits[extra / 8] ^= 1 << (extra % 8);
        check.refused(
            &forged,
            &[LowParticipation, BadSignature],
            "one bit flipped",
        );
        // Another period or slot: signed in a period whose committee is not
        // known, or slots out of order.
        let mut forged = update.clone();
        forged.signature_slot = slot(r, 64, 128);
        forged.sync_aggregate = signed_by(&chain, &forged, &chain.committee(1), SIZE);
        check.refused(&forged, &[WrongPeriod], "unknown period");
        let mut forged = update.clone();
        forged.signature_slot = slot(r, 0, attested + 1);
        check.refused(
            &forged,
            &[Slots, BadSignature],
            "signature not after attested",
        );
        // A swapped attested header: another slot or state, signed or not.
        let mut forged = update.clone();
        forged.attested.beacon.proposer_index ^= 1 + r.below(7);
        check.refused(&forged, &[BadSignature], "attested header changed");
        let mut forged = update.clone();
        forged.attested.beacon.state_root = r.array32();
        forged.sync_aggregate = signed_by(&chain, &forged, &chain.committee(0), SIZE);
        check.refused(&forged, &[BadFinalityBranch], "attested state swapped");
        // A finalized header that does not chain to the attested state: a
        // header of another slot or state, a branch changed, an execution
        // payload its beacon header does not prove.
        let mut forged = update.clone();
        forged.finalized = chain.header(slot(r, 9, attested + 1), r.array32(), r.array32());
        check.refused(&forged, &[BadFinalityBranch], "finalized header swapped");
        let mut forged = update.clone();
        let at = r.index(forged.finality_branch.len());
        forged.finality_branch[at][r.index(32)] ^= 1 << r.below(8);
        check.refused(&forged, &[BadFinalityBranch], "finality branch");
        let mut forged = update.clone();
        forged.finalized.execution.state_root = r.array32();
        check.refused(&forged, &[BadExecutionBranch], "execution root swapped");
        let mut forged = update.clone();
        forged.finalized.execution_branch[r.index(4)][r.index(32)] ^= 1 << r.below(8);
        check.refused(&forged, &[BadExecutionBranch], "execution branch");
        // A next committee the attested state does not hold.
        let mut forged = update.clone();
        forged.next_sync_committee.as_mut().unwrap().0 = Committee::new(98, SIZE).sync_committee();
        check.refused(&forged, &[BadCommitteeBranch], "next committee swapped");
        let mut forged = update.clone();
        let branch = &mut forged.next_sync_committee.as_mut().unwrap().1;
        branch[r.index(branch.len())][r.index(32)] ^= 1 << r.below(8);
        check.refused(&forged, &[BadCommitteeBranch], "committee branch");
        // Damaged encodings do no more than the genuine update; a finality
        // update without the committee is one such.
        check.no_more(&update.encode_finality_update(), true);
        for _ in 0..6 {
            let finality = r.chance(1, 2);
            let bytes = if finality {
                update.encode_finality_update()
            } else {
                update.encode_update(SIZE)
            };
            check.no_more(&r.mutate(&bytes), finality);
        }

        // Deliveries against the root the update anchored.
        let mut messages = Map::default();
        verifier::genesis(
            &mut messages,
            &params(&chain, ob.address),
            ORANGE_CHAIN_ID,
            GOVERNANCE,
        );
        let stored = client::query(
            &genuine,
            &client::u64_call(abi::EXECUTION_ROOT, header.execution.block_number),
        )
        .unwrap();
        let anchor: [u8; 32] = stored[..32].try_into().unwrap();
        assert_eq!(anchor, root);
        let delivery = |state: &EthState, m: &Message, anchor: [u8; 32]| {
            let (account_proof, storage_proof) =
                state.proof(&ob.address, &inbox::slot(&c, m.nonce));
            Delivery {
                anchor,
                message: m.clone(),
                account_proof,
                storage_proof,
            }
        };
        let consume = |data: &[u8]| {
            verifier::call(
                &c,
                &mut messages.clone(),
                &Context {
                    caller: INBOX_ADDRESS,
                    timestamp: NOW,
                },
                data,
            )
        };
        let bad = Err(encode(abi::BAD_PROOF, &[]));
        let m = &ob.messages[r.index(3)];
        let real = delivery(&ob.state, m, anchor);
        let data = real.encode(abi::CONSUME);
        assert_eq!(consume(&data), Ok(vec![]));
        // A root the client does not hold: an unfinalized block's, which
        // reads as zero, or the outbox's state at another block.
        let unknown = client::query(
            &genuine,
            &client::u64_call(abi::EXECUTION_ROOT, header.execution.block_number + 1),
        )
        .unwrap();
        assert_eq!(unknown[..32], [0; 32]);
        let mut edit = real.clone();
        edit.anchor = [0; 32];
        assert_eq!(consume(&edit.encode(abi::CONSUME)), bad);
        let later = delivery(&ob.later, m, ob.later.root());
        assert_ne!(later.anchor, anchor);
        let mut edit = later.clone();
        edit.anchor = anchor;
        assert_eq!(consume(&edit.encode(abi::CONSUME)), bad, "later proofs");
        // A message not sent by then, or changed in any field.
        let unsent = delivery(&ob.later, &ob.messages[3], anchor);
        assert_eq!(consume(&unsent.encode(abi::CONSUME)), bad, "unsent");
        for field in 0..5 {
            let mut edit = real.clone();
            let msg = &mut edit.message;
            match field {
                0 => msg.nonce = (msg.nonce + 1 + r.below(2)) % 3,
                1 => msg.sender[r.index(20)] ^= 1,
                2 => msg.recipient[r.index(20)] ^= 1,
                3 => msg.gas_limit ^= 1 << r.below(64),
                _ => msg.payload.push(r.byte()),
            }
            assert_eq!(
                consume(&edit.encode(abi::CONSUME)),
                bad,
                "message field {field}"
            );
        }
        // Another message's proofs.
        let other = &ob.messages[(usize::try_from(m.nonce).unwrap() + 1) % 3];
        let mut edit = real.clone();
        edit.storage_proof = delivery(&ob.state, other, anchor).storage_proof;
        assert_eq!(consume(&edit.encode(abi::CONSUME)), bad, "another slot");
        // Damaged calldata: whatever is consumed is the genuine delivery.
        for _ in 0..8 {
            let damaged = r.mutate(&data);
            if consume(&damaged).is_ok() {
                let got = Delivery::decode(&damaged).unwrap();
                assert_eq!((got.anchor, &got.message), (anchor, m), "damaged delivery");
            }
        }

        // Period 1: the client rotates to the committee it learned; the
        // previous period's committee, or the one after, signs nothing.
        let mut store = genuine.clone();
        let finalized = slot(r, 64, 110);
        let attested = slot(r, finalized, 126);
        let signature_slot = slot(r, attested + 1, 128);
        let header = chain.header(finalized, r.array32(), r.array32());
        let update = chain.update(attested, &header, true, signature_slot, SIZE);
        let mut genuine = store.clone();
        assert_eq!(submit(&mut genuine, &update, false), Ok(vec![]));
        assert!(genuine.get(&keys::committee(0)).is_none());
        let check = Forger {
            store: &store,
            genuine: &genuine,
        };
        for stale in [chain.committee(0), chain.committee(2)] {
            let mut forged = update.clone();
            forged.sync_aggregate = signed_by(&chain, &forged, &stale, SIZE);
            check.refused(&forged, &[BadSignature], "stale committee");
        }
        assert_eq!(submit(&mut store, &update, false), Ok(vec![]));
        // After the rotation, an update signed in period 0 is refused.
        let a0 = slot(r, 30, 62);
        let old = chain.update(
            a0,
            &chain.header(slot(r, 9, a0 + 1), root, r.array32()),
            false,
            slot(r, a0 + 1, 64),
            SIZE,
        );
        assert_eq!(
            submit(&mut store, &old, true),
            Err(rejected(WrongPeriod)),
            "period 0 again"
        );
    });
}
