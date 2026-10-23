//! Solo to Ethereum end to end (spec 17): four validators run the DKG of
//! spec 15 §6 until finalized blocks carry threshold certificates; a
//! contract on Solo sends two messages through the outbox; the relayer
//! library turns a stored certificate into a light-client submission and
//! the outbox slots into inbox proofs; on revm the light client accepts the
//! submission, the inbox the proofs, and the recipient contract observes the
//! payloads, the second only in the next rate-limit window. Along the way
//! the submission is refused with a forged signature, by a verifier of
//! another chain and when replayed, and the messages are refused with a
//! tampered proof, before their delay, while paused and when replayed.
//! A leader that puts a false anchor in its proposal gets the block
//! finalized but never certified: shareholders sign only anchors that match
//! their own execution, and the one that signs it anyway is slashed. Over
//! several epochs the group key rotates, and a version-2 light client
//! follows the handoffs the chain records and keeps verifying, while it
//! refuses what the shareholders of an old key sign and a key past its age.

mod support;

use k256::ecdsa::SigningKey;
use solo_abi::bridge::{Message, anchor};
use solo_abi::chain::consensus::{KIND_PROPOSE, TOPIC, leader, signing_preimage};
use solo_abi::chain::{ConsensusMessage, Proposal, Receipt, Signature};
use solo_abi::codec::Seq;
use solo_abi::rotation::{certificate_message, rotation_message};
use solo_abi::staking::{
    DkgRequest, DkgRun, KeySetRecord, KeystoreRequest, PartialShare, StakingParams, StakingStatus,
    keys as skeys, query as staking_query,
};
use solo_abi::{Decode, Encode};
use solo_bridge::abi::{self, Value};
use solo_bridge::{
    InboxConfig, Submission, execute_calldata, finality_proof, group_key, light_client_v2_args,
    message_hash, rotations_from, sent_messages, slot_proof, submission_covering,
    submission_covering_key, verifier_v2_args,
};
use solo_node::keystore::Keystore;
use solo_node::{HISTORY_KEYS_PER_BLOCK, Node, NodeConfig, Sim, validator_id};
use solo_trie::keccak256;
use support::eth::{ETH_CHAIN_ID, Eth, init_code, word_u64};
use support::solo::{CHAIN_ID, address, create_address, genesis, kernel_module, key, tx};

const SLOT_MS: u64 = 200;
const DEPLOYER: [u8; 20] = [0xD0; 20];
const RELAYER: [u8; 20] = [0xEE; 20];
const OWNER: [u8; 20] = [0x0A; 20];
const GUARDIAN: [u8; 20] = [0x0B; 20];
const DELAY: u64 = 3_600;
const WINDOW: u64 = 86_400;
const MAX_KEY_AGE: u64 = 2;

fn status(sim: &mut Sim, node: usize) -> StakingStatus {
    let r = sim.nodes[node].query(staking_query::STAKING, &[]).unwrap();
    StakingStatus::from_bytes(&r.body).unwrap()
}

/// Submits `raw` to node 0 and waits until it has a receipt there.
fn included(sim: &mut Sim, raw: &[u8]) -> Receipt {
    let hash = sim.submit(0, raw).unwrap();
    assert!(
        sim.run_until(40 * SLOT_MS, |s| s.nodes[0]
            .receipt(&hash)
            .unwrap()
            .is_some())
            .unwrap()
    );
    sim.nodes[0].receipt(&hash).unwrap().unwrap()
}

fn relay(
    alice: &SigningKey,
    nonce: u64,
    caller: [u8; 20],
    recipient: [u8; 20],
    payload: &[u8],
) -> Vec<u8> {
    let data = abi::call(
        "relay(uint64,address,bytes)",
        &[
            Value::uint(u128::from(ETH_CHAIN_ID)),
            Value::address(&recipient),
            Value::Bytes(payload.to_vec()),
        ],
    );
    tx(alice, nonce, Some(caller), 1_000, &data, 300_000)
}

/// Four validators with stake whose epoch-0 DKG has adopted a key set, and
/// `alice`, funded.
fn certifying_chain(epoch_blocks: u64, alice: &SigningKey) -> (Sim, Vec<SigningKey>) {
    certifying_chain_with(epoch_blocks, alice, &NodeConfig::default())
}

/// [`certifying_chain`] with every node configured as `template`, its clock
/// aside.
fn certifying_chain_with(
    epoch_blocks: u64,
    alice: &SigningKey,
    template: &NodeConfig,
) -> (Sim, Vec<SigningKey>) {
    let validators: Vec<SigningKey> = (1..=4).map(|i| key(0x30 + i)).collect();
    let staking = StakingParams {
        epoch_blocks,
        unbonding_epochs: MAX_KEY_AGE + 2,
        min_stake: 0,
        max_validators: 0,
        dkg_phase_blocks: if epoch_blocks < 24 { 2 } else { 4 },
        max_key_age: MAX_KEY_AGE,
        ..StakingParams::default()
    };
    let genesis = genesis(&validators, &[address(alice)], SLOT_MS, Some(staking));
    let config = NodeConfig {
        now_ms: 10_000,
        ..template.clone()
    };
    let mut sim = Sim::new(kernel_module(), &genesis, &validators, 0, &config, 20).unwrap();
    assert!(
        sim.run_until(80 * SLOT_MS, |s| (0..4)
            .all(|i| status(s, i).active.is_some()))
            .unwrap()
    );
    (sim, validators)
}

#[test]
#[allow(clippy::too_many_lines)]
fn messages_cross_from_solo_to_ethereum() {
    let alice = key(0x11);
    // The DKG of epoch 0 adopts key set 0; its first point is the group key. The epoch is
    // long enough that the key does not rotate in this test.
    let (mut sim, _) = certifying_chain(200, &alice);
    let compressed = status(&mut sim, 0).group_key;
    assert_eq!(compressed.len(), 96);
    // Before the key, finalized blocks have no threshold certificate.
    assert!(finality_proof(&mut sim.nodes[0], 1).unwrap().is_none());

    // The Ethereum side's addresses are known before anything is deployed there:
    // verifier, light client, inbox, recipient, in that order from the deployer.
    let recipient = create_address(&DEPLOYER, 3);

    // On Solo: deploy the caller contract and send two messages through it.
    let deployed = included(
        &mut sim,
        &tx(&alice, 0, None, 0, &init_code("OutboxCaller"), 1_000_000),
    );
    let caller = deployed.contract.unwrap();
    let first = included(
        &mut sim,
        &relay(&alice, 1, caller, recipient, b"to ethereum"),
    );
    let second = included(&mut sim, &relay(&alice, 2, caller, recipient, b"and again"));
    let messages: Vec<(Message, [u8; 32])> = [&first, &second]
        .iter()
        .flat_map(|r| sent_messages(CHAIN_ID, &r.logs.0))
        .collect();
    assert_eq!(messages.len(), 2);
    for (m, hash) in &messages {
        assert_eq!(message_hash(m), *hash);
        assert_eq!(
            (m.sender, m.recipient, m.value, m.dest_chain_id),
            (caller, recipient, 1_000, ETH_CHAIN_ID)
        );
    }
    let sent_at = second.height;

    // The relayer finds a certified proposal anchoring a height at or after both sends.
    let mut submission = None;
    for _ in 0..20 {
        let target = sim.nodes[0].finalized_height().unwrap() + 2;
        assert!(
            sim.run_until(40 * SLOT_MS, |s| s.nodes[0].finalized_height().unwrap()
                >= target)
                .unwrap()
        );
        submission = submission_covering(&mut sim.nodes[0], sent_at).unwrap();
        if submission.is_some() {
            break;
        }
    }
    let submission = submission.expect("a certificate anchors the sends");
    assert!(submission.anchor_height >= sent_at && submission.anchor_height < submission.height);
    assert_eq!(submission.key_id, Some(0));
    // The anchor is the state root the chain committed to at that height.
    let header = sim.nodes[0]
        .block_by_number(submission.anchor_height)
        .unwrap()
        .unwrap();
    assert_eq!(submission.anchor_root, header.state_root);
    for i in 1..4 {
        assert_eq!(
            sim.nodes[i]
                .block_by_number(submission.anchor_height)
                .unwrap()
                .unwrap()
                .state_root,
            header.state_root
        );
    }
    let proofs: Vec<_> = messages
        .iter()
        .map(|(m, _)| {
            slot_proof(&mut sim.nodes[0], m.nonce, submission.anchor_height)
                .unwrap()
                .unwrap()
        })
        .collect();
    for p in &proofs {
        assert_eq!(p.root(), header.state_root);
    }

    // On Ethereum: the version-2 verifier, the light client holding key set 0, the inbox
    // (one message per window) and the recipient.
    let mut eth = Eth::new();
    let key = group_key(&compressed).unwrap();
    let verifier = eth.deploy(
        DEPLOYER,
        &init_code("SoloFinalityVerifierV2"),
        &verifier_v2_args(CHAIN_ID),
    );
    let client = eth.deploy(
        DEPLOYER,
        &init_code("SoloLightClientV2"),
        &light_client_v2_args(&verifier, 0, &key, 200, MAX_KEY_AGE),
    );
    let config = InboxConfig {
        light_client: client,
        first_nonce: 1,
        owner: OWNER,
        guardian: GUARDIAN,
        delay: DELAY,
        window: WINDOW,
        max_messages: 1,
        max_value: 10_000,
    };
    let inbox = eth.deploy(
        DEPLOYER,
        &init_code("SoloInbox"),
        &config.constructor_args(),
    );
    assert_eq!(
        eth.deploy(
            DEPLOYER,
            &init_code("MessageRecipient"),
            &abi::encode(&[Value::address(&inbox)])
        ),
        recipient
    );

    // A forged signature, and the right one for a verifier of another chain, are refused.
    let mut forged = submission.clone();
    forged.signature[100] ^= 1;
    assert!(!eth.call(RELAYER, client, &forged.calldata()).success);
    let other_verifier = eth.deploy(
        DEPLOYER,
        &init_code("SoloFinalityVerifierV2"),
        &verifier_v2_args(CHAIN_ID + 1),
    );
    let other_client = eth.deploy(
        DEPLOYER,
        &init_code("SoloLightClientV2"),
        &light_client_v2_args(&other_verifier, 0, &key, 200, MAX_KEY_AGE),
    );
    assert!(
        !eth.call(RELAYER, other_client, &submission.calldata())
            .success
    );
    // The certified submission is accepted, once.
    let accepted = eth.call(RELAYER, client, &submission.calldata());
    assert!(accepted.success, "{accepted:?}");
    let root = eth
        .view(
            RELAYER,
            client,
            &abi::call(
                "stateRoots(uint64)",
                &[Value::uint(u128::from(submission.anchor_height))],
            ),
        )
        .output;
    assert_eq!(root, header.state_root.to_vec());
    assert!(!eth.call(RELAYER, client, &submission.calldata()).success);
    // The relayer's view of the submission matches the stored proposal it came from.
    let stored = finality_proof(&mut sim.nodes[0], submission.height)
        .unwrap()
        .unwrap();
    assert_eq!(Submission::new(&stored).unwrap(), submission);
    assert_eq!(
        submission.proposal[anchor::ANCHOR_HEIGHT..anchor::ANCHOR_HEIGHT + 8],
        submission.anchor_height.to_le_bytes()
    );

    // A tampered proof is refused; the real ones are accepted.
    let (m1, m2) = (&messages[0].0, &messages[1].0);
    let mut tampered = proofs[0].clone();
    tampered.siblings[0][5] ^= 1;
    assert!(
        !eth.call(RELAYER, inbox, &tampered.prove_calldata(m1))
            .success
    );
    for (p, (m, _)) in proofs.iter().zip(&messages) {
        let proven = eth.call(RELAYER, inbox, &p.prove_calldata(m));
        assert!(proven.success, "{proven:?}");
    }
    assert!(
        !eth.call(RELAYER, inbox, &proofs[0].prove_calldata(m1))
            .success,
        "a replayed proof"
    );
    // Before the delay nothing executes; while paused neither.
    assert!(!eth.call(RELAYER, inbox, &execute_calldata(m1)).success);
    eth.advance(DELAY);
    assert!(
        eth.call(GUARDIAN, inbox, &abi::call("pause()", &[]))
            .success
    );
    assert!(!eth.call(RELAYER, inbox, &execute_calldata(m1)).success);
    assert!(eth.call(OWNER, inbox, &abi::call("unpause()", &[])).success);
    // The first message is delivered; the second waits for the next window.
    assert!(eth.call(RELAYER, inbox, &execute_calldata(m1)).success);
    let get = |eth: &mut Eth, signature: &str| {
        eth.view(RELAYER, recipient, &abi::call(signature, &[]))
            .output
    };
    assert_eq!(word_u64(&get(&mut eth, "received()")), 1);
    assert_eq!(word_u64(&get(&mut eth, "lastNonce()")), m1.nonce);
    assert_eq!(word_u64(&get(&mut eth, "lastSourceChainId()")), CHAIN_ID);
    assert_eq!(get(&mut eth, "lastSender()")[12..], caller);
    assert_eq!(&get(&mut eth, "lastPayload()")[64..64 + 11], b"to ethereum");
    assert!(
        !eth.call(RELAYER, inbox, &execute_calldata(m1)).success,
        "a replayed delivery"
    );
    assert!(
        !eth.call(RELAYER, inbox, &execute_calldata(m2)).success,
        "over the rate limit"
    );
    eth.advance(WINDOW);
    assert!(eth.call(RELAYER, inbox, &execute_calldata(m2)).success);
    assert_eq!(word_u64(&get(&mut eth, "received()")), 2);
    assert_eq!(&get(&mut eth, "lastPayload()")[64..64 + 9], b"and again");
    assert_eq!(word_u64(&get(&mut eth, "lastValue()")), 1_000);
}

#[test]
fn the_relayer_is_offered_anchors_the_node_still_proves_against() {
    // Every node keeps the state of its last three blocks (spec 20 §5.1).
    let alice = key(0x11);
    let template = NodeConfig {
        state_history: 3,
        ..NodeConfig::default()
    };
    let (mut sim, _) = certifying_chain_with(200, &alice, &template);
    let deployed = included(
        &mut sim,
        &tx(&alice, 0, None, 0, &init_code("OutboxCaller"), 1_000_000),
    );
    let caller = deployed.contract.unwrap();
    let sent = included(&mut sim, &relay(&alice, 1, caller, [0xAB; 20], b"kept"));
    let (message, _) = sent_messages(CHAIN_ID, &sent.logs.0).remove(0);
    let sent_at = sent.height;
    let covering = |sim: &mut Sim| submission_covering(&mut sim.nodes[0], sent_at).unwrap();
    // Whatever the relayer is offered anchors a state the node keeps, so the node proves
    // the message's slot against the anchored root.
    let provable = |sim: &mut Sim, s: &Submission| {
        let node = &mut sim.nodes[0];
        assert!(s.anchor_height >= node.oldest_state());
        let proof = slot_proof(node, message.nonce, s.anchor_height)
            .unwrap()
            .expect("the anchored state is kept");
        let header = node.block_by_number(s.anchor_height).unwrap().unwrap();
        assert_eq!(proof.root(), header.state_root);
        assert_eq!(s.anchor_root, header.state_root);
    };

    // Within the window by blocks, the newest certificates anchor heights the node keeps.
    assert!(
        sim.run_until(40 * SLOT_MS, |s| covering(s).is_some())
            .unwrap()
    );
    let within = covering(&mut sim).unwrap();
    provable(&mut sim, &within);

    // Node 0 now keeps one key write of history per block of its window, three in all:
    // every block writes more, so the node keeps the head's state only, fewer blocks than
    // `state_history` (spec 20 §5.1). Every certificate anchors below the head, a state
    // the node has pruned, so the relayer is offered none rather than one that the node
    // cannot prove against.
    sim.nodes[0].history_keys_per_block = 1;
    let shrunk = sim
        .run_until(40 * SLOT_MS, |s| {
            let node = &mut s.nodes[0];
            let head = node.block_number().unwrap();
            node.oldest_state() == head && node.finalized_height().unwrap() == head
        })
        .unwrap();
    assert!(shrunk);
    let node = &mut sim.nodes[0];
    let top = node.finalized_height().unwrap();
    let oldest = node.oldest_state();
    assert_eq!((oldest, node.state_history), (top, 3));
    let mut certified = 0;
    for h in sent_at + 1..=top {
        if let Some(s) = finality_proof(node, h)
            .unwrap()
            .and_then(|p| Submission::new(&p).ok())
        {
            assert!(s.anchor_height < oldest, "{h}");
            assert!(
                slot_proof(node, message.nonce, s.anchor_height)
                    .unwrap()
                    .is_none()
            );
            certified += 1;
        }
    }
    assert!(certified > 0);
    assert_eq!(covering(&mut sim), None);

    // With the default budget again the window grows back from the head, and the next
    // certificates anchor heights in it.
    sim.nodes[0].history_keys_per_block = HISTORY_KEYS_PER_BLOCK;
    assert!(
        sim.run_until(40 * SLOT_MS, |s| covering(s).is_some())
            .unwrap()
    );
    let again = covering(&mut sim).unwrap();
    assert!(again.anchor_height >= oldest);
    provable(&mut sim, &again);
}

#[test]
fn shareholders_do_not_certify_a_proposal_with_a_false_anchor() {
    let alice = key(0x11);
    let (mut sim, validators) = certifying_chain(200, &alice);
    // Validator 3, a shareholder, leaves; the test speaks for it in a view it leads.
    // The other three are exactly the threshold, so every certificate needs all of them.
    sim.crash(3);
    let byzantine = validator_id(&validators[3]);
    let in_led_view = |s: &mut Sim| {
        let first = s.nodes[0].simplex_state().unwrap();
        leader(first.view, 4) == 3
            && (1..3).all(|i| {
                let other = s.nodes[i].simplex_state().unwrap();
                other.view == first.view && other.tip_hash == first.tip_hash
            })
    };
    assert!(sim.run_until(60 * SLOT_MS, in_led_view).unwrap());
    let st = sim.nodes[0].simplex_state().unwrap();
    let executed = sim.nodes[0].block_number().unwrap();
    let forged = Proposal {
        view: st.view,
        height: st.tip_height + 1,
        parent: st.tip_hash,
        timestamp_ms: sim.now_ms.max(st.tip_timestamp_ms + 1),
        anchor_height: executed,
        anchor_root: [0x66; 32],
        ..Proposal::default()
    };
    let hash = keccak256(&forged.to_bytes());
    let digest = keccak256(&signing_preimage(
        KIND_PROPOSE,
        CHAIN_ID,
        forged.view,
        &hash,
    ));
    let (sig, rid) = validators[3].sign_prehash_recoverable(&digest).unwrap();
    let mut signature = [0u8; 65];
    signature[..64].copy_from_slice(&sig.to_bytes());
    signature[64] = rid.to_byte();
    let message = ConsensusMessage::Propose {
        proposal: forged.clone(),
        signature: Signature(signature),
    }
    .to_bytes();
    for i in 0..3 {
        sim.nodes[i]
            .deliver(byzantine, TOPIC, message.clone())
            .unwrap();
    }
    let h = forged.height;
    assert!(
        sim.run_until(40 * SLOT_MS, |s| (0..3)
            .all(|i| s.nodes[i].finalized_height().unwrap() >= h + 3))
            .unwrap()
    );
    // Consensus does not look at anchors: the forged proposal is the block at its height.
    let finalized = sim.nodes[0]
        .persisted()
        .get(&[b"final/".as_slice(), &h.to_le_bytes()].concat())
        .cloned()
        .unwrap();
    assert_eq!(finalized, hash.to_vec());
    // No certificate names it; the blocks after it are certified again.
    for height in h..=h + 3 {
        if let Some(proof) = finality_proof(&mut sim.nodes[0], height).unwrap() {
            assert_ne!(keccak256(&proof.proposal), hash);
        }
    }
    assert!(
        (h + 1..=h + 3).any(|height| finality_proof(&mut sim.nodes[0], height).unwrap().is_some())
    );
    // Validator 3 signs it all the same: its finalize vote carries a partial over the
    // forged proposal. The nodes see that the anchor is not what they executed, put the
    // evidence in a proposal, and the chain slashes validator 3 (spec 15 §5.1).
    let message = certificate_message(CHAIN_ID, 0, h, &hash);
    let partials = partials_of(&sim.nodes[0], &validators[3], 0, &message);
    let digest = keccak256(&signing_preimage(
        solo_abi::chain::consensus::KIND_FINALIZE,
        CHAIN_ID,
        forged.view,
        &hash,
    ));
    let (sig, rid) = validators[3].sign_prehash_recoverable(&digest).unwrap();
    let mut signature = [0u8; 65];
    signature[..64].copy_from_slice(&sig.to_bytes());
    signature[64] = rid.to_byte();
    let share = ConsensusMessage::FinalizeShare {
        view: forged.view,
        hash,
        signature: Signature(signature),
        partials: Seq(partials),
    }
    .to_bytes();
    for i in 0..3 {
        sim.nodes[i]
            .deliver(byzantine, TOPIC, share.clone())
            .unwrap();
    }
    let jailed = |s: &mut Sim| {
        status(s, 0)
            .records
            .0
            .iter()
            .any(|e| e.id == byzantine && e.record.jailed)
    };
    assert!(sim.run_until(40 * SLOT_MS, jailed).unwrap());
}

/// Validator `key`'s partial signatures over `message` with every share it
/// holds of key set `id`, its keystore having replayed the run from `node`'s
/// chain state.
fn partials_of(node: &Node, key: &SigningKey, id: u64, message: &[u8]) -> Vec<PartialShare> {
    let run = DkgRun::from_bytes(
        &node
            .state_get(&[skeys::RUN, &id.to_be_bytes()].concat())
            .unwrap(),
    )
    .unwrap();
    let transcript: Vec<Vec<u8>> = node
        .state_scan(&[skeys::MESSAGE, &id.to_be_bytes()].concat())
        .into_iter()
        .map(|(_, v)| v)
        .collect();
    let position = run
        .recipients
        .0
        .iter()
        .position(|r| *r == validator_id(key))
        .unwrap();
    let mut store = Keystore::default();
    let replay = KeystoreRequest::WeightedDkg {
        request: DkgRequest {
            key_set: id,
            session: run.session,
            threshold: run.threshold,
            dealers: u32::try_from(run.dealers.0.len()).unwrap(),
            recipients: run.keys.clone(),
            recipient: u32::try_from(position).unwrap() + 1,
            transcript: Seq(transcript),
            upto: 3,
            ..DkgRequest::default()
        },
        shares: run.shares.clone(),
    };
    store.handle(Some(key), &replay.to_bytes()).unwrap();
    let sign = KeystoreRequest::SignAll {
        key_set: id,
        message: message.to_vec(),
    };
    Seq::<PartialShare>::from_bytes(&store.handle(Some(key), &sign.to_bytes()).unwrap())
        .unwrap()
        .0
}

/// The group signature, in EIP-2537 encoding, that the shareholders of key set
/// `id` among `signers` make over `message` by combining their partials.
/// Key set `id` as `node`'s chain adopted it.
fn key_set_record(node: &Node, id: u64) -> KeySetRecord {
    KeySetRecord::from_bytes(
        &node
            .state_get(&[skeys::KEY_SET, &id.to_be_bytes()].concat())
            .unwrap(),
    )
    .unwrap()
}

/// The threshold signature of `signers` with their shares of key set `id`
/// over `message`.
fn forged(node: &Node, signers: &[SigningKey], id: u64, message: &[u8]) -> solo_bls::Signature {
    let record = key_set_record(node, id);
    let partials = signers
        .iter()
        .flat_map(|k| partials_of(node, k, id, message))
        .collect();
    let combine = KeystoreRequest::Combine {
        key_set: record.key_set,
        message: message.to_vec(),
        partials: Seq(partials),
    };
    let signature = Keystore::default()
        .handle(None, &combine.to_bytes())
        .unwrap();
    solo_bls::Signature::from_bytes(&signature.try_into().unwrap()).unwrap()
}

/// Whether `signature` verifies over `message` under the group key of key
/// set `id`, checked off chain: the forgery is a real one.
fn verifies_under(node: &Node, id: u64, message: &[u8], signature: &solo_bls::Signature) -> bool {
    let record = key_set_record(node, id);
    solo_bls::PublicKey::from_bytes(record.key_set[..96].try_into().unwrap())
        .unwrap()
        .verify(message, signature)
}

/// [`forged`] in the EIP-2537 encoding the contracts take, after checking
/// that it verifies under key set `id`.
fn forged_signature(node: &Node, signers: &[SigningKey], id: u64, message: &[u8]) -> Vec<u8> {
    let signature = forged(node, signers, id, message);
    assert!(verifies_under(node, id, message, &signature));
    solo_bls::evm::encode_g1(signature.point()).to_vec()
}

fn submit_call(proposal: &[u8], signature: &[u8]) -> Vec<u8> {
    abi::call(
        "submit(bytes,bytes)",
        &[
            Value::Bytes(proposal.to_vec()),
            Value::Bytes(signature.to_vec()),
        ],
    )
}

#[test]
#[allow(clippy::too_many_lines)]
fn a_light_client_follows_the_group_key_across_epochs() {
    let alice = key(0x11);
    // Epochs of 16 blocks: every epoch's DKG makes a fresh key and the old one hands off.
    let (mut sim, validators) = certifying_chain(16, &alice);
    let s = status(&mut sim, 0);
    assert_eq!(s.active.as_ref().unwrap().id, 0);
    let mut eth = Eth::new();
    let verifier = eth.deploy(
        DEPLOYER,
        &init_code("SoloFinalityVerifierV2"),
        &verifier_v2_args(CHAIN_ID),
    );
    let deploy_client = |eth: &mut Eth| {
        eth.deploy(
            DEPLOYER,
            &init_code("SoloLightClientV2"),
            &light_client_v2_args(
                &verifier,
                0,
                &group_key(&s.group_key).unwrap(),
                16,
                MAX_KEY_AGE,
            ),
        )
    };
    let client = deploy_client(&mut eth);
    // Three handoffs: from key set 0 to the key of a later epoch, and on.
    let rotated = sim
        .run_until(400 * SLOT_MS, |s| {
            rotations_from(&mut s.nodes[0], 0).unwrap().len() >= 3
        })
        .unwrap();
    assert!(rotated, "{:?}", sim.finalized_heights().unwrap());
    let rotations = rotations_from(&mut sim.nodes[0], 0).unwrap();
    // The relayer follows the chain: a certificate of the key the client holds, then the
    // handoff to the next key, and again; the client keeps verifying.
    let mut current = 0;
    let mut latest = 0;
    for r in &rotations {
        assert_eq!(r.from, current);
        let submission = submission_covering_key(&mut sim.nodes[0], latest + 1, current)
            .unwrap()
            .expect("a certificate of the current key");
        let outcome = eth.call(RELAYER, client, &submission.calldata());
        assert!(outcome.success, "key set {current}: {outcome:?}");
        latest = submission.anchor_height;
        let outcome = eth.call(RELAYER, client, &r.calldata());
        assert!(
            outcome.success,
            "rotation {} -> {}: {outcome:?}",
            r.from, r.to
        );
        current = r.to;
    }
    let get_from = |eth: &mut Eth, at: [u8; 20], signature: &str| {
        eth.view(RELAYER, at, &abi::call(signature, &[])).output
    };
    let get = |eth: &mut Eth, signature: &str| get_from(eth, client, signature);
    assert_eq!(word_u64(&get(&mut eth, "keyId()")), current);
    let target = sim.nodes[0].finalized_height().unwrap() + 4;
    assert!(
        sim.run_until(40 * SLOT_MS, |s| s.nodes[0].finalized_height().unwrap()
            >= target)
            .unwrap()
    );
    let submission = submission_covering_key(&mut sim.nodes[0], latest + 1, current)
        .unwrap()
        .expect("a certificate of the newest key");
    assert!(eth.call(RELAYER, client, &submission.calldata()).success);
    let root = eth
        .view(
            RELAYER,
            client,
            &abi::call(
                "stateRoots(uint64)",
                &[Value::uint(u128::from(submission.anchor_height))],
            ),
        )
        .output;
    let header = sim.nodes[0]
        .block_by_number(submission.anchor_height)
        .unwrap()
        .unwrap();
    assert_eq!(root, header.state_root.to_vec());
    // The shareholders of key set 0, who left it epochs ago, sign a false root: the client
    // holds a newer key and refuses it, whichever key set the certificate claims.
    let node = &sim.nodes[0];
    let fake = Proposal {
        height: submission.anchor_height + 3,
        anchor_height: submission.anchor_height + 2,
        anchor_root: [0x66; 32],
        ..Proposal::default()
    }
    .to_bytes();
    let fake_hash = keccak256(&fake);
    for claimed in [0, current] {
        let message =
            certificate_message(CHAIN_ID, claimed, submission.anchor_height + 3, &fake_hash);
        let signature = forged_signature(node, &validators[..3], 0, &message);
        let refused = eth.call(RELAYER, client, &submit_call(&fake, &signature));
        assert_eq!(
            refused.output,
            support::eth::selector("InvalidCertificate()"),
            "claimed key set {claimed}"
        );
    }
    // Nor can they hand the client off to a key of their own.
    let theirs = solo_bls::SecretKey::generate(&[0x77; 32], b"")
        .unwrap()
        .public_key();
    let message = rotation_message(CHAIN_ID, current + 1, &theirs.to_bytes());
    let signature = forged_signature(node, &validators[..3], 0, &message);
    let rotate = abi::call(
        "rotate(uint64,bytes,bytes)",
        &[
            Value::uint(u128::from(current + 1)),
            Value::Bytes(solo_bls::evm::encode_g2(theirs.point()).to_vec()),
            Value::Bytes(signature.clone()),
        ],
    );
    assert_eq!(
        eth.call(RELAYER, client, &rotate).output,
        support::eth::selector("InvalidCertificate()")
    );
    // A client still holding key set 0 accepts the same shareholders' false root while
    // the key is within its age: the forgery is real, and only the client having moved
    // on, or the key's age, stops it.
    let stale = deploy_client(&mut eth);
    let young = Proposal {
        height: 21,
        anchor_height: 20,
        anchor_root: [0x67; 32],
        ..Proposal::default()
    }
    .to_bytes();
    let message = certificate_message(CHAIN_ID, 0, 21, &keccak256(&young));
    let signature = forged_signature(node, &validators[..3], 0, &message);
    assert!(
        eth.call(RELAYER, stale, &submit_call(&young, &signature))
            .success
    );
    // It refuses a certificate of key set 0 anchored three epochs on, past the key's age,
    // however well signed, and a handoff that far ahead.
    let old = Proposal {
        height: 51,
        anchor_height: 50,
        anchor_root: [0x67; 32],
        ..Proposal::default()
    }
    .to_bytes();
    let message = certificate_message(CHAIN_ID, 0, 51, &keccak256(&old));
    let signature = forged_signature(node, &validators[..3], 0, &message);
    let refused = eth.call(RELAYER, stale, &submit_call(&old, &signature));
    assert_eq!(refused.output, support::eth::selector("KeyExpired()"));
    let r = rotations.iter().find(|r| r.to > MAX_KEY_AGE).unwrap();
    let message = rotation_message(CHAIN_ID, r.to, &r.key);
    let signature = forged_signature(node, &validators[..3], 0, &message);
    let data = abi::call(
        "rotate(uint64,bytes,bytes)",
        &[
            Value::uint(u128::from(r.to)),
            Value::Bytes(r.key_eip2537.to_vec()),
            Value::Bytes(signature),
        ],
    );
    assert_eq!(
        eth.call(RELAYER, stale, &data).output,
        support::eth::selector("KeyExpired()")
    );
    // Within the age, the same shareholders can hand that client off to a key of their
    // own, which is why a client must be kept current (spec 17 §10).
    let message = rotation_message(CHAIN_ID, MAX_KEY_AGE, &theirs.to_bytes());
    let signature = forged_signature(node, &validators[..3], 0, &message);
    let data = abi::call(
        "rotate(uint64,bytes,bytes)",
        &[
            Value::uint(u128::from(MAX_KEY_AGE)),
            Value::Bytes(solo_bls::evm::encode_g2(theirs.point()).to_vec()),
            Value::Bytes(signature),
        ],
    );
    assert!(eth.call(RELAYER, stale, &data).success);
    assert_eq!(word_u64(&get_from(&mut eth, stale, "keyId()")), MAX_KEY_AGE);
}
