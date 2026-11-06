//! The Ethereum contracts of `contracts/` on revm (spec 17 §4, §6): the
//! fixtures match their sources; the verifier accepts the spec 12 §9.1
//! certificate and nothing else; the light client stores anchored state
//! roots from certified proposals only, moving forward only; the inbox
//! proves, delays, rate-limits, delivers once, pauses and vetoes. Gas of
//! `verify`, `submit`, `prove` and `execute` is pinned here, and spec 17 §8
//! states these numbers.

mod support;

use orange_abi::Encode;
use orange_abi::bridge::{Message, message_key};
use orange_abi::chain::Proposal;
use orange_bridge::abi::{self, Value};
use orange_bridge::{
    InboxConfig, SlotProof, execute_calldata, group_key, light_client_args, message_hash,
    verifier_args,
};
use orange_trie::{Trie, keccak256};
use support::eth::{
    ETH_CHAIN_ID, Eth, Outcome, decode_hex, init_code, selector, source_hashes, word, word_u64,
};

const ORANGE_CHAIN_ID: u64 = 1337;
const DEPLOYER: [u8; 20] = [0xD0; 20];
const RELAYER: [u8; 20] = [0xEE; 20];
const OWNER: [u8; 20] = [0x0A; 20];
const GUARDIAN: [u8; 20] = [0x0B; 20];
const DELAY: u64 = 600;
const WINDOW: u64 = 3_600;

/// Gas `OrangeFinalityVerifierV1.verify` uses in a transaction, intrinsic gas included.
const VERIFY_TX_GAS: u64 = 150_368;
/// Of which execution.
const VERIFY_GAS: u64 = 126_708;
/// Gas of a light client `submit` transaction with a 103-byte proposal.
const SUBMIT_TX_GAS: u64 = 206_756;
/// Gas of an inbox `prove` transaction with a 3-sibling proof and a 4-byte payload.
const PROVE_TX_GAS: u64 = 86_316;
/// Gas of a `prove` transaction in a state of 4 099 entries, whose proof has 14 siblings.
const PROVE_DEEP_TX_GAS: u64 = 98_476;
/// Gas of the `execute` transaction that delivers it to `MessageRecipient`.
const EXECUTE_TX_GAS: u64 = 209_327;

/// Intrinsic gas of a call with `data` (EIP-2028), below the EIP-7623 floor
/// only for calldata-heavy transactions, which these are not.
#[allow(clippy::naive_bytecount)]
fn intrinsic(data: &[u8]) -> u64 {
    let zeros = data.iter().filter(|b| **b == 0).count() as u64;
    21_000 + 4 * zeros + 16 * (data.len() as u64 - zeros)
}

fn reverted_with(outcome: &Outcome, error: &str) {
    assert!(!outcome.success, "{error}: {outcome:?}");
    assert_eq!(outcome.output, selector(error), "{error}");
}

#[test]
fn fixtures_match_their_sources() {
    for (path, actual, recorded) in source_hashes() {
        assert_eq!(
            actual, recorded,
            "{path} changed since contracts/build was built; run tools/build-contracts.sh"
        );
    }
}

/// `sk` of spec 12 §9.1.
fn spec_key() -> orange_bls::SecretKey {
    let ikm: Vec<u8> = (0..32).collect();
    orange_bls::SecretKey::generate(&ikm, b"").unwrap()
}

fn sign(sk: &orange_bls::SecretKey, chain_id: u64, height: u64, hash: &[u8; 32]) -> [u8; 128] {
    orange_bls::evm::encode_g1(
        sk.sign(&orange_bls::certificate::message(chain_id, height, hash))
            .point(),
    )
}

fn deploy_verifier(eth: &mut Eth, chain_id: u64, sk: &orange_bls::SecretKey) -> [u8; 20] {
    let key = group_key(&sk.public_key().to_bytes()).unwrap();
    eth.deploy(
        DEPLOYER,
        &init_code("OrangeFinalityVerifierV1"),
        &verifier_args(chain_id, &key),
    )
}

fn verify_call(height: u64, hash: &[u8; 32], signature: &[u8]) -> Vec<u8> {
    abi::call(
        "verify(uint64,bytes32,bytes)",
        &[
            Value::uint(u128::from(height)),
            Value::Word(*hash),
            Value::Bytes(signature.to_vec()),
        ],
    )
}

fn returns_true(outcome: &Outcome) -> bool {
    assert!(outcome.success, "{outcome:?}");
    outcome.output == word(1)
}

#[test]
fn the_verifier_accepts_the_spec_certificate_and_nothing_else() {
    let mut eth = Eth::new();
    let sk = spec_key();
    let verifier = deploy_verifier(&mut eth, ORANGE_CHAIN_ID, &sk);
    let hash = [0xAB; 32];
    let signature = sign(&sk, ORANGE_CHAIN_ID, 1, &hash);
    // The EIP-2537 signature of spec 12 §9.1.
    assert_eq!(
        signature.to_vec(),
        decode_hex(
            "000000000000000000000000000000000f931999d6a28f2af460ae920a9254c18d79742a3704955a479df804975aa2b1d89d5e1c9a8d56056b91e617a67bd7f20000000000000000000000000000000008b71a684a8467d7879122445ee60ad9165a7e08615b70550485262b455931bb30600192d2ab757b74b8b6c234df056a"
        )
    );
    let data = verify_call(1, &hash, &signature);
    let outcome = eth.call(RELAYER, verifier, &data);
    assert!(returns_true(&outcome));
    assert_eq!(
        (outcome.gas, outcome.gas - intrinsic(&data)),
        (VERIFY_TX_GAS, VERIFY_GAS)
    );
    assert_eq!(
        eth.view(RELAYER, verifier, &abi::call("chainId()", &[]))
            .output,
        word(1337)
    );
    assert_eq!(
        eth.view(RELAYER, verifier, &abi::call("VERSION()", &[]))
            .output,
        word(1)
    );
    // Another height, block or chain id, a signature by another key, a point off the curve.
    assert!(!returns_true(&eth.view(
        RELAYER,
        verifier,
        &verify_call(2, &hash, &signature)
    )));
    assert!(!returns_true(&eth.view(
        RELAYER,
        verifier,
        &verify_call(1, &[0xAC; 32], &signature)
    )));
    assert!(!returns_true(&eth.view(
        RELAYER,
        verifier,
        &verify_call(1, &hash, &sign(&sk, 1338, 1, &hash))
    )));
    let other = orange_bls::SecretKey::generate(&[9; 32], b"").unwrap();
    assert!(!returns_true(&eth.view(
        RELAYER,
        verifier,
        &verify_call(1, &hash, &sign(&other, ORANGE_CHAIN_ID, 1, &hash))
    )));
    let mut off_curve = signature;
    off_curve[127] ^= 1;
    assert!(!returns_true(&eth.view(
        RELAYER,
        verifier,
        &verify_call(1, &hash, &off_curve)
    )));
    reverted_with(
        &eth.view(RELAYER, verifier, &verify_call(1, &hash, &signature[..96])),
        "InvalidSignatureLength()",
    );
}

#[test]
fn the_verifier_refuses_a_bad_group_key() {
    let mut eth = Eth::new();
    let key = group_key(&spec_key().public_key().to_bytes()).unwrap();
    let init = init_code("OrangeFinalityVerifierV1");
    let refused = |eth: &mut Eth, key: &[u8]| {
        let args = abi::encode(&[Value::uint(1337), Value::Bytes(key.to_vec())]);
        let (outcome, _) = eth.try_deploy(DEPLOYER, &init, &args);
        reverted_with(&outcome, "InvalidGroupKey()");
    };
    refused(&mut eth, &key[..255]);
    refused(&mut eth, &[0; 256]);
    let mut off_curve = key;
    off_curve[255] ^= 1;
    refused(&mut eth, &off_curve);
    // Not canonical: a field element at or above p.
    let mut big = key;
    big[16] = 0xFF;
    refused(&mut eth, &big);
}

/// An encoded proposal at `height` anchoring `anchor_height` with `root`.
fn proposal(height: u64, anchor_height: u64, root: [u8; 32]) -> Vec<u8> {
    Proposal {
        view: height + 7,
        height,
        parent: [3; 32],
        timestamp_ms: 1_700_000_000_000,
        anchor_height,
        anchor_root: root,
        txs: orange_abi::codec::Seq(vec![vec![0xC0; 3]]),
        ..Proposal::default()
    }
    .to_bytes()
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

/// A proposal and the certificate signature of it by `sk` on `chain_id`.
fn certified(
    sk: &orange_bls::SecretKey,
    chain_id: u64,
    height: u64,
    anchor_height: u64,
    root: [u8; 32],
) -> (Vec<u8>, [u8; 128]) {
    let p = proposal(height, anchor_height, root);
    let signature = sign(sk, chain_id, height, &keccak256(&p));
    (p, signature)
}

fn state_root(eth: &mut Eth, client: [u8; 20], height: u64) -> [u8; 32] {
    eth.view(
        RELAYER,
        client,
        &abi::call("stateRoots(uint64)", &[Value::uint(u128::from(height))]),
    )
    .output
    .try_into()
    .unwrap()
}

#[test]
fn the_light_client_stores_certified_anchors_in_order() {
    let mut eth = Eth::new();
    let sk = spec_key();
    let verifier = deploy_verifier(&mut eth, ORANGE_CHAIN_ID, &sk);
    let client = eth.deploy(
        DEPLOYER,
        &init_code("OrangeLightClient"),
        &light_client_args(&verifier),
    );
    assert_eq!(
        eth.view(RELAYER, client, &abi::call("chainId()", &[]))
            .output,
        word(1337)
    );
    let (p, signature) = certified(&sk, ORANGE_CHAIN_ID, 20, 18, [0x55; 32]);
    let data = submit_call(&p, &signature);
    let outcome = eth.call(RELAYER, client, &data);
    assert!(outcome.success, "{outcome:?}");
    assert_eq!((p.len(), outcome.gas), (103, SUBMIT_TX_GAS));
    assert_eq!(state_root(&mut eth, client, 18), [0x55; 32]);
    assert_eq!(
        word_u64(
            &eth.view(RELAYER, client, &abi::call("latestHeight()", &[]))
                .output
        ),
        18
    );
    let log = &outcome.logs[0];
    assert_eq!(
        log.data.topics()[0].0,
        keccak256(b"StateRootStored(uint64,bytes32,uint64,bytes32)")
    );
    assert_eq!(log.data.topics()[1].0, word(18));
    // The same anchor again, or an older one, however well certified.
    reverted_with(&eth.call(RELAYER, client, &data), "NotMonotonic()");
    let (older, older_sig) = certified(&sk, ORANGE_CHAIN_ID, 21, 17, [0x56; 32]);
    reverted_with(
        &eth.call(RELAYER, client, &submit_call(&older, &older_sig)),
        "NotMonotonic()",
    );
    // No anchor, an anchor not below the proposal, a proposal cut short.
    let (none, none_sig) = certified(&sk, ORANGE_CHAIN_ID, 30, 0, [0; 32]);
    reverted_with(
        &eth.call(RELAYER, client, &submit_call(&none, &none_sig)),
        "NoAnchor()",
    );
    let (ahead, ahead_sig) = certified(&sk, ORANGE_CHAIN_ID, 30, 30, [0x57; 32]);
    reverted_with(
        &eth.call(RELAYER, client, &submit_call(&ahead, &ahead_sig)),
        "AnchorNotBelowProposal()",
    );
    reverted_with(
        &eth.call(RELAYER, client, &submit_call(&p[..95], &signature)),
        "ProposalTooShort()",
    );
    // A certificate of another chain, a forged signature, a proposal changed after signing.
    let (other_chain, other_sig) = certified(&sk, 1338, 31, 29, [0x58; 32]);
    reverted_with(
        &eth.call(RELAYER, client, &submit_call(&other_chain, &other_sig)),
        "InvalidCertificate()",
    );
    let impostor = orange_bls::SecretKey::generate(&[7; 32], b"").unwrap();
    let (forged, forged_sig) = certified(&impostor, ORANGE_CHAIN_ID, 31, 29, [0x58; 32]);
    reverted_with(
        &eth.call(RELAYER, client, &submit_call(&forged, &forged_sig)),
        "InvalidCertificate()",
    );
    let (mut tampered, tampered_sig) = certified(&sk, ORANGE_CHAIN_ID, 31, 29, [0x58; 32]);
    tampered[64] ^= 1;
    reverted_with(
        &eth.call(RELAYER, client, &submit_call(&tampered, &tampered_sig)),
        "InvalidCertificate()",
    );
    assert_eq!(state_root(&mut eth, client, 29), [0; 32]);
    let (next, next_sig) = certified(&sk, ORANGE_CHAIN_ID, 31, 29, [0x58; 32]);
    assert!(
        eth.call(RELAYER, client, &submit_call(&next, &next_sig))
            .success
    );
    assert_eq!(state_root(&mut eth, client, 29), [0x58; 32]);
}

/// The Ethereum side wired up: verifier, light client, inbox and recipient,
/// with a state root at height 10 that commits `messages` in the outbox.
struct Bridge {
    eth: Eth,
    client: [u8; 20],
    inbox: [u8; 20],
    recipient: [u8; 20],
    trie: Trie,
    messages: Vec<Message>,
    sk: orange_bls::SecretKey,
}

const SENDER: [u8; 20] = [0x5E; 20];

impl Bridge {
    fn new(count: u64, first_nonce: u64, max_messages: u64, max_value: u128) -> Bridge {
        let mut eth = Eth::new();
        let sk = spec_key();
        let verifier = deploy_verifier(&mut eth, ORANGE_CHAIN_ID, &sk);
        let client = eth.deploy(
            DEPLOYER,
            &init_code("OrangeLightClient"),
            &light_client_args(&verifier),
        );
        let config = InboxConfig {
            light_client: client,
            first_nonce,
            owner: OWNER,
            guardian: GUARDIAN,
            delay: DELAY,
            window: WINDOW,
            max_messages,
            max_value,
        };
        let inbox = eth.deploy(
            DEPLOYER,
            &init_code("OrangeInbox"),
            &config.constructor_args(),
        );
        let recipient = eth.deploy(
            DEPLOYER,
            &init_code("MessageRecipient"),
            &orange_bridge::abi::encode(&[Value::address(&inbox)]),
        );
        let messages: Vec<Message> = (1..=count)
            .map(|nonce| Message {
                source_chain_id: ORANGE_CHAIN_ID,
                nonce,
                sender: SENDER,
                dest_chain_id: ETH_CHAIN_ID,
                recipient,
                value: u128::from(nonce) * 10,
                payload: vec![0xC0, 0xFF, 0xEE, u8::try_from(nonce).unwrap()],
            })
            .collect();
        let mut trie = Trie::new();
        for m in &messages {
            trie.insert(&message_key(m.nonce), &message_hash(m));
        }
        trie.insert(b"acct/someone", b"x");
        trie.insert(b"meta/height", b"y");
        let mut bridge = Bridge {
            eth,
            client,
            inbox,
            recipient,
            trie,
            messages,
            sk,
        };
        bridge.anchor(10);
        bridge
    }

    /// Certifies and submits the trie's current root as the state root of `height`.
    fn anchor(&mut self, height: u64) {
        let (p, signature) = certified(
            &self.sk,
            ORANGE_CHAIN_ID,
            height + 1,
            height,
            self.trie.root(),
        );
        assert!(
            self.eth
                .call(RELAYER, self.client, &submit_call(&p, &signature))
                .success
        );
    }

    fn slot_proof(&self, message: &Message, height: u64) -> SlotProof {
        SlotProof::new(
            message.nonce,
            height,
            message_hash(message),
            &self.trie.prove(&message_key(message.nonce)),
        )
        .unwrap()
    }

    fn prove(&mut self, message: &Message) -> Outcome {
        let data = self.slot_proof(message, 10).prove_calldata(message);
        self.eth.call(RELAYER, self.inbox, &data)
    }

    fn execute(&mut self, message: &Message) -> Outcome {
        self.eth
            .call(RELAYER, self.inbox, &execute_calldata(message))
    }

    fn owner(&mut self, signature: &str, args: &[Value]) -> Outcome {
        self.eth
            .call(OWNER, self.inbox, &abi::call(signature, args))
    }

    fn get(&mut self, contract: [u8; 20], signature: &str) -> Vec<u8> {
        self.eth
            .view(RELAYER, contract, &abi::call(signature, &[]))
            .output
    }

    /// `entries(nonce)`: the hash, the time it may execute, the height whose
    /// root proved it and its status.
    fn entry(&mut self, nonce: u64) -> Vec<u8> {
        self.eth
            .view(
                RELAYER,
                self.inbox,
                &abi::call("entries(uint64)", &[Value::uint(u128::from(nonce))]),
            )
            .output
    }

    fn status(&mut self, nonce: u64) -> u64 {
        word_u64(&self.entry(nonce)[96..128])
    }

    fn height_of(&mut self, nonce: u64) -> u64 {
        word_u64(&self.entry(nonce)[64..96])
    }
}

#[test]
fn a_proven_message_is_delivered_once_after_the_delay() {
    let mut b = Bridge::new(3, 1, 10, 1_000);
    let m = b.messages[1].clone();
    let proof = b.slot_proof(&m, 10);
    assert_eq!(proof.root(), b.trie.root());
    let prove = b.prove(&m);
    assert!(prove.success, "{prove:?}");
    assert_eq!((proof.siblings.len(), prove.gas), (3, PROVE_TX_GAS));
    assert_eq!(b.status(2), 1);
    // Proving again is a replay.
    reverted_with(&b.prove(&m), "AlreadyProven()");
    reverted_with(&b.execute(&m), "TooEarly()");
    b.eth.advance(DELAY);
    // Another message under the proven nonce does not execute.
    let altered = Message {
        payload: vec![1],
        ..m.clone()
    };
    reverted_with(&b.execute(&altered), "MessageMismatch()");
    let execute = b.execute(&m);
    assert!(execute.success, "{execute:?}");
    assert_eq!(execute.gas, EXECUTE_TX_GAS);
    assert_eq!(b.status(2), 2);
    let recipient = b.recipient;
    assert_eq!(word_u64(&b.get(recipient, "received()")), 1);
    assert_eq!(
        word_u64(&b.get(recipient, "lastSourceChainId()")),
        ORANGE_CHAIN_ID
    );
    assert_eq!(word_u64(&b.get(recipient, "lastNonce()")), 2);
    assert_eq!(b.get(recipient, "lastSender()")[12..], SENDER);
    assert_eq!(word_u64(&b.get(recipient, "lastValue()")), 20);
    let payload = b.get(recipient, "lastPayload()");
    assert_eq!(&payload[64..68], &[0xC0, 0xFF, 0xEE, 2]);
    // Executing again is a replay.
    reverted_with(&b.execute(&m), "NotPending()");
    reverted_with(&b.prove(&m), "AlreadyProven()");
    assert_eq!(word_u64(&b.get(recipient, "received()")), 1);
    // An unknown nonce does not execute.
    reverted_with(&b.execute(&b.messages[2].clone()), "NotPending()");
}

#[test]
fn proofs_must_lead_to_a_stored_root() {
    let mut b = Bridge::new(3, 1, 10, 1_000);
    let m = b.messages[0].clone();
    let proof = b.slot_proof(&m, 10);
    // A tampered sibling.
    let mut tampered = proof.clone();
    tampered.siblings[0][0] ^= 1;
    reverted_with(
        &b.eth.call(RELAYER, b.inbox, &tampered.prove_calldata(&m)),
        "InvalidProof()",
    );
    // A height whose root the client does not hold.
    let unknown = SlotProof {
        height: 11,
        ..proof.clone()
    };
    reverted_with(
        &b.eth.call(RELAYER, b.inbox, &unknown.prove_calldata(&m)),
        "UnknownStateRoot()",
    );
    // A message the outbox recorded for another destination chain: the inbox hashes it
    // with its own chain id, which is not what the outbox stored.
    let elsewhere = Message {
        dest_chain_id: 5,
        ..b.messages[2].clone()
    };
    b.trie.insert(&message_key(3), &message_hash(&elsewhere));
    b.anchor(12);
    let foreign = b.slot_proof(&elsewhere, 12);
    reverted_with(
        &b.eth
            .call(RELAYER, b.inbox, &foreign.prove_calldata(&elsewhere)),
        "InvalidProof()",
    );
    // The wrong state root: a proof of the state at 10 against the root of 12.
    let stale = SlotProof {
        height: 12,
        ..proof.clone()
    };
    reverted_with(
        &b.eth.call(RELAYER, b.inbox, &stale.prove_calldata(&m)),
        "InvalidProof()",
    );
    // So does a message claimed from another sender, or with more value.
    let impostor = Message {
        sender: [0x66; 20],
        ..m.clone()
    };
    reverted_with(
        &b.eth
            .call(RELAYER, b.inbox, &proof.prove_calldata(&impostor)),
        "InvalidProof()",
    );
    let richer = Message {
        value: 1_000,
        ..m.clone()
    };
    reverted_with(
        &b.eth.call(RELAYER, b.inbox, &proof.prove_calldata(&richer)),
        "InvalidProof()",
    );
    // More siblings than a path has bits.
    let deep = SlotProof {
        siblings: vec![[0; 32]; 257],
        ..proof.clone()
    };
    reverted_with(
        &b.eth.call(RELAYER, b.inbox, &deep.prove_calldata(&m)),
        "ProofTooDeep()",
    );
    assert!(
        b.eth
            .call(RELAYER, b.inbox, &proof.prove_calldata(&m))
            .success
    );
}

#[test]
fn deliveries_are_rate_limited_per_window() {
    let mut b = Bridge::new(4, 1, 2, 60);
    let messages = b.messages.clone();
    for m in &messages {
        assert!(b.prove(m).success);
    }
    b.eth.advance(DELAY);
    assert!(b.execute(&messages[0]).success);
    // Two messages a window: the third waits for the next window.
    assert!(b.execute(&messages[1]).success);
    reverted_with(&b.execute(&messages[2]), "RateLimited()");
    b.eth.advance(WINDOW);
    // 60 wei a window: message 3 (30) fits, message 4 (40) then does not.
    assert!(b.execute(&messages[2]).success);
    reverted_with(&b.execute(&messages[3]), "RateLimited()");
    b.eth.advance(WINDOW);
    assert!(b.execute(&messages[3]).success);
    assert_eq!(word_u64(&b.get(b.recipient, "received()")), 4);
    // The owner moves the limits; nobody else can.
    reverted_with(
        &b.eth.call(
            RELAYER,
            b.inbox,
            &abi::call(
                "setRateLimit(uint64,uint64,uint256)",
                &[Value::uint(1), Value::uint(1), Value::uint(1)],
            ),
        ),
        "NotOwner()",
    );
    reverted_with(
        &b.owner(
            "setRateLimit(uint64,uint64,uint256)",
            &[Value::uint(0), Value::uint(1), Value::uint(1)],
        ),
        "InvalidWindow()",
    );
    assert!(
        b.owner(
            "setRateLimit(uint64,uint64,uint256)",
            &[Value::uint(10), Value::uint(5), Value::uint(7)]
        )
        .success
    );
    assert_eq!(word_u64(&b.get(b.inbox, "window()")), 10);
    assert_eq!(word_u64(&b.get(b.inbox, "maxMessagesPerWindow()")), 5);
    assert_eq!(word_u64(&b.get(b.inbox, "maxValuePerWindow()")), 7);
}

#[test]
fn a_recipient_with_its_own_limit_is_not_crowded_out() {
    // Two messages a window are shared by every recipient but the gateway,
    // which the owner gives a limit of its own.
    let mut b = Bridge::new(3, 1, 2, 1_000);
    let gateway = b.eth.deploy(
        DEPLOYER,
        &init_code("MessageRecipient"),
        &orange_bridge::abi::encode(&[Value::address(&b.inbox)]),
    );
    let to_gateway: Vec<Message> = (4..=7)
        .map(|nonce| Message {
            nonce,
            recipient: gateway,
            value: 0,
            ..b.messages[0].clone()
        })
        .collect();
    for m in &to_gateway {
        b.trie.insert(&message_key(m.nonce), &message_hash(m));
    }
    b.anchor(12);
    let set = |recipient: &[u8; 20], max: u64| {
        abi::call(
            "setRecipientLimit(address,uint64)",
            &[Value::address(recipient), Value::uint(max.into())],
        )
    };
    reverted_with(
        &b.eth.call(GUARDIAN, b.inbox, &set(&gateway, 2)),
        "NotOwner()",
    );
    assert!(b.eth.call(OWNER, b.inbox, &set(&gateway, 2)).success);
    let lane = |b: &mut Bridge| {
        let data = abi::call("recipientLimits(address)", &[Value::address(&gateway)]);
        let out = b.eth.view(RELAYER, b.inbox, &data).output;
        (word_u64(&out[..32]), word_u64(&out[64..96]))
    };
    assert_eq!(lane(&mut b), (2, 0));
    let shared = b.messages.clone();
    for m in shared.iter().chain(&to_gateway) {
        let data = b.slot_proof(m, 12).prove_calldata(m);
        assert!(b.eth.call(RELAYER, b.inbox, &data).success);
    }
    b.eth.advance(DELAY);
    // Others fill the shared window; the gateway's messages still pass, up to
    // its own limit.
    assert!(b.execute(&shared[0]).success);
    assert!(b.execute(&shared[1]).success);
    reverted_with(&b.execute(&shared[2]), "RateLimited()");
    assert!(b.execute(&to_gateway[0]).success);
    assert!(b.execute(&to_gateway[1]).success);
    assert_eq!(lane(&mut b), (2, 2));
    reverted_with(&b.execute(&to_gateway[2]), "RateLimited()");
    // Its window opens on its own: the next one takes it again.
    b.eth.advance(WINDOW);
    assert!(b.execute(&to_gateway[2]).success);
    assert!(b.execute(&shared[2]).success);
    // Without its own limit the gateway shares the window again.
    assert!(b.eth.call(OWNER, b.inbox, &set(&gateway, 0)).success);
    assert_eq!(word_u64(&b.get(b.inbox, "windowMessages()")), 1);
    assert!(b.execute(&to_gateway[3]).success);
    assert_eq!(word_u64(&b.get(b.inbox, "windowMessages()")), 2);
    assert_eq!(lane(&mut b), (0, 1));
    assert_eq!(word_u64(&b.get(gateway, "received()")), 4);
}

#[test]
fn a_limit_lowered_mid_window_refuses_deliveries_until_the_window_ends() {
    let mut b = Bridge::new(2, 1, 10, 1_000);
    let messages = b.messages.clone();
    for m in &messages {
        assert!(b.prove(m).success);
    }
    b.eth.advance(DELAY);
    assert!(b.execute(&messages[0]).success);
    // The window has delivered 10 wei; a 5 wei limit now sits below that.
    let lowered = [Value::uint(WINDOW.into()), Value::uint(10), Value::uint(5)];
    assert!(
        b.owner("setRateLimit(uint64,uint64,uint256)", &lowered)
            .success
    );
    reverted_with(&b.execute(&messages[1]), "RateLimited()");
    let raised = [
        Value::uint(WINDOW.into()),
        Value::uint(10),
        Value::uint(1_000),
    ];
    assert!(
        b.owner("setRateLimit(uint64,uint64,uint256)", &raised)
            .success
    );
    assert!(b.execute(&messages[1]).success);
}

#[test]
fn a_recipient_that_reverts_leaves_the_message_pending() {
    let mut b = Bridge::new(1, 1, 10, 1_000);
    let m = b.messages[0].clone();
    assert!(b.prove(&m).success);
    b.eth.advance(DELAY);
    let recipient = b.recipient;
    assert!(
        b.eth
            .call(
                RELAYER,
                recipient,
                &abi::call("setRejecting(bool)", &[Value::uint(1)])
            )
            .success
    );
    let failed = b.execute(&m);
    assert!(!failed.success);
    assert!(String::from_utf8_lossy(&failed.output).contains("rejecting"));
    assert_eq!(b.status(1), 1);
    assert!(
        b.eth
            .call(
                RELAYER,
                recipient,
                &abi::call("setRejecting(bool)", &[Value::uint(0)])
            )
            .success
    );
    assert!(b.execute(&m).success);
    // The recipient takes messages from its inbox only.
    let direct = abi::call(
        "onOrangeMessage(uint64,uint64,address,uint256,bytes)",
        &[
            Value::uint(1),
            Value::uint(1),
            Value::address(&SENDER),
            Value::uint(0),
            Value::Bytes(vec![]),
        ],
    );
    assert!(!b.eth.call(RELAYER, recipient, &direct).success);
}

#[test]
fn the_guardian_pauses_and_vetoes_and_the_owner_governs() {
    let mut b = Bridge::new(3, 1, 10, 1_000);
    let messages = b.messages.clone();
    assert!(b.prove(&messages[0]).success);
    assert!(b.prove(&messages[1]).success);
    // Pausing stops proving and executing.
    reverted_with(
        &b.eth.call(RELAYER, b.inbox, &abi::call("pause()", &[])),
        "NotGuardian()",
    );
    assert!(
        b.eth
            .call(GUARDIAN, b.inbox, &abi::call("pause()", &[]))
            .success
    );
    b.eth.advance(DELAY);
    reverted_with(&b.execute(&messages[0]), "IsPaused()");
    reverted_with(&b.prove(&messages[2]), "IsPaused()");
    // Only the owner unpauses.
    reverted_with(
        &b.eth.call(GUARDIAN, b.inbox, &abi::call("unpause()", &[])),
        "NotOwner()",
    );
    assert!(b.owner("unpause()", &[]).success);
    assert!(b.owner("pause()", &[]).success);
    assert!(b.owner("unpause()", &[]).success);
    // The guardian vetoes a pending message; it never executes.
    reverted_with(
        &b.eth.call(
            OWNER,
            b.inbox,
            &abi::call("veto(uint64)", &[Value::uint(2)]),
        ),
        "NotGuardian()",
    );
    assert!(
        b.eth
            .call(
                GUARDIAN,
                b.inbox,
                &abi::call("veto(uint64)", &[Value::uint(2)])
            )
            .success
    );
    assert_eq!(b.status(2), 3);
    reverted_with(&b.execute(&messages[1]), "NotPending()");
    reverted_with(&b.prove(&messages[1]), "AlreadyProven()");
    reverted_with(
        &b.eth.call(
            GUARDIAN,
            b.inbox,
            &abi::call("veto(uint64)", &[Value::uint(2)]),
        ),
        "NotPending()",
    );
    assert!(b.execute(&messages[0]).success);
    reverted_with(
        &b.eth.call(
            GUARDIAN,
            b.inbox,
            &abi::call("veto(uint64)", &[Value::uint(1)]),
        ),
        "NotPending()",
    );
    // The delay: at most 30 days, for messages proven after the change.
    reverted_with(
        &b.owner("setDelay(uint64)", &[Value::uint(30 * 86_400 + 1)]),
        "DelayTooLong()",
    );
    assert!(b.owner("setDelay(uint64)", &[Value::uint(0)]).success);
    assert!(b.prove(&messages[2]).success);
    assert!(b.execute(&messages[2]).success);
    // The guardian and the owner change hands, never to nobody.
    reverted_with(
        &b.owner("setGuardian(address)", &[Value::address(&[0; 20])]),
        "ZeroAddress()",
    );
    assert!(
        b.owner("setGuardian(address)", &[Value::address(&[0x0C; 20])])
            .success
    );
    assert_eq!(b.get(b.inbox, "guardian()")[12..], [0x0C; 20]);
    reverted_with(
        &b.owner("transferOwnership(address)", &[Value::address(&[0; 20])]),
        "ZeroAddress()",
    );
    assert!(
        b.owner("transferOwnership(address)", &[Value::address(&[0x0D; 20])])
            .success
    );
    reverted_with(
        &b.owner("setDelay(uint64)", &[Value::uint(1)]),
        "NotOwner()",
    );
    assert!(
        b.eth
            .call(
                [0x0D; 20],
                b.inbox,
                &abi::call("setDelay(uint64)", &[Value::uint(1)])
            )
            .success
    );
    assert_eq!(word_u64(&b.get(b.inbox, "delay()")), 1);
}

#[test]
fn nonces_a_forged_root_proved_are_freed_when_the_guardian_revokes_it() {
    let mut b = Bridge::new(3, 1, 10, 1_000);
    let messages = b.messages.clone();
    // A forged certificate stores, at height 12, a root of junk under nonce 2,
    // under nonce 3 and far ahead of the outbox, at nonce 1 000 000.
    let junk = |nonce: u64| Message {
        nonce,
        payload: b"junk".to_vec(),
        ..messages[0].clone()
    };
    let honest = std::mem::replace(&mut b.trie, Trie::new());
    for nonce in [2, 3, 1_000_000] {
        b.trie
            .insert(&message_key(nonce), &message_hash(&junk(nonce)));
    }
    b.anchor(12);
    let forged = std::mem::replace(&mut b.trie, honest);
    let prove_under = |b: &mut Bridge, trie: &Trie, m: &Message, height: u64| {
        let proof = SlotProof::new(
            m.nonce,
            height,
            message_hash(m),
            &trie.prove(&message_key(m.nonce)),
        )
        .unwrap();
        b.eth.call(RELAYER, b.inbox, &proof.prove_calldata(m))
    };
    for nonce in [2, 3, 1_000_000] {
        let proven = prove_under(&mut b, &forged, &junk(nonce), 12);
        assert!(proven.success, "{proven:?}");
    }
    assert_eq!(b.height_of(2), 12);
    // The honest message 2 cannot take its nonce back, nor can anyone but the
    // guardian or the owner revoke the root.
    reverted_with(&b.prove(&messages[1]), "AlreadyProven()");
    let revoke = |height: u64| abi::call("revokeRoot(uint64)", &[Value::uint(height.into())]);
    reverted_with(&b.eth.call(RELAYER, b.inbox, &revoke(12)), "NotGuardian()");
    // The guardian vetoes the junk at nonce 3, which stays vetoed for good, and
    // revokes the root, during a pause, which a revocation does not need lifted.
    let veto = abi::call("veto(uint64)", &[Value::uint(3)]);
    assert!(b.eth.call(GUARDIAN, b.inbox, &veto).success);
    assert!(
        b.eth
            .call(GUARDIAN, b.inbox, &abi::call("pause()", &[]))
            .success
    );
    let revoked = b.eth.call(GUARDIAN, b.inbox, &revoke(12));
    assert!(revoked.success, "{revoked:?}");
    assert!(b.owner("revokeRoot(uint64)", &[Value::uint(12)]).success);
    assert!(b.owner("unpause()", &[]).success);
    let is_revoked = |b: &mut Bridge, height: u64| {
        let data = abi::call("revoked(uint64)", &[Value::uint(height.into())]);
        word_u64(&b.eth.view(RELAYER, b.inbox, &data).output)
    };
    assert_eq!((is_revoked(&mut b, 12), is_revoked(&mut b, 10)), (1, 0));
    // Nothing more is proven under it, and what it proved never executes.
    let more = prove_under(&mut b, &forged, &junk(1_000_000), 12);
    reverted_with(&more, "RevokedRoot()");
    b.eth.advance(DELAY);
    reverted_with(&b.execute(&junk(2)), "RevokedRoot()");
    reverted_with(&b.execute(&junk(1_000_000)), "RevokedRoot()");
    // The honest message takes its nonce back under a good root, waits its own
    // delay and is delivered.
    let reproven = b.prove(&messages[1]);
    assert!(reproven.success, "{reproven:?}");
    assert_eq!((b.status(2), b.height_of(2)), (1, 10));
    reverted_with(&b.prove(&messages[1]), "AlreadyProven()");
    reverted_with(&b.execute(&messages[1]), "TooEarly()");
    b.eth.advance(DELAY);
    assert!(b.execute(&messages[1]).success);
    assert_eq!(b.status(2), 2);
    // A vetoed nonce is not proven again: the token gateway refunds it (spec 21
    // §5.1), so delivering it as well would pay twice.
    assert_eq!(b.status(3), 3);
    reverted_with(&b.prove(&messages[2]), "AlreadyProven()");
}

#[test]
fn an_inbox_starts_at_its_first_nonce_and_checks_its_configuration() {
    let mut b = Bridge::new(3, 3, 10, 1_000);
    reverted_with(&b.prove(&b.messages[1].clone()), "NonceBelowFirst()");
    assert!(b.prove(&b.messages[2].clone()).success);
    assert_eq!(word_u64(&b.get(b.inbox, "firstNonce()")), 3);
    assert_eq!(
        word_u64(&b.get(b.inbox, "sourceChainId()")),
        ORANGE_CHAIN_ID
    );
    let init = init_code("OrangeInbox");
    let config = InboxConfig {
        light_client: b.client,
        first_nonce: 1,
        owner: OWNER,
        guardian: GUARDIAN,
        delay: DELAY,
        window: WINDOW,
        max_messages: 1,
        max_value: 1,
    };
    for (bad, error) in [
        (
            InboxConfig {
                owner: [0; 20],
                ..config.clone()
            },
            "ZeroAddress()",
        ),
        (
            InboxConfig {
                guardian: [0; 20],
                ..config.clone()
            },
            "ZeroAddress()",
        ),
        (
            InboxConfig {
                delay: 30 * 86_400 + 1,
                ..config.clone()
            },
            "DelayTooLong()",
        ),
        (
            InboxConfig {
                window: 0,
                ..config.clone()
            },
            "InvalidWindow()",
        ),
    ] {
        let (outcome, _) = b.eth.try_deploy(DEPLOYER, &init, &bad.constructor_args());
        reverted_with(&outcome, error);
    }
}

#[test]
fn proving_costs_grow_with_the_depth_of_the_proof() {
    let mut b = Bridge::new(1, 1, 10, 1_000);
    for i in 0..4_096u32 {
        b.trie.insert(&i.to_be_bytes(), b"noise");
    }
    b.anchor(12);
    let m = b.messages[0].clone();
    let proof = b.slot_proof(&m, 12);
    let outcome = b.eth.call(RELAYER, b.inbox, &proof.prove_calldata(&m));
    assert!(outcome.success, "{outcome:?}");
    assert_eq!((proof.siblings.len(), outcome.gas), (14, PROVE_DEEP_TX_GAS));
}

#[test]
fn relayer_inputs_that_a_light_client_would_refuse_are_refused_first() {
    use orange_abi::bridge::FinalityProof;
    use orange_bridge::{Error, Submission};
    let sk = spec_key();
    let certify = |p: &[u8], height: u64| {
        let hash = keccak256(p);
        let signature = sk.sign(&orange_bls::certificate::message(
            ORANGE_CHAIN_ID,
            height,
            &hash,
        ));
        FinalityProof {
            certificate: orange_bls::Certificate {
                height,
                block_hash: hash,
                signature,
            }
            .to_bytes()
            .to_vec(),
            proposal: p.to_vec(),
        }
    };
    let none = proposal(9, 0, [0; 32]);
    assert!(matches!(
        Submission::new(&certify(&none, 9)),
        Err(Error::NoAnchor)
    ));
    assert!(matches!(
        Submission::new(&certify(&none, 8)),
        Err(Error::ProposalMismatch)
    ));
    assert!(matches!(
        Submission::new(&FinalityProof {
            certificate: vec![2],
            proposal: none
        }),
        Err(Error::Bls(_))
    ));
    let good = proposal(9, 7, [1; 32]);
    let s = Submission::new(&certify(&good, 9)).unwrap();
    assert_eq!((s.height, s.anchor_height, s.anchor_root), (9, 7, [1; 32]));
    assert!(matches!(group_key(&[0; 95]), Err(Error::Bls(_))));
    assert!(matches!(group_key(&[0; 96]), Err(Error::Bls(_))));
}
