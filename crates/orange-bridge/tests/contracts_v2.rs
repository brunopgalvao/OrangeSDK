//! The version-2 Ethereum contracts on revm (spec 12 §8, spec 17 §5.3): the
//! verifier checks keys, compresses them as spec 12 §2 says, and verifies
//! version-2 certificates and rotation messages against the key it is
//! given; the light client moves from key set to key set by rotation
//! certificates of the key it holds, refuses certificates of any other key
//! and certificates anchored past its key's age, and an unchanged
//! `OrangeInbox` delivers against its roots; a client stranded on a
//! superseded key set is recovered by its owner from its previous key set
//! (spec 17 §5.4). Gas of `verify`, `verifyRotation`, `submit`, `rotate` and
//! `recover` is pinned here, and spec 17 §8 states these numbers.

mod support;

use orange_abi::Encode;
use orange_abi::bridge::{Message, message_key};
use orange_abi::chain::Proposal;
use orange_bridge::abi::{self, Value};
use orange_bridge::{
    InboxConfig, SlotProof, execute_calldata, group_key, light_client_v2_args, message_hash,
    verifier_v2_args,
};
use orange_trie::{Trie, keccak256};
use support::eth::{ETH_CHAIN_ID, Eth, Outcome, decode_hex, init_code, selector, word, word_u64};

const ORANGE_CHAIN_ID: u64 = 1337;
const DEPLOYER: [u8; 20] = [0xD0; 20];
const RELAYER: [u8; 20] = [0xEE; 20];
const EPOCH_BLOCKS: u64 = 16;
const MAX_KEY_AGE: u64 = 2;
/// The owner of the version-2 light client (spec 17 §5.4).
const LIGHT_CLIENT_OWNER: [u8; 20] = [0x0C; 20];

/// Execution gas of `OrangeFinalityVerifierV2.verify` called with the key.
const VERIFY_GAS: u64 = 127_279;
/// Execution gas of `OrangeFinalityVerifierV2.verifyRotation`.
const VERIFY_ROTATION_GAS: u64 = 129_050;
/// Gas of an `OrangeLightClientV2.submit` transaction with a 103-byte proposal.
const SUBMIT_TX_GAS: u64 = 228_248;
/// Gas of an `OrangeLightClientV2.rotate` transaction.
const ROTATE_TX_GAS: u64 = 239_729;
/// Gas of an `OrangeLightClientV2.recover` transaction (spec 17 §5.4).
const RECOVER_TX_GAS: u64 = 245_148;

#[allow(clippy::naive_bytecount)]
fn intrinsic(data: &[u8]) -> u64 {
    let zeros = data.iter().filter(|b| **b == 0).count() as u64;
    21_000 + 4 * zeros + 16 * (data.len() as u64 - zeros)
}

fn reverted_with(outcome: &Outcome, error: &str) {
    assert!(!outcome.success, "{error}: {outcome:?}");
    assert_eq!(outcome.output, selector(error), "{error}");
}

fn returns_true(outcome: &Outcome) -> bool {
    assert!(outcome.success, "{outcome:?}");
    outcome.output == word(1)
}

/// `sk` of spec 12 §9.1.
fn spec_key() -> orange_bls::SecretKey {
    let ikm: Vec<u8> = (0..32).collect();
    orange_bls::SecretKey::generate(&ikm, b"").unwrap()
}

fn key_of(sk: &orange_bls::SecretKey) -> [u8; 256] {
    group_key(&sk.public_key().to_bytes()).unwrap()
}

fn g1(signature: &orange_bls::Signature) -> Vec<u8> {
    orange_bls::evm::encode_g1(signature.point()).to_vec()
}

fn sign_v2(sk: &orange_bls::SecretKey, key_id: u64, height: u64, hash: &[u8; 32]) -> Vec<u8> {
    g1(&sk.sign(&orange_bls::certificate::message_v2(
        ORANGE_CHAIN_ID,
        key_id,
        height,
        hash,
    )))
}

fn sign_rotation(sk: &orange_bls::SecretKey, to: u64, next: &orange_bls::SecretKey) -> Vec<u8> {
    g1(&sk.sign(&orange_bls::certificate::rotation_message(
        ORANGE_CHAIN_ID,
        to,
        &next.public_key(),
    )))
}

fn verify_call(key: &[u8], key_id: u64, height: u64, hash: &[u8; 32], signature: &[u8]) -> Vec<u8> {
    abi::call(
        "verify(bytes,uint64,uint64,bytes32,bytes)",
        &[
            Value::Bytes(key.to_vec()),
            Value::uint(u128::from(key_id)),
            Value::uint(u128::from(height)),
            Value::Word(*hash),
            Value::Bytes(signature.to_vec()),
        ],
    )
}

fn rotation_call(key: &[u8], to: u64, new_key: &[u8], signature: &[u8]) -> Vec<u8> {
    abi::call(
        "verifyRotation(bytes,uint64,bytes,bytes)",
        &[
            Value::Bytes(key.to_vec()),
            Value::uint(u128::from(to)),
            Value::Bytes(new_key.to_vec()),
            Value::Bytes(signature.to_vec()),
        ],
    )
}

fn bytes_call(signature: &str, data: &[u8]) -> Vec<u8> {
    abi::call(signature, &[Value::Bytes(data.to_vec())])
}

/// The ABI-encoded `bytes` return value's contents.
fn returned_bytes(output: &[u8]) -> Vec<u8> {
    let len = usize::try_from(word_u64(&output[32..64])).unwrap();
    output[64..64 + len].to_vec()
}

#[test]
#[allow(clippy::too_many_lines)]
fn the_verifier_checks_keys_certificates_and_rotations() {
    let mut eth = Eth::new();
    let verifier = eth.deploy(
        DEPLOYER,
        &init_code("OrangeFinalityVerifierV2"),
        &verifier_v2_args(ORANGE_CHAIN_ID),
    );
    let get = |eth: &mut Eth, signature: &str| {
        eth.view(RELAYER, verifier, &abi::call(signature, &[]))
            .output
    };
    assert_eq!(get(&mut eth, "chainId()"), word(1337));
    assert_eq!(get(&mut eth, "VERSION()"), word(2));
    let sk = spec_key();
    let key = key_of(&sk);
    // Keys: the spec's is valid; a short one, the identity, a point off the curve and a
    // non-canonical encoding are not.
    let valid = |eth: &mut Eth, key: &[u8]| {
        returns_true(&eth.view(RELAYER, verifier, &bytes_call("isValidKey(bytes)", key)))
    };
    assert!(valid(&mut eth, &key));
    assert!(!valid(&mut eth, &key[..255]));
    assert!(!valid(&mut eth, &[0; 256]));
    let mut off_curve = key;
    off_curve[255] ^= 1;
    assert!(!valid(&mut eth, &off_curve));
    let mut big = key;
    big[16] = 0xFF;
    assert!(!valid(&mut eth, &big));
    // Compression is the spec 12 §2 encoding, whichever root y is.
    let mut flags = [false; 2];
    for seed in 1..=12u8 {
        let pk = orange_bls::SecretKey::generate(&[seed; 32], b"")
            .unwrap()
            .public_key();
        let out = eth.view(
            RELAYER,
            verifier,
            &bytes_call("compress(bytes)", &orange_bls::evm::encode_g2(pk.point())),
        );
        assert!(out.success);
        let compressed = returned_bytes(&out.output);
        assert_eq!(compressed, pk.to_bytes().to_vec(), "seed {seed}");
        flags[usize::from(compressed[0] & 0x20 != 0)] = true;
    }
    assert_eq!(flags, [true, true]);
    reverted_with(
        &eth.view(
            RELAYER,
            verifier,
            &bytes_call("compress(bytes)", &key[..200]),
        ),
        "InvalidLength()",
    );
    // The spec 12 §9.5 certificate verifies, as key set 3 and nothing else.
    let hash = [0xAB; 32];
    let signature = sign_v2(&sk, 3, 1, &hash);
    let data = verify_call(&key, 3, 1, &hash, &signature);
    let outcome = eth.call(RELAYER, verifier, &data);
    assert!(returns_true(&outcome));
    assert_eq!(
        outcome.gas - intrinsic(&data),
        VERIFY_GAS,
        "{}",
        outcome.gas - intrinsic(&data)
    );
    assert!(!returns_true(&eth.view(
        RELAYER,
        verifier,
        &verify_call(&key, 4, 1, &hash, &signature)
    )));
    assert!(!returns_true(&eth.view(
        RELAYER,
        verifier,
        &verify_call(&key, 3, 2, &hash, &signature)
    )));
    let v1 = g1(&sk.sign(&orange_bls::certificate::message(ORANGE_CHAIN_ID, 1, &hash)));
    assert!(!returns_true(&eth.view(
        RELAYER,
        verifier,
        &verify_call(&key, 3, 1, &hash, &v1)
    )));
    let other = key_of(&orange_bls::SecretKey::generate(&[9; 32], b"").unwrap());
    assert!(!returns_true(&eth.view(
        RELAYER,
        verifier,
        &verify_call(&other, 3, 1, &hash, &signature)
    )));
    reverted_with(
        &eth.view(
            RELAYER,
            verifier,
            &verify_call(&key, 3, 1, &hash, &signature[..96]),
        ),
        "InvalidLength()",
    );
    reverted_with(
        &eth.view(
            RELAYER,
            verifier,
            &verify_call(&key[..128], 3, 1, &hash, &signature),
        ),
        "InvalidLength()",
    );
    // The spec 12 §9.5 rotation: the §9.1 key hands off to the §9.3 group key as key set 4.
    let next = orange_bls::PublicKey::from_bytes(
        &decode_hex("a1e907f8b3d3f525da3021ff8d62eaa7fa2f001625aad5ada2ca101c5407cc2b34217dadbfdb3a08a242ff3c2515ea95084f49c59dcdcaff6ce064f18bd217383e191d75e3b85e9e88d84dda61d1ca84f4ca998ca0cc5f3b63dfd217bb0a5799")
            .try_into()
            .unwrap(),
    )
    .unwrap();
    let next_key = orange_bls::evm::encode_g2(next.point());
    let rotation = g1(&sk.sign(&orange_bls::certificate::rotation_message(
        ORANGE_CHAIN_ID,
        4,
        &next,
    )));
    assert_eq!(
        rotation[16..64],
        decode_hex(
            "08b60f250b5a4bb41acadf55b22cd9330032d5a5c5a4e43f670b4179b2e5450439df95c143d63e21a5da1933671c17ed"
        )[..]
    );
    let data = rotation_call(&key, 4, &next_key, &rotation);
    let outcome = eth.call(RELAYER, verifier, &data);
    assert!(returns_true(&outcome));
    assert_eq!(
        outcome.gas - intrinsic(&data),
        VERIFY_ROTATION_GAS,
        "{}",
        outcome.gas - intrinsic(&data)
    );
    assert!(!returns_true(&eth.view(
        RELAYER,
        verifier,
        &rotation_call(&key, 5, &next_key, &rotation)
    )));
    assert!(!returns_true(&eth.view(
        RELAYER,
        verifier,
        &rotation_call(&key, 4, &key, &rotation)
    )));
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

/// The proposal anchoring `anchor` with `root` one height below, certified by
/// `sk` as key set `key_id`.
fn certified(sk: &orange_bls::SecretKey, key_id: u64, anchor: u64, root: [u8; 32]) -> Vec<u8> {
    let p = proposal(anchor + 1, anchor, root);
    submit_call(&p, &sign_v2(sk, key_id, anchor + 1, &keccak256(&p)))
}

fn rotate_call(to: u64, next: &orange_bls::SecretKey, signature: &[u8]) -> Vec<u8> {
    abi::call(
        "rotate(uint64,bytes,bytes)",
        &[
            Value::uint(u128::from(to)),
            Value::Bytes(key_of(next).to_vec()),
            Value::Bytes(signature.to_vec()),
        ],
    )
}

struct Deployed {
    eth: Eth,
    verifier: [u8; 20],
    client: [u8; 20],
}

impl Deployed {
    fn new(key_id: u64, sk: &orange_bls::SecretKey) -> Deployed {
        let mut eth = Eth::new();
        let verifier = eth.deploy(
            DEPLOYER,
            &init_code("OrangeFinalityVerifierV2"),
            &verifier_v2_args(ORANGE_CHAIN_ID),
        );
        let client = eth.deploy(
            DEPLOYER,
            &init_code("OrangeLightClientV2"),
            &light_client_v2_args(
                &verifier,
                key_id,
                &key_of(sk),
                EPOCH_BLOCKS,
                MAX_KEY_AGE,
                &LIGHT_CLIENT_OWNER,
            ),
        );
        Deployed {
            eth,
            verifier,
            client,
        }
    }

    fn call(&mut self, data: &[u8]) -> Outcome {
        self.eth.call(RELAYER, self.client, data)
    }

    fn get(&mut self, signature: &str, args: &[Value]) -> Vec<u8> {
        self.eth
            .view(RELAYER, self.client, &abi::call(signature, args))
            .output
    }

    fn root(&mut self, height: u64) -> Vec<u8> {
        self.get("stateRoots(uint64)", &[Value::uint(u128::from(height))])
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn the_light_client_follows_rotations_and_expires_old_keys() {
    let keys: Vec<orange_bls::SecretKey> = (1..=4u8)
        .map(|i| orange_bls::SecretKey::generate(&[0x40 + i; 32], b"").unwrap())
        .collect();
    let mut c = Deployed::new(0, &keys[0]);
    assert_eq!(c.get("chainId()", &[]), word(1337));
    assert_eq!(c.get("verifier()", &[]), word_address(&c.verifier));
    assert_eq!(
        (
            word_u64(&c.get("epochBlocks()", &[])),
            word_u64(&c.get("maxKeyAge()", &[])),
            word_u64(&c.get("keyId()", &[]))
        ),
        (EPOCH_BLOCKS, MAX_KEY_AGE, 0)
    );
    assert_eq!(
        returned_bytes(&c.get("currentKey()", &[])),
        key_of(&keys[0]).to_vec()
    );
    assert_eq!(
        [0, 1, 16, 17, 48, 49].map(|h| word_u64(&c.get("epochOf(uint64)", &[Value::uint(h)]))),
        [0, 0, 0, 1, 2, 3]
    );
    // Key set 0 certifies an anchor in epoch 1.
    let data = certified(&keys[0], 0, 18, [0x51; 32]);
    let outcome = c.call(&data);
    assert!(outcome.success, "{outcome:?}");
    assert_eq!(outcome.gas, SUBMIT_TX_GAS, "{}", outcome.gas);
    assert_eq!(c.root(18), [0x51; 32].to_vec());
    // An anchor in epoch 3 is past the key's age, however well signed.
    reverted_with(
        &c.call(&certified(&keys[0], 0, 49, [0x52; 32])),
        "KeyExpired()",
    );
    // The shape checks come first, as in version 1.
    reverted_with(
        &c.call(&submit_call(&proposal(30, 29, [1; 32])[..95], &[0; 128])),
        "ProposalTooShort()",
    );
    reverted_with(&c.call(&certified(&keys[0], 0, 0, [0; 32])), "NoAnchor()");
    let ahead = proposal(30, 30, [1; 32]);
    reverted_with(
        &c.call(&submit_call(
            &ahead,
            &sign_v2(&keys[0], 0, 30, &keccak256(&ahead)),
        )),
        "AnchorNotBelowProposal()",
    );
    reverted_with(
        &c.call(&certified(&keys[0], 0, 18, [0x51; 32])),
        "NotMonotonic()",
    );
    // Another key set's id, or another key, is not the current key.
    reverted_with(
        &c.call(&certified(&keys[0], 1, 20, [0x53; 32])),
        "InvalidCertificate()",
    );
    reverted_with(
        &c.call(&certified(&keys[1], 0, 20, [0x53; 32])),
        "InvalidCertificate()",
    );
    // Key set 0 hands off to key set 1.
    let data = rotate_call(1, &keys[1], &sign_rotation(&keys[0], 1, &keys[1]));
    let outcome = c.call(&data);
    assert!(outcome.success, "{outcome:?}");
    assert_eq!(outcome.gas, ROTATE_TX_GAS, "{}", outcome.gas);
    assert_eq!(
        outcome.logs[0].data.topics()[0].0,
        keccak256(b"KeyRotated(uint64,uint64)")
    );
    assert_eq!(word_u64(&c.get("keyId()", &[])), 1);
    assert_eq!(
        returned_bytes(&c.get("currentKey()", &[])),
        key_of(&keys[1]).to_vec()
    );
    // The old key's shareholders, gone or not, certify nothing any more.
    reverted_with(
        &c.call(&certified(&keys[0], 0, 20, [0x66; 32])),
        "InvalidCertificate()",
    );
    reverted_with(
        &c.call(&certified(&keys[0], 1, 20, [0x66; 32])),
        "InvalidCertificate()",
    );
    // Key set 1 is trusted up to epoch 3.
    assert!(c.call(&certified(&keys[1], 1, 49, [0x54; 32])).success);
    reverted_with(
        &c.call(&certified(&keys[1], 1, 65, [0x55; 32])),
        "KeyExpired()",
    );
    // Rotations: not newer, too far ahead, an invalid key, a signature of the old key or
    // over another target.
    reverted_with(
        &c.call(&rotate_call(
            1,
            &keys[2],
            &sign_rotation(&keys[1], 1, &keys[2]),
        )),
        "NotNewer()",
    );
    reverted_with(
        &c.call(&rotate_call(
            4,
            &keys[2],
            &sign_rotation(&keys[1], 4, &keys[2]),
        )),
        "KeyExpired()",
    );
    let mut bad = rotate_call(2, &keys[2], &sign_rotation(&keys[1], 2, &keys[2]));
    let at = bad.len() - 32 * 4 - 128 - 32 - 1;
    bad[at] ^= 1;
    reverted_with(&c.call(&bad), "InvalidKey()");
    reverted_with(
        &c.call(&rotate_call(
            2,
            &keys[2],
            &sign_rotation(&keys[0], 2, &keys[2]),
        )),
        "InvalidCertificate()",
    );
    reverted_with(
        &c.call(&rotate_call(
            2,
            &keys[2],
            &sign_rotation(&keys[1], 3, &keys[2]),
        )),
        "InvalidCertificate()",
    );
    // Key set 1 hands off to key set 3 (run 2 failed): the handoff skips an id.
    assert!(
        c.call(&rotate_call(
            3,
            &keys[3],
            &sign_rotation(&keys[1], 3, &keys[3])
        ))
        .success
    );
    assert!(c.call(&certified(&keys[3], 3, 80, [0x56; 32])).success);
    assert_eq!(c.root(80), [0x56; 32].to_vec());
    // Deployment refuses a zero epoch length or key age, a zero owner and an invalid key.
    let init = init_code("OrangeLightClientV2");
    for (epoch_blocks, age, key, owner, error) in [
        (
            0u64,
            2u64,
            key_of(&keys[0]),
            LIGHT_CLIENT_OWNER,
            "InvalidParameters()",
        ),
        (
            16,
            0,
            key_of(&keys[0]),
            LIGHT_CLIENT_OWNER,
            "InvalidParameters()",
        ),
        (16, 2, key_of(&keys[0]), [0; 20], "ZeroAddress()"),
        (16, 2, [0; 256], LIGHT_CLIENT_OWNER, "InvalidKey()"),
    ] {
        let args = light_client_v2_args(&c.verifier, 0, &key, epoch_blocks, age, &owner);
        let (outcome, _) = c.eth.try_deploy(DEPLOYER, &init, &args);
        reverted_with(&outcome, error);
    }
}

fn recover_call(
    from: u64,
    from_key: &orange_bls::SecretKey,
    to: u64,
    next: &[u8; 256],
    signature: &[u8],
) -> Vec<u8> {
    abi::call(
        "recover(uint64,bytes,uint64,bytes,bytes)",
        &[
            Value::uint(u128::from(from)),
            Value::Bytes(key_of(from_key).to_vec()),
            Value::uint(u128::from(to)),
            Value::Bytes(next.to_vec()),
            Value::Bytes(signature.to_vec()),
        ],
    )
}

#[test]
#[allow(clippy::too_many_lines)]
fn a_stranded_client_is_recovered_from_its_previous_key() {
    let keys: Vec<orange_bls::SecretKey> = (1..=4u8)
        .map(|i| orange_bls::SecretKey::generate(&[0x70 + i; 32], b"").unwrap())
        .collect();
    let mut c = Deployed::new(0, &keys[0]);
    let owner = |c: &mut Deployed, data: &[u8]| c.eth.call(LIGHT_CLIENT_OWNER, c.client, data);
    // Before any rotation the previous key set is the one the client started from.
    assert_eq!(word_u64(&c.get("previousKeyId()", &[])), 0);
    assert_eq!(c.get("owner()", &[]), word_address(&LIGHT_CLIENT_OWNER));
    // Key set 0's shareholders signed a handoff to key set 1, which key set 2 superseded
    // before the chain recorded it; the chain then recorded 0 → 2 (spec 15 §6.6). Someone
    // relays the stale certificate, and the client holds key set 1, which never hands off.
    assert!(
        c.call(&rotate_call(
            1,
            &keys[1],
            &sign_rotation(&keys[0], 1, &keys[1])
        ))
        .success
    );
    assert_eq!(word_u64(&c.get("previousKeyId()", &[])), 0);
    let handoff = sign_rotation(&keys[0], 2, &keys[2]);
    // The chain's handoff does not verify under the key the client holds, and nothing
    // else will: the client is stranded.
    reverted_with(
        &c.call(&rotate_call(2, &keys[2], &handoff)),
        "InvalidCertificate()",
    );
    reverted_with(
        &c.call(&certified(&keys[2], 2, 40, [0x71; 32])),
        "InvalidCertificate()",
    );
    let recover = recover_call(0, &keys[0], 2, &key_of(&keys[2]), &handoff);
    // Only the owner recovers, and only while paused.
    reverted_with(&c.call(&recover), "NotOwner()");
    reverted_with(&owner(&mut c, &recover), "NotPaused()");
    reverted_with(&c.call(&abi::call("pause()", &[])), "NotOwner()");
    let paused = owner(&mut c, &abi::call("pause()", &[]));
    assert!(paused.success, "{paused:?}");
    assert_eq!(paused.logs[0].data.topics()[0].0, keccak256(b"Paused()"));
    assert_eq!(c.get("paused()", &[]), word(1));
    // Paused, the client takes neither roots nor rotations.
    reverted_with(
        &c.call(&certified(&keys[1], 1, 20, [0x72; 32])),
        "IsPaused()",
    );
    reverted_with(
        &c.call(&rotate_call(
            3,
            &keys[3],
            &sign_rotation(&keys[1], 3, &keys[3]),
        )),
        "IsPaused()",
    );
    // The recovery must start from the previous key set, by id and key.
    reverted_with(
        &owner(
            &mut c,
            &recover_call(
                1,
                &keys[1],
                2,
                &key_of(&keys[2]),
                &sign_rotation(&keys[1], 2, &keys[2]),
            ),
        ),
        "NotPreviousKey()",
    );
    reverted_with(
        &owner(
            &mut c,
            &recover_call(5, &keys[0], 2, &key_of(&keys[2]), &handoff),
        ),
        "NotPreviousKey()",
    );
    // It moves past the stranded key set, within the previous key's age.
    reverted_with(
        &owner(
            &mut c,
            &recover_call(
                0,
                &keys[0],
                1,
                &key_of(&keys[1]),
                &sign_rotation(&keys[0], 1, &keys[1]),
            ),
        ),
        "NotNewer()",
    );
    reverted_with(
        &owner(
            &mut c,
            &recover_call(
                0,
                &keys[0],
                3,
                &key_of(&keys[3]),
                &sign_rotation(&keys[0], 3, &keys[3]),
            ),
        ),
        "KeyExpired()",
    );
    reverted_with(
        &owner(&mut c, &recover_call(0, &keys[0], 2, &[0; 256], &handoff)),
        "InvalidKey()",
    );
    // The owner cannot choose a key the previous key set did not sign over.
    reverted_with(
        &owner(
            &mut c,
            &recover_call(0, &keys[0], 2, &key_of(&keys[3]), &handoff),
        ),
        "InvalidCertificate()",
    );
    reverted_with(
        &owner(
            &mut c,
            &recover_call(
                0,
                &keys[0],
                2,
                &key_of(&keys[2]),
                &sign_rotation(&keys[1], 2, &keys[2]),
            ),
        ),
        "InvalidCertificate()",
    );
    // The recorded handoff out of key set 0 recovers the client.
    let recovered = owner(&mut c, &recover);
    assert!(recovered.success, "{recovered:?}");
    assert_eq!(recovered.gas, RECOVER_TX_GAS, "{}", recovered.gas);
    let topics = recovered.logs[0].data.topics();
    assert_eq!(
        topics[0].0,
        keccak256(b"KeyRecovered(uint64,uint64,uint64)")
    );
    assert_eq!(
        [&topics[1].0[..], &topics[2].0[..], &topics[3].0[..]],
        [&word(1)[..], &word(0)[..], &word(2)[..]]
    );
    assert_eq!(word_u64(&c.get("keyId()", &[])), 2);
    assert_eq!(word_u64(&c.get("previousKeyId()", &[])), 0);
    assert_eq!(
        returned_bytes(&c.get("currentKey()", &[])),
        key_of(&keys[2]).to_vec()
    );
    reverted_with(&c.call(&abi::call("unpause()", &[])), "NotOwner()");
    let unpaused = owner(&mut c, &abi::call("unpause()", &[]));
    assert!(unpaused.success, "{unpaused:?}");
    assert_eq!(
        unpaused.logs[0].data.topics()[0].0,
        keccak256(b"Unpaused()")
    );
    assert_eq!(c.get("paused()", &[]), word(0));
    // The client follows the chain again: key set 2 certifies and hands off to 3.
    assert!(c.call(&certified(&keys[2], 2, 40, [0x73; 32])).success);
    assert_eq!(c.root(40), [0x73; 32].to_vec());
    assert!(
        c.call(&rotate_call(
            3,
            &keys[3],
            &sign_rotation(&keys[2], 3, &keys[3])
        ))
        .success
    );
    assert_eq!(word_u64(&c.get("previousKeyId()", &[])), 2);
    // The rotation retired key set 0 as the previous one: it recovers nothing any more.
    assert!(owner(&mut c, &abi::call("pause()", &[])).success);
    reverted_with(
        &owner(
            &mut c,
            &recover_call(
                0,
                &keys[0],
                4,
                &key_of(&keys[1]),
                &sign_rotation(&keys[0], 4, &keys[1]),
            ),
        ),
        "NotPreviousKey()",
    );
    // Ownership moves, never to zero, and only by the owner.
    let transfer = |to: &[u8; 20]| abi::call("transferOwnership(address)", &[Value::address(to)]);
    reverted_with(&c.call(&transfer(&RELAYER)), "NotOwner()");
    reverted_with(&owner(&mut c, &transfer(&[0; 20])), "ZeroAddress()");
    let moved = owner(&mut c, &transfer(&RELAYER));
    assert!(moved.success, "{moved:?}");
    assert_eq!(
        moved.logs[0].data.topics()[0].0,
        keccak256(b"OwnerChanged(address)")
    );
    assert_eq!(c.get("owner()", &[]), word_address(&RELAYER));
    reverted_with(&owner(&mut c, &abi::call("unpause()", &[])), "NotOwner()");
    assert!(c.call(&abi::call("unpause()", &[])).success);
}

fn word_address(a: &[u8; 20]) -> Vec<u8> {
    let mut w = vec![0u8; 12];
    w.extend_from_slice(a);
    w
}

#[test]
fn the_inbox_delivers_against_a_version_two_client() {
    let sk = orange_bls::SecretKey::generate(&[0x61; 32], b"").unwrap();
    let mut c = Deployed::new(5, &sk);
    let config = InboxConfig {
        light_client: c.client,
        first_nonce: 1,
        owner: [0x0A; 20],
        guardian: [0x0B; 20],
        delay: 60,
        window: 3_600,
        max_messages: 10,
        max_value: 1_000,
    };
    let inbox = c.eth.deploy(
        DEPLOYER,
        &init_code("OrangeInbox"),
        &config.constructor_args(),
    );
    let recipient = c.eth.deploy(
        DEPLOYER,
        &init_code("MessageRecipient"),
        &abi::encode(&[Value::address(&inbox)]),
    );
    let m = Message {
        source_chain_id: ORANGE_CHAIN_ID,
        nonce: 1,
        sender: [0x5E; 20],
        dest_chain_id: ETH_CHAIN_ID,
        recipient,
        value: 7,
        payload: b"rotated".to_vec(),
    };
    let mut trie = Trie::new();
    trie.insert(&message_key(1), &message_hash(&m));
    trie.insert(b"meta/height", b"y");
    // Key set 5 is trusted up to epoch 7: anchor 100 is in epoch 6.
    assert!(c.call(&certified(&sk, 5, 100, trie.root())).success);
    let proof = SlotProof::new(1, 100, message_hash(&m), &trie.prove(&message_key(1))).unwrap();
    let proven = c.eth.call(RELAYER, inbox, &proof.prove_calldata(&m));
    assert!(proven.success, "{proven:?}");
    c.eth.advance(60);
    assert!(c.eth.call(RELAYER, inbox, &execute_calldata(&m)).success);
    let received = c
        .eth
        .view(RELAYER, recipient, &abi::call("received()", &[]))
        .output;
    assert_eq!(word_u64(&received), 1);
}
