//! The relayer side of the Solo-to-Ethereum bridge (spec 17).
//!
//! A relayer moves two things from a Solo node to Ethereum:
//!
//! - **State roots.** [`Submission::new`] turns a stored threshold
//!   certificate and the proposal it certifies ([`finality_proof`]) into the
//!   light client's `submit(proposal, signature)` call, with the signature
//!   decompressed into its EIP-2537 encoding. The proposal's anchor names the
//!   height whose state root the light client then stores.
//! - **Messages.** [`sent_messages`] reads the outbox's `MessageSent` logs
//!   from receipts; [`slot_proof`] proves the outbox slot of a message against
//!   the state root of a recent height, and [`SlotProof::prove_calldata`] and
//!   [`execute_calldata`] build the inbox's `prove` and `execute` calls.
//!
//! - **Key rotations.** Solo's group key rotates (spec 15 §6.6): [`rotation`]
//!   and [`rotations_from`] read the handoffs the chain recorded, and
//!   [`Rotation::calldata`] builds `SoloLightClientV2.rotate`, which moves a
//!   light client from one key set to the next. A version-2 certificate
//!   names its key set, and [`submission_covering_key`] picks one that
//!   verifies under the key set a light client holds, passing over, with
//!   the reason, any that names another or does not verify.
//!
//! - **Tokens.** [`tokens`] holds what the canonical token bridge of spec 21
//!   adds on top of both channels: its messages, the addresses of wrapped
//!   tokens, and the calls of users, owners and relayers.
//!
//! [`verifier_args`], [`light_client_args`], [`verifier_v2_args`],
//! [`light_client_v2_args`] and [`InboxConfig`] encode the constructor
//! arguments of the contracts in `contracts/`.

#![forbid(unsafe_code)]

pub mod abi;
pub mod tokens;

use std::fmt;

use solo_abi::bridge::{
    FinalityProof, Message, OUTBOX_ADDRESS, anchor, message_key, message_slot, query,
};
use solo_abi::chain::Log;
use solo_abi::rotation::{Handoff, query as rotation_query, threshold_certificate};
use solo_abi::staking::{KeySetRecord, keys as staking_keys};
use solo_abi::types::{Address, Hash};
use solo_abi::{Decode, Encode};
use solo_node::{Node, NodeError};
use solo_trie::{Proof, Terminal, bit, branch_hash, keccak256, leaf_hash};

use crate::abi::Value;

/// Why a relayer step failed.
#[derive(Debug)]
pub enum Error {
    /// A certificate or group key that does not decode (spec 12 §2, §7).
    Bls(solo_bls::Error),
    /// A proposal that does not hash to the certificate's block hash, or
    /// names another height.
    ProposalMismatch,
    /// A proposal without an anchor: a light client would refuse it.
    NoAnchor,
    /// A state proof that does not show the outbox slot holding the
    /// message hash: the message is not in the state at that height.
    NotCommitted,
    /// The chain holds no key set of this id with a usable group key.
    UnknownKeySet(u64),
    /// The node failed.
    Node(NodeError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Bls(e) => write!(f, "bad certificate or key: {e:?}"),
            Error::ProposalMismatch => {
                f.write_str("the proposal is not the one the certificate names")
            }
            Error::NoAnchor => f.write_str("the proposal carries no anchor"),
            Error::NotCommitted => f.write_str("the message is not committed at that height"),
            Error::UnknownKeySet(id) => write!(f, "the chain holds no key set {id}"),
            Error::Node(e) => write!(f, "node: {e}"),
        }
    }
}

impl std::error::Error for Error {}

fn le64(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap_or_default())
}

/// What a relayer submits to the light client for one certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Submission {
    /// The key set a version-2 certificate names; `None` for version 1.
    pub key_id: Option<u64>,
    /// The certified proposal's height.
    pub height: u64,
    /// The certified proposal's hash, the certificate's block hash.
    pub block_hash: Hash,
    /// The height the proposal anchors.
    pub anchor_height: u64,
    /// The state root of that height.
    pub anchor_root: Hash,
    /// The encoded proposal.
    pub proposal: Vec<u8>,
    /// The certificate's signature in EIP-2537 encoding.
    pub signature: [u8; 128],
}

impl Submission {
    /// The submission of `proof`, checked as the light client checks it
    /// except for the signature, which it decompresses.
    ///
    /// # Errors
    /// [`Error::Bls`] for a certificate that does not decode,
    /// [`Error::ProposalMismatch`] for a proposal it does not certify,
    /// [`Error::NoAnchor`] for one without an anchor.
    pub fn new(proof: &FinalityProof) -> Result<Submission, Error> {
        let certificate = threshold_certificate(&proof.certificate)
            .ok_or(Error::Bls(solo_bls::Error::UnsupportedVersion))?;
        let signature = signature_point(certificate.signature)?;
        let p = &proof.proposal;
        if keccak256(p) != certificate.block_hash
            || p.len() < anchor::MIN_LENGTH
            || le64(p, anchor::HEIGHT) != certificate.height
        {
            return Err(Error::ProposalMismatch);
        }
        let anchor_height = le64(p, anchor::ANCHOR_HEIGHT);
        if anchor_height == 0 {
            return Err(Error::NoAnchor);
        }
        Ok(Submission {
            key_id: (certificate.version == 2).then_some(certificate.key_id),
            height: certificate.height,
            block_hash: certificate.block_hash,
            anchor_height,
            anchor_root: p[anchor::ANCHOR_ROOT..anchor::ANCHOR_ROOT + 32]
                .try_into()
                .unwrap_or_default(),
            proposal: p.clone(),
            signature: solo_bls::evm::encode_g1(signature.point()),
        })
    }

    /// The light client's `submit(bytes,bytes)` calldata.
    #[must_use]
    pub fn calldata(&self) -> Vec<u8> {
        abi::call(
            "submit(bytes,bytes)",
            &[
                Value::Bytes(self.proposal.clone()),
                Value::Bytes(self.signature.to_vec()),
            ],
        )
    }
}

/// A compressed signature (48 bytes) as a point.
fn signature_point(bytes: &[u8]) -> Result<solo_bls::Signature, Error> {
    let bytes: [u8; 48] = bytes
        .try_into()
        .ok()
        .ok_or(Error::Bls(solo_bls::Error::InvalidLength))?;
    solo_bls::Signature::from_bytes(&bytes).map_err(Error::Bls)
}

/// The EIP-2537 encoding of a chain's compressed 96-byte group key, as the
/// verifier's constructor takes it.
///
/// # Errors
/// [`Error::Bls`] for a key that is not 96 bytes or does not decode.
pub fn group_key(compressed: &[u8]) -> Result<[u8; 256], Error> {
    let bytes: [u8; 96] = compressed
        .try_into()
        .ok()
        .ok_or(Error::Bls(solo_bls::Error::InvalidLength))?;
    Ok(solo_bls::evm::encode_g2(
        solo_bls::PublicKey::from_bytes(&bytes)
            .map_err(Error::Bls)?
            .point(),
    ))
}

/// Constructor arguments of `SoloFinalityVerifierV1(uint64 chainId, bytes groupKey)`.
#[must_use]
pub fn verifier_args(chain_id: u64, group_key: &[u8; 256]) -> Vec<u8> {
    abi::encode(&[
        Value::uint(u128::from(chain_id)),
        Value::Bytes(group_key.to_vec()),
    ])
}

/// Constructor arguments of `SoloLightClient(address verifier)`.
#[must_use]
pub fn light_client_args(verifier: &Address) -> Vec<u8> {
    abi::encode(&[Value::address(verifier)])
}

/// Constructor arguments of `SoloFinalityVerifierV2(uint64 chainId)`.
#[must_use]
pub fn verifier_v2_args(chain_id: u64) -> Vec<u8> {
    abi::encode(&[Value::uint(u128::from(chain_id))])
}

/// Constructor arguments of `SoloLightClientV2(address verifier, uint64
/// keyId, bytes key, uint64 epochBlocks, uint64 maxKeyAge)`: the trusted key
/// set to start from, in EIP-2537 encoding, and the chain's epoch length and
/// key age.
#[must_use]
pub fn light_client_v2_args(
    verifier: &Address,
    key_id: u64,
    key: &[u8; 256],
    epoch_blocks: u64,
    max_key_age: u64,
) -> Vec<u8> {
    abi::encode(&[
        Value::address(verifier),
        Value::uint(u128::from(key_id)),
        Value::Bytes(key.to_vec()),
        Value::uint(u128::from(epoch_blocks)),
        Value::uint(u128::from(max_key_age)),
    ])
}

/// A recorded handoff, ready for `SoloLightClientV2.rotate`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rotation {
    /// The key set handed off from.
    pub from: u64,
    /// The key set handed off to.
    pub to: u64,
    /// Its group key, compressed.
    pub key: Vec<u8>,
    /// Its group key in EIP-2537 encoding.
    pub key_eip2537: [u8; 256],
    /// The group signature of `from` in EIP-2537 encoding.
    pub signature: [u8; 128],
    /// The Solo height that recorded the handoff.
    pub height: u64,
}

impl Rotation {
    /// The rotation of a recorded handoff, with its key and signature
    /// decompressed.
    ///
    /// # Errors
    /// [`Error::Bls`] for a key or signature that does not decode.
    pub fn new(handoff: &Handoff) -> Result<Rotation, Error> {
        let signature = signature_point(&handoff.signature)?;
        Ok(Rotation {
            from: handoff.from,
            to: handoff.to,
            key: handoff.key.clone(),
            key_eip2537: group_key(&handoff.key)?,
            signature: solo_bls::evm::encode_g1(signature.point()),
            height: handoff.height,
        })
    }

    /// The light client's `rotate(uint64,bytes,bytes)` calldata.
    #[must_use]
    pub fn calldata(&self) -> Vec<u8> {
        abi::call(
            "rotate(uint64,bytes,bytes)",
            &[
                Value::uint(u128::from(self.to)),
                Value::Bytes(self.key_eip2537.to_vec()),
                Value::Bytes(self.signature.to_vec()),
            ],
        )
    }
}

/// The handoff out of key set `from` that `node`'s chain recorded; `None` if
/// none was.
///
/// # Errors
/// [`Error::Node`] if the query fails, [`Error::Bls`] for a record that
/// does not decode.
pub fn rotation(node: &mut Node, from: u64) -> Result<Option<Rotation>, Error> {
    let r = node
        .query(rotation_query::HANDOFF, &from.to_bytes())
        .map_err(Error::Node)?;
    if r.status != 0 {
        return Ok(None);
    }
    let handoff = Handoff::from_bytes(&r.body)
        .ok()
        .ok_or(Error::Node(NodeError::Decode(rotation_query::HANDOFF)))?;
    Rotation::new(&handoff).map(Some)
}

/// Every handoff from key set `from` on, in order: what a light client
/// holding `from` submits to reach the chain's active key set.
///
/// # Errors
/// As [`rotation`].
pub fn rotations_from(node: &mut Node, from: u64) -> Result<Vec<Rotation>, Error> {
    let mut out = Vec::new();
    let mut at = from;
    while let Some(r) = rotation(node, at)? {
        at = r.to;
        out.push(r);
    }
    Ok(out)
}

/// The configuration a `SoloInbox` is deployed with (spec 17 §6.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboxConfig {
    /// The light client.
    pub light_client: Address,
    /// The lowest nonce the inbox accepts.
    pub first_nonce: u64,
    /// The owner.
    pub owner: Address,
    /// The guardian.
    pub guardian: Address,
    /// Seconds between proving and executing a message.
    pub delay: u64,
    /// Rate-limit window in seconds.
    pub window: u64,
    /// Most messages executed per window.
    pub max_messages: u64,
    /// Most value executed per window.
    pub max_value: u128,
}

impl InboxConfig {
    /// The constructor arguments.
    #[must_use]
    pub fn constructor_args(&self) -> Vec<u8> {
        abi::encode(&[
            Value::address(&self.light_client),
            Value::uint(u128::from(self.first_nonce)),
            Value::address(&self.owner),
            Value::address(&self.guardian),
            Value::uint(u128::from(self.delay)),
            Value::uint(u128::from(self.window)),
            Value::uint(u128::from(self.max_messages)),
            Value::uint(self.max_value),
        ])
    }
}

/// The message hash (spec 17 §3).
#[must_use]
pub fn message_hash(message: &Message) -> Hash {
    keccak256(&message.encode())
}

/// The inbox's `Message` tuple of `message`.
fn message_value(message: &Message) -> Value {
    Value::Tuple(vec![
        Value::uint(u128::from(message.nonce)),
        Value::address(&message.sender),
        Value::address(&message.recipient),
        Value::uint(message.value),
        Value::Bytes(message.payload.clone()),
    ])
}

/// The inbox's `execute(Message)` calldata.
#[must_use]
pub fn execute_calldata(message: &Message) -> Vec<u8> {
    abi::call(
        "execute((uint64,address,address,uint256,bytes))",
        &[message_value(message)],
    )
}

/// A proof that the outbox slot of message `nonce` holds `message_hash` in
/// the state of the block at `height`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotProof {
    /// The message's nonce.
    pub nonce: u64,
    /// The height whose state root the proof leads to.
    pub height: u64,
    /// The message hash the slot holds.
    pub message_hash: Hash,
    /// The sibling hashes, root first (spec 10 §5).
    pub siblings: Vec<Hash>,
}

impl SlotProof {
    /// The slot proof of a state proof of `message_key(nonce)`.
    ///
    /// # Errors
    /// [`Error::NotCommitted`] if `proof` does not end at the leaf of that
    /// key holding `message_hash`.
    pub fn new(
        nonce: u64,
        height: u64,
        message_hash: Hash,
        proof: &Proof,
    ) -> Result<SlotProof, Error> {
        let leaf = Terminal::Leaf {
            path: keccak256(&message_key(nonce)),
            value_hash: keccak256(&message_hash),
        };
        if proof.terminal != leaf {
            return Err(Error::NotCommitted);
        }
        Ok(SlotProof {
            nonce,
            height,
            message_hash,
            siblings: proof.siblings.clone(),
        })
    }

    /// The state root this proof leads to, computed as the inbox computes it.
    #[must_use]
    pub fn root(&self) -> Hash {
        let path = keccak256(&message_key(self.nonce));
        let mut h = leaf_hash(keccak256, &path, &keccak256(&self.message_hash));
        for (i, sibling) in self.siblings.iter().enumerate().rev() {
            h = if bit(&path, i) {
                branch_hash(keccak256, sibling, &h)
            } else {
                branch_hash(keccak256, &h, sibling)
            };
        }
        h
    }

    /// The inbox's `prove(uint64,Message,bytes32[])` calldata for `message`.
    #[must_use]
    pub fn prove_calldata(&self, message: &Message) -> Vec<u8> {
        abi::call(
            "prove(uint64,(uint64,address,address,uint256,bytes),bytes32[])",
            &[
                Value::uint(u128::from(self.height)),
                message_value(message),
                Value::Words(self.siblings.clone()),
            ],
        )
    }
}

/// The messages the outbox logged in `logs` of chain `chain_id`, each with
/// the hash its log states.
#[must_use]
pub fn sent_messages(chain_id: u64, logs: &[Log]) -> Vec<(Message, Hash)> {
    logs.iter()
        .filter(|l| l.address == OUTBOX_ADDRESS)
        .filter_map(|l| Message::from_log(chain_id, &l.topics.0, &l.data))
        .collect()
}

/// The threshold certificate `node` stored for `height` and the proposal it
/// certifies; `None` if it stored none.
///
/// # Errors
/// [`Error::Node`] if the query fails.
pub fn finality_proof(node: &mut Node, height: u64) -> Result<Option<FinalityProof>, Error> {
    let r = node
        .query(query::FINALITY_PROOF, &height.to_bytes())
        .map_err(Error::Node)?;
    Ok((r.status == 0)
        .then(|| solo_abi::Decode::from_bytes(&r.body).ok())
        .flatten())
}

/// The submission with the highest anchor at or after `height` among the
/// certified proposals of `node` whose anchor the node still proves state
/// against: an anchor at or after [`Node::oldest_state`], which is within
/// [`Node::state_history`] blocks of the head and nearer when the blocks of
/// the window wrote more keys than history keeps (spec 20 §5.1). `None` if
/// there is none, as when every certificate anchors a height the node has
/// pruned: the next certificates anchor later heights, so a relayer asks
/// again. [`slot_proof`] against the anchor returned is `None` only while
/// the node has not executed the anchored block.
///
/// # Errors
/// [`Error::Node`] if a query fails.
pub fn submission_covering(node: &mut Node, height: u64) -> Result<Option<Submission>, Error> {
    Ok(covering(node, height, None)?.submission)
}

/// Why [`submission_covering_key`] passed over a stored certificate that
/// it would otherwise have chosen: the light client would revert the call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Skip {
    /// It names another key set, or none (`None`, version 1).
    OtherKeySet(Option<u64>),
    /// It names the light client's key set, but its signature does not
    /// verify under that key set's group key on this chain.
    BadSignature,
}

impl fmt::Display for Skip {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Skip::OtherKeySet(Some(id)) => write!(f, "the certificate names key set {id}"),
            Skip::OtherKeySet(None) => f.write_str("the certificate names no key set"),
            Skip::BadSignature => {
                f.write_str("the certificate does not verify under the key set it names")
            }
        }
    }
}

/// What [`submission_covering_key`] found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Covering {
    /// The submission, if a certificate qualifies.
    pub submission: Option<Submission>,
    /// The certificates passed over, by height, highest first, each with
    /// why: what a relayer logs instead of sending a call that reverts.
    pub skipped: Vec<(u64, Skip)>,
}

/// The key set a version-2 light client holds: what a certificate must
/// verify under for its `submit` to pass (spec 17 §5.3).
struct HeldKey {
    id: u64,
    chain_id: u64,
    key: solo_bls::PublicKey,
}

impl HeldKey {
    /// Whether the light client holding this key set takes `proof`: it
    /// names this key set and its signature verifies under the group key
    /// over `message_v2` of this chain, as the light client checks it.
    fn check(&self, proof: &FinalityProof) -> Result<(), Skip> {
        let certificate = threshold_certificate(&proof.certificate);
        let named = certificate.filter(|c| c.version == 2).map(|c| c.key_id);
        if named != Some(self.id) {
            return Err(Skip::OtherKeySet(named));
        }
        let verifies = certificate
            .and_then(|c| Some((c.message(self.chain_id), signature_point(c.signature).ok()?)))
            .is_some_and(|(message, signature)| self.key.verify(&message, &signature));
        if verifies {
            Ok(())
        } else {
            Err(Skip::BadSignature)
        }
    }
}

/// [`submission_covering`] among the version-2 certificates that a light
/// client holding key set `key_id` takes: each candidate must name that key
/// set and verify under its group key, which the relayer checks off chain
/// against the key set `node`'s chain adopted, so that a mislabelled or
/// badly signed certificate costs no reverted call. The certificates it
/// passes over for that are in [`Covering::skipped`].
///
/// # Errors
/// [`Error::UnknownKeySet`] if the chain holds no such key set,
/// [`Error::Node`] if a query fails.
pub fn submission_covering_key(
    node: &mut Node,
    height: u64,
    key_id: u64,
) -> Result<Covering, Error> {
    let key = node
        .state_get(&[staking_keys::KEY_SET, &key_id.to_be_bytes()].concat())
        .and_then(|bytes| KeySetRecord::from_bytes(&bytes).ok())
        .and_then(|record| {
            let key: [u8; 96] = record.group_key()?.try_into().ok()?;
            solo_bls::PublicKey::from_bytes(&key).ok()
        })
        .ok_or(Error::UnknownKeySet(key_id))?;
    let held = HeldKey {
        id: key_id,
        chain_id: node.chain_id().map_err(Error::Node)?,
        key,
    };
    covering(node, height, Some(&held))
}

fn covering(node: &mut Node, height: u64, held: Option<&HeldKey>) -> Result<Covering, Error> {
    let top = node.finalized_height().map_err(Error::Node)?;
    // An anchor below the oldest state the node keeps cannot be proven
    // against, and a proposal anchors a height below its own (spec 17 §4),
    // so the proposals at or below that floor anchor nothing of use.
    let oldest = height.max(node.oldest_state());
    let mut found = Covering {
        submission: None,
        skipped: Vec::new(),
    };
    for h in (oldest + 1..=top).rev() {
        let candidate = finality_proof(node, h)?.and_then(|p| Some((Submission::new(&p).ok()?, p)));
        let floor = oldest.max(found.submission.as_ref().map_or(0, |b| b.anchor_height + 1));
        let Some((s, proof)) = candidate.filter(|(s, _)| s.anchor_height >= floor) else {
            continue;
        };
        // Checked last, as only a certificate that would be chosen is worth a pairing.
        match held.map_or(Ok(()), |k| k.check(&proof)) {
            Ok(()) => found.submission = Some(s),
            Err(skip) => found.skipped.push((h, skip)),
        }
    }
    Ok(found)
}

/// The proof of message `nonce`'s outbox slot against the state root of
/// `height`; `None` if `node` does not hold that height's state: before
/// [`Node::oldest_state`], which is within [`Node::state_history`] blocks
/// of the head and nearer when the window's blocks wrote more keys than
/// history keeps (spec 20 §5.1), or not executed yet.
///
/// # Errors
/// [`Error::NotCommitted`] if the message is not in that state,
/// [`Error::Node`] if a query fails.
pub fn slot_proof(node: &mut Node, nonce: u64, height: u64) -> Result<Option<SlotProof>, Error> {
    let message_hash = node
        .storage(&OUTBOX_ADDRESS, &message_slot(nonce))
        .map_err(Error::Node)?;
    let Some(proof) = node.state_proof_at(height, &message_key(nonce)) else {
        return Ok(None);
    };
    SlotProof::new(nonce, height, message_hash, &proof).map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_display() {
        for (e, text) in [
            (
                Error::Bls(solo_bls::Error::InvalidPoint),
                "bad certificate or key: InvalidPoint",
            ),
            (
                Error::ProposalMismatch,
                "the proposal is not the one the certificate names",
            ),
            (Error::NoAnchor, "the proposal carries no anchor"),
            (
                Error::NotCommitted,
                "the message is not committed at that height",
            ),
            (Error::UnknownKeySet(7), "the chain holds no key set 7"),
            (
                Error::Node(NodeError::Decode("x")),
                "node: x returned an undecodable result",
            ),
        ] {
            assert_eq!(e.to_string(), text);
        }
    }

    #[test]
    fn group_keys_decode_or_fail() {
        assert!(matches!(
            group_key(&[0; 95]),
            Err(Error::Bls(solo_bls::Error::InvalidLength))
        ));
        assert!(matches!(group_key(&[0; 96]), Err(Error::Bls(_))));
        let key = solo_bls::SecretKey::generate(&[1; 32], b"")
            .unwrap()
            .public_key();
        assert_eq!(
            group_key(&key.to_bytes()).unwrap(),
            solo_bls::evm::encode_g2(key.point())
        );
    }

    #[test]
    fn submissions_check_the_proposal_and_its_anchor() {
        let sk = solo_bls::SecretKey::generate(&[2; 32], b"").unwrap();
        let mut proposal = vec![0u8; 120];
        proposal[8..16].copy_from_slice(&9u64.to_le_bytes());
        let certify = |proposal: &[u8], height: u64| {
            let hash = keccak256(proposal);
            let signature = sk.sign(&solo_bls::certificate::message(1, height, &hash));
            let certificate = solo_bls::Certificate {
                height,
                block_hash: hash,
                signature,
            };
            FinalityProof {
                certificate: certificate.to_bytes().to_vec(),
                proposal: proposal.to_vec(),
            }
        };
        assert!(matches!(
            Submission::new(&certify(&proposal, 9)),
            Err(Error::NoAnchor)
        ));
        assert!(matches!(
            Submission::new(&certify(&proposal, 8)),
            Err(Error::ProposalMismatch)
        ));
        let mut wrong = certify(&proposal, 9);
        wrong.proposal[100] = 1;
        assert!(matches!(
            Submission::new(&wrong),
            Err(Error::ProposalMismatch)
        ));
        assert!(matches!(
            Submission::new(&FinalityProof {
                certificate: vec![2],
                proposal
            }),
            Err(Error::Bls(_))
        ));
    }

    /// A version-2 certificate of height 9, anchoring 8, labelled key set
    /// `labelled` and signed by `sk` as key set `signed` on chain 1.
    fn signed_v2(sk: &solo_bls::SecretKey, signed: u64, labelled: u64) -> FinalityProof {
        let mut proposal = vec![0u8; 120];
        proposal[8..16].copy_from_slice(&9u64.to_le_bytes());
        proposal[56..64].copy_from_slice(&8u64.to_le_bytes());
        let hash = keccak256(&proposal);
        let certificate = solo_bls::certificate::CertificateV2 {
            key_id: labelled,
            height: 9,
            block_hash: hash,
            signature: sk.sign(&solo_bls::certificate::message_v2(1, signed, 9, &hash)),
        };
        FinalityProof {
            certificate: certificate.to_bytes().to_vec(),
            proposal,
        }
    }

    #[test]
    fn relayers_check_certificates_against_the_held_key_set() {
        let sk = solo_bls::SecretKey::generate(&[3; 32], b"").unwrap();
        let proof = signed_v2(&sk, 4, 4);
        // A light client holding key set 4 takes it; one holding another key
        // set, or the same id under another key or chain, would revert.
        let held = |id: u64, chain_id: u64, key: solo_bls::PublicKey| HeldKey { id, chain_id, key };
        assert_eq!(held(4, 1, sk.public_key()).check(&proof), Ok(()));
        assert_eq!(
            held(5, 1, sk.public_key()).check(&proof),
            Err(Skip::OtherKeySet(Some(4)))
        );
        let other = solo_bls::SecretKey::generate(&[5; 32], b"").unwrap();
        assert_eq!(
            held(4, 1, other.public_key()).check(&proof),
            Err(Skip::BadSignature)
        );
        assert_eq!(
            held(4, 2, sk.public_key()).check(&proof),
            Err(Skip::BadSignature)
        );
        // Signed as key set 5 but labelled 4: mislabelled, refused.
        assert_eq!(
            held(4, 1, sk.public_key()).check(&signed_v2(&sk, 5, 4)),
            Err(Skip::BadSignature)
        );
        let hash = keccak256(&proof.proposal);
        let v1 = solo_bls::Certificate {
            height: 9,
            block_hash: hash,
            signature: sk.sign(&solo_bls::certificate::message(1, 9, &hash)),
        };
        let v1 = FinalityProof {
            certificate: v1.to_bytes().to_vec(),
            proposal: proof.proposal.clone(),
        };
        assert_eq!(
            held(4, 1, sk.public_key()).check(&v1),
            Err(Skip::OtherKeySet(None))
        );
        for (skip, text) in [
            (
                Skip::OtherKeySet(Some(3)),
                "the certificate names key set 3",
            ),
            (Skip::OtherKeySet(None), "the certificate names no key set"),
            (
                Skip::BadSignature,
                "the certificate does not verify under the key set it names",
            ),
        ] {
            assert_eq!(skip.to_string(), text);
        }
    }

    #[test]
    fn version_two_submissions_and_rotations() {
        let sk = solo_bls::SecretKey::generate(&[3; 32], b"").unwrap();
        let proof = signed_v2(&sk, 4, 4);
        let s = Submission::new(&proof).unwrap();
        assert_eq!((s.key_id, s.height, s.anchor_height), (Some(4), 9, 8));
        let mut bad = proof.clone();
        bad.certificate[49..].fill(0xFF);
        assert!(matches!(
            Submission::new(&bad),
            Err(Error::Bls(solo_bls::Error::InvalidPoint))
        ));
        let next = solo_bls::SecretKey::generate(&[4; 32], b"")
            .unwrap()
            .public_key();
        let handoff = Handoff {
            from: 4,
            to: 5,
            key: next.to_bytes().to_vec(),
            signature: sk
                .sign(&solo_bls::certificate::rotation_message(1, 5, &next))
                .to_bytes()
                .to_vec(),
            height: 30,
        };
        let r = Rotation::new(&handoff).unwrap();
        assert_eq!((r.from, r.to, r.height), (4, 5, 30));
        assert_eq!(r.key_eip2537, solo_bls::evm::encode_g2(next.point()));
        assert_eq!(
            &r.calldata()[..4],
            &keccak256(b"rotate(uint64,bytes,bytes)")[..4]
        );
        let short = Handoff {
            signature: vec![1; 47],
            ..handoff.clone()
        };
        assert!(matches!(
            Rotation::new(&short),
            Err(Error::Bls(solo_bls::Error::InvalidLength))
        ));
        let bad_key = Handoff {
            key: vec![0; 96],
            ..handoff
        };
        assert!(matches!(Rotation::new(&bad_key), Err(Error::Bls(_))));
        assert_eq!(verifier_v2_args(7), abi::encode(&[Value::uint(7)]));
        assert_eq!(
            light_client_v2_args(&[1; 20], 2, &[3; 256], 16, 2).len(),
            32 * 5 + 32 + 256
        );
    }

    #[test]
    fn slot_proofs_need_the_message_leaf() {
        let mut trie = solo_trie::Trie::new();
        trie.insert(&message_key(1), &[7; 32]);
        trie.insert(b"other", b"x");
        let proof = trie.prove(&message_key(1));
        let slot = SlotProof::new(1, 5, [7; 32], &proof).unwrap();
        assert_eq!(slot.root(), trie.root());
        assert!(matches!(
            SlotProof::new(1, 5, [8; 32], &proof),
            Err(Error::NotCommitted)
        ));
        assert!(matches!(
            SlotProof::new(2, 5, [7; 32], &trie.prove(&message_key(2))),
            Err(Error::NotCommitted)
        ));
    }
}
