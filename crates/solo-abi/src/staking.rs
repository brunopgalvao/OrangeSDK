//! Records of the reference kernel's validator lifecycle (spec 15): staking
//! through the staking address, epochs, slashing, the threshold key that the
//! validators of each epoch generate afresh, and the keystore requests a
//! driver makes of its host for the secret halves of that key (spec 05 §4.3).

use alloc::vec::Vec;

use crate::chain::{Signature, ValidatorSet};
use crate::codec::{Decode, DecodeError, Decoder, Encode, Encoder, Seq};
use crate::types::{Address, Hash};

macro_rules! record {
    ($(#[$meta:meta])* $name:ident { $($(#[$fmeta:meta])* $field:ident : $ty:ty),* $(,)? }) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, Default)]
        pub struct $name {
            $($(#[$fmeta])* pub $field: $ty,)*
        }
        impl Encode for $name {
            fn encode(&self, e: &mut Encoder) {
                $(self.$field.encode(e);)*
            }
        }
        impl Decode for $name {
            fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
                Ok($name { $($field: d.get()?,)* })
            }
        }
    };
}

/// The staking address, `0x0000000000000000000000000000000000005354`. A
/// transaction to it carries a staking action (spec 15 §3).
pub const STAKING_ADDRESS: Address = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x53, 0x54,
];

/// One gwei in wei. Stake moves in whole gwei, and a validator's weight is
/// its stake in gwei.
pub const GWEI: u128 = 1_000_000_000;

/// The fraction of an offender's stake that slashing burns, in basis points.
pub const SLASH_BPS: u128 = 1_000;

/// Most validators registered at once; genesis validators count, and records
/// that hold nothing are pruned at epoch ends.
pub const MAX_REGISTERED: usize = 256;

/// Most delegators one validator has at once (spec 15 §10.1), so that the
/// work of an epoch end, which pays every one of them, stays bounded.
pub const MAX_DELEGATORS: usize = 64;

/// Most validators one account delegates to at once, so that `withdraw`
/// looks at a bounded number of delegations.
pub const MAX_DELEGATIONS: usize = 16;

/// Most DKG envelopes one proposal carries; a proposal with more gets no votes.
pub const MAX_DKG: usize = 16;

/// Signing domain of a DKG envelope, beside the consensus kinds 0–2 (spec 08 §4).
pub const KIND_DKG: u8 = 3;

/// Key role of the host's threshold keystore (`sign`, spec 05 §4.3).
pub const KEY_ROLE_THRESHOLD: u64 = 2;

/// Length of a compressed G1 point: an encryption key or a signature.
pub const G1_LENGTH: usize = 48;

/// Length of a compressed G2 point: a public key share or a commitment.
pub const G2_LENGTH: usize = 96;

/// Envelope kinds (spec 15 §6.2).
pub mod envelope {
    /// The body is a DKG message of spec 12 §5.
    pub const MESSAGE: u8 = 0;
    /// The body is a [`KeySetVote`](super::KeySetVote).
    pub const CONFIRM: u8 = 1;
    /// The body is a [`RotationShare`](crate::rotation::RotationShare):
    /// gossip only, never carried in a proposal.
    pub const ROTATION_SHARE: u8 = 2;
    /// The body is a [`RotationCertificate`](crate::rotation::RotationCertificate).
    pub const HANDOFF: u8 = 3;
    /// The body is a [`ThresholdEvidence`](crate::rotation::ThresholdEvidence).
    pub const EVIDENCE: u8 = 4;
}

/// Query method names (spec 15 §8).
pub mod query {
    /// `() -> StakingStatus`.
    pub const STAKING: &str = "staking";
    /// `(u64 epoch) -> ValidatorSet` the validator set of an epoch, if decided.
    pub const STAKING_SET: &str = "staking_set";
    /// `(Address) -> vec<DelegationEntry>` the delegations of an account,
    /// in the order they were made.
    pub const DELEGATIONS: &str = "staking_delegations";
}

/// Function selectors of the staking interface: the first four bytes of
/// `keccak256` of each signature.
pub mod selector {
    /// `register(bytes)`.
    pub const REGISTER: [u8; 4] = [0x82, 0xfb, 0xdc, 0x9c];
    /// `bond()`.
    pub const BOND: [u8; 4] = [0x64, 0xc9, 0xec, 0x6f];
    /// `unbond(uint256)`.
    pub const UNBOND: [u8; 4] = [0x27, 0xde, 0x9e, 0x32];
    /// `withdraw()`.
    pub const WITHDRAW: [u8; 4] = [0x3c, 0xcf, 0xd6, 0x0b];
    /// `report(bytes)`.
    pub const REPORT: [u8; 4] = [0xb5, 0x76, 0x71, 0x66];
    /// `delegate(address)`.
    pub const DELEGATE: [u8; 4] = [0x5c, 0x19, 0xa9, 0x5c];
    /// `undelegate(address,uint256)`.
    pub const UNDELEGATE: [u8; 4] = [0x4d, 0x99, 0xdd, 0x16];
}

/// Event topics of the staking interface: `keccak256` of each event signature.
pub mod event {
    use crate::types::Hash;

    /// `Registered(address,bytes32)`.
    pub const REGISTERED: Hash = [
        0xb8, 0x14, 0x2d, 0x42, 0xf0, 0x5d, 0x95, 0xab, 0xf0, 0xa6, 0x57, 0x07, 0x99, 0x77, 0x4d,
        0x59, 0x27, 0x6e, 0x49, 0xea, 0x32, 0xa0, 0x4d, 0x9a, 0x4e, 0xc3, 0x16, 0xea, 0x4a, 0x68,
        0x86, 0xbc,
    ];
    /// `Bonded(address,uint256)`.
    pub const BONDED: Hash = [
        0xd0, 0xa0, 0x09, 0x03, 0x4e, 0x24, 0xa3, 0x91, 0x06, 0x65, 0x3c, 0x49, 0x03, 0xcf, 0x28,
        0xb1, 0x94, 0x7b, 0x8a, 0x99, 0x64, 0xd0, 0x32, 0x06, 0x64, 0x8e, 0x0f, 0x0a, 0x5d, 0xe7,
        0x4a, 0x46,
    ];
    /// `Unbonded(address,uint256,uint64)`.
    pub const UNBONDED: Hash = [
        0xf0, 0x0b, 0xd8, 0xf1, 0xdc, 0xf6, 0x6a, 0x1f, 0xe9, 0x6c, 0xe2, 0x5a, 0xa6, 0x3d, 0xe9,
        0x1c, 0x4b, 0x8f, 0xe4, 0xf4, 0x07, 0xe9, 0xf0, 0xc0, 0x27, 0xd9, 0x28, 0xe6, 0xc5, 0xdb,
        0x79, 0xf9,
    ];
    /// `Withdrawn(address,uint256)`.
    pub const WITHDRAWN: Hash = [
        0x70, 0x84, 0xf5, 0x47, 0x66, 0x18, 0xd8, 0xe6, 0x0b, 0x11, 0xef, 0x0d, 0x7d, 0x3f, 0x06,
        0x91, 0x46, 0x55, 0xad, 0xb8, 0x79, 0x3e, 0x28, 0xff, 0x7f, 0x01, 0x8d, 0x4c, 0x76, 0xd5,
        0x05, 0xd5,
    ];
    /// `Reported(address,uint8,uint64)`.
    pub const REPORTED: Hash = [
        0x6c, 0x00, 0x70, 0xf6, 0x7c, 0xd1, 0x94, 0x46, 0xdb, 0xdc, 0x0b, 0x7a, 0x4a, 0xeb, 0xa0,
        0x70, 0xd5, 0xa9, 0x8e, 0x17, 0xee, 0xbc, 0x23, 0x15, 0x8c, 0xbf, 0xd8, 0xa9, 0xfb, 0x98,
        0x1c, 0xfe,
    ];
    /// `Delegated(address,address,uint256)`: delegator, validator, amount.
    pub const DELEGATED: Hash = [
        0xe5, 0x54, 0x1a, 0x6b, 0x61, 0x03, 0xd4, 0xfa, 0x7e, 0x02, 0x1e, 0xd5, 0x4f, 0xad, 0x39,
        0xc6, 0x6f, 0x27, 0xa7, 0x6b, 0xd1, 0x3d, 0x37, 0x4c, 0xf6, 0x24, 0x0a, 0xe6, 0xbd, 0x0b,
        0xb7, 0x2b,
    ];
    /// `Undelegated(address,address,uint256,uint64)`: delegator, validator,
    /// amount, release epoch.
    pub const UNDELEGATED: Hash = [
        0xa4, 0x10, 0xe3, 0x21, 0x57, 0xa4, 0x44, 0x14, 0xa5, 0x02, 0xbb, 0x47, 0xd7, 0x75, 0x23,
        0x4d, 0xe1, 0xaa, 0x7d, 0xa1, 0x23, 0xf5, 0xad, 0xfe, 0x42, 0x68, 0x98, 0xf1, 0x60, 0x18,
        0x83, 0xfd,
    ];
}

/// The tag every threshold signature is hashed under (spec 12 §3, `DST_SIG`).
pub const DST_SIGNATURE: &[u8] = b"SOLO-V01-CS01-with-BLS12381G1_XMD:SHA-256_SSWU_RO_";

/// Length of a version-1 threshold certificate (spec 12 §7).
pub const CERTIFICATE_LENGTH: usize = 89;

/// The 62 bytes a version-1 certificate signs (spec 12 §7).
#[must_use]
pub fn certificate_message(chain_id: u64, height: u64, block_hash: &Hash) -> Vec<u8> {
    let mut out = b"SOLO-FINALITY".to_vec();
    out.push(1);
    out.extend_from_slice(&chain_id.to_be_bytes());
    out.extend_from_slice(&height.to_be_bytes());
    out.extend_from_slice(block_hash);
    out
}

/// A version-1 certificate: version, height, block hash, signature.
#[must_use]
pub fn certificate_bytes(height: u64, block_hash: &Hash, signature: &[u8]) -> Vec<u8> {
    let mut out = alloc::vec![1u8];
    out.extend_from_slice(&height.to_be_bytes());
    out.extend_from_slice(block_hash);
    out.extend_from_slice(signature);
    out
}

/// The height, block hash and signature of a version-1 certificate; `None`
/// for another version or length.
///
/// # Panics
/// Never: the length is checked first.
#[must_use]
pub fn certificate_parts(bytes: &[u8]) -> Option<(u64, Hash, &[u8])> {
    if bytes.len() != CERTIFICATE_LENGTH || bytes[0] != 1 {
        return None;
    }
    let height = u64::from_be_bytes(bytes[1..9].try_into().expect("8 bytes"));
    let hash: Hash = bytes[9..41].try_into().expect("32 bytes");
    Some((height, hash, &bytes[41..]))
}

/// Storage key prefixes of staking and the threshold key (spec 15 §7).
pub mod keys {
    /// `stake/v/` + id → `StakeRecord`.
    pub const RECORD: &[u8] = b"stake/v/";
    /// `stake/a/` + address → id.
    pub const BY_ADDRESS: &[u8] = b"stake/a/";
    /// `stake/ids` → `vec<Hash>`, registered ids in registration order.
    pub const IDS: &[u8] = b"stake/ids";
    /// `stake/set/` + epoch (big-endian u64) → `ValidatorSet`.
    pub const SET: &[u8] = b"stake/set/";
    /// `dkg/run/` + epoch → `DkgRun`.
    pub const RUN: &[u8] = b"dkg/run/";
    /// `dkg/msg/` + epoch ‖ phase ‖ sender index (big-endian u32) → DKG message.
    pub const MESSAGE: &[u8] = b"dkg/msg/";
    /// `dkg/vote/` + epoch ‖ id → hash of the `KeySetVote` the validator confirmed.
    pub const VOTE: &[u8] = b"dkg/vote/";
    /// `dkg/tally/` + epoch ‖ vote hash → u128 weight behind it.
    pub const TALLY: &[u8] = b"dkg/tally/";
    /// `dkg/keyset/` + id (big-endian u64) → `KeySetRecord`.
    pub const KEY_SET: &[u8] = b"dkg/keyset/";
    /// `dkg/active` → u64, the id of the key set validators sign with.
    pub const ACTIVE: &[u8] = b"dkg/active";
    /// `dkg/group_key` → the 96-byte group public key of the active key set.
    pub const GROUP_KEY: &[u8] = b"dkg/group_key";
    /// `stake/d/` + validator id ‖ delegator address → `Delegation` (spec 15 §10.1).
    pub const DELEGATION: &[u8] = b"stake/d/";
    /// `stake/dl/` + validator id → `vec<Address>`, the validator's
    /// delegators in the order they first delegated.
    pub const DELEGATORS: &[u8] = b"stake/dl/";
    /// `stake/dv/` + delegator address → `vec<Hash>`, the validators the
    /// account delegates to, in the order it first did.
    pub const DELEGATED_TO: &[u8] = b"stake/dv/";
    /// `stake/pool` → `u128`, the priority fees collected since the last
    /// epoch end, held by the staking address (spec 15 §10.2).
    pub const POOL: &[u8] = b"stake/pool";
}

record! {
    /// Genesis parameters of staking (spec 15 §2), `GenesisParams::staking`.
    StakingParams {
        /// Blocks per epoch; zero disables staking, epochs and threshold keys,
        /// and the genesis validator set stays fixed.
        epoch_blocks: u64,
        /// Whole epochs unbonded stake waits, after the epoch it was unbonded
        /// in, before it can be withdrawn.
        unbonding_epochs: u64,
        /// Least stake, in wei, that a validator needs to be selected.
        min_stake: u128,
        /// Most validators in a set; zero means no limit.
        max_validators: u32,
        /// Blocks per DKG phase; zero disables threshold keys. Four phases
        /// must fit an epoch.
        dkg_phase_blocks: u64,
        /// Most epochs past its own that a key set is trusted by light
        /// clients (spec 15 §6.7); at least 1 with threshold keys, and
        /// `unbonding_epochs` must exceed it plus the handoff latency.
        max_key_age: u64,
        /// DKG encryption keys of genesis validators, by validator id.
        keys: Seq<ValidatorKey>,
    }
}

record! {
    /// A genesis validator's DKG encryption key.
    ValidatorKey {
        /// Validator id.
        id: Hash,
        /// Compressed G1 encryption key (48 bytes).
        dkg_key: Vec<u8>,
    }
}

record! {
    /// A registered validator's stake.
    StakeRecord {
        /// The account that controls it: the consensus key's address.
        address: Address,
        /// Bonded stake in wei.
        stake: u128,
        /// Unbonded stake in wei still waiting to be withdrawn.
        unbonding: u128,
        /// The epoch from which `unbonding` can be withdrawn.
        release_epoch: u64,
        /// Compressed G1 DKG encryption key, or empty for none.
        dkg_key: Vec<u8>,
        /// Slashed: never selected again, never slashed again.
        jailed: bool,
        /// Stake delegated to it, in wei: the sum of its delegations' bonded
        /// stake (spec 15 §10.1). It counts in its total stake, not in the
        /// self-bond the minimum stake asks for.
        delegated: u128,
    }
}

record! {
    /// One account's stake behind one validator (spec 15 §10.1).
    Delegation {
        /// Bonded stake in wei.
        stake: u128,
        /// Undelegated stake in wei still waiting to be withdrawn.
        unbonding: u128,
        /// The epoch from which `unbonding` can be withdrawn.
        release_epoch: u64,
    }
}

record! {
    /// A delegation with the validator it is behind, as the `staking_delegations`
    /// query lists them.
    DelegationEntry {
        /// Validator id.
        validator: Hash,
        /// The delegation.
        delegation: Delegation,
    }
}

record! {
    /// A validator id with its record, as the `staking` query lists them.
    StakeEntry {
        /// Validator id.
        id: Hash,
        /// Its record.
        record: StakeRecord,
    }
}

record! {
    /// One epoch's DKG run (spec 15 §6.1): a fresh key (the reference
    /// kernel's only kind since key rotation), or a resharing of
    /// the active one.
    DkgRun {
        /// The epoch it runs in; also the id of the key set it makes.
        epoch: u64,
        /// The session of spec 12 §5.
        session: Hash,
        /// Threshold of the key it makes.
        threshold: u32,
        /// Dealer `i` is `dealers[i − 1]`.
        dealers: Seq<Hash>,
        /// Recipient `j` is `recipients[j − 1]`.
        recipients: Seq<Hash>,
        /// Recipient `j`'s encryption key is `keys[j − 1]`.
        keys: Seq<Vec<u8>>,
        /// The key set being reshared, by id; `None` for a fresh key, as
        /// in every run the reference kernel schedules.
        previous: Option<u64>,
    }
}

record! {
    /// An adopted threshold key set.
    KeySetRecord {
        /// The epoch whose run made it.
        id: u64,
        /// The public key set of spec 12 §4: `threshold` compressed G2 points.
        key_set: Vec<u8>,
        /// Public key share of shareholder `j` at `j − 1`, compressed G2.
        public_shares: Seq<Vec<u8>>,
        /// Shareholder `j` is `shareholders[j − 1]`.
        shareholders: Seq<Hash>,
    }
}

impl KeySetRecord {
    /// The threshold: the number of points in the key set.
    #[must_use]
    pub fn threshold(&self) -> usize {
        self.key_set.len() / G2_LENGTH
    }

    /// The group public key, the key set's first point.
    #[must_use]
    pub fn group_key(&self) -> Option<&[u8]> {
        self.key_set.get(..G2_LENGTH)
    }
}

record! {
    /// What a validator confirms at the end of a run: the public outcome it
    /// computed (spec 15 §6.3).
    KeySetVote {
        /// The public key set.
        key_set: Vec<u8>,
        /// Every recipient's public key share, in recipient order.
        public_shares: Seq<Vec<u8>>,
    }
}

record! {
    /// A DKG message or a key-set confirmation, signed by its sender's
    /// consensus key (spec 15 §6.2).
    DkgEnvelope {
        /// The epoch of the run.
        epoch: u64,
        /// [`envelope`] kind.
        kind: u8,
        /// The DKG message or the encoded `KeySetVote`.
        body: Vec<u8>,
        /// Recoverable signature over [`DkgEnvelope::signed_hash_preimage`].
        signature: Signature,
    }
}

impl DkgEnvelope {
    /// The bytes whose `keccak256` the signature's consensus message names:
    /// the kind followed by the body.
    #[must_use]
    pub fn signed_hash_preimage(kind: u8, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + body.len());
        out.push(kind);
        out.extend_from_slice(body);
        out
    }
}

record! {
    /// A threshold partial signature carried by a finalize vote (spec 08 §4).
    PartialShare {
        /// Id of the key set the share belongs to.
        key_set: u64,
        /// Shareholder index, from 1.
        index: u32,
        /// Compressed G1 partial signature (48 bytes).
        signature: Vec<u8>,
    }
}

record! {
    /// `query::STAKING` result.
    StakingStatus {
        /// Epoch of the next block.
        epoch: u64,
        /// Genesis staking parameters, without the genesis keys.
        params: StakingParams,
        /// The current validator set.
        validators: ValidatorSet,
        /// Every registered validator, in registration order.
        records: Seq<StakeEntry>,
        /// The active key set, if any.
        active: Option<KeySetRecord>,
        /// The group public key, or empty before the first key set.
        group_key: Vec<u8>,
        /// The reward pool: priority fees collected since the last epoch
        /// end, in wei (spec 15 §10.2).
        pool: u128,
    }
}

/// The epoch of block `height` with `epoch_blocks` blocks per epoch: epoch
/// `e` holds the heights `e·L + 1` to `(e + 1)·L`.
#[must_use]
pub const fn epoch_of(height: u64, epoch_blocks: u64) -> u64 {
    height.saturating_sub(1) / epoch_blocks
}

/// The first height of epoch `epoch`.
#[must_use]
pub const fn epoch_start(epoch: u64, epoch_blocks: u64) -> u64 {
    epoch * epoch_blocks + 1
}

/// The last height of epoch `epoch`.
#[must_use]
pub const fn epoch_end(epoch: u64, epoch_blocks: u64) -> u64 {
    (epoch + 1) * epoch_blocks
}

/// The epoch a consensus view belongs to: its high 32 bits (spec 08 §3).
#[must_use]
pub const fn view_epoch(view: u64) -> u64 {
    view >> 32
}

/// The first view of epoch `epoch`.
#[must_use]
pub const fn first_view(epoch: u64) -> u64 {
    (epoch << 32) + 1
}

/// The threshold of a key with `n` shareholders: more than two thirds.
#[must_use]
pub const fn dkg_threshold(n: usize) -> usize {
    n * 2 / 3 + 1
}

/// The bytes whose `keccak256` is the session of epoch `epoch`'s run.
#[must_use]
pub fn session_preimage(chain_id: u64, epoch: u64) -> Vec<u8> {
    let mut out = b"SOLO-DKG-SESSION".to_vec();
    out.extend_from_slice(&chain_id.to_be_bytes());
    out.extend_from_slice(&epoch.to_be_bytes());
    out
}

/// The phase (its tag), session and sender index (dealer or accuser) that
/// open every DKG message of spec 12 §5, without decoding the rest.
#[must_use]
pub fn dkg_header(message: &[u8]) -> Option<(u8, Hash, u32)> {
    let phase = *message.first()?;
    let session: Hash = message.get(1..33)?.try_into().ok()?;
    let index = u32::from_le_bytes(message.get(33..37)?.try_into().ok()?);
    (phase <= 2).then_some((phase, session, index))
}

/// A staking action (spec 15 §3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StakingAction {
    /// Registers the sender's consensus key as a validator, bonding the
    /// transaction's value (at least the minimum stake), or replaces its
    /// DKG encryption key.
    Register {
        /// Compressed G1 encryption key, 48 bytes.
        dkg_key: Vec<u8>,
    },
    /// Adds the transaction's value to the sender's stake.
    Bond,
    /// Moves `amount` wei of stake to unbonding.
    Unbond {
        /// Wei.
        amount: u128,
    },
    /// Pays out released unbonded stake.
    Withdraw,
    /// Reports threshold misbehaviour: an encoded
    /// [`ThresholdEvidence`](crate::rotation::ThresholdEvidence).
    Report {
        /// The encoded evidence.
        evidence: Vec<u8>,
    },
    /// Puts the transaction's value behind the validator whose account
    /// this is (spec 15 §10.1).
    Delegate {
        /// The validator's account.
        validator: Address,
    },
    /// Moves `amount` wei of the sender's delegation to unbonding.
    Undelegate {
        /// The validator's account.
        validator: Address,
        /// Wei.
        amount: u128,
    },
}

/// The canonical ABI encoding of one `bytes` argument of at most
/// [`MAX_REPORT`](crate::rotation::MAX_REPORT) bytes: offset word 32, length
/// word, the bytes, zero padding to a whole word, and nothing after.
fn decode_bytes(body: &[u8]) -> Option<Vec<u8>> {
    let (head, rest) = body.split_at_checked(64)?;
    let length = u128::from_be_bytes(head[48..].try_into().ok()?);
    let n = usize::try_from(length)
        .ok()
        .filter(|n| *n <= crate::rotation::MAX_REPORT)?;
    let canonical = head[..32] == word(32)
        && head[32..48].iter().all(|b| *b == 0)
        && rest.len() == n.next_multiple_of(32)
        && rest[n..].iter().all(|b| *b == 0);
    canonical.then(|| rest[..n].to_vec())
}

/// A 32-byte big-endian ABI word holding `value`.
#[must_use]
pub fn word(value: u128) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[16..].copy_from_slice(&value.to_be_bytes());
    w
}

/// The word holding `address`.
#[must_use]
pub fn address_word(address: &Address) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(address);
    w
}

/// The address an ABI word holds, if its high 12 bytes are zero.
fn address_of(w: &[u8]) -> Option<Address> {
    w[..12]
        .iter()
        .all(|b| *b == 0)
        .then(|| w[12..32].try_into().expect("20 bytes"))
}

/// The `u128` an ABI word holds, if its high 16 bytes are zero.
fn u128_of(w: &[u8]) -> Option<u128> {
    w[..16]
        .iter()
        .all(|b| *b == 0)
        .then(|| u128::from_be_bytes(w[16..32].try_into().expect("16 bytes")))
}

impl StakingAction {
    /// The calldata of this action: the Solidity ABI encoding of the call.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            StakingAction::Register { dkg_key } => {
                out.extend_from_slice(&selector::REGISTER);
                out.extend_from_slice(&word(32));
                out.extend_from_slice(&word(dkg_key.len() as u128));
                out.extend_from_slice(dkg_key);
                out.resize(
                    out.len() + dkg_key.len().next_multiple_of(32) - dkg_key.len(),
                    0,
                );
            }
            StakingAction::Bond => out.extend_from_slice(&selector::BOND),
            StakingAction::Unbond { amount } => {
                out.extend_from_slice(&selector::UNBOND);
                out.extend_from_slice(&word(*amount));
            }
            StakingAction::Withdraw => out.extend_from_slice(&selector::WITHDRAW),
            StakingAction::Report { evidence } => {
                out.extend_from_slice(&selector::REPORT);
                out.extend_from_slice(&word(32));
                out.extend_from_slice(&word(evidence.len() as u128));
                out.extend_from_slice(evidence);
                out.resize(
                    out.len() + evidence.len().next_multiple_of(32) - evidence.len(),
                    0,
                );
            }
            StakingAction::Delegate { validator } => {
                out.extend_from_slice(&selector::DELEGATE);
                out.extend_from_slice(&address_word(validator));
            }
            StakingAction::Undelegate { validator, amount } => {
                out.extend_from_slice(&selector::UNDELEGATE);
                out.extend_from_slice(&address_word(validator));
                out.extend_from_slice(&word(*amount));
            }
        }
        out
    }

    /// Decodes calldata that is exactly the canonical encoding of an action:
    /// `register` with a 48-byte key, `unbond` and `undelegate` with an
    /// amount below 2^128, addresses with zero high bytes.
    ///
    /// # Panics
    /// Never: every slice is taken after its length is checked.
    #[must_use]
    pub fn decode(data: &[u8]) -> Option<StakingAction> {
        let (sel, body) = data.split_at_checked(4)?;
        match <[u8; 4]>::try_from(sel).ok()? {
            selector::REGISTER if body.len() == 128 => {
                let header_ok = body[..32] == word(32) && body[32..64] == word(G1_LENGTH as u128);
                let padding_ok = body[112..].iter().all(|b| *b == 0);
                (header_ok && padding_ok).then(|| StakingAction::Register {
                    dkg_key: body[64..112].to_vec(),
                })
            }
            selector::BOND if body.is_empty() => Some(StakingAction::Bond),
            selector::UNBOND if body.len() == 32 => Some(StakingAction::Unbond {
                amount: u128_of(body)?,
            }),
            selector::DELEGATE if body.len() == 32 => Some(StakingAction::Delegate {
                validator: address_of(body)?,
            }),
            selector::UNDELEGATE if body.len() == 64 => Some(StakingAction::Undelegate {
                validator: address_of(&body[..32])?,
                amount: u128_of(&body[32..])?,
            }),
            selector::WITHDRAW if body.is_empty() => Some(StakingAction::Withdraw),
            selector::REPORT => {
                decode_bytes(body).map(|evidence| StakingAction::Report { evidence })
            }
            _ => None,
        }
    }
}

record! {
    /// One DKG step the keystore runs for this node (spec 05 §4.3): the run's
    /// public parameters, this node's roles, and the messages recorded on
    /// chain so far.
    DkgRequest {
        /// Id under which a finished run installs this node's share.
        key_set: u64,
        /// Session.
        session: Hash,
        /// Threshold of the new key.
        threshold: u32,
        /// Number of dealers.
        dealers: u32,
        /// Recipients' encryption keys, in recipient order.
        recipients: Seq<Vec<u8>>,
        /// The public key set being reshared; empty for a fresh key.
        previous: Vec<u8>,
        /// Id of this dealer's current share, for a resharing.
        previous_id: u64,
        /// This node's dealer index, or zero.
        dealer: u32,
        /// This node's recipient index, or zero.
        recipient: u32,
        /// DKG messages recorded on chain, in phase order.
        transcript: Seq<Vec<u8>>,
        /// How many phases have ended: 0 asks for the dealing, 1 for
        /// complaints, 2 for a justification, 3 for the outcome.
        upto: u8,
    }
}

/// A request of the threshold keystore, key role 2 (spec 05 §4.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeystoreRequest {
    /// This node's DKG encryption key (48 bytes).
    EncryptionKey,
    /// Runs the DKG for this node up to a phase boundary; answers a `DkgReply`.
    Dkg(DkgRequest),
    /// A partial signature (48 bytes) with the share of a key set.
    Sign {
        /// Key set id.
        key_set: u64,
        /// The message.
        message: Vec<u8>,
    },
    /// Combines partial signatures into a group signature (48 bytes) that
    /// verifies under the key set's group key. Uses no key.
    Combine {
        /// The public key set.
        key_set: Vec<u8>,
        /// The message.
        message: Vec<u8>,
        /// Partial signatures with their shareholder indices.
        partials: Seq<PartialShare>,
    },
}

impl Encode for KeystoreRequest {
    fn encode(&self, e: &mut Encoder) {
        match self {
            KeystoreRequest::EncryptionKey => {
                e.raw(&[0]);
            }
            KeystoreRequest::Dkg(request) => {
                e.raw(&[1]);
                e.put(request);
            }
            KeystoreRequest::Sign { key_set, message } => {
                e.raw(&[2]);
                e.put(key_set).put(message);
            }
            KeystoreRequest::Combine {
                key_set,
                message,
                partials,
            } => {
                e.raw(&[3]);
                e.put(key_set).put(message).put(partials);
            }
        }
    }
}

impl Decode for KeystoreRequest {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(match d.raw(1)?[0] {
            0 => KeystoreRequest::EncryptionKey,
            1 => KeystoreRequest::Dkg(d.get()?),
            2 => KeystoreRequest::Sign {
                key_set: d.get()?,
                message: d.get()?,
            },
            3 => KeystoreRequest::Combine {
                key_set: d.get()?,
                message: d.get()?,
                partials: d.get()?,
            },
            tag => return Err(DecodeError::BadTag(tag)),
        })
    }
}

/// The keystore's answer to a [`KeystoreRequest::Dkg`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DkgReply {
    /// Nothing for this node to send at this boundary.
    Idle,
    /// A DKG message for this node to broadcast.
    Message(Vec<u8>),
    /// The run is over: its public outcome. The node's share, if it has one,
    /// is installed under the request's `key_set`.
    Finished(KeySetVote),
}

impl Encode for DkgReply {
    fn encode(&self, e: &mut Encoder) {
        match self {
            DkgReply::Idle => {
                e.raw(&[0]);
            }
            DkgReply::Message(m) => {
                e.raw(&[1]);
                e.put(m);
            }
            DkgReply::Finished(vote) => {
                e.raw(&[2]);
                e.put(vote);
            }
        }
    }
}

impl Decode for DkgReply {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(match d.raw(1)?[0] {
            0 => DkgReply::Idle,
            1 => DkgReply::Message(d.get()?),
            2 => DkgReply::Finished(d.get()?),
            tag => return Err(DecodeError::BadTag(tag)),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn roundtrip<T: Encode + Decode + PartialEq + core::fmt::Debug>(v: &T) {
        assert_eq!(&T::from_bytes(&v.to_bytes()).unwrap(), v);
    }

    #[test]
    fn records_roundtrip() {
        let params = StakingParams {
            epoch_blocks: 24,
            unbonding_epochs: 1,
            min_stake: GWEI,
            max_validators: 4,
            dkg_phase_blocks: 4,
            max_key_age: 2,
            keys: Seq(vec![ValidatorKey {
                id: [1; 32],
                dkg_key: vec![2; 48],
            }]),
        };
        roundtrip(&params);
        let record = StakeRecord {
            address: [3; 20],
            stake: 5,
            unbonding: 6,
            release_epoch: 7,
            dkg_key: vec![8; 48],
            jailed: true,
            delegated: 9,
        };
        roundtrip(&record);
        roundtrip(&DelegationEntry {
            validator: [4; 32],
            delegation: Delegation {
                stake: 1,
                unbonding: 2,
                release_epoch: 3,
            },
        });
        let key_set = KeySetRecord {
            id: 2,
            key_set: vec![9; 192],
            public_shares: Seq(vec![vec![1; 96]]),
            shareholders: Seq(vec![[4; 32]]),
        };
        assert_eq!(key_set.threshold(), 2);
        assert_eq!(key_set.group_key(), Some(&[9u8; 96][..]));
        assert_eq!(KeySetRecord::default().group_key(), None);
        roundtrip(&key_set);
        roundtrip(&StakingStatus {
            epoch: 1,
            params,
            validators: ValidatorSet::default(),
            records: Seq(vec![StakeEntry {
                id: [5; 32],
                record,
            }]),
            active: Some(key_set),
            group_key: vec![9; 96],
            pool: 1 << 90,
        });
        roundtrip(&DkgRun {
            epoch: 3,
            session: [6; 32],
            threshold: 3,
            dealers: Seq(vec![[7; 32]]),
            recipients: Seq(vec![[8; 32]]),
            keys: Seq(vec![vec![1; 48]]),
            previous: Some(2),
        });
        roundtrip(&DkgEnvelope {
            epoch: 1,
            kind: envelope::CONFIRM,
            body: vec![1, 2],
            signature: Signature([3; 65]),
        });
        assert_eq!(
            DkgEnvelope::signed_hash_preimage(envelope::MESSAGE, &[7, 8]),
            vec![0, 7, 8]
        );
        roundtrip(&PartialShare {
            key_set: 1,
            index: 2,
            signature: vec![3; 48],
        });
        assert!(!format!("{:?}", StakeRecord::default()).is_empty());
    }

    #[test]
    fn constants_and_epochs() {
        assert_eq!(STAKING_ADDRESS[18..], [0x53, 0x54]);
        assert!(STAKING_ADDRESS[..18].iter().all(|b| *b == 0));
        assert_eq!(
            (GWEI, SLASH_BPS, MAX_REGISTERED, MAX_DKG),
            (1_000_000_000, 1_000, 256, 16)
        );
        assert_eq!((MAX_DELEGATORS, MAX_DELEGATIONS), (64, 16));
        assert_ne!(event::DELEGATED, event::UNDELEGATED);
        assert_eq!(
            (KIND_DKG, KEY_ROLE_THRESHOLD, G1_LENGTH, G2_LENGTH),
            (3, 2, 48, 96)
        );
        assert_eq!((envelope::MESSAGE, envelope::CONFIRM), (0, 1));
        assert_eq!(
            (
                envelope::ROTATION_SHARE,
                envelope::HANDOFF,
                envelope::EVIDENCE
            ),
            (2, 3, 4)
        );
        assert_ne!(event::REPORTED, event::WITHDRAWN);
        assert_eq!(
            (query::STAKING, query::STAKING_SET, query::DELEGATIONS),
            ("staking", "staking_set", "staking_delegations")
        );
        for key in [
            keys::RECORD,
            keys::BY_ADDRESS,
            keys::IDS,
            keys::SET,
            keys::RUN,
            keys::MESSAGE,
            keys::VOTE,
            keys::TALLY,
            keys::KEY_SET,
            keys::ACTIVE,
            keys::GROUP_KEY,
            keys::DELEGATION,
            keys::DELEGATORS,
            keys::DELEGATED_TO,
            keys::POOL,
        ] {
            assert!(!key.is_empty());
        }
        // Epoch e holds e·L + 1 ..= (e + 1)·L; height 0, the genesis, counts as epoch 0.
        assert_eq!([0, 1, 24, 25, 48].map(|h| epoch_of(h, 24)), [0, 0, 0, 1, 1]);
        assert_eq!((epoch_start(2, 24), epoch_end(2, 24)), (49, 72));
        assert_eq!((view_epoch(7), view_epoch(first_view(3) + 9)), (0, 3));
        assert_eq!(first_view(0), 1);
        assert_eq!([1, 3, 4, 7].map(dkg_threshold), [1, 3, 3, 5]);
        let preimage = session_preimage(1337, 2);
        assert_eq!(&preimage[..16], b"SOLO-DKG-SESSION");
        assert_eq!(&preimage[16..24], &1337u64.to_be_bytes());
        assert_eq!(&preimage[24..], &2u64.to_be_bytes());
    }

    #[test]
    fn threshold_certificates() {
        let message = certificate_message(1337, 1, &[0xab; 32]);
        assert_eq!(message.len(), 62);
        assert_eq!(&message[..14], b"SOLO-FINALITY\x01");
        let cert = certificate_bytes(7, &[2; 32], &[3; 48]);
        assert_eq!(cert.len(), CERTIFICATE_LENGTH);
        assert_eq!(certificate_parts(&cert), Some((7, [2; 32], &[3u8; 48][..])));
        assert_eq!(certificate_parts(&cert[..88]), None);
        let mut other = cert.clone();
        other[0] = 2;
        assert_eq!(certificate_parts(&other), None);
        assert_eq!(DST_SIGNATURE.len(), 50);
        assert_ne!(event::REGISTERED, event::BONDED);
        assert_ne!(event::UNBONDED, event::WITHDRAWN);
    }

    #[test]
    fn dkg_headers() {
        let mut message = vec![1u8];
        message.extend_from_slice(&[5; 32]);
        message.extend_from_slice(&9u32.to_le_bytes());
        message.push(0);
        assert_eq!(dkg_header(&message), Some((1, [5; 32], 9)));
        assert_eq!(dkg_header(&message[..36]), None);
        assert_eq!(dkg_header(&message[..20]), None);
        assert_eq!(dkg_header(&[]), None);
        message[0] = 3;
        assert_eq!(dkg_header(&message), None);
    }

    #[test]
    fn actions_encode_canonically() {
        let actions = [
            StakingAction::Register {
                dkg_key: vec![7; 48],
            },
            StakingAction::Bond,
            StakingAction::Unbond { amount: 5 * GWEI },
            StakingAction::Withdraw,
            StakingAction::Report {
                evidence: vec![9; 40],
            },
            StakingAction::Report { evidence: vec![] },
            StakingAction::Delegate {
                validator: [0x11; 20],
            },
            StakingAction::Undelegate {
                validator: [0x12; 20],
                amount: u128::MAX,
            },
        ];
        for action in &actions {
            assert_eq!(
                StakingAction::decode(&action.encode()).as_ref(),
                Some(action)
            );
        }
        let register = actions[0].encode();
        assert_eq!(register.len(), 132);
        assert_eq!(&register[..4], &selector::REGISTER);
        assert_eq!(word(5)[31], 5);
        // Anything but the canonical encoding is not an action.
        let mut bad = register.clone();
        bad[131] = 1;
        assert_eq!(StakingAction::decode(&bad), None);
        let mut bad = register.clone();
        bad[4 + 63] = 47;
        assert_eq!(StakingAction::decode(&bad), None);
        let mut bad = register.clone();
        bad[4 + 31] = 64;
        assert_eq!(StakingAction::decode(&bad), None);
        assert_eq!(StakingAction::decode(&register[..100]), None);
        let mut unbond = actions[2].encode();
        unbond[5] = 1;
        assert_eq!(StakingAction::decode(&unbond), None);
        assert_eq!(StakingAction::decode(&unbond[..20]), None);
        let mut bond = actions[1].encode();
        bond.push(0);
        assert_eq!(StakingAction::decode(&bond), None);
        let mut withdraw = actions[3].encode();
        withdraw.push(0);
        assert_eq!(StakingAction::decode(&withdraw), None);
        assert_eq!(StakingAction::decode(&[1, 2, 3, 4]), None);
        // A report is the canonical encoding of one `bytes` argument.
        let report = actions[4].encode();
        assert_eq!(report.len(), 4 + 64 + 64);
        for (at, value) in [(4 + 31, 64u8), (4 + 40, 1), (4 + 63, 65), (131, 1)] {
            let mut bad = report.clone();
            bad[at] = value;
            assert_eq!(StakingAction::decode(&bad), None, "{at}");
        }
        assert_eq!(StakingAction::decode(&report[..60]), None);
        let mut long = report.clone();
        long.extend_from_slice(&[0; 32]);
        assert_eq!(StakingAction::decode(&long), None);
        let mut huge = report[..68].to_vec();
        huge[4 + 60] = 0x10;
        assert_eq!(StakingAction::decode(&huge), None);
        assert_eq!(StakingAction::decode(&[1, 2]), None);
        // Addresses are words with zero high bytes, amounts below 2^128.
        let delegate = actions[6].encode();
        assert_eq!(delegate.len(), 36);
        assert_eq!(&delegate[4 + 12..], &[0x11; 20]);
        let mut bad = delegate.clone();
        bad[4] = 1;
        assert_eq!(StakingAction::decode(&bad), None);
        assert_eq!(StakingAction::decode(&delegate[..35]), None);
        let undelegate = actions[7].encode();
        assert_eq!(undelegate.len(), 68);
        assert_eq!(&undelegate[4 + 32 + 16..], &[0xFF; 16]);
        let mut bad = undelegate.clone();
        bad[4 + 32 + 15] = 1;
        assert_eq!(StakingAction::decode(&bad), None);
        let mut bad = undelegate.clone();
        bad[4 + 11] = 1;
        assert_eq!(StakingAction::decode(&bad), None);
        assert_eq!(StakingAction::decode(&undelegate[..67]), None);
        assert_eq!(address_word(&[0x11; 20])[12..], [0x11; 20]);
    }

    #[test]
    fn keystore_messages_roundtrip() {
        let request = DkgRequest {
            key_set: 1,
            session: [2; 32],
            threshold: 3,
            dealers: 4,
            recipients: Seq(vec![vec![5; 48]]),
            previous: vec![6; 96],
            previous_id: 0,
            dealer: 1,
            recipient: 2,
            transcript: Seq(vec![vec![7]]),
            upto: 3,
        };
        for message in [
            KeystoreRequest::EncryptionKey,
            KeystoreRequest::Dkg(request),
            KeystoreRequest::Sign {
                key_set: 1,
                message: vec![2],
            },
            KeystoreRequest::Combine {
                key_set: vec![1; 96],
                message: vec![2],
                partials: Seq(vec![PartialShare::default()]),
            },
        ] {
            roundtrip(&message);
            assert!(!format!("{message:?}").is_empty());
        }
        for reply in [
            DkgReply::Idle,
            DkgReply::Message(vec![1]),
            DkgReply::Finished(KeySetVote {
                key_set: vec![1; 96],
                public_shares: Seq(vec![vec![2; 96]]),
            }),
        ] {
            roundtrip(&reply);
            assert!(!format!("{reply:?}").is_empty());
        }
        assert_eq!(
            KeystoreRequest::from_bytes(&[9]),
            Err(DecodeError::BadTag(9))
        );
        assert_eq!(DkgReply::from_bytes(&[9]), Err(DecodeError::BadTag(9)));
    }
}
