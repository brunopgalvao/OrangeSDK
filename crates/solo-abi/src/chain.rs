//! Records of the reference kernel: how it lays out accounts, blocks,
//! receipts and its genesis parameters. The host reads these to build
//! contexts and answer RPC; the kernel writes them.

use alloc::vec::Vec;

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

record! {
    /// An account.
    Account {
        /// Balance in wei.
        balance: u128,
        /// Next nonce.
        nonce: u64,
        /// `keccak256` of the contract code; zero for an account without code.
        code_hash: Hash,
    }
}

record! {
    /// A genesis account: a balance and, for a predeploy, a nonce, code and storage.
    Allocation {
        /// Account.
        address: Address,
        /// Balance in wei.
        balance: u128,
        /// Nonce.
        nonce: u64,
        /// Contract code; empty for an account without code.
        code: Vec<u8>,
        /// Storage slots; a zero value is the same as no entry. The reference
        /// kernel refuses non-zero storage on an account with neither code nor
        /// nonce, where a creation could land (it does not apply EIP-7610).
        storage: Seq<StorageSlot>,
    }
}

record! {
    /// A storage slot set at genesis.
    StorageSlot {
        /// Slot, big-endian.
        key: Hash,
        /// Value, big-endian.
        value: Hash,
    }
}

record! {
    /// Kernel parameters carried in `Genesis::params`.
    GenesisParams {
        /// Slot length of the dev driver in milliseconds.
        slot_ms: u64,
        /// Maximum transactions per block.
        max_txs: u32,
        /// Initial accounts: balances and predeployed contracts.
        allocations: Seq<Allocation>,
        /// Governed kernel upgrades and host feature gates (spec 13).
        upgrades: UpgradeParams,
        /// Staking, epochs, slashing and threshold keys (spec 15).
        staking: crate::staking::StakingParams,
        /// The Ethereum-to-Solo bridge (spec 18); disabled by default.
        bridge_in: crate::bridge_in::BridgeInParams,
        /// Two-track governance (spec 13 §9): the mode and the proposal rules.
        governance: crate::governance::GovernanceParams,
    }
}

record! {
    /// Genesis parameters of governed kernel upgrades and host feature gates
    /// (spec 13), carried in `GenesisParams::upgrades`.
    UpgradeParams {
        /// The governance key (spec 13 §9.1): under the key track the
        /// account that stages, proposes and cancels kernel upgrades and
        /// executes every other governance action; under the stake track
        /// the guardian, unless a proposal named another. Zero: no key, so
        /// under the key track no upgrades and no governance at all.
        governance: Address,
        /// Fewest blocks between the block that proposes an upgrade and its
        /// activation height; a proposal is always at least one block ahead.
        min_delay: u64,
        /// Blocks per feature-gate epoch; zero disables feature-gate signalling.
        epoch_blocks: u64,
    }
}

record! {
    /// A block header as the kernel stores it. The block hash is not of this
    /// encoding but of the Ethereum header derived from it
    /// (`solo_eth::header`, spec 20 §3.1).
    BlockHeader {
        /// Height.
        height: u64,
        /// Parent block hash; zero for the first block.
        parent_hash: Hash,
        /// Timestamp in milliseconds.
        timestamp_ms: u64,
        /// State root after execution (spec 10).
        state_root: Hash,
        /// Root of the Merkle-Patricia trie of the block's receipts, each in
        /// its Ethereum encoding under `rlp(index)` (spec 20 §3.2).
        receipts_root: Hash,
        /// Hashes of the transactions the block records, in order: each has its
        /// receipt here. A transaction that cannot run and already has a
        /// receipt from an earlier inclusion is left out.
        tx_hashes: Seq<Hash>,
        /// Gas used.
        gas_used: u64,
        /// Root of the Merkle-Patricia trie of the recorded transactions, each
        /// as received under `rlp(index)` (spec 20 §3.2).
        transactions_root: Hash,
        /// Bloom of every log of the block: 256 bytes, empty in a template.
        logs_bloom: Vec<u8>,
        /// Block gas limit.
        gas_limit: u64,
        /// Base fee per gas.
        base_fee: u64,
        /// Fee recipient.
        beneficiary: Address,
    }
}

record! {
    /// A transaction receipt.
    Receipt {
        /// 1 if execution succeeded, 0 if it reverted, halted, or could not run.
        status: u8,
        /// Gas used by this transaction.
        gas_used: u64,
        /// Sender.
        from: Address,
        /// Recipient; zero for a contract creation.
        to: Address,
        /// Value transferred.
        value: u128,
        /// Block height.
        height: u64,
        /// Index within the block.
        index: u32,
        /// Gas used by this and every earlier transaction in the block.
        cumulative_gas_used: u64,
        /// The created contract, for a successful creation.
        contract: Option<Address>,
        /// Logs emitted, in order.
        logs: Seq<Log>,
        /// Transaction type: 0 legacy, 1 access list, 2 dynamic fee.
        tx_type: u8,
        /// Price paid per gas.
        effective_gas_price: u128,
    }
}

record! {
    /// A log entry emitted by a contract.
    Log {
        /// Emitting contract.
        address: Address,
        /// Indexed topics.
        topics: Seq<Hash>,
        /// Data.
        data: Vec<u8>,
    }
}

record! {
    /// `query::STORAGE` parameters.
    StorageQuery {
        /// Contract.
        address: Address,
        /// Slot, big-endian.
        slot: Hash,
    }
}

record! {
    /// An EIP-2930 access list entry: an account and the storage keys of it
    /// that a message declares it will touch.
    AccessItem {
        /// Account.
        address: Address,
        /// Storage keys, big-endian.
        keys: Seq<Hash>,
    }
}

record! {
    /// `query::CALL` parameters: a message executed against the head state,
    /// with the head block's number and timestamp, and thrown away
    /// (`eth_call`, `eth_estimateGas`).
    CallRequest {
        /// Caller.
        from: Address,
        /// Callee; `None` runs `data` as initcode.
        to: Option<Address>,
        /// Value in wei.
        value: u128,
        /// Calldata or initcode.
        data: Vec<u8>,
        /// Gas limit.
        gas: u64,
        /// Access list: charged as intrinsic gas and warm from the start, as
        /// in an EIP-2930 transaction.
        access_list: Seq<AccessItem>,
        /// Authorization list: when not empty the message runs as an EIP-7702
        /// set-code transaction, its authorizations charged and applied.
        authorization_list: Seq<SignedAuthorization>,
    }
}

record! {
    /// An EIP-7702 authorization as signed: the authority, recovered from the
    /// signature, is to run `address`'s code from its nonce `nonce` on.
    SignedAuthorization {
        /// Chain id, big-endian; 0 for every chain.
        chain_id: Hash,
        /// The account whose code the authority delegates to.
        address: Address,
        /// The authority's nonce.
        nonce: u64,
        /// Signature y parity.
        y_parity: u8,
        /// Signature `r`, big-endian.
        r: Hash,
        /// Signature `s`, big-endian.
        s: Hash,
    }
}

record! {
    /// `query::CALL` result.
    CallResult {
        /// `call_status::*`.
        status: u8,
        /// Gas the message used.
        gas_used: u64,
        /// Return data, or revert data.
        output: Vec<u8>,
    }
}

/// `CallResult::status` values.
pub mod call_status {
    /// Execution succeeded.
    pub const SUCCESS: u8 = 0;
    /// Execution reverted; the output is the revert data.
    pub const REVERT: u8 = 1;
    /// Execution halted (out of gas, invalid opcode, ...).
    pub const HALT: u8 = 2;
    /// The message could not run (for example, the caller cannot pay the value).
    pub const INVALID: u8 = 3;
}

record! {
    /// Persisted dev-driver state.
    DriverState {
        /// Height of the next block to produce.
        next_height: u64,
        /// Hash of the last executed block.
        last_hash: Hash,
        /// Last observed time.
        last_now_ms: u64,
        /// Whether a block is being executed.
        pending: bool,
    }
}

/// Query method names served by the reference kernel.
pub mod query {
    /// `() -> u64`
    pub const CHAIN_ID: &str = "chain_id";
    /// `() -> u64` last executed height.
    pub const BLOCK_NUMBER: &str = "block_number";
    /// `() -> u64` last finalized height.
    pub const FINALIZED: &str = "finalized";
    /// `(Address) -> Account`
    pub const ACCOUNT: &str = "account";
    /// `(u64) -> BlockHeader`
    pub const BLOCK_BY_NUMBER: &str = "block_by_number";
    /// `(Hash) -> BlockHeader`
    pub const BLOCK_BY_HASH: &str = "block_by_hash";
    /// `(Hash) -> Receipt`
    pub const RECEIPT: &str = "receipt";
    /// `(Hash) -> bytes` raw transaction.
    pub const TRANSACTION: &str = "transaction";
    /// `(Address) -> bytes` contract code.
    pub const CODE: &str = "code";
    /// `(StorageQuery) -> Hash` storage slot value.
    pub const STORAGE: &str = "storage";
    /// `(CallRequest) -> CallResult` a message against the head state, discarded.
    pub const CALL: &str = "call";
    /// `(u64 first) -> vec<Evidence>` equivocation evidence recorded on chain,
    /// in the order recorded, from index `first`, at most
    /// [`EVIDENCE_PAGE`](super::consensus::EVIDENCE_PAGE) records.
    pub const EVIDENCE: &str = "evidence";
}

/// Validation failure reasons reported by the reference kernel.
pub mod reason {
    /// Malformed RLP or wrong field shapes.
    pub const MALFORMED: u32 = 1;
    /// Signature recovery failed.
    pub const BAD_SIGNATURE: u32 = 2;
    /// Chain id mismatch.
    pub const WRONG_CHAIN: u32 = 3;
    /// Nonce is not the account's next nonce, or that nonce is 2^64 − 1, which
    /// no transaction may carry (EIP-2681).
    pub const BAD_NONCE: u32 = 4;
    /// Balance below value plus the maximum fee.
    pub const INSUFFICIENT_FUNDS: u32 = 5;
    /// Gas limit below the intrinsic cost.
    pub const GAS_TOO_LOW: u32 = 6;
    /// A transaction type the kernel does not execute (blob, set-code).
    pub const UNSUPPORTED: u32 = 7;
    /// The maximum fee per gas is below the base fee.
    pub const FEE_TOO_LOW: u32 = 8;
    /// The gas limit is above the per-transaction cap (EIP-7825) or the block's.
    pub const GAS_LIMIT_TOO_HIGH: u32 = 9;
    /// Contract initcode above the EIP-3860 limit.
    pub const INITCODE_TOO_LARGE: u32 = 10;
    /// The sender has code other than an EIP-7702 delegation designator (EIP-3607).
    pub const SENDER_NOT_EOA: u32 = 11;
    /// A transaction to the governance (upgrade) system address that cannot
    /// run: value where none is allowed, calldata that is neither an action
    /// nor a governance call, or a sender the action or call does not
    /// authorize in the current governance mode (spec 13 §2, §9). Also a
    /// transaction to the module address that is not a module install that
    /// can run (spec 16 §4.2).
    pub const SYSTEM_ACTION: u32 = 12;
    /// A transaction to the staking address that cannot run: staking
    /// disabled, calldata that is not a staking action, or an action the
    /// sender's stake does not allow (spec 15 §3).
    pub const STAKING_ACTION: u32 = 13;
    /// A transaction to the outbox address whose calldata is not a `send`
    /// the outbox accepts (spec 17 §2.2).
    pub const OUTBOX_MESSAGE: u32 = 14;
    /// A transaction to the light-client or inbox address of spec 18 on a
    /// chain without the bridge, or carrying value, or, to the inbox,
    /// calldata that is not a canonical `deliver` call (spec 18 §7). Codes
    /// 15 to 19 are left to other system addresses.
    pub const BRIDGE_CALL: u32 = 20;
    /// A light-client update that does not decode or would not advance the
    /// light client (spec 18 §7).
    pub const BRIDGE_UPDATE: u32 = 21;
    /// An inbox delivery of a message already delivered (spec 18 §7).
    pub const MESSAGE_DELIVERED: u32 = 22;
    /// An inbox delivery while the inbox is paused (spec 18 §7).
    pub const INBOX_PAUSED: u32 = 23;
}

/// Storage key prefixes of the reference kernel.
pub mod keys {
    /// `meta/chain_id` → u64.
    pub const CHAIN_ID: &[u8] = b"meta/chain_id";
    /// `meta/height` → u64, last executed height.
    pub const HEIGHT: &[u8] = b"meta/height";
    /// `local/finalized` → u64. Under [`LOCAL`], so outside the commitment:
    /// when a node learns of finality differs between nodes.
    pub const FINALIZED: &[u8] = b"local/finalized";
    /// Prefix of kernel keys the state commitment skips.
    pub const LOCAL: &[u8] = b"local/";
    /// `meta/last_hash` → Hash.
    pub const LAST_HASH: &[u8] = b"meta/last_hash";
    /// `acct/` + address → Account.
    pub const ACCOUNT: &[u8] = b"acct/";
    /// `block/` + height (big-endian u64) → `BlockHeader`.
    pub const BLOCK: &[u8] = b"block/";
    /// `bhash/` + hash → u64 height.
    pub const BLOCK_HASH: &[u8] = b"bhash/";
    /// `bnum/` + height (big-endian u64) → the block's 32-byte hash, which
    /// `BLOCKHASH` reads without decoding and hashing the header (spec 19 §4).
    pub const BLOCK_NUMBER: &[u8] = b"bnum/";
    /// `receipt/` + tx hash → Receipt.
    pub const RECEIPT: &[u8] = b"receipt/";
    /// `txraw/` + tx hash → raw transaction bytes.
    pub const TX_RAW: &[u8] = b"txraw/";
    /// `code/` + code hash → contract code.
    pub const CODE: &[u8] = b"code/";
    /// `slot/` + address + slot → 32-byte value; absent means zero.
    pub const SLOT: &[u8] = b"slot/";
    /// `evidence/` + index (big-endian u64) → `Evidence`, in the order recorded.
    pub const EVIDENCE: &[u8] = b"evidence/";
    /// `meta/evidence_count` → u64, number of evidence records.
    pub const EVIDENCE_COUNT: &[u8] = b"meta/evidence_count";
    /// `evseen/` + `Evidence::id` → u64 index: one record per offence.
    pub const EVIDENCE_SEEN: &[u8] = b"evseen/";
}

/// Intrinsic gas of a value transfer.
pub const TRANSFER_GAS: u64 = 21_000;

/// Gas limit of every block.
pub const BLOCK_GAS_LIMIT: u64 = 30_000_000;

/// Base fee per gas of the reference kernel: zero in this version, so a
/// transaction pays its priority fee (or its legacy gas price) and nothing more.
pub const BASE_FEE: u64 = 0;

record! {
    /// A consensus validator. `id` is `keccak256` of the uncompressed
    /// secp256k1 public key (64 bytes), which is what signature recovery yields.
    Validator {
        /// Identity, also the peer id.
        id: Hash,
        /// Voting weight: the validator's stake in gwei (spec 15). Quorums
        /// are more than two thirds of the set's total weight (spec 08 §1).
        weight: u64,
    }
}

record! {
    /// The validator set carried in `Genesis::validators`.
    ValidatorSet {
        /// Validators in leader-rotation order.
        validators: Seq<Validator>,
    }
}

record! {
    /// What a leader proposes in a view. The proposal hash is `keccak256` of
    /// this encoding; it is what votes name and what parents link to.
    Proposal {
        /// View the proposal was made in.
        view: u64,
        /// Height, one above the parent.
        height: u64,
        /// Hash of the parent proposal; zero for the first block.
        parent: Hash,
        /// Proposer's clock when it built the block.
        timestamp_ms: u64,
        /// Height of an executed block whose state root this proposal
        /// carries for light clients (spec 08 §5, spec 17 §4); 0 for none.
        anchor_height: u64,
        /// That block's state root; zero for none.
        anchor_root: Hash,
        /// Transactions, raw.
        txs: Seq<Vec<u8>>,
        /// Equivocation evidence for the chain to record, at most
        /// [`consensus::MAX_EVIDENCE`] records.
        evidence: Seq<Evidence>,
        /// Encoded DKG envelopes for the chain to record (spec 15 §6.2), at
        /// most [`crate::staking::MAX_DKG`].
        dkg: Seq<Vec<u8>>,
    }
}

/// A recoverable secp256k1 signature: `r || s || recovery id`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signature(pub [u8; 65]);

impl Default for Signature {
    fn default() -> Signature {
        Signature([0; 65])
    }
}

impl Encode for Signature {
    fn encode(&self, e: &mut Encoder) {
        e.put(&self.0);
    }
}

impl Decode for Signature {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(Signature(d.get()?))
    }
}

record! {
    /// One validator's signature over a consensus message.
    SignedVote {
        /// Index in the validator set.
        validator: u32,
        /// The signature.
        signature: Signature,
    }
}

record! {
    /// A quorum of votes of one kind for one proposal in one view. This is
    /// the certificate `FinalizeBlock` carries until threshold BLS replaces it.
    Certificate {
        /// Kind: `consensus::KIND_*`.
        kind: u8,
        /// View.
        view: u64,
        /// Proposal hash; zero for a timeout certificate.
        hash: Hash,
        /// The votes.
        votes: Seq<SignedVote>,
    }
}

record! {
    /// A hash and a validator's signature over it: one consensus message
    /// whose kind and view are known from context.
    SignedHash {
        /// Proposal hash, or zero for a timeout vote.
        hash: Hash,
        /// The signature.
        signature: Signature,
    }
}

record! {
    /// Proof that a validator signed two different hashes of one kind in one
    /// view (spec 08 §9): two proposals, two block votes, or two finalize
    /// votes. Canonical when `first.hash < second.hash`.
    Evidence {
        /// Kind: `consensus::KIND_*`.
        kind: u8,
        /// View both messages name.
        view: u64,
        /// The offender's index in the validator set.
        validator: u32,
        /// The message with the lower hash.
        first: SignedHash,
        /// The message with the higher hash.
        second: SignedHash,
    }
}

impl Evidence {
    /// Canonical evidence from two messages of `validator`, in either order.
    #[must_use]
    pub fn new(kind: u8, view: u64, validator: u32, a: SignedHash, b: SignedHash) -> Evidence {
        let (first, second) = if a.hash <= b.hash { (a, b) } else { (b, a) };
        Evidence {
            kind,
            view,
            validator,
            first,
            second,
        }
    }

    /// Names the offence rather than the signatures: validator (big-endian
    /// u32), view (big-endian u64) and kind. One record per offence.
    #[must_use]
    pub fn id(&self) -> [u8; 13] {
        let mut out = [0u8; 13];
        out[..4].copy_from_slice(&self.validator.to_be_bytes());
        out[4..12].copy_from_slice(&self.view.to_be_bytes());
        out[12] = self.kind;
        out
    }

    /// The checks that need no signature recovery: a known kind, two
    /// different hashes in canonical order, and no timeout vote among them
    /// (a timeout vote and a block vote in one view are allowed).
    #[must_use]
    pub fn well_formed(&self) -> bool {
        self.kind <= consensus::KIND_FINALIZE
            && self.first.hash < self.second.hash
            && !(self.kind == consensus::KIND_VOTE && self.first.hash == [0; 32])
    }
}

record! {
    /// What the reference kernel puts in `Block::participation`: consensus
    /// facts about validators that executing the block records in chain state.
    Participation {
        /// Equivocation evidence, as the proposal carried it.
        evidence: Seq<Evidence>,
        /// DKG envelopes, as the proposal carried them (spec 15 §6.2).
        dkg: Seq<Vec<u8>>,
    }
}

record! {
    /// The reference driver's persisted state (`PersistState` and `kernel_driver_state`).
    SimplexState {
        /// Current view, starting at 1.
        view: u64,
        /// View of the notarized tip.
        tip_view: u64,
        /// Height of the notarized tip; zero before the first block.
        tip_height: u64,
        /// Proposal hash of the notarized tip.
        tip_hash: Hash,
        /// Timestamp of the notarized tip, for pacing.
        tip_timestamp_ms: u64,
        /// Highest finalized height.
        finalized_height: u64,
        /// Voted for a proposal in the current view.
        voted: bool,
        /// Voted for the timeout in the current view.
        timed_out: bool,
        /// Asked the host for mempool contents in the current view.
        proposing: bool,
        /// This node's validator index, if it is a validator.
        me: Option<u32>,
        /// Last clock reading.
        now_ms: u64,
        /// A sync request is outstanding.
        sync_pending: bool,
        /// Id of the outstanding sync request; ids increase per request.
        sync_request_id: u64,
        /// Peer the outstanding sync request went to.
        sync_peer: Hash,
        /// Peers sent this view's entry certificate since the view began or
        /// its timeout last fired (spec 08 §5a).
        answered: Seq<Hash>,
        /// Doublings of the view timeout: one more for each view left by a
        /// timeout certificate, one fewer for each view notarized within half
        /// the timeout, at most `consensus::MAX_BACKOFF` (spec 08 §5a).
        backoff: u8,
        /// When this node entered or resumed its current view.
        view_started_ms: u64,
    }
}

record! {
    /// Asks a peer for finalized blocks from `from_height` on (spec 08 §7).
    SyncRequest {
        /// First height wanted.
        from_height: u64,
    }
}

record! {
    /// A peer's finalized blocks: consecutive proposals from the requested
    /// height and the finalize certificate of the last one.
    SyncResponse {
        /// The responder's finalized height, so the requester knows if more remain.
        finalized_height: u64,
        /// Consecutive finalized proposals, lowest first; empty if none.
        proposals: Seq<Proposal>,
        /// Finalize certificate whose hash is the last proposal's.
        certificate: Option<Certificate>,
        /// The threshold certificate of spec 12 §7 for the last proposal, if
        /// the responder holds one; empty otherwise.
        threshold: Vec<u8>,
    }
}

/// A consensus message on `consensus::TOPIC`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsensusMessage {
    /// A leader's proposal, signed over its hash.
    Propose {
        /// The proposal.
        proposal: Proposal,
        /// Leader's signature.
        signature: Signature,
    },
    /// A vote for a proposal, or for the timeout when `hash` is zero.
    Vote {
        /// View.
        view: u64,
        /// Proposal hash, or zero.
        hash: Hash,
        /// Signature.
        signature: Signature,
    },
    /// A finalize vote for the proposal notarized in `view`.
    Finalize {
        /// View.
        view: u64,
        /// Proposal hash.
        hash: Hash,
        /// Signature.
        signature: Signature,
    },
    /// A quorum certificate for a peer that lags (spec 08 §5a): timeout
    /// votes, block votes with the proposal they notarize, or finalize votes
    /// with the proposal they finalize.
    Certificate {
        /// The votes; `kind` is `KIND_VOTE` or `KIND_FINALIZE`.
        certificate: Certificate,
        /// The certified proposal, when the certificate names one the sender holds.
        proposal: Option<Proposal>,
    },
    /// A finalize vote with the voter's threshold partial signature over
    /// the proposal's certificate message (spec 08 §4, spec 12 §7).
    FinalizeShare {
        /// View.
        view: u64,
        /// Proposal hash.
        hash: Hash,
        /// Signature of the finalize vote.
        signature: Signature,
        /// The partial signature.
        partial: crate::staking::PartialShare,
    },
    /// A DKG envelope for leaders to put in proposals (spec 15 §6.2).
    Dkg {
        /// The encoded `DkgEnvelope`.
        envelope: Vec<u8>,
    },
}

impl Encode for ConsensusMessage {
    fn encode(&self, e: &mut Encoder) {
        match self {
            ConsensusMessage::Propose {
                proposal,
                signature,
            } => {
                e.raw(&[0]);
                e.put(proposal).put(signature);
            }
            ConsensusMessage::Vote {
                view,
                hash,
                signature,
            } => {
                e.raw(&[1]);
                e.put(view).put(hash).put(signature);
            }
            ConsensusMessage::Finalize {
                view,
                hash,
                signature,
            } => {
                e.raw(&[2]);
                e.put(view).put(hash).put(signature);
            }
            ConsensusMessage::Certificate {
                certificate,
                proposal,
            } => {
                e.raw(&[3]);
                e.put(certificate).put(proposal);
            }
            ConsensusMessage::FinalizeShare {
                view,
                hash,
                signature,
                partial,
            } => {
                e.raw(&[4]);
                e.put(view).put(hash).put(signature).put(partial);
            }
            ConsensusMessage::Dkg { envelope } => {
                e.raw(&[5]);
                e.put(envelope);
            }
        }
    }
}

impl Decode for ConsensusMessage {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(match d.raw(1)?[0] {
            0 => ConsensusMessage::Propose {
                proposal: d.get()?,
                signature: d.get()?,
            },
            1 => ConsensusMessage::Vote {
                view: d.get()?,
                hash: d.get()?,
                signature: d.get()?,
            },
            2 => ConsensusMessage::Finalize {
                view: d.get()?,
                hash: d.get()?,
                signature: d.get()?,
            },
            3 => ConsensusMessage::Certificate {
                certificate: d.get()?,
                proposal: d.get()?,
            },
            4 => ConsensusMessage::FinalizeShare {
                view: d.get()?,
                hash: d.get()?,
                signature: d.get()?,
                partial: d.get()?,
            },
            5 => ConsensusMessage::Dkg { envelope: d.get()? },
            tag => return Err(DecodeError::BadTag(tag)),
        })
    }
}

/// Constants of the reference Simplex driver (spec 08).
pub mod consensus {
    use alloc::vec::Vec;

    use crate::types::Hash;

    /// Network topic of every consensus message.
    pub const TOPIC: u16 = 1;
    /// Signing domain of a proposal.
    pub const KIND_PROPOSE: u8 = 0;
    /// Signing domain of a vote (block or timeout).
    pub const KIND_VOTE: u8 = 1;
    /// Signing domain of a finalize vote.
    pub const KIND_FINALIZE: u8 = 2;
    /// Key role the driver signs with (`sign` host function).
    pub const KEY_ROLE: u64 = 0;
    /// The timeout of a view, in slots, before backoff. A node still in the
    /// view when it fires repeats its timeout vote and re-arms it.
    pub const TIMEOUT_SLOTS: u64 = 3;
    /// Most doublings of the view timeout after views that timed out.
    pub const MAX_BACKOFF: u8 = 4;
    /// Most evidence records one proposal carries; a proposal with more gets no votes.
    pub const MAX_EVIDENCE: usize = 8;
    /// Most evidence records one `query::EVIDENCE` answer holds.
    pub const EVIDENCE_PAGE: u64 = 64;
    /// Peer score change for the peer that delivered an equivocation.
    pub const EQUIVOCATION_PENALTY: i64 = -100;

    /// How long a node waits in a view before timing out, and between repeats
    /// of its timeout vote: `TIMEOUT_SLOTS` slots doubled `backoff` times
    /// (at most `MAX_BACKOFF`), saturating.
    #[must_use]
    pub const fn view_timeout_ms(slot_ms: u64, backoff: u8) -> u64 {
        let doublings = if backoff < MAX_BACKOFF {
            backoff
        } else {
            MAX_BACKOFF
        };
        TIMEOUT_SLOTS
            .saturating_mul(slot_ms)
            .saturating_mul(1 << doublings)
    }

    /// Timer id of the timeout of `view`.
    #[must_use]
    pub const fn timeout_timer(view: u64) -> u64 {
        view * 2
    }

    /// Timer id of the leader's proposal time in `view`.
    #[must_use]
    pub const fn propose_timer(view: u64) -> u64 {
        view * 2 + 1
    }

    /// The view a timer id belongs to.
    #[must_use]
    pub const fn timer_view(timer_id: u64) -> u64 {
        timer_id / 2
    }

    /// Votes needed among `n` validators: more than two thirds.
    #[must_use]
    pub const fn quorum(n: usize) -> usize {
        n * 2 / 3 + 1
    }

    /// Index of the leader of `view` among `n` validators.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub const fn leader(view: u64, n: usize) -> usize {
        // The remainder is below `n`, so it fits a `usize`.
        ((view - 1) % n as u64) as usize
    }

    /// The bytes a validator hashes and signs: kind, chain id, view, hash.
    #[must_use]
    pub fn signing_preimage(kind: u8, chain_id: u64, view: u64, hash: &Hash) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 8 + 8 + 32);
        out.push(kind);
        out.extend_from_slice(&chain_id.to_le_bytes());
        out.extend_from_slice(&view.to_le_bytes());
        out.extend_from_slice(hash);
        out
    }

    /// The domain-separated message of a vote on the genesis, used by a node
    /// to learn its own validator index from the `sign` host function.
    #[must_use]
    pub fn identity_preimage(chain_id: u64) -> Vec<u8> {
        signing_preimage(KIND_VOTE, chain_id, 0, &[0; 32])
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
    #[allow(clippy::too_many_lines)]
    fn records_roundtrip() {
        roundtrip(&Account {
            balance: 5,
            nonce: 1,
            code_hash: [9; 32],
        });
        roundtrip(&GenesisParams {
            slot_ms: 400,
            max_txs: 10,
            allocations: Seq(vec![Allocation {
                address: [1; 20],
                balance: 7,
                nonce: 1,
                code: vec![0x60, 0x00],
                storage: Seq(vec![StorageSlot {
                    key: [1; 32],
                    value: [2; 32],
                }]),
            }]),
            upgrades: UpgradeParams {
                governance: [2; 20],
                min_delay: 10,
                epoch_blocks: 100,
            },
            staking: crate::staking::StakingParams {
                epoch_blocks: 24,
                ..crate::staking::StakingParams::default()
            },
            bridge_in: crate::bridge_in::BridgeInParams {
                outbox: [5; 20],
                ..crate::bridge_in::BridgeInParams::default()
            },
            governance: crate::governance::GovernanceParams {
                mode: crate::governance::mode::STAKE,
                voting_blocks: 3,
                ..crate::governance::GovernanceParams::default()
            },
        });
        roundtrip(&BlockHeader {
            height: 1,
            parent_hash: [2; 32],
            timestamp_ms: 3,
            state_root: [4; 32],
            receipts_root: [5; 32],
            tx_hashes: Seq(vec![[6; 32]]),
            gas_used: 21_000,
            transactions_root: [7; 32],
            logs_bloom: vec![8; 256],
            gas_limit: 30_000_000,
            base_fee: 9,
            beneficiary: [10; 20],
        });
        roundtrip(&Receipt {
            status: 1,
            gas_used: 21_000,
            from: [1; 20],
            to: [2; 20],
            value: 3,
            height: 4,
            index: 5,
            cumulative_gas_used: 42_000,
            contract: Some([3; 20]),
            logs: Seq(vec![Log {
                address: [4; 20],
                topics: Seq(vec![[5; 32]]),
                data: vec![6],
            }]),
            tx_type: 2,
            effective_gas_price: 7,
        });
        roundtrip(&StorageQuery {
            address: [1; 20],
            slot: [2; 32],
        });
        roundtrip(&CallRequest {
            from: [1; 20],
            to: None,
            value: 2,
            data: vec![3],
            gas: 4,
            access_list: Seq(vec![AccessItem {
                address: [5; 20],
                keys: Seq(vec![[6; 32], [7; 32]]),
            }]),
            authorization_list: Seq(vec![SignedAuthorization {
                chain_id: [8; 32],
                address: [9; 20],
                nonce: 10,
                y_parity: 1,
                r: [11; 32],
                s: [12; 32],
            }]),
        });
        roundtrip(&CallResult {
            status: call_status::REVERT,
            gas_used: 5,
            output: vec![6],
        });
        assert_eq!(
            (
                call_status::SUCCESS,
                call_status::HALT,
                call_status::INVALID,
                BLOCK_GAS_LIMIT,
                BASE_FEE
            ),
            (0, 2, 3, 30_000_000, 0)
        );
        roundtrip(&DriverState {
            next_height: 1,
            last_hash: [0; 32],
            last_now_ms: 9,
            pending: true,
        });
        assert_eq!(TRANSFER_GAS, 21_000);
        assert_eq!(query::ACCOUNT, "account");
        assert_eq!(
            (
                reason::BAD_NONCE,
                reason::SYSTEM_ACTION,
                reason::STAKING_ACTION
            ),
            (4, 12, 13)
        );
        assert_eq!(keys::ACCOUNT, b"acct/");
        assert!(alloc::format!("{:?}", Account::default()).contains("Account"));
        for name in [
            query::CHAIN_ID,
            query::BLOCK_NUMBER,
            query::FINALIZED,
            query::BLOCK_BY_NUMBER,
            query::BLOCK_BY_HASH,
            query::RECEIPT,
            query::TRANSACTION,
            query::EVIDENCE,
        ] {
            assert!(!name.is_empty());
        }
        for key in [
            keys::CHAIN_ID,
            keys::HEIGHT,
            keys::FINALIZED,
            keys::LAST_HASH,
            keys::BLOCK,
            keys::BLOCK_HASH,
            keys::BLOCK_NUMBER,
            keys::RECEIPT,
            keys::TX_RAW,
            keys::EVIDENCE,
            keys::EVIDENCE_COUNT,
            keys::EVIDENCE_SEEN,
        ] {
            assert!(!key.is_empty());
        }
        let _ = (
            reason::MALFORMED,
            reason::BAD_SIGNATURE,
            reason::WRONG_CHAIN,
            reason::INSUFFICIENT_FUNDS,
            reason::GAS_TOO_LOW,
            reason::UNSUPPORTED,
        );
    }

    #[test]
    fn consensus_records_roundtrip() {
        let proposal = Proposal {
            view: 3,
            height: 2,
            parent: [1; 32],
            timestamp_ms: 9,
            anchor_height: 1,
            anchor_root: [5; 32],
            txs: Seq(vec![vec![1, 2], vec![]]),
            evidence: Seq(vec![Evidence::default()]),
            dkg: Seq(vec![vec![3]]),
        };
        roundtrip(&proposal);
        roundtrip(&Validator {
            id: [7; 32],
            weight: 1,
        });
        roundtrip(&ValidatorSet {
            validators: Seq(vec![Validator {
                id: [7; 32],
                weight: 1,
            }]),
        });
        let vote = SignedVote {
            validator: 2,
            signature: Signature([9; 65]),
        };
        roundtrip(&vote);
        roundtrip(&Certificate {
            kind: consensus::KIND_FINALIZE,
            view: 3,
            hash: [2; 32],
            votes: Seq(vec![vote.clone()]),
        });
        roundtrip(&SyncRequest { from_height: 4 });
        roundtrip(&SyncResponse {
            finalized_height: 9,
            proposals: Seq(vec![Proposal::default()]),
            certificate: Some(Certificate::default()),
            threshold: vec![1; 89],
        });
        roundtrip(&SimplexState {
            view: 4,
            me: Some(1),
            voted: true,
            answered: Seq(vec![[5; 32]]),
            backoff: 2,
            view_started_ms: 7,
            ..SimplexState::default()
        });
        assert_eq!(Signature::default(), Signature([0; 65]));
        assert_eq!(Signature([9; 65]).to_bytes(), vec![9; 65]);
        for message in [
            ConsensusMessage::Propose {
                proposal,
                signature: Signature([1; 65]),
            },
            ConsensusMessage::Vote {
                view: 1,
                hash: [0; 32],
                signature: Signature([2; 65]),
            },
            ConsensusMessage::Finalize {
                view: 1,
                hash: [3; 32],
                signature: Signature([3; 65]),
            },
            ConsensusMessage::Certificate {
                certificate: Certificate {
                    kind: consensus::KIND_VOTE,
                    view: 3,
                    hash: [0; 32],
                    votes: Seq(vec![vote.clone()]),
                },
                proposal: None,
            },
            ConsensusMessage::Certificate {
                certificate: Certificate::default(),
                proposal: Some(Proposal::default()),
            },
            ConsensusMessage::FinalizeShare {
                view: 2,
                hash: [4; 32],
                signature: Signature([5; 65]),
                partial: crate::staking::PartialShare {
                    key_set: 1,
                    index: 2,
                    signature: vec![6; 48],
                },
            },
            ConsensusMessage::Dkg {
                envelope: vec![7, 8],
            },
        ] {
            roundtrip(&message);
            assert!(format!("{message:?}").len() > 10);
        }
        assert_eq!(
            ConsensusMessage::from_bytes(&[7]),
            Err(DecodeError::BadTag(7))
        );
    }

    #[test]
    fn evidence_is_canonical() {
        let low = SignedHash {
            hash: [1; 32],
            signature: Signature([7; 65]),
        };
        let high = SignedHash {
            hash: [2; 32],
            signature: Signature([8; 65]),
        };
        // Either arrival order gives the same record.
        let e = Evidence::new(consensus::KIND_VOTE, 9, 3, high.clone(), low.clone());
        assert_eq!(
            e,
            Evidence::new(consensus::KIND_VOTE, 9, 3, low.clone(), high.clone())
        );
        assert_eq!((e.first.hash, e.second.hash), ([1; 32], [2; 32]));
        roundtrip(&e);
        roundtrip(&low);
        roundtrip(&Participation {
            evidence: Seq(vec![e.clone()]),
            dkg: Seq(vec![vec![1]]),
        });
        // The id names validator, view and kind, big-endian, so records sort by offender.
        let mut id = vec![0, 0, 0, 3];
        id.extend_from_slice(&9u64.to_be_bytes());
        id.push(consensus::KIND_VOTE);
        assert_eq!(e.id().to_vec(), id);
        assert!(e.well_formed());
        let zero = SignedHash {
            hash: [0; 32],
            signature: Signature([9; 65]),
        };
        // A timeout vote beside a block vote is allowed; two proposals or finalize votes are not.
        assert!(
            !Evidence::new(consensus::KIND_VOTE, 9, 3, zero.clone(), high.clone()).well_formed()
        );
        assert!(
            Evidence::new(consensus::KIND_PROPOSE, 9, 3, zero.clone(), high.clone()).well_formed()
        );
        assert!(
            Evidence::new(consensus::KIND_FINALIZE, 9, 3, low.clone(), high.clone()).well_formed()
        );
        // The same hash twice, an unknown kind, or a non-canonical order is not evidence.
        assert!(!Evidence::new(consensus::KIND_VOTE, 9, 3, low.clone(), low.clone()).well_formed());
        assert!(!Evidence::new(3, 9, 3, low.clone(), high.clone()).well_formed());
        let swapped = Evidence {
            first: high,
            second: low,
            ..e
        };
        assert!(!swapped.well_formed());
    }

    #[test]
    fn consensus_constants() {
        use consensus::*;
        assert_eq!((timeout_timer(5), propose_timer(5)), (10, 11));
        assert_eq!((timer_view(10), timer_view(11)), (5, 5));
        assert_eq!((quorum(1), quorum(3), quorum(4), quorum(7)), (1, 3, 3, 5));
        assert_eq!((leader(1, 4), leader(4, 4), leader(5, 4)), (0, 3, 0));
        let preimage = signing_preimage(KIND_VOTE, 1337, 2, &[0xAA; 32]);
        assert_eq!(preimage.len(), 49);
        assert_eq!(preimage[0], KIND_VOTE);
        assert_eq!(&preimage[1..9], &1337u64.to_le_bytes());
        assert_eq!(&preimage[9..17], &2u64.to_le_bytes());
        assert_eq!(&preimage[17..], &[0xAA; 32]);
        assert_eq!(
            identity_preimage(1337),
            signing_preimage(KIND_VOTE, 1337, 0, &[0; 32])
        );
        assert_eq!((TOPIC, KEY_ROLE, TIMEOUT_SLOTS, MAX_BACKOFF), (1, 0, 3, 4));
        // The timeout doubles per step of backoff up to 16 times the base, and saturates.
        assert_eq!(
            [0, 1, 2, 4, 5, 255].map(|b| view_timeout_ms(400, b)),
            [1_200, 2_400, 4_800, 19_200, 19_200, 19_200]
        );
        assert_eq!(view_timeout_ms(u64::MAX / 2, 1), u64::MAX);
        assert_eq!(
            (MAX_EVIDENCE, EVIDENCE_PAGE, EQUIVOCATION_PENALTY),
            (8, 64, -100)
        );
        assert_eq!((KIND_PROPOSE, KIND_FINALIZE), (0, 2));
    }
}
