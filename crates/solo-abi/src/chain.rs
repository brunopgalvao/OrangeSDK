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
    /// A genesis balance.
    Allocation {
        /// Account.
        address: Address,
        /// Balance in wei.
        balance: u128,
    }
}

record! {
    /// Kernel parameters carried in `Genesis::params`.
    GenesisParams {
        /// Slot length of the dev driver in milliseconds.
        slot_ms: u64,
        /// Maximum transactions per block.
        max_txs: u32,
        /// Initial balances.
        allocations: Seq<Allocation>,
    }
}

record! {
    /// A block header as the kernel stores it. The block hash is `keccak256`
    /// of this encoding.
    BlockHeader {
        /// Height.
        height: u64,
        /// Parent block hash; zero for the first block.
        parent_hash: Hash,
        /// Timestamp in milliseconds.
        timestamp_ms: u64,
        /// State root after execution.
        state_root: Hash,
        /// Receipts root.
        receipts_root: Hash,
        /// Transaction hashes in order.
        tx_hashes: Seq<Hash>,
        /// Gas used.
        gas_used: u64,
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
    /// `query::CALL` parameters: a message executed against the latest state
    /// and thrown away (`eth_call`, `eth_estimateGas`).
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
    /// `(CallRequest) -> CallResult` a message against the latest state, discarded.
    pub const CALL: &str = "call";
}

/// Validation failure reasons reported by the reference kernel.
pub mod reason {
    /// Malformed RLP or wrong field shapes.
    pub const MALFORMED: u32 = 1;
    /// Signature recovery failed.
    pub const BAD_SIGNATURE: u32 = 2;
    /// Chain id mismatch.
    pub const WRONG_CHAIN: u32 = 3;
    /// Nonce is not the account's next nonce.
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
    /// `receipt/` + tx hash → Receipt.
    pub const RECEIPT: &[u8] = b"receipt/";
    /// `txraw/` + tx hash → raw transaction bytes.
    pub const TX_RAW: &[u8] = b"txraw/";
    /// `code/` + code hash → contract code.
    pub const CODE: &[u8] = b"code/";
    /// `slot/` + address + slot → 32-byte value; absent means zero.
    pub const SLOT: &[u8] = b"slot/";
}

/// Intrinsic gas of a value transfer.
pub const TRANSFER_GAS: u64 = 21_000;

/// Gas limit of every block.
pub const BLOCK_GAS_LIMIT: u64 = 30_000_000;

record! {
    /// A consensus validator. `id` is `keccak256` of the uncompressed
    /// secp256k1 public key (64 bytes), which is what signature recovery yields.
    Validator {
        /// Identity, also the peer id.
        id: Hash,
        /// Voting weight; the reference driver counts validators, not weight.
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
        /// Transactions, raw.
        txs: Seq<Vec<u8>>,
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
    /// The timeout of a view, in slots.
    pub const TIMEOUT_SLOTS: u64 = 3;

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
            }]),
        });
        roundtrip(&BlockHeader {
            height: 1,
            parent_hash: [2; 32],
            timestamp_ms: 3,
            state_root: [4; 32],
            receipts_root: [5; 32],
            tx_hashes: Seq(vec![[6; 32]]),
            gas_used: 21_000,
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
                BLOCK_GAS_LIMIT
            ),
            (0, 2, 3, 30_000_000)
        );
        roundtrip(&DriverState {
            next_height: 1,
            last_hash: [0; 32],
            last_now_ms: 9,
            pending: true,
        });
        assert_eq!(TRANSFER_GAS, 21_000);
        assert_eq!(query::ACCOUNT, "account");
        assert_eq!(reason::BAD_NONCE, 4);
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
            keys::RECEIPT,
            keys::TX_RAW,
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
            txs: Seq(vec![vec![1, 2], vec![]]),
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
        });
        roundtrip(&SimplexState {
            view: 4,
            me: Some(1),
            voted: true,
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
        assert_eq!((TOPIC, KEY_ROLE, TIMEOUT_SLOTS), (1, 0, 3));
        assert_eq!((KIND_PROPOSE, KIND_FINALIZE), (0, 2));
    }
}
