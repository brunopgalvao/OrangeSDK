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
        /// 1 for success, 0 for a transaction that was included but failed validation.
        status: u8,
        /// Gas used.
        gas_used: u64,
        /// Sender.
        from: Address,
        /// Recipient.
        to: Address,
        /// Value transferred.
        value: u128,
        /// Block height.
        height: u64,
        /// Index within the block.
        index: u32,
    }
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
    /// Contract creation or calldata, which the reference kernel does not execute.
    pub const UNSUPPORTED: u32 = 7;
}

/// Storage key prefixes of the reference kernel.
pub mod keys {
    /// `meta/chain_id` → u64.
    pub const CHAIN_ID: &[u8] = b"meta/chain_id";
    /// `meta/height` → u64, last executed height.
    pub const HEIGHT: &[u8] = b"meta/height";
    /// `meta/finalized` → u64.
    pub const FINALIZED: &[u8] = b"meta/finalized";
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
}

/// Intrinsic gas of a value transfer.
pub const TRANSFER_GAS: u64 = 21_000;

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
    fn records_roundtrip() {
        roundtrip(&Account {
            balance: 5,
            nonce: 1,
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
        });
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
