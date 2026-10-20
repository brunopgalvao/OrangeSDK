//! Records of the reference kernel: how it lays out accounts, blocks,
//! receipts and its genesis parameters. The host reads these to build
//! contexts and answer RPC; the kernel writes them.

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
}
