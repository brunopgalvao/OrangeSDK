//! The records the EVM conformance harness passes to its guest and back
//! (spec 07 §4.2): one Ethereum state test case in, the outcome of its
//! transaction out. The post-state is not returned: the host reads it from
//! storage, where the kernel's own state code wrote it.

use alloc::vec::Vec;

use crate::chain::{Allocation, Log};
use crate::codec::{Decode, DecodeError, Decoder, Encode, Encoder, Seq};
use crate::types::{Address, Hash};

/// The export of the conformance guest that runs one case.
pub const EXPORT: &str = "conformance_run";

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
    /// The block environment of a state test.
    Env {
        /// Chain id.
        chain_id: u64,
        /// `currentCoinbase`.
        beneficiary: Address,
        /// `currentNumber`.
        number: u64,
        /// `currentTimestamp`, in seconds.
        timestamp: u64,
        /// `currentGasLimit`.
        gas_limit: u64,
        /// `currentBaseFee`.
        base_fee: u64,
        /// `currentRandom`.
        prevrandao: Hash,
        /// `currentDifficulty`, big-endian.
        difficulty: Hash,
        /// `currentExcessBlobGas`.
        excess_blob_gas: u64,
    }
}

record! {
    /// One case: the environment, the pre-state as genesis allocations, and
    /// the signed transaction.
    Case {
        /// Block environment.
        env: Env,
        /// Pre-state.
        allocations: Seq<Allocation>,
        /// The transaction as signed bytes (legacy RLP or typed envelope).
        tx: Vec<u8>,
    }
}

record! {
    /// What the transaction did.
    Outcome {
        /// `chain::call_status::*`; `INVALID` when the transaction could not
        /// be decoded or was refused before execution.
        status: u8,
        /// Gas used, refunds deducted.
        gas_used: u64,
        /// Logs, in order.
        logs: Seq<Log>,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::StorageSlot;

    #[test]
    fn records_round_trip() {
        let case = Case {
            env: Env {
                chain_id: 1,
                beneficiary: [2; 20],
                number: 3,
                timestamp: 4,
                gas_limit: 5,
                base_fee: 6,
                prevrandao: [7; 32],
                difficulty: [8; 32],
                excess_blob_gas: 9,
            },
            allocations: Seq(alloc::vec![Allocation {
                address: [1; 20],
                balance: 10,
                nonce: 1,
                code: alloc::vec![0x00],
                storage: Seq(alloc::vec![StorageSlot {
                    key: [1; 32],
                    value: [2; 32]
                }]),
            }]),
            tx: alloc::vec![0xc0],
        };
        assert_eq!(Case::from_bytes(&case.to_bytes()), Ok(case));
        let outcome = Outcome {
            status: 1,
            gas_used: 21_000,
            logs: Seq(alloc::vec![Log {
                address: [3; 20],
                topics: Seq(alloc::vec![[4; 32]]),
                data: alloc::vec![5]
            }]),
        };
        assert_eq!(Outcome::from_bytes(&outcome.to_bytes()), Ok(outcome));
        assert_eq!(EXPORT, "conformance_run");
    }
}
