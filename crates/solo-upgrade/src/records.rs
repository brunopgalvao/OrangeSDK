//! Records the reference kernel keeps in chain state and serves through the
//! `upgrade_status` query (spec 13 §5–§6).

use solo_abi::chain::UpgradeParams;
use solo_abi::codec::Seq;
use solo_abi::types::Hash;

use crate::gates::GateBook;

record! {
    /// An upgrade proposed and not yet enacted, cancelled or lapsed.
    PendingUpgrade {
        /// `keccak256` of the new kernel module.
        code_hash: Hash,
        /// The last block the current kernel executes; the new kernel
        /// executes the next one.
        activation_height: u64,
        /// Feature gates (a bit per gate) that must be active for the block
        /// after `activation_height`, or the upgrade lapses.
        required_gates: u64,
        /// Size of the module in bytes.
        size: u32,
        /// Number of chunks it was staged in.
        chunks: u32,
        /// Height of the block that proposed it.
        proposed_at: u64,
    }
}

record! {
    /// The latest kernel switch, written by the new kernel's `kernel_migrate`.
    EnactedUpgrade {
        /// Code hash of the kernel now running.
        code_hash: Hash,
        /// The activation height: the last block of the previous kernel.
        height: u64,
        /// Version of the previous kernel.
        from_version: u32,
        /// Version of the kernel now running.
        to_version: u32,
    }
}

record! {
    /// A validator's feature-gate signal: the features its host supports.
    Signal {
        /// The epoch of the block that carried the signal.
        epoch: u64,
        /// One bit per feature gate.
        features: u64,
    }
}

record! {
    /// A validator and its latest signal.
    ValidatorSignal {
        /// Validator id (spec 08).
        id: Hash,
        /// Its stake: the weight the validator set gives it.
        weight: u64,
        /// Its latest signal, if it ever signalled.
        signal: Option<Signal>,
    }
}

record! {
    /// What the `upgrade_status` query returns.
    UpgradeStatus {
        /// The running kernel's version.
        version: u32,
        /// The genesis parameters of upgrades and gates.
        params: UpgradeParams,
        /// The pending upgrade, if any.
        pending: Option<PendingUpgrade>,
        /// The latest switch, if any happened.
        enacted: Option<EnactedUpgrade>,
        /// Feature-gate progress.
        gates: GateBook,
        /// Every validator, in validator-set order, with its latest signal.
        validators: Seq<ValidatorSignal>,
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use solo_abi::{Decode, Encode};

    use super::*;
    use crate::gates::GateRecord;

    fn roundtrip<T: Encode + Decode + PartialEq + core::fmt::Debug>(v: &T) {
        assert_eq!(&T::from_bytes(&v.to_bytes()).unwrap(), v);
    }

    #[test]
    fn records_roundtrip() {
        let pending = PendingUpgrade {
            code_hash: [1; 32],
            activation_height: 100,
            required_gates: 1,
            size: 5,
            chunks: 1,
            proposed_at: 9,
        };
        roundtrip(&pending);
        let enacted = EnactedUpgrade {
            code_hash: [2; 32],
            height: 100,
            from_version: 1,
            to_version: 2,
        };
        roundtrip(&enacted);
        let signal = Signal {
            epoch: 3,
            features: 0b101,
        };
        roundtrip(&signal);
        let status = UpgradeStatus {
            version: 2,
            params: UpgradeParams {
                governance: [3; 20],
                min_delay: 10,
                epoch_blocks: 50,
            },
            pending: Some(pending),
            enacted: Some(enacted),
            gates: GateBook {
                next_epoch: 4,
                gates: Seq(vec![GateRecord {
                    gate: 0,
                    streak: 2,
                    activation_height: 251,
                }]),
            },
            validators: Seq(vec![
                ValidatorSignal {
                    id: [4; 32],
                    weight: 1,
                    signal: Some(signal),
                },
                ValidatorSignal {
                    id: [5; 32],
                    weight: 2,
                    signal: None,
                },
            ]),
        };
        roundtrip(&status);
        roundtrip(&UpgradeStatus::default());
        assert!(alloc::format!("{status:?}").contains("UpgradeStatus"));
    }
}
