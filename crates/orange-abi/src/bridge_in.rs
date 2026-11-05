//! The Ethereum-to-Orange bridge of the reference kernel (spec 18): its two
//! system addresses and its genesis parameters. The light client's records
//! and its logic are in `orange-ethlc`.

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

/// The light-client address, `0x000000000000000000000000000000000000454C`
/// ("EL"): a native contract running the light-client module, to which
/// anyone submits Ethereum light-client updates (spec 18 §4).
pub const LIGHT_CLIENT_ADDRESS: Address = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x45, 0x4C,
];

/// The verifier address, `0x000000000000000000000000000000000000454D`
/// ("EM"): a native contract running the message-verifier module, which
/// proves outbox messages for the inbox and records each delivered once
/// (spec 18 §5.2).
pub const VERIFIER_ADDRESS: Address = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x45, 0x4D,
];

/// The inbox address, `0x0000000000000000000000000000000000004549` ("EI"):
/// the EVM contract that delivers proven Ethereum messages to their
/// recipients on Orange (spec 18 §6).
pub const INBOX_ADDRESS: Address = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x45, 0x49,
];

record! {
    /// An Ethereum fork the light client knows: from `epoch` on, sync
    /// committees sign under `version`.
    Fork {
        /// First epoch of the fork.
        epoch: u64,
        /// The fork version.
        version: [u8; 4],
    }
}

record! {
    /// The Ethereum consensus chain a light client follows.
    LightClientConfig {
        /// `genesis_validators_root` of the beacon chain.
        genesis_validators_root: Hash,
        /// Forks in ascending epoch order; the first is the earliest fork
        /// whose headers the client accepts (spec 18 §3.1).
        forks: Seq<Fork>,
        /// `SYNC_COMMITTEE_SIZE`: 512 on mainnet, 32 in the minimal preset.
        sync_committee_size: u32,
        /// `SLOTS_PER_EPOCH`.
        slots_per_epoch: u64,
        /// `EPOCHS_PER_SYNC_COMMITTEE_PERIOD`.
        epochs_per_period: u64,
    }
}

record! {
    /// How the inbox paces deliveries (spec 18 §6.3).
    InboxLimits {
        /// Seconds between the block that stores an Ethereum state root and
        /// the first delivery proven against it.
        delay: u64,
        /// Length of a rate-limit window in seconds.
        window: u64,
        /// Deliveries allowed per window.
        max_messages: u64,
    }
}

record! {
    /// Genesis parameters of the bridge, carried in
    /// `GenesisParams::bridge_in`. An empty `light_client` disables it.
    BridgeInParams {
        /// The light-client module (an Orange module, spec 03).
        light_client: Vec<u8>,
        /// The message-verifier module.
        verifier: Vec<u8>,
        /// The Ethereum chain it follows.
        config: LightClientConfig,
        /// The trusted checkpoint: an SSZ `LightClientBootstrap` (spec 18 §3.4).
        bootstrap: Vec<u8>,
        /// The `EthereumOutbox` contract on Ethereum whose messages the inbox accepts.
        outbox: Address,
        /// Delivery pacing.
        limits: InboxLimits,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn addresses_are_in_the_system_range_and_params_round_trip() {
        for a in [LIGHT_CLIENT_ADDRESS, VERIFIER_ADDRESS, INBOX_ADDRESS] {
            assert!(a[..18].iter().all(|b| *b == 0));
        }
        assert_eq!(&LIGHT_CLIENT_ADDRESS[18..], b"EL");
        assert_eq!(&INBOX_ADDRESS[18..], b"EI");
        assert_eq!(&VERIFIER_ADDRESS[18..], b"EM");
        let params = BridgeInParams {
            light_client: vec![1, 2, 3],
            verifier: vec![9],
            config: LightClientConfig {
                genesis_validators_root: [7; 32],
                forks: Seq(vec![Fork {
                    epoch: 9,
                    version: [5, 0, 0, 0],
                }]),
                sync_committee_size: 512,
                slots_per_epoch: 32,
                epochs_per_period: 256,
            },
            bootstrap: vec![4],
            outbox: [8; 20],
            limits: InboxLimits {
                delay: 1,
                window: 2,
                max_messages: 3,
            },
        };
        assert_eq!(BridgeInParams::from_bytes(&params.to_bytes()), Ok(params));
    }
}
