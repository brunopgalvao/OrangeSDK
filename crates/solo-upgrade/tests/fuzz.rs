//! Seeded fuzzing of the upgrade actions' calldata and the upgrade records
//! (spec 13): mutated bytes never panic a decoder, and whatever one accepts
//! re-encodes to exactly its input. See `solo-fuzz` for the long mode.

use std::fmt::Debug;

use solo_abi::{Decode, Encode};
use solo_fuzz::{evolve, zero_seeds};
use solo_upgrade::{
    Action, EnactedUpgrade, PendingUpgrade, Signal, UpgradeStatus, ValidatorSignal,
};

#[test]
fn actions_decode_only_canonical_calldata() {
    let seeds = vec![
        Action::Stage {
            code_hash: [1; 32],
            index: 2,
            chunk: vec![3; 45],
        }
        .encode(),
        Action::Stage {
            code_hash: [1; 32],
            index: 0,
            chunk: vec![3; 32],
        }
        .encode(),
        Action::Propose {
            code_hash: [4; 32],
            activation_height: 100,
            required_gates: 5,
        }
        .encode(),
        Action::Cancel { code_hash: [6; 32] }.encode(),
        Action::Signal { features: 7 }.encode(),
    ];
    let accepted = evolve("upgrade-actions", 4_000, seeds, |bytes| {
        let Some(action) = Action::decode(bytes) else {
            return false;
        };
        assert_eq!(action.encode(), bytes, "{action:?} is not canonical");
        true
    });
    assert!(accepted > 300, "{accepted}");
}

fn codec<T: Encode + Decode + PartialEq + Debug>(name: &str) {
    evolve(name, 600, zero_seeds(3, 120), |bytes| {
        let Ok(value) = T::from_bytes(bytes) else {
            return false;
        };
        assert_eq!(
            value.to_bytes(),
            bytes,
            "{name}: {value:?} is not canonical"
        );
        true
    });
}

#[test]
fn records_decode_only_canonical_bytes() {
    codec::<PendingUpgrade>("upgrade-pending");
    codec::<EnactedUpgrade>("upgrade-enacted");
    codec::<Signal>("upgrade-signal");
    codec::<ValidatorSignal>("upgrade-validator-signal");
    codec::<UpgradeStatus>("upgrade-status");
}
