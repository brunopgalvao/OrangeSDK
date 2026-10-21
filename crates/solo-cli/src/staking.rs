//! The `staking` object of a genesis file: staking, epochs, slashing and the
//! threshold key of spec 15 (§2).
//!
//! ```json
//! "staking": {
//!   "epochBlocks": 20, "dkgPhaseBlocks": 5,
//!   "unbondingEpochs": 4, "maxKeyAge": 2,
//!   "minStake": "0", "maxValidators": 0,
//!   "keys": {"0x<validator id>": "0x<48-byte DKG encryption key>"}
//! }
//! ```
//!
//! `epochBlocks` is required; zero, or no `staking` object, leaves the
//! genesis validator set fixed. `dkgPhaseBlocks` (default 0) turns the
//! threshold key on; four phases must fit an epoch. With a threshold key,
//! `maxKeyAge` defaults to 2 and `unbondingEpochs` to `maxKeyAge + 2`, the
//! least spec 15 §6.7 allows; without one both default to 0. `minStake` is
//! in wei, as a balance is written in `alloc`. `keys` lists the DKG
//! encryption key of each genesis validator that takes part in the DKG, as
//! `solo key` prints it; a validator without one holds no share.

use serde_json::{Map, Value};
use solo_abi::codec::Seq;
use solo_abi::staking::{StakingParams, ValidatorKey};

fn number(fields: &Map<String, Value>, name: &str, default: u64) -> Result<u64, String> {
    match fields.get(name) {
        None => Ok(default),
        Some(n) => n.as_u64().ok_or(format!(
            "genesis: staking.{name} must be a non-negative integer"
        )),
    }
}

fn hex(text: Option<&str>, what: &str, len: usize) -> Result<Vec<u8>, String> {
    text.and_then(|s| solo_rpc::methods::parse_hex(s).ok())
        .filter(|b| b.len() == len)
        .ok_or(format!(
            "genesis: staking.keys {what} must be 0x hex of {len} bytes"
        ))
}

/// Parses `staking`; the default parameters, which leave staking off,
/// without it.
///
/// # Errors
/// A message naming the first problem.
pub fn parse_staking(v: &Value) -> Result<StakingParams, String> {
    let fields = match v.get("staking") {
        None => return Ok(StakingParams::default()),
        Some(Value::Object(fields)) => fields,
        Some(_) => return Err("genesis: staking must be an object".to_owned()),
    };
    if !fields.contains_key("epochBlocks") {
        return Err("genesis: staking.epochBlocks missing".to_owned());
    }
    let epoch_blocks = number(fields, "epochBlocks", 0)?;
    let dkg_phase_blocks = number(fields, "dkgPhaseBlocks", 0)?;
    let threshold = dkg_phase_blocks != 0;
    let max_key_age = number(fields, "maxKeyAge", if threshold { 2 } else { 0 })?;
    let unbonding_default = if threshold { max_key_age + 2 } else { 0 };
    let unbonding_epochs = number(fields, "unbondingEpochs", unbonding_default)?;
    let min_stake = fields.get("minStake").map_or(Ok(0), crate::parse_balance)?;
    let max_validators = u32::try_from(number(fields, "maxValidators", 0)?)
        .ok()
        .ok_or("genesis: staking.maxValidators too large")?;
    let mut keys = Vec::new();
    match fields.get("keys") {
        None => {}
        Some(Value::Object(entries)) => {
            for (id, key) in entries {
                keys.push(ValidatorKey {
                    id: hex(Some(id), "validator id", 32)?
                        .try_into()
                        .ok()
                        .ok_or("genesis: staking.keys validator id must be 32 bytes")?,
                    dkg_key: hex(key.as_str(), "encryption key", 48)?,
                });
            }
        }
        Some(_) => return Err("genesis: staking.keys must be an object".to_owned()),
    }
    Ok(StakingParams {
        epoch_blocks,
        unbonding_epochs,
        min_stake,
        max_validators,
        dkg_phase_blocks,
        max_key_age,
        keys: Seq(keys),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_follow_the_threshold_key() {
        assert_eq!(
            parse_staking(&serde_json::json!({})).unwrap(),
            StakingParams::default()
        );
        let plain = parse_staking(&serde_json::json!({"staking": {"epochBlocks": 8}})).unwrap();
        assert_eq!(
            (
                plain.epoch_blocks,
                plain.dkg_phase_blocks,
                plain.max_key_age,
                plain.unbonding_epochs
            ),
            (8, 0, 0, 0)
        );
        let threshold =
            parse_staking(&serde_json::json!({"staking": {"epochBlocks": 8, "dkgPhaseBlocks": 2}}))
                .unwrap();
        assert_eq!((threshold.max_key_age, threshold.unbonding_epochs), (2, 4));
        let id = format!("0x{}", "11".repeat(32));
        let key = format!("0x{}", "22".repeat(48));
        let full = parse_staking(&serde_json::json!({"staking": {
            "epochBlocks": 8, "dkgPhaseBlocks": 2, "maxKeyAge": 3, "unbondingEpochs": 9,
            "minStake": "0x10", "maxValidators": 7, "keys": {id: key}
        }}))
        .unwrap();
        assert_eq!(
            full,
            StakingParams {
                epoch_blocks: 8,
                unbonding_epochs: 9,
                min_stake: 16,
                max_validators: 7,
                dkg_phase_blocks: 2,
                max_key_age: 3,
                keys: Seq(vec![ValidatorKey {
                    id: [0x11; 32],
                    dkg_key: vec![0x22; 48],
                }]),
            }
        );
    }

    #[test]
    fn each_mistake_is_named() {
        let cases = [
            (
                serde_json::json!({"staking": 1}),
                "staking must be an object",
            ),
            (
                serde_json::json!({"staking": {}}),
                "staking.epochBlocks missing",
            ),
            (
                serde_json::json!({"staking": {"epochBlocks": -1}}),
                "staking.epochBlocks must be a non-negative integer",
            ),
            (
                serde_json::json!({"staking": {"epochBlocks": 8, "minStake": true}}),
                "balance must be a string or number",
            ),
            (
                serde_json::json!({"staking": {"epochBlocks": 8, "maxValidators": 5_000_000_000u64}}),
                "staking.maxValidators too large",
            ),
            (
                serde_json::json!({"staking": {"epochBlocks": 8, "keys": []}}),
                "staking.keys must be an object",
            ),
            (
                serde_json::json!({"staking": {"epochBlocks": 8, "keys": {"0x01": "0x02"}}}),
                "staking.keys validator id must be 0x hex of 32 bytes",
            ),
            (
                serde_json::json!({"staking": {"epochBlocks": 8, "keys": {format!("0x{}", "11".repeat(32)): "0x02"}}}),
                "staking.keys encryption key must be 0x hex of 48 bytes",
            ),
        ];
        for (v, message) in cases {
            let err = parse_staking(&v).unwrap_err();
            assert!(err.contains(message), "{v}: {err}");
        }
    }
}
