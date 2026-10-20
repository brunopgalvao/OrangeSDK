//! The `bridgeIn` object of a genesis file: the Ethereum-to-Solo bridge of
//! spec 18.
//!
//! ```json
//! "bridgeIn": {
//!   "lightClient": "0x<Solo module>", "verifier": "0x<Solo module>",
//!   "genesisValidatorsRoot": "0x<32 bytes>",
//!   "forks": [{"epoch": 364032, "version": "0x05000000"}, {"epoch": 411392, "version": "0x06000000"}],
//!   "syncCommitteeSize": 512, "slotsPerEpoch": 32, "epochsPerPeriod": 256,
//!   "bootstrap": "0x<SSZ LightClientBootstrap>",
//!   "outbox": "0x<EthereumOutbox address>",
//!   "delay": 600, "window": 3600, "maxMessages": 100
//! }
//! ```
//!
//! The two modules are the outputs of `solo-recompile` for
//! `guest/modules/eth-light-client` and `guest/modules/eth-message-verifier`.
//! Every field is required except the three preset numbers, which default
//! to Ethereum mainnet's. Without `bridgeIn` the bridge is off.

use serde_json::{Map, Value};
use solo_abi::bridge_in::{BridgeInParams, Fork, InboxLimits, LightClientConfig};
use solo_abi::codec::Seq;

fn hex(fields: &Map<String, Value>, name: &str) -> Result<Vec<u8>, String> {
    fields
        .get(name)
        .and_then(Value::as_str)
        .and_then(|s| solo_rpc::methods::parse_hex(s).ok())
        .ok_or(format!("genesis: bridgeIn.{name} must be 0x hex"))
}

fn number(fields: &Map<String, Value>, name: &str, default: Option<u64>) -> Result<u64, String> {
    match fields.get(name) {
        None => default.ok_or(format!("genesis: bridgeIn.{name} missing")),
        Some(n) => n.as_u64().ok_or(format!(
            "genesis: bridgeIn.{name} must be a non-negative integer"
        )),
    }
}

fn fork(entry: &Value) -> Result<Fork, String> {
    let fields = entry
        .as_object()
        .ok_or("genesis: a bridgeIn fork must be an object")?;
    let version = hex(fields, "version")?
        .try_into()
        .ok()
        .ok_or("genesis: a bridgeIn fork version must be 4 bytes")?;
    Ok(Fork {
        epoch: number(fields, "epoch", None)?,
        version,
    })
}

/// Parses `bridgeIn`; the default parameters, which leave the bridge off,
/// without it.
///
/// # Errors
/// A message naming the first problem.
pub fn parse_bridge(v: &Value) -> Result<BridgeInParams, String> {
    let fields = match v.get("bridgeIn") {
        None => return Ok(BridgeInParams::default()),
        Some(Value::Object(fields)) => fields,
        Some(_) => return Err("genesis: bridgeIn must be an object".to_owned()),
    };
    let forks = fields
        .get("forks")
        .and_then(Value::as_array)
        .ok_or("genesis: bridgeIn.forks must be an array")?
        .iter()
        .map(fork)
        .collect::<Result<Vec<Fork>, String>>()?;
    let size = u32::try_from(number(fields, "syncCommitteeSize", Some(512))?)
        .ok()
        .ok_or("genesis: bridgeIn.syncCommitteeSize too large")?;
    Ok(BridgeInParams {
        light_client: hex(fields, "lightClient")?,
        verifier: hex(fields, "verifier")?,
        config: LightClientConfig {
            genesis_validators_root: hex(fields, "genesisValidatorsRoot")?
                .try_into()
                .ok()
                .ok_or("genesis: bridgeIn.genesisValidatorsRoot must be 32 bytes")?,
            forks: Seq(forks),
            sync_committee_size: size,
            slots_per_epoch: number(fields, "slotsPerEpoch", Some(32))?,
            epochs_per_period: number(fields, "epochsPerPeriod", Some(256))?,
        },
        bootstrap: hex(fields, "bootstrap")?,
        outbox: hex(fields, "outbox")?
            .try_into()
            .ok()
            .ok_or("genesis: bridgeIn.outbox must be 20 bytes")?,
        limits: InboxLimits {
            delay: number(fields, "delay", None)?,
            window: number(fields, "window", None)?,
            max_messages: number(fields, "maxMessages", None)?,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full() -> Value {
        serde_json::json!({"bridgeIn": {
            "lightClient": "0x01", "verifier": "0x02",
            "genesisValidatorsRoot": format!("0x{}", "42".repeat(32)),
            "forks": [{"epoch": 5, "version": "0x05000000"}],
            "bootstrap": "0x0304", "outbox": format!("0x{}", "aa".repeat(20)),
            "delay": 6, "window": 7, "maxMessages": 8
        }})
    }

    #[test]
    fn a_full_object_parses_with_mainnet_defaults() {
        let p = parse_bridge(&full()).unwrap();
        assert_eq!(
            (p.light_client, p.verifier, p.bootstrap),
            (vec![1], vec![2], vec![3, 4])
        );
        assert_eq!(
            p.config.forks.0,
            vec![Fork {
                epoch: 5,
                version: [5, 0, 0, 0]
            }]
        );
        assert_eq!(
            (
                p.config.sync_committee_size,
                p.config.slots_per_epoch,
                p.config.epochs_per_period
            ),
            (512, 32, 256)
        );
        assert_eq!(
            (p.outbox, p.config.genesis_validators_root),
            ([0xAA; 20], [0x42; 32])
        );
        assert_eq!(
            p.limits,
            InboxLimits {
                delay: 6,
                window: 7,
                max_messages: 8
            }
        );
        assert_eq!(
            parse_bridge(&serde_json::json!({})).unwrap(),
            BridgeInParams::default()
        );
    }

    #[test]
    fn each_mistake_is_named() {
        let cases: [(&str, Value, &str); 10] = [
            ("", Value::from(1), "bridgeIn must be an object"),
            ("forks", Value::from(1), "bridgeIn.forks must be an array"),
            ("forks", serde_json::json!([1]), "fork must be an object"),
            (
                "forks",
                serde_json::json!([{"epoch": 1, "version": "0x01"}]),
                "version must be 4 bytes",
            ),
            (
                "forks",
                serde_json::json!([{"version": "0x01020304"}]),
                "bridgeIn.epoch missing",
            ),
            (
                "syncCommitteeSize",
                Value::from(u64::MAX),
                "syncCommitteeSize too large",
            ),
            (
                "delay",
                Value::from(-1),
                "bridgeIn.delay must be a non-negative integer",
            ),
            (
                "genesisValidatorsRoot",
                Value::from("0x01"),
                "genesisValidatorsRoot must be 32 bytes",
            ),
            ("outbox", Value::from("0x01"), "outbox must be 20 bytes"),
            (
                "bootstrap",
                Value::from(1),
                "bridgeIn.bootstrap must be 0x hex",
            ),
        ];
        for (field, value, message) in cases {
            let mut v = full();
            if field.is_empty() {
                v["bridgeIn"] = value;
            } else {
                v["bridgeIn"][field] = value;
            }
            let err = parse_bridge(&v).unwrap_err();
            assert!(err.contains(message), "{field}: {err}");
        }
        let mut v = full();
        v["bridgeIn"].as_object_mut().unwrap().remove("maxMessages");
        assert!(
            parse_bridge(&v)
                .unwrap_err()
                .contains("bridgeIn.maxMessages missing")
        );
    }
}
