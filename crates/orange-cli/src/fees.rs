//! The `fees` object of a genesis file: the fee market of spec 23 (§2).
//!
//! ```json
//! "fees": {"denominator": 125, "elasticity": 2, "minBaseFee": "1000000000", "treasury": "0x<address>"}
//! ```
//!
//! Without a `fees` object the market is off and every block's base fee is
//! zero, which is what `orange dev`'s example genesis keeps so that
//! transactions at a gas price of zero keep working. `orange devnet init`
//! writes the production defaults: a denominator of 125, an elasticity of
//! 2, a floor of one gwei and a burned base fee. `denominator` is 0 (the
//! market off, with `elasticity` 0) or 100 to 125, and `elasticity` 2 to
//! 4, as the kernel's `kernel_init` requires; `minBaseFee` is in wei, as a
//! balance is written in `alloc`, at most 1 000 gwei; `treasury` names the
//! account the base fee is credited to, never the staking address, and is
//! absent, or the zero address, when it is burned.

use orange_abi::Decode;
use orange_abi::chain::{GenesisParams, ValidatorSet};
use orange_abi::fees::{
    DEFAULT_DENOMINATOR, DEFAULT_ELASTICITY, DEFAULT_MIN_BASE_FEE, FeeParams, MAX_MIN_BASE_FEE,
};
use orange_abi::staking::STAKING_ADDRESS;
use orange_abi::types::Genesis;
use serde_json::{Map, Value, json};
use std::io::Write;

fn number(fields: &Map<String, Value>, name: &str) -> Result<u64, String> {
    match fields.get(name) {
        None => Ok(0),
        Some(n) => n.as_u64().ok_or(format!(
            "genesis: fees.{name} must be a non-negative integer"
        )),
    }
}

/// Parses `fees`; the default parameters, which leave the market off at a
/// zero base fee, without it.
///
/// # Errors
/// A message naming the first problem.
pub fn parse_fees(v: &Value) -> Result<FeeParams, String> {
    let fields = match v.get("fees") {
        None => return Ok(FeeParams::default()),
        Some(Value::Object(fields)) => fields,
        Some(_) => return Err("genesis: fees must be an object".to_owned()),
    };
    let min_base_fee = fields
        .get("minBaseFee")
        .map_or(Ok(0), crate::parse_balance)
        .map_err(|e| e.replace("balance", "fees.minBaseFee"))?;
    let min_base_fee = u64::try_from(min_base_fee)
        .ok()
        .ok_or("genesis: fees.minBaseFee must be below 2^64 wei")?;
    let treasury = match fields.get("treasury") {
        None => [0; 20],
        Some(text) => text
            .as_str()
            .and_then(|t| orange_rpc::methods::parse_hex(t).ok())
            .and_then(|b| <[u8; 20]>::try_from(b).ok())
            .ok_or("genesis: fees.treasury must be a 0x address")?,
    };
    let params = FeeParams {
        denominator: number(fields, "denominator")?,
        elasticity: number(fields, "elasticity")?,
        min_base_fee,
        treasury,
    };
    // The kernel refuses to start with parameters that cannot work (spec 23
    // §2); say so here, before a node traps in `kernel_init`.
    match unworkable(&params, "fees.") {
        Some(why) => Err(format!("genesis: {why}")),
        None => Ok(params),
    }
}

/// Why `params` cannot work (spec 23 §2), naming each field behind
/// `prefix`; `None` when they can.
#[must_use]
pub fn unworkable(params: &FeeParams, prefix: &str) -> Option<String> {
    if params.workable() {
        return None;
    }
    Some(if params.min_base_fee > MAX_MIN_BASE_FEE {
        format!(
            "{prefix}minBaseFee must be at most {MAX_MIN_BASE_FEE} wei (1 000 gwei, spec 23 §2)"
        )
    } else if params.treasury == STAKING_ADDRESS {
        format!(
            "{prefix}treasury must not be the staking address, where nothing pays a base fee out (spec 23 §2)"
        )
    } else {
        format!(
            "{prefix}denominator must be 0 (the market off, with {prefix}elasticity 0) or 100 to 125 with {prefix}elasticity 2 to 4 (spec 23 §2)"
        )
    })
}

/// Writes to `log` the warning `orange node` gives at start (spec 23 §2.1)
/// when `genesis` names more than one validator and leaves every base fee
/// at zero: transactions, and every way of spamming the chain, then cost
/// nothing. A genesis that does not decode is the kernel's to refuse.
pub fn warn_free(genesis: &Genesis, log: &mut dyn Write) {
    let validators =
        ValidatorSet::from_bytes(&genesis.validators).map_or(0, |s| s.validators.0.len());
    let fees = GenesisParams::from_bytes(&genesis.params)
        .map(|p| p.fees)
        .unwrap_or_default();
    if validators > 1 && !fees.market_on() && fees.min_base_fee == 0 {
        let _ = writeln!(
            log,
            "WARNING: this genesis has {validators} validators and no fee market (no `fees` object, or one with the market off and no floor): every base fee is zero, so transactions, and spam of the pools and blocks, cost nothing; give the genesis a `fees` object (spec 23 §2.1)"
        );
    }
}

/// The `fees` object of the production defaults, which `orange devnet init`
/// writes: [`FeeParams::production`].
#[must_use]
pub fn production_json() -> Value {
    json!({
        "denominator": DEFAULT_DENOMINATOR,
        "elasticity": DEFAULT_ELASTICITY,
        "minBaseFee": DEFAULT_MIN_BASE_FEE.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_and_the_full_object() {
        assert_eq!(parse_fees(&json!({})).unwrap(), FeeParams::default());
        let production = json!({ "fees": production_json() });
        assert_eq!(parse_fees(&production).unwrap(), FeeParams::production());
        let treasury = format!("0x{}", "ab".repeat(20));
        let full = parse_fees(&json!({"fees": {
            "denominator": 100, "elasticity": 4, "minBaseFee": "0x10", "treasury": treasury
        }}))
        .unwrap();
        assert_eq!(
            full,
            FeeParams {
                denominator: 100,
                elasticity: 4,
                min_base_fee: 16,
                treasury: [0xAB; 20],
            }
        );
        let off = parse_fees(&json!({"fees": {"minBaseFee": 7}})).unwrap();
        assert_eq!(
            off,
            FeeParams {
                min_base_fee: 7,
                ..FeeParams::default()
            }
        );
    }

    /// `orange node` warns at start when a genesis of several validators
    /// leaves the base fee at zero for ever (spec 23 §2.1).
    #[test]
    fn a_free_chain_of_several_validators_is_warned_about() {
        let warned = |text: Value| {
            let genesis = crate::parse_genesis(&text.to_string()).unwrap();
            let mut log = Vec::new();
            warn_free(&genesis, &mut log);
            String::from_utf8(log).unwrap()
        };
        let ids = json!([
            format!("0x{}", "11".repeat(32)),
            format!("0x{}", "22".repeat(32))
        ]);
        let free = warned(json!({ "chainId": 7, "validators": ids }));
        assert!(free.starts_with("WARNING: "), "{free}");
        assert!(free.contains("2 validators"), "{free}");
        assert!(free.contains("no fee market"), "{free}");
        // An explicit market that is off with no floor is as free.
        let off = json!({ "chainId": 7, "validators": ids, "fees": {} });
        assert_eq!(warned(off), free);
        // A market, a floor, or one validator: nothing.
        let market = json!({ "chainId": 7, "validators": ids, "fees": production_json() });
        assert_eq!(warned(market), "");
        let floor = json!({ "chainId": 7, "validators": ids, "fees": {"minBaseFee": 7} });
        assert_eq!(warned(floor), "");
        assert_eq!(warned(json!({ "chainId": 7 })), "");
    }

    #[test]
    fn each_mistake_is_named() {
        let cases = [
            (json!({"fees": 1}), "fees must be an object"),
            (
                json!({"fees": {"denominator": -1}}),
                "fees.denominator must be a non-negative integer",
            ),
            (
                json!({"fees": {"elasticity": "two"}}),
                "fees.elasticity must be a non-negative integer",
            ),
            (
                json!({"fees": {"minBaseFee": true}}),
                "fees.minBaseFee must be a string or number",
            ),
            (
                json!({"fees": {"minBaseFee": "x"}}),
                "fees.minBaseFee must be a decimal or 0x hex string",
            ),
            (
                json!({"fees": {"minBaseFee": "0x10000000000000000"}}),
                "fees.minBaseFee must be below 2^64 wei",
            ),
            (
                json!({"fees": {"treasury": "0x01"}}),
                "fees.treasury must be a 0x address",
            ),
            (
                json!({"fees": {"treasury": 5}}),
                "fees.treasury must be a 0x address",
            ),
            (
                json!({"fees": {"denominator": 99, "elasticity": 2}}),
                "fees.denominator must be 0",
            ),
            (
                json!({"fees": {"denominator": 125, "elasticity": 5}}),
                "fees.denominator must be 0",
            ),
            (
                json!({"fees": {"elasticity": 2}}),
                "fees.denominator must be 0",
            ),
            (
                json!({"fees": {"minBaseFee": "1000000000001"}}),
                "fees.minBaseFee must be at most 1000000000000 wei",
            ),
            (
                json!({"fees": {"treasury": "0x0000000000000000000000000000000000005354"}}),
                "fees.treasury must not be the staking address",
            ),
        ];
        for (v, message) in cases {
            let err = parse_fees(&v).unwrap_err();
            assert!(err.contains(message), "{v}: {err}");
        }
    }
}
