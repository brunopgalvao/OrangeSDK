//! Governance in the `solo` command (spec 13 §9): the governance fields of a
//! genesis file, and `solo gov`, which prints the calldata of a governance
//! call so that any wallet or `cast send` can carry it to the governance
//! address.
//!
//! ```json
//! "governance": "0x<key>", "upgradeDelay": 20, "epochBlocks": 100,
//! "governanceMode": "key", "votingBlocks": 1000, "timelockBlocks": 500, "quorumBps": 5000,
//! "proposalDeposit": "1000000000000000000"
//! ```
//!
//! `governanceMode` is `key` (the default, for development chains: the
//! `governance` key acts alone) or `stake` (validators vote; the key is the
//! guardian). The other fields default to zero, which leaves the stake track
//! unusable until `setParams` runs, so a chain that starts under it, or
//! means to switch to it, sets `votingBlocks` at least.
//!
//! ```sh
//! solo gov submit <target> <0x calldata>           # a proposal, or under the key an action executed at once
//! solo gov vote <id> yes|no                         # a validator's vote
//! solo gov execute <id>                             # a passed proposal, after its timelock
//! solo gov veto <id>                                # the guardian
//! solo gov pause <target>                           # the guardian
//! solo gov set-guardian <address>                   # the actions governance applies to itself,
//! solo gov set-mode stake                           # each wrapped in `submit` to the governance address
//! solo gov set-params <voting> <timelock> <quorumBps> <deposit wei>
//! ```

use serde_json::Value;
use solo_abi::governance::{Call, GOVERNANCE_ADDRESS, GovernanceParams, mode};

fn address(text: &str, what: &str) -> Result<[u8; 20], String> {
    solo_rpc::methods::parse_hex(text)
        .ok()
        .and_then(|b| <[u8; 20]>::try_from(b).ok())
        .ok_or_else(|| format!("gov: {what} must be a 0x address"))
}

fn number(text: &str, what: &str) -> Result<u64, String> {
    text.parse().ok().ok_or_else(|| format!("gov: {what} must be a number"))
}

fn wei(text: &str, what: &str) -> Result<u128, String> {
    let (digits, radix) = match text.strip_prefix("0x") {
        Some(hex) => (hex, 16),
        None => (text, 10),
    };
    if digits.is_empty() || !digits.chars().all(|c| c.is_digit(radix)) {
        return Err(format!("gov: {what} must be a decimal or 0x hex amount in wei"));
    }
    u128::from_str_radix(digits, radix)
        .ok()
        .ok_or_else(|| format!("gov: {what} must be a decimal or 0x hex amount in wei"))
}

/// The governance call `args` (the words after `solo gov`) name.
///
/// # Errors
/// A usage message naming the first problem.
pub fn parse(args: &[String]) -> Result<Call, String> {
    let word = |i: usize, what: &str| -> Result<&str, String> {
        args.get(i)
            .map(String::as_str)
            .ok_or_else(|| format!("gov: {what} missing"))
    };
    let action = |call: Call| Call::Submit {
        target: GOVERNANCE_ADDRESS,
        data: call.encode(),
    };
    Ok(match word(0, "subcommand")? {
        "submit" => Call::Submit {
            target: address(word(1, "target")?, "target")?,
            data: solo_rpc::methods::parse_hex(word(2, "calldata")?)
                .ok()
                .ok_or("gov: calldata must be 0x hex")?,
        },
        "vote" => Call::Vote {
            id: number(word(1, "proposal id")?, "proposal id")?,
            support: match word(2, "yes or no")? {
                "yes" => true,
                "no" => false,
                _ => return Err("gov: vote yes or no".to_owned()),
            },
        },
        "execute" => Call::Execute {
            id: number(word(1, "proposal id")?, "proposal id")?,
        },
        "veto" => Call::Veto {
            id: number(word(1, "proposal id")?, "proposal id")?,
        },
        "pause" => Call::Pause {
            target: address(word(1, "target")?, "target")?,
        },
        "set-guardian" => action(Call::SetGuardian {
            guardian: address(word(1, "guardian")?, "guardian")?,
        }),
        "set-mode" => match word(1, "mode")? {
            "stake" => action(Call::SetMode { mode: mode::STAKE }),
            _ => return Err("gov: the only mode to set is stake".to_owned()),
        },
        "set-params" => action(Call::SetParams {
            voting_blocks: number(word(1, "voting blocks")?, "voting blocks")?,
            timelock_blocks: number(word(2, "timelock blocks")?, "timelock blocks")?,
            quorum_bps: number(word(3, "quorum")?, "quorum")?,
            deposit: wei(word(4, "deposit")?, "deposit")?,
        }),
        other => return Err(format!("gov: unknown subcommand {other}")),
    })
}

/// What `solo gov` prints: where to send the call and its calldata.
#[must_use]
pub fn describe(call: &Call) -> String {
    format!(
        "to       {}\ncalldata {}",
        solo_rpc::methods::data(&GOVERNANCE_ADDRESS),
        solo_rpc::methods::data(&call.encode())
    )
}

/// The governance parameters of a genesis document: `governanceMode`,
/// `votingBlocks`, `timelockBlocks`, `quorumBps` and `proposalDeposit`,
/// each optional.
///
/// # Errors
/// A message naming the first problem.
pub fn parse_governance(v: &Value) -> Result<GovernanceParams, String> {
    let mode = match v.get("governanceMode").and_then(Value::as_str) {
        None | Some("key") => mode::KEY,
        Some("stake") => mode::STAKE,
        Some(_) => return Err("genesis: governanceMode must be key or stake".to_owned()),
    };
    if v.get("governanceMode").is_some_and(|m| !m.is_string()) {
        return Err("genesis: governanceMode must be key or stake".to_owned());
    }
    let number = |name: &str| match v.get(name) {
        None => Ok(0),
        Some(n) => n
            .as_u64()
            .ok_or(format!("genesis: {name} must be a non-negative integer")),
    };
    let deposit = match v.get("proposalDeposit") {
        None => 0,
        Some(Value::String(s)) => wei(s, "proposalDeposit")
            .map_err(|_| "genesis: proposalDeposit must be a decimal or 0x hex string")?,
        Some(Value::Number(n)) => n
            .as_u64()
            .ok_or("genesis: proposalDeposit must be a non-negative integer")?
            .into(),
        Some(_) => return Err("genesis: proposalDeposit must be a string or number".to_owned()),
    };
    Ok(GovernanceParams {
        mode,
        voting_blocks: number("votingBlocks")?,
        timelock_blocks: number("timelockBlocks")?,
        quorum_bps: number("quorumBps")?,
        deposit,
    })
}
