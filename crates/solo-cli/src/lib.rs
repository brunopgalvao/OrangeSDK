//! The `solo` command.
//!
//! `solo dev --kernel <kernel.elf|kernel.solo> --genesis <genesis.json>
//! [--rpc 127.0.0.1:8545] [--blocks <n>] [--kernel-gas <n>] [--query-gas <n>]
//! [--state-history <blocks> | --archive] [--data-dir <dir>]`
//! runs a single-node development chain with Ethereum JSON-RPC. The node keeps
//! the state of its latest 1 024 blocks for historical queries and proofs, or
//! `--state-history` of them, or every block's with `--archive` (spec 20 §5).
//! `--data-dir` keeps the node's data on disk: the driver's node-local data
//! ([`solo_node::DriverStore`]), so that a node started again over the same
//! directory resumes the view it left with the votes it cast there and never
//! votes twice in one view (spec 08 §3 and §7), and the chain state
//! ([`solo_store::DiskStore`], spec 22), so that it resumes from the block it
//! had executed without executing anything again, its history and proofs
//! intact; `solo node` requires it for a validator. `--snapshot <file>`
//! starts a node whose directory holds no chain yet from a verified snapshot
//! (see [`snapshot`]), and `solo snapshot` exports, verifies and imports one.
//! `solo node --sync-from-peers` fetches one from its `--peer`s instead
//! (spec 22 §7.4), and `--serve-snapshots` serves them to such nodes.
//! `solo node` runs peer exchange (spec 09 §5a) unless `--no-discovery`: it
//! learns the network from its `--peer`s and `--bootstrap` addresses, keeps
//! up to `--outbound-peers` connections it dials itself and `--max-peers` in
//! all, and advertises `--advertise` (by default its listen address) in a
//! record signed with its key.
//! The genesis file is
//! JSON: `{"chainId": 1337, "slotMs": 400, "maxTxs": 64,
//! "alloc": {"0x<address>": "<wei>"}, "validators": ["0x<32-byte id>"]}`.
//! An `alloc` entry is a balance, or a geth-style account that predeploys a
//! contract: `{"balance": "<wei>", "nonce": "0x1", "code": "0x<bytecode>",
//! "storage": {"0x<slot>": "0x<value>"}}`, every field optional. An
//! optional `"timestamp"`, Unix seconds as geth writes it, is the genesis
//! time (spec 20 §3.4); `solo dev` without `--data-dir` gives a genesis
//! without one the time it starts. Without
//! `validators` the dev node is the only validator, signing with
//! [`DEV_KEY_SEED`]. Governed upgrades and feature gates (spec 13) are off
//! unless the file names a `"governance"` address (with an optional
//! `"upgradeDelay"` in blocks) or a non-zero `"epochBlocks"`. Governance runs
//! under the key track unless `"governanceMode"` says `"stake"`; see [`gov`],
//! which also has `solo gov`, the encoder of governance calls. Kernel modules
//! installed at genesis (spec 16) are listed under `"modules"`; see [`modules`].
//! The Ethereum-to-Solo bridge (spec 18) is configured under `"bridgeIn"`;
//! see [`bridge`]. Staking, epochs and the threshold key (spec 15) under
//! `"staking"`; see [`staking`]. The fee market (spec 23) under `"fees"`;
//! see [`fees`]: without it the base fee is zero, as a development chain
//! wants it.
//!
//! `solo upgrade` stages and proposes a kernel upgrade through governance
//! (see [`upgrade`]), and `solo devnet` runs a network of validator
//! processes on one machine and watches it (see [`devnet`]).

#![forbid(unsafe_code)]

pub mod bridge;
pub mod client;
pub mod devnet;
pub mod doctor;
pub mod fees;
pub mod gov;
pub mod modules;
pub mod snapshot;
pub mod staking;
pub mod upgrade;

use std::cell::Cell;
use std::rc::Rc;
use std::time::{Duration, Instant};

use serde_json::Value;
use solo_abi::chain::{
    Allocation, GenesisParams, StorageSlot, UpgradeParams, Validator, ValidatorSet,
};
use solo_abi::codec::Seq;
use solo_abi::types::Genesis;
use solo_abi::{Decode, Encode};

/// A message for the user.
#[derive(Debug)]
struct CliError(String);

impl From<String> for CliError {
    fn from(message: String) -> CliError {
        CliError(message)
    }
}

impl From<&str> for CliError {
    fn from(message: &str) -> CliError {
        CliError(message.to_owned())
    }
}

impl From<solo_node::NodeError> for CliError {
    fn from(e: solo_node::NodeError) -> CliError {
        CliError(e.to_string())
    }
}

/// Seed of the development node's consensus key.
pub const DEV_KEY_SEED: [u8; 32] = [0x42; 32];

/// The development node's consensus key.
///
/// # Panics
/// Never: the seed is a valid scalar.
#[must_use]
pub fn dev_key() -> k256::ecdsa::SigningKey {
    k256::ecdsa::SigningKey::from_slice(&DEV_KEY_SEED).expect("valid seed")
}

/// Where the JSON-RPC server listens unless `--rpc` says otherwise.
pub const DEFAULT_RPC: &str = "127.0.0.1:8545";

/// Usage line printed on a command-line mistake.
pub const USAGE: &str = "usage:
  solo dev  --kernel <kernel.elf|kernel.solo> --genesis <genesis.json> [--rpc 127.0.0.1:8545] [--blocks <n>] [--kernel-gas <n>] [--query-gas <n>] [--state-history <blocks> | --archive] [--data-dir <dir>]
  solo node --kernel <kernel.elf|kernel.solo> --genesis <genesis.json> [--key <64 hex> | --key-file <path>] [--data-dir <dir>] [--snapshot <file> | --sync-from-peers] [--trust-key <0x 96 bytes>] [--serve-snapshots] [--listen 127.0.0.1:30333] [--peer <addr>]... [--bootstrap <addr>]... [--max-peers 32] [--outbound-peers 8] [--advertise <addr>] [--no-discovery] [--rpc 127.0.0.1:8545] [--blocks <n>] [--query-gas <n>] [--state-history <blocks> | --archive]
  solo key  <64 hex>
  solo snapshot export --data-dir <dir> --out <file> [--epoch <n>] | verify --snapshot <file> --genesis <genesis.json> [--trust-key <0x 96 bytes>] | import --snapshot <file> --data-dir <dir> --kernel <kernel> --genesis <genesis.json> [--trust-key <0x 96 bytes>]
  solo gov  submit <target> <0x calldata> | vote <id> yes|no | execute <id> | veto <id> | pause <target> | set-guardian <address> | set-mode stake | set-params <voting> <timelock> <quorumBps> <deposit> | set-fee-params <denominator> <elasticity> <minBaseFee> <treasury|burn>
  solo doctor [--rpc 127.0.0.1:8545] [--max-head-age <s>] [--max-finality-lag <blocks>] [--min-peers <n>] [--max-mempool <txs>] [--max-call-ms <ms>]
  solo upgrade --kernel <kernel.elf|kernel.solo> (--key <64 hex> | --key-file <path>) [--rpc 127.0.0.1:8545] [--delay <blocks>] [--required-gates <g,g,...>] [--timeout <s>]
  solo devnet init --dir <dir> --kernel <kernel.elf|kernel.solo> [--validators 4] [--chain-id 1337] [--slot-ms 400] [--epoch-blocks 20] [--dkg-phase-blocks 5] [--upgrade-delay 2] [--host 127.0.0.1] [--p2p-port 30301] [--rpc-port 8545] [--seed <64 hex>] [--governance-key <64 hex>] [--force]
  solo devnet up --dir <dir> [--blocks <n>]
  solo devnet down --dir <dir>
  solo devnet stop|start --dir <dir> --node <i>
  solo devnet status (--dir <dir> | --rpc <addr,...>) [--json]
  solo devnet wait (--dir <dir> | --rpc <addr,...>) [--nodes <i,...>] [--timeout <s>] [--head <n>] [--finalized <n>] [--peers <n>] [--kernel-version <v>] [--kernel-hash <0x...>] [--active-gates <g,...>] [--signalled <g,...>] [--locked-in <g,...>] [--certified <n> --above <height>] [--caught-up] [--no-equivocations]
  solo devnet node --dir <dir> --index <i> [solo node options]";

/// Where `solo node` listens for peers unless `--listen` says otherwise.
pub const DEFAULT_LISTEN: &str = "127.0.0.1:30333";

/// Parses a genesis JSON document.
///
/// # Errors
/// A message naming the first problem.
pub fn parse_genesis(text: &str) -> Result<Genesis, String> {
    let Ok(v) = serde_json::from_str::<Value>(text) else {
        return Err("genesis: not valid JSON".to_owned());
    };
    let chain_id = v
        .get("chainId")
        .and_then(Value::as_u64)
        .ok_or("genesis: chainId missing")?;
    let slot_ms = v.get("slotMs").and_then(Value::as_u64).unwrap_or(400);
    let max_txs = v.get("maxTxs").and_then(Value::as_u64).unwrap_or(64);
    let mut allocations = Vec::new();
    if let Some(alloc) = v.get("alloc").and_then(Value::as_object) {
        for (address, entry) in alloc {
            let bytes = solo_rpc::methods::parse_hex(address)
                .ok()
                .ok_or("genesis: alloc address must be 0x hex")?;
            let address = <[u8; 20]>::try_from(bytes)
                .ok()
                .ok_or("genesis: alloc address must be 20 bytes")?;
            allocations.push(parse_account(address, entry)?);
        }
    }
    let modules = modules::parse_modules(&v, &mut allocations)?;
    let params = GenesisParams {
        slot_ms,
        max_txs: u32::try_from(max_txs)
            .ok()
            .ok_or("genesis: maxTxs too large")?,
        allocations: Seq(allocations),
        upgrades: parse_upgrades(&v)?,
        staking: staking::parse_staking(&v)?,
        bridge_in: bridge::parse_bridge(&v)?,
        governance: gov::parse_governance(&v)?,
        fees: fees::parse_fees(&v)?,
        genesis_time: parse_timestamp(&v)?,
    };
    let mut validators = Vec::new();
    match v.get("validators") {
        None => validators.push(Validator {
            id: solo_node::validator_id(&dev_key()),
            weight: 1,
        }),
        Some(Value::Array(ids)) => {
            for id in ids {
                let text = id
                    .as_str()
                    .ok_or("genesis: validator ids must be strings")?;
                let bytes = solo_rpc::methods::parse_hex(text)
                    .ok()
                    .ok_or("genesis: validator id must be 0x hex")?;
                let id = <[u8; 32]>::try_from(bytes)
                    .ok()
                    .ok_or("genesis: validator id must be 32 bytes")?;
                validators.push(Validator { id, weight: 1 });
            }
        }
        Some(_) => return Err("genesis: validators must be an array".to_owned()),
    }
    Ok(Genesis {
        chain_id,
        fee_schedule: vec![],
        modules: Seq(modules),
        params: params.to_bytes(),
        validators: ValidatorSet {
            validators: Seq(validators),
        }
        .to_bytes(),
    })
}

/// One `alloc` entry: a balance alone, or a geth-style account object
/// `{"balance", "nonce", "code", "storage"}` for a predeploy.
fn parse_account(address: [u8; 20], entry: &Value) -> Result<Allocation, String> {
    let Value::Object(fields) = entry else {
        return Ok(Allocation {
            address,
            balance: parse_balance(entry)?,
            ..Allocation::default()
        });
    };
    let balance = fields.get("balance").map_or(Ok(0), parse_balance)?;
    let nonce = match fields.get("nonce") {
        None => 0,
        Some(Value::Number(n)) => n
            .as_u64()
            .ok_or("genesis: nonce must be a non-negative integer")?,
        Some(Value::String(s)) => parse_number_text(s)
            .and_then(|n| u64::try_from(n).ok())
            .ok_or("genesis: nonce must be a decimal or 0x hex string")?,
        Some(_) => return Err("genesis: nonce must be a string or number".to_owned()),
    };
    let code = match fields.get("code") {
        None => Vec::new(),
        Some(code) => code
            .as_str()
            .and_then(|s| solo_rpc::methods::parse_hex(s).ok())
            .ok_or("genesis: code must be 0x hex")?,
    };
    let mut storage = Vec::new();
    match fields.get("storage") {
        None => {}
        Some(Value::Object(slots)) => {
            for (key, value) in slots {
                storage.push(StorageSlot {
                    key: parse_word(Some(key))?,
                    value: parse_word(value.as_str())?,
                });
            }
        }
        Some(_) => return Err("genesis: storage must be an object".to_owned()),
    }
    // A CREATE can land on an account with neither code nor nonce, and revm leaves
    // out EIP-7610, so the reference kernel refuses storage on such an account.
    if code.is_empty() && nonce == 0 && storage.iter().any(|slot| slot.value != [0; 32]) {
        return Err("genesis: an account with storage needs code or a non-zero nonce".to_owned());
    }
    Ok(Allocation {
        address,
        balance,
        nonce,
        code,
        storage: Seq(storage),
    })
}

/// A balance: a decimal or `0x` hex string, or a JSON number.
pub(crate) fn parse_balance(value: &Value) -> Result<u128, String> {
    Ok(match value {
        Value::String(s) => {
            parse_number_text(s).ok_or("genesis: balance must be a decimal or 0x hex string")?
        }
        Value::Number(n) => n
            .as_u64()
            .ok_or("genesis: balance must be a non-negative integer")?
            .into(),
        _ => return Err("genesis: balance must be a string or number".to_owned()),
    })
}

/// The genesis time, `timestamp` in Unix seconds as geth writes it (a
/// number, or a decimal or `0x` hex string); zero, no time, without one
/// (spec 20 §3.4).
fn parse_timestamp(v: &Value) -> Result<u64, String> {
    let Some(value) = v.get("timestamp") else {
        return Ok(0);
    };
    let seconds = match value {
        Value::String(s) => parse_number_text(s).and_then(|n| u64::try_from(n).ok()),
        other => other.as_u64(),
    };
    seconds.ok_or(
        "genesis: timestamp must be Unix seconds, a number or a decimal or 0x hex string"
            .to_owned(),
    )
}

/// `genesis` with the genesis time `seconds`, for a `solo dev` chain that
/// lives in memory and whose genesis names no time: it starts now.
fn timed(mut genesis: Genesis, seconds: u64) -> Genesis {
    let mut params = GenesisParams::from_bytes(&genesis.params).unwrap_or_default();
    if params.genesis_time == 0 {
        params.genesis_time = seconds;
        genesis.params = params.to_bytes();
    }
    genesis
}

/// A number written in decimal or as `0x` hex.
fn parse_number_text(text: &str) -> Option<u128> {
    let (digits, radix) = match text.strip_prefix("0x") {
        Some(hex) => (hex, 16),
        None => (text, 10),
    };
    // `from_str_radix` alone would also take a leading `+`.
    if digits.chars().all(|c| c.is_digit(radix)) {
        u128::from_str_radix(digits, radix).ok()
    } else {
        None
    }
}

/// A storage key or value: `0x` hex of at most 32 bytes, left-padded with zeros, as geth reads it.
fn parse_word(text: Option<&str>) -> Result<[u8; 32], String> {
    let bytes = text
        .and_then(|s| solo_rpc::methods::parse_hex(s).ok())
        .filter(|b| b.len() <= 32)
        .ok_or("genesis: storage keys and values must be 0x hex of at most 32 bytes")?;
    let mut word = [0u8; 32];
    word[32 - bytes.len()..].copy_from_slice(&bytes);
    Ok(word)
}

/// The upgrade parameters of a genesis document: `governance`, `upgradeDelay`
/// and `epochBlocks`, each optional.
fn parse_upgrades(v: &Value) -> Result<UpgradeParams, String> {
    let governance = match v.get("governance") {
        None => [0; 20],
        Some(text) => text
            .as_str()
            .and_then(|t| solo_rpc::methods::parse_hex(t).ok())
            .and_then(|b| <[u8; 20]>::try_from(b).ok())
            .ok_or("genesis: governance must be a 0x address")?,
    };
    let number = |name: &str| match v.get(name) {
        None => Ok(0),
        Some(n) => n
            .as_u64()
            .ok_or(format!("genesis: {name} must be a non-negative integer")),
    };
    Ok(UpgradeParams {
        governance,
        min_delay: number("upgradeDelay")?,
        epoch_blocks: number("epochBlocks")?,
    })
}

/// Parses a 32-byte secp256k1 secret key from hex, with or without `0x`.
///
/// # Errors
/// A message if it is not 32 bytes of hex or not a valid scalar.
pub fn parse_key(text: &str) -> Result<k256::ecdsa::SigningKey, String> {
    let hex = if text.starts_with("0x") {
        text.to_owned()
    } else {
        format!("0x{text}")
    };
    let bytes = solo_rpc::methods::parse_hex(&hex)
        .ok()
        .ok_or("key: expected 64 hex digits")?;
    k256::ecdsa::SigningKey::from_slice(&bytes)
        .ok()
        .ok_or_else(|| "key: not a valid secp256k1 secret key".to_owned())
}

/// What `solo key` prints: the validator id for genesis, the Ethereum
/// address, and the DKG encryption key to list under `staking.keys` (spec
/// 15 §2).
#[must_use]
pub fn describe_key(key: &k256::ecdsa::SigningKey) -> String {
    let id = solo_node::validator_id(key);
    format!(
        "validator {}\naddress   {}\ndkg       {}",
        solo_rpc::methods::data(&id),
        solo_rpc::methods::data(&id[12..]),
        solo_rpc::methods::data(&solo_node::keystore::encryption_key(key))
    )
}

/// The consensus key named by `--key <hex>` or `--key-file <path>`, if either
/// is given.
///
/// # Errors
/// A message if both are given, the file cannot be read, or the key does not parse.
pub fn key_argument(args: &[String]) -> Result<Option<k256::ecdsa::SigningKey>, String> {
    match (arg(args, "--key"), arg(args, "--key-file")) {
        (Some(_), Some(_)) => Err("--key and --key-file exclude each other".to_owned()),
        (Some(hex), None) => parse_key(&hex).map(Some),
        (None, Some(path)) => match std::fs::read_to_string(&path) {
            Ok(text) => parse_key(text.trim()).map(Some),
            Err(e) => Err(format!("{path}: {e}")),
        },
        (None, None) => Ok(None),
    }
}

/// Every value following an occurrence of `name` in `args`.
#[must_use]
pub fn args_all(args: &[String], name: &str) -> Vec<String> {
    args.windows(2)
        .filter(|w| w[0] == name)
        .map(|w| w[1].clone())
        .collect()
}

/// The value following `name` in `args`, if any.
#[must_use]
pub fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1).cloned())
}

/// Reads a kernel from disk: a `.solo` module is used as is, an ELF is recompiled.
///
/// # Errors
/// A message naming the file and the problem.
pub fn load_kernel(path: &str) -> Result<Vec<u8>, String> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) => return Err(format!("{path}: {e}")),
    };
    if bytes.starts_with(b"SOLO") {
        return Ok(bytes);
    }
    let input = match solo_recompile::Input::load(&bytes) {
        Ok(input) => input,
        Err(e) => return Err(format!("{path}: {e}")),
    };
    match solo_recompile::recompile(&input, &solo_recompile::Options::default()) {
        Ok(module) => Ok(module),
        Err(e) => Err(format!("{path}: {e}")),
    }
}

pub(crate) fn parse_number(args: &[String], name: &str) -> Result<Option<u64>, String> {
    match arg(args, name) {
        Some(text) => match text.parse() {
            Ok(n) => Ok(Some(n)),
            Err(_) => Err(format!("{name} must be a number")),
        },
        None => Ok(None),
    }
}

/// A gas budget option: `default` when absent, saturating at `i64::MAX`.
fn parse_gas(args: &[String], name: &str, default: i64) -> Result<i64, String> {
    Ok(parse_number(args, name)?.map_or(default, |gas| i64::try_from(gas).unwrap_or(i64::MAX)))
}

/// How many blocks' states the node keeps: `--archive` for all,
/// `--state-history` blocks, or [`solo_node::STATE_HISTORY`].
fn state_history(args: &[String]) -> Result<usize, String> {
    let archive = args.iter().any(|a| a == "--archive");
    match (archive, parse_number(args, "--state-history")?) {
        (true, Some(_)) => Err("--archive and --state-history exclude each other".into()),
        (true, None) => Ok(solo_node::ARCHIVE),
        (false, Some(0)) => Err("--state-history must be at least 1".into()),
        (false, Some(n)) => Ok(usize::try_from(n).unwrap_or(solo_node::ARCHIVE)),
        (false, None) => Ok(solo_node::STATE_HISTORY),
    }
}

fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// Runs the command line. Returns when `--blocks` blocks have been produced
/// or a `solo_stop` request arrives; without either it runs until killed.
///
/// # Errors
/// A message for the user; the caller exits non-zero.
pub fn run(args: &[String]) -> Result<(), String> {
    run_until(args, |_| true)
}

/// [`run`] with an extra stop condition, checked between connections.
///
/// # Errors
/// As [`run`].
pub fn run_until(
    args: &[String],
    mut keep_going: impl FnMut(&solo_rpc::Rpc) -> bool,
) -> Result<(), String> {
    match run_inner(args, &mut keep_going) {
        Ok(()) => Ok(()),
        Err(CliError(message)) => Err(message),
    }
}

/// Prints a node error; the node keeps running (spec 06 §6 has the host
/// restart the driver, which a later host increment does).
fn report(result: Result<(), solo_node::NodeError>) {
    if let Err(e) = result {
        eprintln!("node error: {e}");
    }
}

fn parse_peers(args: &[String]) -> Result<Vec<std::net::SocketAddr>, String> {
    parse_addresses(args, "--peer")
}

/// Every address given with `flag`, each `ip:port`.
fn parse_addresses(args: &[String], flag: &str) -> Result<Vec<std::net::SocketAddr>, String> {
    args_all(args, flag)
        .into_iter()
        .map(|peer| {
            peer.parse()
                .ok()
                .ok_or_else(|| format!("{flag} {peer}: expected ip:port"))
        })
        .collect()
}

/// Peer exchange as the options say (spec 09 §5a): on unless
/// `--no-discovery`, signing the node's record with its consensus key and
/// keeping its table under `--data-dir` (spec 09 §5a.7).
fn discovery(
    args: &[String],
    key: Option<k256::ecdsa::SigningKey>,
) -> Result<Option<solo_node::Discovery>, String> {
    let defaults = solo_node::Discovery::default();
    let limit = |flag: &str, default: usize| -> Result<usize, String> {
        match parse_number(args, flag)? {
            None => Ok(default),
            Some(0) => Err(format!("{flag} must be at least 1")),
            Some(n) => Ok(usize::try_from(n).unwrap_or(usize::MAX)),
        }
    };
    let advertise = match arg(args, "--advertise") {
        None => None,
        Some(text) => Some(
            text.parse()
                .ok()
                .filter(solo_node::peers::dialable)
                .ok_or_else(|| format!("--advertise {text}: expected an ip:port peers can dial"))?,
        ),
    };
    let discovery = solo_node::Discovery {
        key,
        advertise,
        bootstrap: parse_addresses(args, "--bootstrap")?,
        max_peers: limit("--max-peers", defaults.max_peers)?,
        outbound: limit("--outbound-peers", defaults.outbound)?,
        peer_file: arg(args, "--data-dir")
            .map(|dir| std::path::Path::new(&dir).join(solo_node::peers::PEER_FILE)),
    };
    if args.iter().any(|a| a == "--no-discovery") {
        let given = [
            "--bootstrap",
            "--advertise",
            "--max-peers",
            "--outbound-peers",
        ];
        if let Some(flag) = given.iter().find(|f| args.iter().any(|a| a == *f)) {
            return Err(format!(
                "{flag} configures peer exchange, which --no-discovery turns off"
            ));
        }
        return Ok(None);
    }
    Ok(Some(discovery))
}

/// What the commands that run no node print: `key`, `doctor`, `gov` and
/// `upgrade`. `None` for any other command.
fn tool_output(command: &str, args: &[String]) -> Option<Result<String, CliError>> {
    Some(
        match command {
            "key" => args
                .get(2)
                .ok_or_else(|| "key: expected 64 hex digits".to_owned())
                .and_then(|hex| parse_key(hex))
                .map(|key| describe_key(&key)),
            "doctor" => doctor::run(args),
            "gov" => gov::parse(args.get(2..).unwrap_or(&[])).map(|call| gov::describe(&call)),
            "upgrade" => upgrade::run(args),
            "snapshot" => snapshot::run(args),
            _ => return None,
        }
        .map_err(CliError::from),
    )
}

/// The peer-to-peer transport of `solo node`, bound to `--listen`.
fn bind_transport(
    args: &[String],
    node: &solo_node::Node,
    chain_id: u64,
    peers: Vec<std::net::SocketAddr>,
) -> Result<solo_node::Transport, CliError> {
    let listen_arg = arg(args, "--listen");
    let listen = listen_arg.as_deref().unwrap_or(DEFAULT_LISTEN);
    // A validator proves its id with its consensus key; an observer with a
    // key of its own, fresh at every start (spec 09 §3).
    let key = match node.services_key() {
        Some(key) => key,
        None => solo_node::net::fresh_key()
            .ok()
            .ok_or("node key: the operating system gave no randomness")?,
    };
    let discovery = discovery(args, node.services_key())?;
    let genesis = node.genesis_hash();
    let mut t = match solo_node::Transport::bind(listen, key, chain_id, genesis, peers) {
        Ok(t) => t,
        Err(e) => return Err(format!("{listen}: {e}").into()),
    };
    let bound = t.local_addr().map_or(listen.to_owned(), |a| a.to_string());
    eprintln!("p2p listening on {bound}");
    if let Some(discovery) = discovery {
        let bootstrap = discovery.bootstrap.len();
        t.enable_discovery(discovery);
        eprintln!("peer exchange on, {bootstrap} bootstrap address(es)");
    }
    Ok(t)
}

/// A driver store, if any, with the tables and the state it holds from a
/// previous run.
type Opened = (
    Option<solo_node::DriverStore>,
    solo_node::store::Tables,
    Option<Vec<u8>>,
);

/// The driver store `--data-dir` names and what it holds; none without the
/// option, which a validator's `solo node` may not leave out.
fn open_store(args: &[String], validator: bool) -> Result<Opened, CliError> {
    let Some(dir) = arg(args, "--data-dir") else {
        if validator {
            return Err(
                "--data-dir is required for a validator: its driver state must outlive a restart (spec 08 §7)"
                    .into(),
            );
        }
        return Ok((None, solo_node::store::Tables::new(), None));
    };
    let mut store = solo_node::DriverStore::open(std::path::Path::new(&dir))
        .map_err(|e| format!("{dir}: {e}"))?;
    let (persisted, resumed) = store.take_loaded();
    Ok((Some(store), persisted, resumed))
}

/// Where `--data-dir` keeps the chain state, and the snapshot `--snapshot`
/// names, read and verified under the trust the arguments give (spec 22
/// §7); a snapshot without a data directory has nowhere to go.
fn chain_store_arguments(
    args: &[String],
    genesis: &Genesis,
) -> Result<(solo_node::StoreConfig, Option<solo_store::Snapshot>), CliError> {
    let chain_store = match arg(args, "--data-dir") {
        Some(dir) => solo_node::StoreConfig::Disk(dir.into()),
        None => solo_node::StoreConfig::Memory,
    };
    let memory = chain_store == solo_node::StoreConfig::Memory;
    for flag in ["--sync-from-peers", "--serve-snapshots"] {
        if memory && args.iter().any(|a| a == flag) {
            return Err(format!("{flag} needs --data-dir, where the snapshots are kept").into());
        }
    }
    let snapshot = match arg(args, "--snapshot") {
        Some(_) if args.iter().any(|a| a == "--sync-from-peers") => {
            return Err(
                "--snapshot and --sync-from-peers both name where the state comes from; give one"
                    .into(),
            );
        }
        Some(_) if memory => {
            return Err("--snapshot needs --data-dir, where the snapshot is loaded".into());
        }
        Some(path) => Some(
            solo_store::Snapshot::open(std::path::Path::new(&path))
                .map_err(|e| format!("{path}: {e}"))?,
        ),
        None => None,
    };
    if let Some(snapshot) = &snapshot {
        snapshot::verify(args, snapshot, genesis)?;
    }
    Ok((chain_store, snapshot))
}

/// Loads the state before the driver starts into a data directory that
/// holds no chain yet, from the verified `--snapshot` file or, for
/// `--sync-from-peers`, from the peers (a directory that holds a chain keeps
/// it, and an import that fails stops the node), and serves snapshots for
/// `--serve-snapshots` (spec 22 §7).
fn load_state(
    args: &[String],
    genesis: &Genesis,
    node: &mut solo_node::Node,
    (snapshot, transport): (
        Option<&solo_store::Snapshot>,
        Option<&mut solo_node::Transport>,
    ),
    clock: &dyn Fn() -> u64,
) -> Result<(), CliError> {
    if let Some(snapshot) = snapshot {
        match node.chain_store().map_or(0, solo_store::DiskStore::head) {
            0 => {
                snapshot::import_into(node, snapshot)?;
                eprintln!("{} imported", snapshot::describe(snapshot));
            }
            head => eprintln!(
                "--snapshot ignored: the data directory already holds chain state at height {head}"
            ),
        }
    }
    if let Some(t) = transport
        && args.iter().any(|a| a == "--sync-from-peers")
    {
        match node.chain_store().map_or(0, solo_store::DiskStore::head) {
            0 => {
                let config = node.sync_config(snapshot::trust(args, genesis)?)?;
                let fetched = snapshot::sync_from_peers(config, t, clock)?;
                node.import_snapshot(&fetched)?;
                let _ = fetched.path().parent().map(std::fs::remove_dir_all);
                eprintln!(
                    "{} fetched from peers and imported",
                    snapshot::describe(&fetched)
                );
            }
            head => eprintln!(
                "--sync-from-peers ignored: the data directory already holds chain state at height {head}"
            ),
        }
    }
    if args.iter().any(|a| a == "--serve-snapshots") {
        node.serve_snapshots(solo_node::statesync::ServeLimits::default())?;
    }
    Ok(())
}

/// Says where the driver's state lives, which view it started in and, on a
/// resume, how many of its own finalized blocks it re-executed from its
/// tables before anything else happened (spec 08 §7), and where the chain
/// state lives and at which height it was opened (spec 22 §5).
fn report_driver_state(node: &solo_node::Node, resumed: Option<&[u8]>, opened_at: u64) {
    if let Some(store) = node.store() {
        let view = node.simplex_state().map_or(0, |s| s.view);
        let how = if let Some(resumed) = resumed {
            // Re-executed blocks are at or below the height the driver had
            // finalized when it stopped; blocks it proposed on starting are
            // above it.
            let remembered = solo_abi::chain::SimplexState::from_bytes(resumed)
                .map_or(0, |s| s.finalized_height);
            let replayed = node
                .executed
                .iter()
                .filter(|(height, _)| *height <= remembered)
                .count();
            format!("resumed in view {view}, {replayed} blocks re-executed from its tables")
        } else {
            format!("new, from view {view}")
        };
        eprintln!("driver state in {}: {how}", store.dir().display());
    }
    if let Some(chain) = node.chain_store() {
        let stats = chain.stats();
        eprintln!(
            "chain state in {}: height {opened_at}, {} versions kept, {} bytes",
            chain.path().display(),
            stats.versions,
            stats.size_bytes
        );
    }
}

/// Binds the JSON-RPC listener and announces the node.
fn bind_rpc(
    rpc_addr: &str,
    command: &str,
    chain_id: u64,
    key: Option<&k256::ecdsa::SigningKey>,
) -> Result<std::net::TcpListener, CliError> {
    let listener = match solo_rpc::http::bind(rpc_addr) {
        Ok(listener) => listener,
        Err(e) => return Err(format!("{rpc_addr}: {e}").into()),
    };
    let bound = listener.local_addr().ok();
    let bound = bound.map_or(rpc_addr.to_owned(), |a| a.to_string());
    let validator = key.map_or("none (observer)".to_owned(), |k| {
        solo_rpc::methods::data(&solo_node::validator_id(k))
    });
    eprintln!(
        "solo {command} node: chain id {chain_id}, validator {validator}, JSON-RPC on http://{bound}"
    );
    Ok(listener)
}

/// Prints every kernel switch (spec 06 §7.3) the node performed since `seen`.
fn report_switches(node: &solo_node::Node, seen: &mut usize) {
    for s in &node.upgrades().switches[*seen..] {
        eprintln!(
            "kernel switch after block {}: version {} to {} ({})",
            s.height,
            s.from_version,
            s.to_version,
            solo_rpc::methods::data(&s.code_hash)
        );
    }
    *seen = node.upgrades().switches.len();
}

/// Refuses options the command would otherwise ignore without a word:
/// `solo dev` runs no transport, so it has no peers to fetch a snapshot
/// from, serve one to, listen for or dial, and it always signs with the
/// development key; `--trust-key` only says which snapshot to believe, so
/// it needs `--snapshot` or `--sync-from-peers`.
fn check_options(args: &[String], command: &str) -> Result<(), CliError> {
    if command == "dev" {
        for flag in [
            "--sync-from-peers",
            "--serve-snapshots",
            "--peer",
            "--listen",
            "--bootstrap",
            "--max-peers",
            "--outbound-peers",
            "--advertise",
            "--no-discovery",
            "--key",
            "--key-file",
        ] {
            if args.iter().any(|a| a == flag) {
                let why = if flag.starts_with("--key") {
                    "it always signs with the development key"
                } else {
                    "it runs no peer-to-peer transport"
                };
                return Err(format!("solo dev does not take {flag}: {why}; use solo node").into());
            }
        }
    }
    let verifies = ["--snapshot", "--sync-from-peers"];
    if args.iter().any(|a| a == "--trust-key")
        && !args.iter().any(|a| verifies.contains(&a.as_str()))
    {
        return Err(
            "--trust-key verifies a snapshot: give it with --snapshot or --sync-from-peers".into(),
        );
    }
    Ok(())
}

/// The genesis `--genesis` names. A `solo dev` chain in memory only, whose
/// genesis names no time, starts now; with a data directory the genesis is
/// the file's, so that a restart and the snapshot commands, which read the
/// file, find the same chain (spec 20 §3.4).
fn genesis_argument(args: &[String], command: &str) -> Result<Genesis, CliError> {
    let genesis_path = arg(args, "--genesis").ok_or("--genesis is required")?;
    let genesis_text = match std::fs::read_to_string(&genesis_path) {
        Ok(text) => text,
        Err(e) => return Err(format!("{genesis_path}: {e}").into()),
    };
    let genesis = parse_genesis(&genesis_text)?;
    if command == "dev" && arg(args, "--data-dir").is_none() {
        return Ok(timed(genesis, unix_ms() / 1000));
    }
    Ok(genesis)
}

pub(crate) fn run_inner(
    args: &[String],
    keep_going: &mut dyn FnMut(&solo_rpc::Rpc) -> bool,
) -> Result<(), CliError> {
    let command = args.get(1).map_or("", String::as_str);
    if let Some(output) = tool_output(command, args) {
        println!("{}", output?);
        return Ok(());
    }
    if command == "devnet" {
        return devnet::run(args, keep_going).map_err(CliError);
    }
    if command != "dev" && command != "node" {
        return Err(USAGE.into());
    }
    check_options(args, command)?;
    let kernel = load_kernel(&arg(args, "--kernel").ok_or("--kernel is required")?)?;
    let genesis = genesis_argument(args, command)?;
    let rpc_arg = arg(args, "--rpc");
    let rpc_addr = rpc_arg.as_deref().unwrap_or(DEFAULT_RPC);
    let max_blocks = parse_number(args, "--blocks")?;
    let kernel_gas = parse_gas(args, "--kernel-gas", solo_node::node::KERNEL_GAS)?;
    let query_gas = parse_gas(args, "--query-gas", solo_node::node::QUERY_GAS)?;
    let state_history = state_history(args)?;
    let key = if command == "dev" {
        Some(dev_key())
    } else {
        key_argument(args)?
    };
    let peers = parse_peers(args)?;
    let (store, persisted, resumed) = open_store(args, command == "node" && key.is_some())?;
    let (chain_store, snapshot) = chain_store_arguments(args, &genesis)?;
    let start = Instant::now();
    let epoch = unix_ms();
    let mut node = solo_node::Node::open(
        &kernel,
        &genesis,
        solo_node::NodeConfig {
            now_ms: epoch,
            key: key.clone(),
            persisted,
            kernel_gas,
            query_gas,
            state_history,
            store: chain_store,
            // Exports and DKG computations stay off the loop that answers
            // peers and keeps the clock (spec 22 §7.4, spec 15 §6.4).
            background: true,
            ..solo_node::NodeConfig::default()
        },
    )?;
    let chain_id = node.chain_id().unwrap_or(0);
    let mut transport = if command == "node" {
        Some(bind_transport(args, &node, chain_id, peers)?)
    } else {
        None
    };
    let clock = || epoch + u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
    let sources = (snapshot.as_ref(), transport.as_mut());
    load_state(args, &genesis, &mut node, sources, &clock)?;
    let opened_at = node.block_number().unwrap_or(0);
    if let Some(store) = store {
        node.attach_store(store);
    }
    node.start(resumed.clone())?;
    report_driver_state(&node, resumed.as_deref(), opened_at);
    let mut rpc = solo_rpc::Rpc::new(node);
    let listener = bind_rpc(rpc_addr, command, chain_id, key.as_ref())?;
    let mut last_tick = Instant::now();
    let mut switches_seen = 0usize;
    let blocks_seen = Rc::new(Cell::new(0u64));
    let seen = Rc::clone(&blocks_seen);
    // The network and the clock, between connections and between the steps
    // of long requests.
    rpc.set_background(Box::new(move |node: &mut solo_node::Node| {
        let now = epoch + u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
        if let Some(t) = transport.as_mut() {
            report(t.poll(node, now));
        }
        if last_tick.elapsed() < Duration::from_millis(20) {
            return;
        }
        last_tick = Instant::now();
        report(node.tick(now));
        // What a timer step did reaches the disk now; a transport does the
        // same before it sends (spec 08 §7).
        report(node.sync_store());
        report_switches(node, &mut switches_seen);
        let executed = node.blocks_executed();
        if executed > seen.get()
            && let Some((height, hash)) = node.executed.last()
        {
            seen.set(executed);
            eprintln!("block {height} {}", solo_rpc::methods::data(hash));
        }
    }));
    solo_rpc::http::serve(&listener, &mut rpc, |rpc| {
        !rpc.stopped && max_blocks.is_none_or(|n| blocks_seen.get() < n) && keep_going(rpc)
    });
    Ok(())
}
