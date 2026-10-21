//! The `solo` command.
//!
//! `solo dev --kernel <kernel.elf|kernel.solo> --genesis <genesis.json>
//! [--rpc 127.0.0.1:8545] [--blocks <n>] [--kernel-gas <n>] [--query-gas <n>]
//! [--state-history <blocks> | --archive]`
//! runs a single-node development chain with Ethereum JSON-RPC. The node keeps
//! the state of its latest 1 024 blocks for historical queries and proofs, or
//! `--state-history` of them, or every block's with `--archive` (spec 20 §5).
//! The genesis file is
//! JSON: `{"chainId": 1337, "slotMs": 400, "maxTxs": 64,
//! "alloc": {"0x<address>": "<wei>"}, "validators": ["0x<32-byte id>"]}`.
//! An `alloc` entry is a balance, or a geth-style account that predeploys a
//! contract: `{"balance": "<wei>", "nonce": "0x1", "code": "0x<bytecode>",
//! "storage": {"0x<slot>": "0x<value>"}}`, every field optional. Without
//! `validators` the dev node is the only validator, signing with
//! [`DEV_KEY_SEED`]. Governed upgrades and feature gates (spec 13) are off
//! unless the file names a `"governance"` address (with an optional
//! `"upgradeDelay"` in blocks) or a non-zero `"epochBlocks"`. Governance runs
//! under the key track unless `"governanceMode"` says `"stake"`; see [`gov`],
//! which also has `solo gov`, the encoder of governance calls. Kernel modules
//! installed at genesis (spec 16) are listed under `"modules"`; see [`modules`].
//! The Ethereum-to-Solo bridge (spec 18) is configured under `"bridgeIn"`;
//! see [`bridge`].

#![forbid(unsafe_code)]

pub mod bridge;
pub mod doctor;
pub mod gov;
pub mod modules;

use std::cell::Cell;
use std::rc::Rc;
use std::time::{Duration, Instant};

use serde_json::Value;
use solo_abi::Encode;
use solo_abi::chain::{
    Allocation, GenesisParams, StorageSlot, UpgradeParams, Validator, ValidatorSet,
};
use solo_abi::codec::Seq;
use solo_abi::types::Genesis;

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
  solo dev  --kernel <kernel.elf|kernel.solo> --genesis <genesis.json> [--rpc 127.0.0.1:8545] [--blocks <n>] [--kernel-gas <n>] [--query-gas <n>] [--state-history <blocks> | --archive]
  solo node --kernel <kernel.elf|kernel.solo> --genesis <genesis.json> [--key <64 hex>] [--listen 127.0.0.1:30333] [--peer <addr>]... [--rpc 127.0.0.1:8545] [--blocks <n>] [--query-gas <n>] [--state-history <blocks> | --archive]
  solo key  <64 hex>
  solo gov  submit <target> <0x calldata> | vote <id> yes|no | execute <id> | veto <id> | pause <target> | set-guardian <address> | set-mode stake | set-params <voting> <timelock> <quorumBps> <deposit>
  solo doctor [--rpc 127.0.0.1:8545] [--max-head-age <s>] [--max-finality-lag <blocks>] [--min-peers <n>] [--max-mempool <txs>] [--max-call-ms <ms>]";

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
        bridge_in: bridge::parse_bridge(&v)?,
        governance: gov::parse_governance(&v)?,
        ..GenesisParams::default()
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
fn parse_balance(value: &Value) -> Result<u128, String> {
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

/// What `solo key` prints: the validator id for genesis and the Ethereum address.
#[must_use]
pub fn describe_key(key: &k256::ecdsa::SigningKey) -> String {
    let id = solo_node::validator_id(key);
    format!(
        "validator {}\naddress   {}",
        solo_rpc::methods::data(&id),
        solo_rpc::methods::data(&id[12..])
    )
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

fn parse_number(args: &[String], name: &str) -> Result<Option<u64>, String> {
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
    args_all(args, "--peer")
        .into_iter()
        .map(|peer| {
            peer.parse()
                .ok()
                .ok_or_else(|| format!("--peer {peer}: expected ip:port"))
        })
        .collect()
}

/// What the commands that run no node print: `key`, `doctor` and `gov`.
/// `None` for any other command.
fn tool_output(command: &str, args: &[String]) -> Option<Result<String, CliError>> {
    Some(match command {
        "key" => args
            .get(2)
            .ok_or_else(|| "key: expected 64 hex digits".to_owned())
            .and_then(|hex| parse_key(hex))
            .map(|key| describe_key(&key)),
        "doctor" => doctor::run(args),
        "gov" => gov::parse(args.get(2..).unwrap_or(&[])).map(|call| gov::describe(&call)),
        _ => return None,
    }
    .map_err(CliError::from))
}

fn run_inner(
    args: &[String],
    keep_going: &mut dyn FnMut(&solo_rpc::Rpc) -> bool,
) -> Result<(), CliError> {
    let command = args.get(1).map_or("", String::as_str);
    if let Some(output) = tool_output(command, args) {
        println!("{}", output?);
        return Ok(());
    }
    if command != "dev" && command != "node" {
        return Err(USAGE.into());
    }
    let kernel = load_kernel(&arg(args, "--kernel").ok_or("--kernel is required")?)?;
    let genesis_path = arg(args, "--genesis").ok_or("--genesis is required")?;
    let genesis_text = match std::fs::read_to_string(&genesis_path) {
        Ok(text) => text,
        Err(e) => return Err(format!("{genesis_path}: {e}").into()),
    };
    let genesis = parse_genesis(&genesis_text)?;
    let rpc_arg = arg(args, "--rpc");
    let rpc_addr = rpc_arg.as_deref().unwrap_or(DEFAULT_RPC);
    let max_blocks = parse_number(args, "--blocks")?;
    let kernel_gas = parse_gas(args, "--kernel-gas", solo_node::node::KERNEL_GAS)?;
    let query_gas = parse_gas(args, "--query-gas", solo_node::node::QUERY_GAS)?;
    let state_history = state_history(args)?;
    let key = if command == "dev" {
        Some(dev_key())
    } else {
        arg(args, "--key").map(|k| parse_key(&k)).transpose()?
    };
    let peers = parse_peers(args)?;
    let start = Instant::now();
    let epoch = unix_ms();
    let mut node = solo_node::Node::open(
        &kernel,
        &genesis,
        solo_node::NodeConfig {
            now_ms: epoch,
            key: key.clone(),
            kernel_gas,
            query_gas,
            state_history,
            ..solo_node::NodeConfig::default()
        },
    )?;
    let chain_id = node.chain_id().unwrap_or(0);
    node.start(None)?;
    let mut transport = None;
    if command == "node" {
        let listen_arg = arg(args, "--listen");
        let listen = listen_arg.as_deref().unwrap_or(DEFAULT_LISTEN);
        // An observer still needs an identity for its peers; a hash of its address will do.
        let id = node
            .validator_id()
            .unwrap_or_else(|| solo_host::hash::keccak256(listen.as_bytes()));
        let t = match solo_node::Transport::bind(listen, id, chain_id, peers) {
            Ok(t) => t,
            Err(e) => return Err(format!("{listen}: {e}").into()),
        };
        let bound = t.local_addr().map_or(listen.to_owned(), |a| a.to_string());
        eprintln!("p2p listening on {bound}");
        transport = Some(t);
    }
    let mut rpc = solo_rpc::Rpc::new(node);
    let listener = match solo_rpc::http::bind(rpc_addr) {
        Ok(listener) => listener,
        Err(e) => return Err(format!("{rpc_addr}: {e}").into()),
    };
    let bound = listener.local_addr().ok();
    let bound = bound.map_or(rpc_addr.to_owned(), |a| a.to_string());
    let validator = key.as_ref().map_or("none (observer)".to_owned(), |k| {
        solo_rpc::methods::data(&solo_node::validator_id(k))
    });
    eprintln!(
        "solo {command} node: chain id {chain_id}, validator {validator}, JSON-RPC on http://{bound}"
    );
    let mut last_tick = Instant::now();
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
        let executed = node.executed.len();
        if executed as u64 > seen.get() {
            seen.set(executed as u64);
            let (height, hash) = node.executed[executed - 1];
            eprintln!("block {height} {}", solo_rpc::methods::data(&hash));
        }
    }));
    solo_rpc::http::serve(&listener, &mut rpc, |rpc| {
        !rpc.stopped && max_blocks.is_none_or(|n| blocks_seen.get() < n) && keep_going(rpc)
    });
    Ok(())
}
