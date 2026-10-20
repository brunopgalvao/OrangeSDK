//! The `solo` command.
//!
//! `solo dev --kernel <kernel.elf|kernel.solo> --genesis <genesis.json>
//! [--rpc 127.0.0.1:8545] [--blocks <n>] [--kernel-gas <n>]` runs a
//! single-node development chain with Ethereum JSON-RPC. The genesis file is
//! JSON: `{"chainId": 1337, "slotMs": 400, "maxTxs": 64,
//! "alloc": {"0x<address>": "<wei>"}}`.

#![forbid(unsafe_code)]

use std::time::{Duration, Instant};

use serde_json::Value;
use solo_abi::Encode;
use solo_abi::chain::{Allocation, GenesisParams};
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

/// Where the JSON-RPC server listens unless `--rpc` says otherwise.
pub const DEFAULT_RPC: &str = "127.0.0.1:8545";

/// Usage line printed on a command-line mistake.
pub const USAGE: &str = "usage: solo dev --kernel <kernel.elf|kernel.solo> --genesis <genesis.json> [--rpc 127.0.0.1:8545] [--blocks <n>] [--kernel-gas <n>]";

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
        for (address, balance) in alloc {
            let bytes = solo_rpc::methods::parse_hex(address)
                .ok()
                .ok_or("genesis: alloc address must be 0x hex")?;
            let address = <[u8; 20]>::try_from(bytes)
                .ok()
                .ok_or("genesis: alloc address must be 20 bytes")?;
            let balance: u128 = match balance {
                Value::String(s) => s
                    .parse()
                    .ok()
                    .ok_or("genesis: balance must be a decimal string")?,
                Value::Number(n) => n
                    .as_u64()
                    .ok_or("genesis: balance must be a non-negative integer")?
                    .into(),
                _ => return Err("genesis: balance must be a string or number".to_owned()),
            };
            allocations.push(Allocation { address, balance });
        }
    }
    let params = GenesisParams {
        slot_ms,
        max_txs: u32::try_from(max_txs)
            .ok()
            .ok_or("genesis: maxTxs too large")?,
        allocations: Seq(allocations),
    };
    Ok(Genesis {
        chain_id,
        fee_schedule: vec![],
        modules: Seq(vec![]),
        params: params.to_bytes(),
        validators: vec![],
    })
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
    keep_going: impl FnMut(&solo_rpc::Rpc) -> bool,
) -> Result<(), String> {
    match run_inner(args, keep_going) {
        Ok(()) => Ok(()),
        Err(CliError(message)) => Err(message),
    }
}

fn run_inner(
    args: &[String],
    mut keep_going: impl FnMut(&solo_rpc::Rpc) -> bool,
) -> Result<(), CliError> {
    if args.get(1).map(String::as_str) != Some("dev") {
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
    let kernel_gas = parse_number(args, "--kernel-gas")?;
    let start = Instant::now();
    let epoch = unix_ms();
    let mut node = solo_node::Node::new(&kernel, &genesis, epoch)?;
    let chain_id = node.chain_id().unwrap_or(0);
    if let Some(gas) = kernel_gas {
        node.kernel_gas = i64::try_from(gas).unwrap_or(i64::MAX);
    }
    node.start(None)?;
    let mut rpc = solo_rpc::Rpc::new(node);
    let listener = match solo_rpc::http::bind(rpc_addr) {
        Ok(listener) => listener,
        Err(e) => return Err(format!("{rpc_addr}: {e}").into()),
    };
    let bound = listener.local_addr().ok();
    let bound = bound.map_or(rpc_addr.to_owned(), |a| a.to_string());
    eprintln!("solo dev node: chain id {chain_id}, JSON-RPC on http://{bound}");
    let mut last_tick = Instant::now();
    let blocks_seen = std::cell::Cell::new(0u64);
    solo_rpc::http::serve(
        &listener,
        &mut rpc,
        |rpc| {
            if last_tick.elapsed() < Duration::from_millis(20) {
                return;
            }
            last_tick = Instant::now();
            let now = epoch + u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
            if let Err(e) = rpc.node_mut().tick(now) {
                eprintln!("node error: {e}");
            }
            let executed = rpc.node_mut().executed.len();
            if executed as u64 > blocks_seen.get() {
                blocks_seen.set(executed as u64);
                let (height, hash) = rpc.node_mut().executed[executed - 1];
                eprintln!("block {height} {}", solo_rpc::methods::data(&hash));
            }
        },
        |rpc| !rpc.stopped && max_blocks.is_none_or(|n| blocks_seen.get() < n) && keep_going(rpc),
    );
    Ok(())
}
