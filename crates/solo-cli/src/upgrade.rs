//! `solo upgrade`: proposes a kernel upgrade through governance (spec 13).
//!
//! ```text
//! solo upgrade --kernel <kernel.elf|kernel.solo> (--key <64 hex> | --key-file <path>)
//!              [--rpc 127.0.0.1:8545] [--delay <blocks>] [--required-gates <g,g,...>] [--timeout <s>]
//! ```
//!
//! The key is the chain's governance account (spec 13 §1.1). The command
//! recompiles the kernel if it is an ELF, uploads the module in `stage`
//! transactions of one chunk each, waits for every receipt, and sends
//! `propose` with an activation height `delay` blocks after the head it
//! then sees, plus two blocks of slack for the proposal's own inclusion;
//! `delay` defaults to the chain's `upgradeDelay`. It refuses to start
//! while another upgrade is pending or when the key is not the governance
//! account, and fails if any transaction reverts or the receipts do not
//! arrive within the timeout (default 600 s). It prints the code hash, the
//! blocks the chunks landed in, the block of the proposal and the
//! activation height. Watch the switch with `solo devnet wait
//! --kernel-version` or `GET /status`.

use std::time::{Duration, Instant};

use k256::ecdsa::SigningKey;
use serde_json::{Value, json};
use solo_host::hash::keccak256;
use solo_rpc::methods::data;
use solo_upgrade::{Action, CHUNK_SIZE, UPGRADE_ADDRESS};

use crate::client::{address, call, legacy_tx, quantity, wait_receipt};
use crate::{DEFAULT_RPC, arg, key_argument, load_kernel, parse_number};

/// Gas limit of a stage transaction: above the calldata floor (EIP-7623) of
/// a full chunk.
pub const STAGE_GAS: u64 = 3_000_000;

/// Gas limit of a propose transaction.
pub const PROPOSE_GAS: u64 = 200_000;

/// Blocks of slack between the head seen when proposing and the earliest
/// activation height, for the proposal's own inclusion.
pub const SLACK: u64 = 2;

/// Parses a list of gates (`0,1,2`) into a bit set.
///
/// # Errors
/// If an entry is not a gate index below 64.
pub fn parse_gates(text: &str) -> Result<u64, String> {
    let mut mask = 0u64;
    for gate in text.split(',').filter(|g| !g.is_empty()) {
        let g: u32 = gate
            .trim()
            .parse()
            .ok()
            .filter(|g| *g < 64)
            .ok_or_else(|| format!("{gate}: not a gate index (0 to 63)"))?;
        mask |= 1 << g;
    }
    Ok(mask)
}

/// What the governance key sends: a legacy transaction to the upgrade
/// address carrying `action`, with gas price zero (the reference kernel's
/// base fee is zero, so actions cost the governance account nothing).
#[must_use]
pub fn action_tx(
    key: &SigningKey,
    chain_id: u64,
    nonce: u64,
    gas: u64,
    action: &Action,
) -> Vec<u8> {
    legacy_tx(
        key,
        chain_id,
        nonce,
        0,
        gas,
        UPGRADE_ADDRESS,
        0,
        &action.encode(),
    )
}

/// The receipt's block number, if it succeeded.
fn landed(receipt: &Value, what: &str) -> Result<u64, String> {
    if receipt.get("status").and_then(Value::as_str) != Some("0x1") {
        return Err(format!("{what} reverted: {receipt}"));
    }
    quantity(&receipt["blockNumber"])
}

/// Stages `code` and proposes it; see the module documentation.
///
/// # Errors
/// A message naming the first problem.
pub fn submit(
    rpc: &str,
    key: &SigningKey,
    code: &[u8],
    delay: Option<u64>,
    required_gates: u64,
    timeout: Duration,
) -> Result<String, String> {
    let deadline = Instant::now() + timeout;
    let status = call(rpc, "solo_upgradeStatus", &json!([]))?;
    if let Some(pending) = status.get("pending").filter(|p| !p.is_null()) {
        return Err(format!(
            "an upgrade is already pending: code hash {}, activation height {}",
            pending["codeHash"], pending["activationHeight"]
        ));
    }
    let sender = address(key);
    let governance = status["params"]["governance"].as_str().unwrap_or("none");
    if governance != data(&sender) {
        return Err(format!(
            "the governance account is {governance}, not this key's {}",
            data(&sender)
        ));
    }
    let min_delay = status["params"]["minDelay"].as_u64().unwrap_or(0);
    let chain_id = quantity(&call(rpc, "eth_chainId", &json!([]))?)?;
    let mut nonce = quantity(&call(
        rpc,
        "eth_getTransactionCount",
        &json!([data(&sender), "pending"]),
    )?)?;
    let code_hash = keccak256(code);
    let chunks: Vec<&[u8]> = code.chunks(CHUNK_SIZE).collect();
    let mut hashes = Vec::with_capacity(chunks.len());
    for (index, chunk) in chunks.iter().enumerate() {
        // An index past MAX_CHUNKS is no action; the node refuses it below.
        let action = Action::Stage {
            code_hash,
            index: u32::try_from(index).unwrap_or(u32::MAX),
            chunk: chunk.to_vec(),
        };
        let raw = action_tx(key, chain_id, nonce, STAGE_GAS, &action);
        let hash = call(rpc, "eth_sendRawTransaction", &json!([data(&raw)]))?;
        hashes.push(hash.as_str().unwrap_or_default().to_owned());
        nonce += 1;
    }
    let mut blocks = Vec::with_capacity(hashes.len());
    for (index, hash) in hashes.iter().enumerate() {
        let what = format!("chunk {index}");
        let receipt = wait_receipt(rpc, hash, &what, deadline)?;
        blocks.push(landed(&receipt, &what)?);
    }
    let head = quantity(&call(rpc, "eth_blockNumber", &json!([]))?)?;
    let activation_height = head + delay.unwrap_or(min_delay).max(1) + SLACK;
    let propose = Action::Propose {
        code_hash,
        activation_height,
        required_gates,
    };
    let raw = action_tx(key, chain_id, nonce, PROPOSE_GAS, &propose);
    let hash = call(rpc, "eth_sendRawTransaction", &json!([data(&raw)]))?;
    let receipt = wait_receipt(rpc, hash.as_str().unwrap_or_default(), "proposal", deadline)?;
    let proposed_at = landed(&receipt, "proposal")?;
    Ok(format!(
        "code hash  {}\nstaged     {} chunks ({} bytes) in blocks {}..{}\nproposed   block {proposed_at}\nactivation {activation_height}",
        data(&code_hash),
        chunks.len(),
        code.len(),
        blocks.iter().min().unwrap_or(&0),
        blocks.iter().max().unwrap_or(&0),
    ))
}

/// Runs `solo upgrade`; returns the report to print.
///
/// # Errors
/// A message naming the first problem.
pub fn run(args: &[String]) -> Result<String, String> {
    let rpc = arg(args, "--rpc");
    let rpc = rpc.as_deref().unwrap_or(DEFAULT_RPC);
    let kernel = load_kernel(&arg(args, "--kernel").ok_or("--kernel is required")?)?;
    let key = key_argument(args)?.ok_or("--key or --key-file is required")?;
    let delay = parse_number(args, "--delay")?;
    let gates = arg(args, "--required-gates");
    let required_gates = parse_gates(gates.as_deref().unwrap_or(""))?;
    let timeout = Duration::from_secs(parse_number(args, "--timeout")?.unwrap_or(600));
    submit(rpc, &key, &kernel, delay, required_gates, timeout)
}
