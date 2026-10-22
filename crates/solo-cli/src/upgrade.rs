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
//! then sees, plus [`SLACK`] blocks for the proposal's own inclusion;
//! `delay` defaults to the chain's `upgradeDelay`. The kernel takes a
//! proposal only from a block at least `upgradeDelay` (one at the least)
//! before its activation height (spec 13 §3), so a proposal that lands
//! later than the slack allowed reverts; the command then proposes again
//! from the head it sees, with twice the slack, up to [`RESENDS`] times,
//! and a loaded network delays the activation instead of failing the
//! command. It refuses to start while another upgrade is pending or when
//! the key is not the governance account, and fails if any transaction
//! reverts for another reason or the receipts do not arrive within the
//! timeout (default 600 s). It prints the code hash, the blocks the chunks
//! landed in, how many proposals landed too late, the block of the
//! proposal and the activation height. Watch the switch with `solo devnet
//! wait --kernel-version` or `GET /status`.

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
/// activation height, for the proposal's own inclusion; doubled every time
/// a proposal lands too late for its activation height.
pub const SLACK: u64 = 2;

/// How many times a proposal that landed too late for its activation
/// height is sent again, from the head seen then and with twice the slack.
pub const RESENDS: u32 = 3;

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
/// address carrying `action` at `gas_price`, the node's `eth_gasPrice`
/// (the base fee and the suggested tip, spec 23 §7), so that it runs on a
/// chain whose base fee is above zero.
#[must_use]
pub fn action_tx(
    key: &SigningKey,
    chain_id: u64,
    nonce: u64,
    gas_price: u128,
    gas: u64,
    action: &Action,
) -> Vec<u8> {
    legacy_tx(
        key,
        chain_id,
        nonce,
        gas_price,
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
    let gas_price = u128::from(quantity(&call(rpc, "eth_gasPrice", &json!([]))?)?);
    let account = json!([data(&sender), "pending"]);
    let mut nonce = quantity(&call(rpc, "eth_getTransactionCount", &account)?)?;
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
        let raw = action_tx(key, chain_id, nonce, gas_price, STAGE_GAS, &action);
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
    let delay = delay.unwrap_or(min_delay).max(1);
    let mut slack = SLACK;
    let mut resent = 0;
    let (proposed_at, activation_height) = loop {
        let head = quantity(&call(rpc, "eth_blockNumber", &json!([]))?)?;
        let activation_height = head + delay + slack;
        let propose = Action::Propose {
            code_hash,
            activation_height,
            required_gates,
        };
        let raw = action_tx(key, chain_id, nonce, gas_price, PROPOSE_GAS, &propose);
        nonce += 1;
        let hash = call(rpc, "eth_sendRawTransaction", &json!([data(&raw)]))?;
        let receipt = wait_receipt(rpc, hash.as_str().unwrap_or_default(), "proposal", deadline)?;
        let reverted = match landed(&receipt, "proposal") {
            Ok(block) => break (block, activation_height),
            Err(reverted) => reverted,
        };
        // The kernel takes a proposal only from a block at least `min_delay`
        // (one at the least) before its activation height (spec 13 §3).
        // One that landed too late for that is sent again from the head
        // seen now, with twice the slack; any other revert is final.
        let block = quantity(&receipt["blockNumber"])?;
        if activation_height >= block + min_delay.max(1) {
            return Err(reverted);
        }
        if resent == RESENDS {
            return Err(format!(
                "{} proposals landed too late for their activation height; the last: {receipt}",
                RESENDS + 1
            ));
        }
        resent += 1;
        slack *= 2;
    };
    let resent = match resent {
        0 => String::new(),
        1 => "\nresent     1 time: a proposal landed too late for its activation height".to_owned(),
        n => {
            format!("\nresent     {n} times: a proposal landed too late for its activation height")
        }
    };
    Ok(format!(
        "code hash  {}\nstaged     {} chunks ({} bytes) in blocks {}..{}{resent}\nproposed   block {proposed_at}\nactivation {activation_height}",
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
