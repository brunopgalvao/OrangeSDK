//! Governed kernel upgrades and host feature-gate signalling (spec 13): the
//! actions carried by transactions to the upgrade system address, the
//! bookkeeping at the end of every block, the queries, and this kernel's
//! version and migration rule (spec 06 §7).

use alloc::vec;
use alloc::vec::Vec;

use solo_abi::chain::{Log, UpgradeParams, ValidatorSet, call_status, reason};
use solo_abi::codec::Seq;
use solo_abi::types::{Address, Hash, MigrateArgs, QueryResult};
use solo_abi::{Decode, Encode};
use solo_upgrade::action::{cancelled_log, proposed_log};
use solo_upgrade::gates::{ended_epoch, epoch_of};
use solo_upgrade::{Action, EnactedUpgrade, GateBook, MAX_CHUNKS, PendingUpgrade, Signal, UPGRADE_ADDRESS, UpgradeStatus, ValidatorSignal, keys, query};

use crate::evm::{BlockFields, Message, Outcome};
use crate::state;
use crate::tx::Signed;

/// This kernel's version (spec 06 §7.1). The `upgrade-test` build reports the
/// next version, so tests can upgrade a running chain to a kernel that differs.
#[cfg(not(feature = "upgrade-test"))]
pub const KERNEL_VERSION: u32 = 1;
/// This kernel's version (spec 06 §7.1), as built for the upgrade tests.
#[cfg(feature = "upgrade-test")]
pub const KERNEL_VERSION: u32 = 2;

fn params() -> UpgradeParams {
    state::params().upgrades
}

/// Validator ids and weights, in validator-set order.
fn validators() -> Vec<(Hash, u64)> {
    state::get_raw(b"meta/validators")
        .and_then(|b| ValidatorSet::from_bytes(&b).ok())
        .map(|set| set.validators.0.into_iter().map(|v| (v.id, v.weight)).collect())
        .unwrap_or_default()
}

/// The validator whose consensus key controls `address`: a validator id is the
/// hash an Ethereum address is the last 20 bytes of.
fn validator_id(address: &Address) -> Option<Hash> {
    validators().into_iter().map(|(id, _)| id).find(|id| id[12..] == address[..])
}

fn pending() -> Option<PendingUpgrade> {
    state::get(keys::PENDING)
}

/// Whether `code_hash` is the code of a kernel this chain has switched to:
/// its staged code stays as it is for good (spec 13 §5).
fn enacted(code_hash: &Hash) -> bool {
    state::get_raw(&keys::kernel(code_hash)).is_some()
}

fn book() -> GateBook {
    state::get(keys::BOOK).unwrap_or_default()
}

/// The action a transaction to the upgrade address carries, if it can run:
/// signed for this chain (EIP-155 or a typed transaction, so it cannot be
/// replayed from another chain), no value, calldata that is an action, and a
/// sender that action authorizes.
fn action_of(s: &Signed) -> Option<Action> {
    if s.tx.chain_id != Some(state::chain_id()) || s.tx.value != 0 {
        return None;
    }
    let action = Action::decode(&s.tx.input)?;
    let p = params();
    let allowed = if action.is_governance() { p.governance != [0; 20] && s.from == p.governance } else { p.epoch_blocks != 0 && validator_id(&s.from).is_some() };
    allowed.then_some(action)
}

/// Admission: a transaction to the upgrade address must be able to run.
pub fn admit(s: &Signed) -> Result<(), u32> {
    if s.tx.to == Some(UPGRADE_ADDRESS) && action_of(s).is_none() { Err(reason::SYSTEM_ACTION) } else { Ok(()) }
}

/// Executes a transaction. One to the upgrade address that cannot run changes
/// nothing, like any transaction that should not have been included; one that
/// can runs through the EVM as a plain call (gas, fees, nonce), then applies
/// its action. An action whose state checks fail reverts: the transaction
/// keeps its gas and nonce and changes nothing else.
pub fn run(s: &Signed, height: u64, message: Message, block: BlockFields) -> Outcome {
    if s.tx.to != Some(UPGRADE_ADDRESS) {
        return crate::native::run(message, block, true);
    }
    let Some(action) = action_of(s) else {
        return Outcome { status: call_status::INVALID, gas_used: 0, output: Vec::new(), logs: Vec::new(), contract: None };
    };
    let mut outcome = crate::native::run(message, block, true);
    if outcome.status == call_status::SUCCESS {
        match apply(action, &s.from, height) {
            Some(logs) => outcome.logs.extend(logs),
            None => outcome.status = call_status::REVERT,
        }
    }
    outcome
}

/// Applies an authorized action in the block at `height`; `None` if its state
/// checks fail.
fn apply(action: Action, from: &Address, height: u64) -> Option<Vec<Log>> {
    match action {
        Action::Stage { code_hash, index, chunk } => {
            // The code of a pending upgrade, and of every enacted kernel, is frozen.
            if pending().is_some_and(|p| p.code_hash == code_hash) || enacted(&code_hash) {
                return None;
            }
            state::set_raw(&keys::chunk(&code_hash, index), &chunk);
            Some(Vec::new())
        }
        Action::Propose { code_hash, activation_height, required_gates } => {
            let earliest = height.saturating_add(params().min_delay.max(1));
            // Block `H + 1` must exist, and a kernel the chain already ran never comes back.
            if pending().is_some() || activation_height < earliest || activation_height == u64::MAX || enacted(&code_hash) {
                return None;
            }
            let (code, chunks) = assemble(&code_hash)?;
            if state::keccak256(&code) != code_hash {
                return None;
            }
            let size = u32::try_from(code.len()).ok()?;
            state::set(keys::PENDING, &PendingUpgrade { code_hash, activation_height, required_gates, size, chunks, proposed_at: height });
            Some(vec![proposed_log(&code_hash, activation_height, required_gates)])
        }
        Action::Cancel { code_hash } => {
            pending().filter(|p| p.code_hash == code_hash)?;
            state::delete(keys::PENDING);
            Some(vec![cancelled_log(&code_hash)])
        }
        Action::Signal { features } => {
            let id = validator_id(from)?;
            state::set(&keys::signal(&id), &Signal { epoch: epoch_of(height, params().epoch_blocks), features });
            Some(Vec::new())
        }
    }
}

/// The staged code of `code_hash`: chunks 0, 1, … up to the first missing
/// one, concatenated, and how many there were; `None` without chunk 0.
fn assemble(code_hash: &Hash) -> Option<(Vec<u8>, u32)> {
    let mut code = Vec::new();
    let mut chunks = 0;
    while chunks < MAX_CHUNKS {
        let Some(chunk) = state::get_raw(&keys::chunk(code_hash, chunks)) else { break };
        code.extend_from_slice(&chunk);
        chunks += 1;
    }
    (chunks > 0).then_some((code, chunks))
}

/// Bookkeeping at the end of the block at `height`, before the state commitment.
pub fn end_block(height: u64) {
    if pending().is_some_and(|up| height > up.activation_height) {
        // This kernel was superseded at the activation height. A host still
        // running it past there must halt rather than fork the chain.
        solo_guest::trap();
    }
    let p = params();
    if let Some(epoch) = ended_epoch(height, p.epoch_blocks) {
        let mut signals = Vec::new();
        let mut total = 0u64;
        for (id, weight) in validators() {
            total = total.saturating_add(weight);
            if let Some(signal) = state::get::<Signal>(&keys::signal(&id))
                && signal.epoch == epoch
            {
                signals.push((weight, signal.features));
            }
        }
        state::set(keys::BOOK, &book().end_epoch(epoch, p.epoch_blocks, &signals, total));
    }
    if let Some(up) = pending()
        && up.activation_height == height
        && up.required_gates & !book().active_at(height + 1) != 0
    {
        // The new kernel needs host features that will not be active: it lapses.
        state::delete(keys::PENDING);
    }
}

fn status() -> UpgradeStatus {
    let validators = validators().into_iter().map(|(id, weight)| ValidatorSignal { id, weight, signal: state::get(&keys::signal(&id)) }).collect();
    UpgradeStatus { version: KERNEL_VERSION, params: params(), pending: pending(), enacted: state::get(keys::ENACTED), gates: book(), validators: Seq(validators) }
}

/// The upgrade queries; status 3 for any other method.
pub fn query(method: &str, params: &[u8]) -> QueryResult {
    let ok = |body: Vec<u8>| QueryResult { status: 0, body };
    match method {
        query::KERNEL_VERSION => ok(KERNEL_VERSION.to_bytes()),
        query::STATUS => ok(status().to_bytes()),
        query::CODE => match Hash::from_bytes(params) {
            Ok(code_hash) => assemble(&code_hash).map_or(QueryResult { status: 1, body: Vec::new() }, |(code, _)| ok(code.to_bytes())),
            Err(_) => QueryResult { status: 2, body: Vec::new() },
        },
        _ => QueryResult { status: 3, body: Vec::new() },
    }
}

/// The chain-state half of `kernel_migrate` (spec 06 §7.2). Accepts only the
/// version this kernel supersedes, and only at the pending upgrade's
/// activation height; anything else traps so the host halts. Enacts the
/// upgrade in chain state, from chain state alone: the driver state differs
/// between nodes and must not reach the commitment.
pub fn migrate(args: &MigrateArgs) {
    let Some(up) = pending() else { solo_guest::trap() };
    if args.from_version.checked_add(1) != Some(KERNEL_VERSION) || state::height() != Some(up.activation_height) {
        solo_guest::trap();
    }
    state::delete(keys::PENDING);
    let enacted = EnactedUpgrade { code_hash: up.code_hash, height: up.activation_height, from_version: args.from_version, to_version: KERNEL_VERSION };
    state::set(&keys::kernel(&up.code_hash), &enacted);
    state::set(keys::ENACTED, &enacted);
}
