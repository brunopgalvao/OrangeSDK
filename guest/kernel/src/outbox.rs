//! The outbox (spec 17 §2–§3): the system address `0x…4f42` that any
//! account or contract calls with `send(destChainId, recipient, payload)`.
//!
//! The precompile provider serves it inside revm, so a call from a contract
//! at any depth works, and everything it does goes through revm's journal:
//! it bumps the nonce in slot 0 of the outbox's EVM storage, writes the
//! message hash into the slot named by the nonce, and logs `MessageSent`.
//! A revert of any enclosing frame takes all three back, exactly as for an
//! `SSTORE` and a `LOG` at the same point. The slot of message `n` is then
//! the chain-state key `slot/ ‖ outbox ‖ n`, which a state proof (spec 10)
//! shows committed under a block's state root.

use alloc::string::String;

use revm::context_interface::{ContextTr, JournalTr};
use revm::interpreter::{CallInputs, CallScheme, Gas, InstructionResult, InterpreterResult};
use revm::primitives::{B256, Bytes, Log as RLog, U256};
use revm::state::Account as RAccount;
use solo_abi::bridge::{Message, NONCE_SLOT, OUTBOX_ADDRESS, SendCall, message_slot, send_gas};
use solo_abi::chain::reason;
use solo_abi::types::Address;

use crate::state;
use crate::tx::Signed;

/// Admission (spec 17 §2.2): a transaction sent to the outbox must carry a
/// `send` it accepts.
pub fn admit(s: &Signed) -> Result<(), u32> {
    if s.tx.to == Some(OUTBOX_ADDRESS) && !SendCall::decode(&s.tx.input).is_some_and(|c| c.acceptable(state::chain_id())) {
        Err(reason::OUTBOX_MESSAGE)
    } else {
        Ok(())
    }
}

/// Whether a message call runs the outbox's code: a call to it, or a
/// `DELEGATECALL` or `CALLCODE` naming it.
pub fn is_outbox(inputs: &CallInputs) -> bool {
    inputs.bytecode_address.0.0 == OUTBOX_ADDRESS
}

/// Serves a message call that [`is_outbox`].
pub fn call<CTX: ContextTr>(ctx: &mut CTX, inputs: &CallInputs) -> Result<InterpreterResult, String> {
    let limit = inputs.gas_limit;
    let mut gas = Gas::new_with_regular_gas_and_reservoir(limit, inputs.reservoir);
    let target = inputs.target_address;
    let data = inputs.input.bytes(ctx);
    let call = SendCall::decode(&data).filter(|c| c.acceptable(state::chain_id()));
    let Some(call) = call.filter(|_| inputs.scheme == CallScheme::Call && !inputs.is_static && target.0.0 == OUTBOX_ADDRESS) else {
        return Ok(InterpreterResult::new(InstructionResult::Revert, Bytes::new(), gas));
    };
    let cost = send_gas(call.payload.len());
    if !gas.record_regular_cost(cost) {
        gas.spend_all();
        return Ok(InterpreterResult::new(InstructionResult::PrecompileOOG, Bytes::new(), gas));
    }
    let journal = ctx.journal_mut();
    let last = journal.sload(target, U256::from_be_bytes(NONCE_SLOT)).map_err(|_| String::from("database"))?.data;
    let nonce = u64::try_from(last).unwrap_or(u64::MAX - 1) + 1;
    let message = Message {
        source_chain_id: state::chain_id(),
        nonce,
        sender: inputs.caller.0.0,
        dest_chain_id: call.dest_chain_id,
        recipient: call.recipient,
        value: u128::try_from(inputs.call_value()).unwrap_or(u128::MAX),
        payload: call.payload,
    };
    let hash = state::keccak256(&message.encode());
    journal.sstore(target, U256::from_be_bytes(NONCE_SLOT), U256::from(nonce)).map_err(|_| String::from("database"))?;
    journal.sstore(target, U256::from_be_bytes(message_slot(nonce)), U256::from_be_bytes(hash)).map_err(|_| String::from("database"))?;
    let topics = message.topics().iter().map(|t| B256::from(*t)).collect();
    journal.log(RLog::new_unchecked(target, topics, Bytes::from(message.log_data(&hash))));
    Ok(InterpreterResult::new(InstructionResult::Return, Bytes::from(message_slot(nonce).to_vec()), gas))
}

/// Commits the slots the outbox wrote. It has no code and no nonce, so the
/// EIP-161 rule of `evm::commit` would delete it with its slots unwritten;
/// the outbox keeps them whatever its balance, and `evm::commit` then writes
/// or deletes the account itself by its balance (spec 17 §2.3).
pub fn commit(address: &Address, account: &RAccount) -> bool {
    if *address != OUTBOX_ADDRESS {
        return false;
    }
    for (key, slot) in account.changed_storage_slots() {
        state::set_raw(&state::slot_key(address, &key.to_be_bytes::<32>()), &slot.present_value.to_be_bytes::<32>());
    }
    true
}
