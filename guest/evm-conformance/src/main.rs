//! The EVM conformance guest (spec 07 §4.2): runs one Ethereum state test
//! case through the reference kernel's own EVM code.
//!
//! The kernel's `evm`, `state` and `tx` modules are compiled here from their
//! source files, so there is one copy of the code under test: revm over the
//! kernel's `StateDb`, its commit of revm's changes to storage, the host
//! crypto behind the precompiles, genesis allocation and sender recovery.
//! The case's pre-state goes in as genesis allocations, the transaction as
//! signed bytes; the post-state stays in storage for the host to read.

#![no_std]
#![no_main]

extern crate alloc;

#[allow(dead_code)]
#[path = "../../kernel/src/evm.rs"]
mod evm;
#[allow(dead_code)]
#[path = "../../kernel/src/state.rs"]
mod state;
#[allow(dead_code)]
#[path = "../../kernel/src/tx.rs"]
mod tx;

use alloc::vec::Vec;

use solo_abi::chain::{GenesisParams, call_status};
use solo_abi::codec::Seq;
use solo_abi::conformance::{Case, Outcome};
use solo_abi::types::Genesis;
use solo_abi::{Decode, Encode};

use crate::evm::{Env, Message};

fn run(case: Case) -> Outcome {
    let env = case.env;
    let params = GenesisParams { allocations: case.allocations, ..GenesisParams::default() };
    state::init(&Genesis { chain_id: env.chain_id, params: params.to_bytes(), ..Genesis::default() });
    let Ok(signed) = tx::decode_signed(&case.tx, env.chain_id) else {
        return Outcome { status: call_status::INVALID, gas_used: 0, logs: Seq(Vec::new()) };
    };
    let tx = signed.tx;
    let message = Message {
        tx_type: tx.tx_type,
        caller: signed.from,
        to: tx.to,
        value: tx.value,
        data: tx.input,
        gas_limit: tx.gas_limit,
        gas_price: tx.gas_price,
        priority_fee: tx.priority_fee,
        nonce: Some(tx.nonce),
        access_list: tx.access_list,
    };
    let env = Env {
        chain_id: env.chain_id,
        number: env.number,
        timestamp: env.timestamp,
        gas_limit: env.gas_limit,
        basefee: env.base_fee,
        beneficiary: env.beneficiary,
        prevrandao: env.prevrandao,
        difficulty: env.difficulty,
        excess_blob_gas: env.excess_blob_gas,
    };
    let outcome = evm::run_in(message, &env, true);
    Outcome { status: outcome.status, gas_used: outcome.gas_used, logs: Seq(outcome.logs) }
}

solo_guest::solo_export!(conformance_run, |input: &[u8]| -> Vec<u8> {
    match Case::from_bytes(input) {
        Ok(case) => run(case).to_bytes(),
        Err(_) => solo_guest::trap(),
    }
});

// The VM starts at an export; `main` exists only so the linker is satisfied.
solo_guest::solo_main!(unused_main);

fn unused_main(_: u64, _: u64, _: u64, _: u64, _: u64, _: u64) -> (u64, u64) {
    (0, 0)
}
