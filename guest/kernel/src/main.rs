//! The reference kernel (spec 06): the Simplex driver (spec 08) and a state
//! transition that executes Ethereum transactions on the EVM.

#![no_std]
#![no_main]

extern crate alloc;

mod dkg;
mod driver;
mod evm;
mod governance;
mod modules;
mod native;
mod persist;
mod staking;
mod state;
mod stf;
mod tx;

use alloc::vec::Vec;

use solo_abi::types::{BuildArgs, ExecuteArgs, FinalizeArgs, Genesis, Input, MigrateArgs, QueryArgs, QueryResult, ValidateArgs};
use solo_abi::{Decode, Encode};

fn decode_or_trap<T: Decode>(bytes: &[u8]) -> T {
    match T::from_bytes(bytes) {
        Ok(v) => v,
        Err(_) => solo_guest::trap(),
    }
}

solo_guest::solo_export!(kernel_init, |input: &[u8]| -> Vec<u8> {
    let genesis: Genesis = decode_or_trap(input);
    state::init(&genesis);
    staking::init(&genesis);
    modules::init(&genesis);
    Vec::new()
});

solo_guest::solo_export!(kernel_driver_step, |input: &[u8]| -> Vec<u8> {
    let step: Input = decode_or_trap(input);
    driver::step(&step).to_bytes()
});

solo_guest::solo_export!(kernel_driver_state, |_input: &[u8]| -> Vec<u8> {
    driver::load().to_bytes()
});

solo_guest::solo_export!(kernel_migrate, |input: &[u8]| -> Vec<u8> {
    let args: MigrateArgs = decode_or_trap(input);
    governance::migrate(&args);
    driver::migrate(&args);
    Vec::new()
});

solo_guest::solo_export!(kernel_version, |_input: &[u8]| -> Vec<u8> { governance::KERNEL_VERSION.to_bytes() });

solo_guest::solo_export!(kernel_stf_validate_tx, |input: &[u8]| -> Vec<u8> {
    let args: ValidateArgs = decode_or_trap(input);
    stf::validate(&args).to_bytes()
});

solo_guest::solo_export!(kernel_stf_build_block, |input: &[u8]| -> Vec<u8> {
    let args: BuildArgs = decode_or_trap(input);
    stf::build(&args).to_bytes()
});

solo_guest::solo_export!(kernel_stf_execute_block, |input: &[u8]| -> Vec<u8> {
    let args: ExecuteArgs = decode_or_trap(input);
    stf::execute(&args).to_bytes()
});

solo_guest::solo_export!(kernel_stf_finalize_block, |input: &[u8]| -> Vec<u8> {
    let args: FinalizeArgs = decode_or_trap(input);
    stf::finalize(&args);
    Vec::new()
});

solo_guest::solo_export!(kernel_query, |input: &[u8]| -> Vec<u8> {
    let args: QueryArgs = decode_or_trap(input);
    let result: QueryResult = stf::query(&args);
    result.to_bytes()
});

// The VM starts at an export; `main` exists only so the linker is satisfied.
solo_guest::solo_main!(unused_main);

fn unused_main(_: u64, _: u64, _: u64, _: u64, _: u64, _: u64) -> (u64, u64) {
    (0, 0)
}
