//! The guest heap under the EVM (spec 03 §8 rule 10).
//!
//! Transactions that allocate and drop memory for their whole gas limit must
//! run to completion inside the guest, as they do on Ethereum: the EVM's
//! scratch memory (call inputs and return data, call frames) is garbage once
//! a call returns, and the guest's allocator must take it back rather than
//! run out. The churn cases run with a 16 MiB heap, where only an allocator
//! that reuses freed blocks can finish them: one that never took memory back
//! needs more than 128 MiB for the identity loop. The allocator's own rules
//! are checked from inside the guest, and the heaviest known transaction
//! pins how much of the 1 GiB default one transaction can keep live.

mod common;

use common::{TX_GAS, account, case};
use orange_abi::Encode;
use orange_abi::chain::{Account, call_status, keys};
use orange_conformance::{GUEST, Runner};
use orange_host::hash::keccak256;
use orange_host::{Backend, MemStorage, Storage};
use orange_recompile::Options;
use orange_vm::status::Termination;

const CALLEE: [u8; 20] = [0xCA; 20];
const MIB: u32 = 1 << 20;

fn runner(backend: Backend, heap_max: u32) -> Runner {
    Runner::with_options(
        GUEST,
        backend,
        &Options {
            heap_max,
            ..Options::default()
        },
    )
    .unwrap()
}

/// `loop: CALL(gas, target, 0, 0, args, 0, 0); POP; JUMP loop`, until out of gas.
fn call_loop(target: [u8; 20], args: u16) -> Vec<u8> {
    let mut code = vec![0x5B, 0x60, 0x00, 0x60, 0x00, 0x61];
    code.extend_from_slice(&args.to_be_bytes());
    code.extend_from_slice(&[0x60, 0x00, 0x60, 0x00, 0x73]);
    code.extend_from_slice(&target);
    code.extend_from_slice(&[0x5A, 0xF1, 0x50, 0x60, 0x00, 0x56]);
    code
}

/// Runs `code` with the whole per-transaction gas cap on a 16 MiB heap, on
/// both backends, and requires it to end by running out of EVM gas.
fn runs_out_of_gas_in_16_mib(code: &[u8]) {
    for backend in [Backend::Interpreter, Backend::Native] {
        let executed = runner(backend, 16 * MIB)
            .run(&case(
                code.to_vec(),
                TX_GAS,
                vec![account(CALLEE, 0, vec![0x00])],
            ))
            .unwrap_or_else(|status| panic!("the guest ended with {status:?} on {backend:?}"));
        assert_eq!(executed.outcome.status, call_status::HALT, "{backend:?}");
        assert_eq!(executed.outcome.gas_used, TX_GAS, "{backend:?}");
    }
}

/// Every iteration copies 32 KiB into the identity precompile and gets 32 KiB
/// back: about 10 bytes of garbage per unit of gas, 160 MiB in all.
#[test]
fn identity_churn_runs_out_of_gas() {
    runs_out_of_gas_in_16_mib(&call_loop(
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4],
        0x8000,
    ));
}

/// Every iteration enters and leaves a call frame of a contract that stops.
#[test]
fn call_frame_churn_runs_out_of_gas() {
    runs_out_of_gas_in_16_mib(&call_loop(CALLEE, 0));
}

/// The allocator's rules, checked by the guest's `heap_check` export (see
/// `guest/evm-conformance`): reuse of freed small and large blocks, growth in
/// place within a size class, growth across classes that frees the old block,
/// and alignment above a page.
#[test]
fn allocator_reuses_blocks_and_honours_alignment() {
    for backend in [Backend::Interpreter, Backend::Native] {
        let mut runner = runner(backend, 16 * MIB);
        let checks = runner
            .call("heap_check", &[], MemStorage::default())
            .unwrap();
        let names = [
            "a freed block is reused",
            "a freed 1 MiB block is reused",
            "growth within a class stays in place",
            "growth across classes moves and frees the old block",
            "blocks aligned above a page are aligned",
        ];
        assert_eq!(checks.len(), names.len(), "{backend:?}");
        for (check, name) in checks.iter().zip(names) {
            assert_eq!(*check, 1, "{name} on {backend:?}");
        }
    }
}

/// Cold accounts the code-loading case reads, from address `0x01_0000`.
const LOADED: u32 = 6_600;

/// `a = 0x010000; loop: EXTCODESIZE(a); a += 1; JUMP loop`, until out of gas.
const EXTCODESIZE_LOOP: [u8; 14] = [
    0x62, 0x01, 0x00, 0x00, 0x5B, 0x80, 0x3B, 0x50, 0x60, 0x01, 0x01, 0x60, 0x04, 0x56,
];

/// Storage holding `LOADED` contracts that share one 24 KiB code (EIP-170's
/// limit), written in the kernel's layout: too much to pass as allocations.
fn loaded_storage() -> MemStorage {
    let code = vec![0u8; 24_576];
    let code_hash = keccak256(&code);
    let mut storage = MemStorage::default();
    storage.set(&[keys::CODE, &code_hash[..]].concat(), &code);
    let account = Account {
        balance: 0,
        nonce: 1,
        code_hash,
    }
    .to_bytes();
    for i in 0..LOADED {
        let mut address = [0u8; 20];
        address[16..].copy_from_slice(&(0x01_0000 + i).to_be_bytes());
        storage.set(&[keys::ACCOUNT, &address[..]].concat(), &account);
    }
    storage
}

fn run_extcodesize_loop(heap_max: u32) -> Result<u64, Termination> {
    let mut runner = runner(Backend::Native, heap_max);
    let result = runner.run_on(
        &case(EXTCODESIZE_LOOP.to_vec(), TX_GAS, Vec::new()),
        loaded_storage(),
    );
    assert_eq!(runner.runs_natively(), Some(true));
    result.map(|executed| {
        assert_eq!(executed.outcome.status, call_status::HALT);
        executed.outcome.gas_used
    })
}

/// The heaviest transaction known: every cold `EXTCODESIZE` (2,600 gas)
/// loads a 24 KiB code, whose padded copy (a 32 KiB block) and jump table
/// stay live to the end of the transaction, about 20 bytes per unit of gas.
/// It needs more than 256 MiB of heap and fits in 320 MiB; the 1 GiB default
/// leaves about 3x over it per transaction (spec 03 §8 rule 10). Native only:
/// the interpreter takes minutes over 150 MiB of bytecode analysis.
#[test]
fn code_loading_fits_in_320_mib_and_not_in_256() {
    assert_eq!(run_extcodesize_loop(320 * MIB), Ok(TX_GAS));
    assert_eq!(run_extcodesize_loop(256 * MIB), Err(Termination::Trap));
}
