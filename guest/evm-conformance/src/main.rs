//! The EVM conformance guest (spec 07 §4.2): runs one Ethereum state test
//! case through the reference kernel's own EVM code.
//!
//! The kernel's `evm`, `native`, `outbox`, `modules`, `precompiles`, `state` and `tx` modules are
//! compiled here from their source files, so there is one copy of the code
//! under test: revm over the kernel's `StateDb` with the kernel's precompile
//! provider (Ethereum's precompiles and native contracts), its commit of
//! revm's changes to storage, the host crypto behind the precompiles, genesis
//! allocation and sender recovery.
//! The case's pre-state goes in as genesis allocations, the transaction as
//! signed bytes; the post-state stays in storage for the host to read.
//! `conformance_run` runs the precompiles as the kernel does before feature
//! gate 2, in the guest; `conformance_run_gated` as it does once the gate is
//! active, on the host through the precompile module (spec 19), which needs
//! a host that serves the gate's functions.

#![no_std]
#![no_main]

extern crate alloc;

#[allow(dead_code)]
#[path = "../../kernel/src/evm.rs"]
mod evm;
#[allow(dead_code)]
#[path = "../../kernel/src/modules.rs"]
mod modules;
#[allow(dead_code)]
#[path = "../../kernel/src/native.rs"]
mod native;
#[allow(dead_code)]
#[path = "../../kernel/src/outbox.rs"]
mod outbox;
#[allow(dead_code)]
#[path = "../../kernel/src/precompiles.rs"]
mod precompiles;
#[allow(dead_code)]
#[path = "../../kernel/src/state.rs"]
mod state;
#[allow(dead_code)]
#[path = "../../kernel/src/tx.rs"]
mod tx;

use alloc::boxed::Box;
use alloc::vec::Vec;

use solo_abi::chain::{GenesisParams, call_status};
use solo_abi::codec::Seq;
use solo_abi::conformance::{Case, Outcome};
use solo_abi::types::Genesis;
use solo_abi::{Decode, Encode};

use crate::evm::{Env, Message};

fn run(case: Case, accelerated: bool) -> Outcome {
    let env = case.env;
    let params = GenesisParams { allocations: case.allocations, ..GenesisParams::default() };
    state::init(&Genesis { chain_id: env.chain_id, params: params.to_bytes(), ..Genesis::default() });
    precompiles::begin(accelerated);
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
    let outcome = native::run_in(message, &env, true);
    Outcome { status: outcome.status, gas_used: outcome.gas_used, logs: Seq(outcome.logs) }
}

solo_guest::solo_export!(conformance_run, |input: &[u8]| -> Vec<u8> {
    match Case::from_bytes(input) {
        Ok(case) => run(case, false).to_bytes(),
        Err(_) => solo_guest::trap(),
    }
});

solo_guest::solo_export!(conformance_run_gated, |input: &[u8]| -> Vec<u8> {
    match Case::from_bytes(input) {
        Ok(case) => run(case, true).to_bytes(),
        Err(_) => solo_guest::trap(),
    }
});

/// The address of a heap block, opaque to the optimizer so that it can
/// neither elide the allocation nor fold comparisons between blocks.
fn address<T: ?Sized>(block: &T) -> usize {
    core::hint::black_box(core::ptr::from_ref(block).cast::<u8>()) as usize
}

/// A block whose alignment is larger than a page.
#[repr(C, align(8192))]
struct PageAligned([u8; 16]);

/// Checks the guest runtime's allocator (`solo_guest::heap::Pool`) from the
/// inside, one byte per property, 1 when it holds, in this order:
///
/// 0. a freed block is the next one handed out in its size class;
/// 1. a freed block of a large class (1 MiB) is handed out again too;
/// 2. growing a block within its class keeps it in place;
/// 3. growing it past its class moves it, keeps its contents and frees the
///    old block for the next allocation of that class;
/// 4. blocks aligned above a page come out aligned, every time.
///
/// Nothing else allocates between the steps, so each comparison is exact.
fn heap_check() -> Vec<u8> {
    let small = Box::new([7u8; 100]);
    let freed = address(&*small);
    drop(small);
    let again = Box::new([9u8; 120]);
    let reuse = address(&*again) == freed;
    drop(again);

    let large = alloc::vec![1u8; 1 << 20];
    let freed = address(&*large);
    drop(large);
    let again = alloc::vec![2u8; (1 << 20) - 100];
    let reuse_large = address(&*again) == freed;
    drop(again);

    let mut grown: Vec<u8> = Vec::with_capacity(40);
    grown.extend_from_slice(b"solo");
    let first = address(grown.as_slice());
    grown.reserve_exact(56);
    let in_place = address(grown.as_slice()) == first && grown.capacity() >= 60;
    grown.reserve_exact(200);
    let moved = address(grown.as_slice()) != first && grown == b"solo";
    let next = Box::new([3u8; 64]);
    let moved = moved && address(&*next) == first;
    drop(next);
    drop(grown);

    let one = Box::new(PageAligned([0; 16]));
    let two = Box::new(PageAligned([1; 16]));
    let aligned = address(&*one) % 8192 == 0 && address(&*two) % 8192 == 0;
    drop(one);
    let three = Box::new(PageAligned([2; 16]));
    let aligned = aligned && address(&*three) % 8192 == 0 && two.0[0] == 1 && three.0[0] == 2;
    drop((two, three));

    [reuse, reuse_large, in_place, moved, aligned].into_iter().map(u8::from).collect()
}

solo_guest::solo_export!(heap_check, |_input: &[u8]| -> Vec<u8> { heap_check() });

// The VM starts at an export; `main` exists only so the linker is satisfied.
solo_guest::solo_main!(unused_main);

fn unused_main(_: u64, _: u64, _: u64, _: u64, _: u64, _: u64) -> (u64, u64) {
    (0, 0)
}
