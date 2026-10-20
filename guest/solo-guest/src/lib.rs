//! Runtime for Solo guest programs.
//!
//! A guest is an ordinary `no_std` Rust crate for `riscv64imac-unknown-none-elf`.
//! Host calls are ordinary `extern "C"` functions named `__solo_import_<name>`;
//! the recompiler replaces every call to one with an `ecall` (spec 03 §8). The
//! stubs below exist only so the ELF links; their bodies never run.

#![no_std]

extern crate alloc;

use core::arch::global_asm;

pub mod heap;

/// Declares the stub symbols the recompiler recognises. Each is a function
/// whose body is `unimp`, so running one unrecompiled traps immediately.
macro_rules! stubs {
    ($($name:ident),* $(,)?) => {
        global_asm!(
            ".section .text.solo_stubs,\"ax\",@progbits",
            $(
                concat!(".globl ", stringify!($name)),
                concat!(".type ", stringify!($name), ",@function"),
                concat!(stringify!($name), ":"),
                "unimp",
                "ret",
            )*
        );
    };
}

stubs!(
    __solo_halt,
    __solo_trap,
    __solo_sbrk,
    __solo_import_abi_version,
    __solo_import_input_len,
    __solo_import_input_read,
    __solo_import_output_write,
    __solo_import_gas_remaining,
    __solo_import_storage_get,
    __solo_import_storage_set,
    __solo_import_storage_delete,
    __solo_import_storage_iter_open,
    __solo_import_storage_iter_next,
    __solo_import_storage_commit,
    __solo_import_storage_proof,
    __solo_import_hash_keccak256,
    __solo_import_hash_sha256,
    __solo_import_hash_blake2b256,
    __solo_import_secp256k1_recover,
    __solo_import_p256_verify,
    __solo_import_bls12381_verify,
    __solo_import_bls12381_pairing_check,
    __solo_import_bls12381_fast_aggregate_verify,
    __solo_import_sign,
    __solo_import_invoke,
    __solo_import_invoke_output_len,
    __solo_import_invoke_output_read,
    __solo_import_net_send,
    __solo_import_net_broadcast,
    __solo_import_net_disseminate,
    __solo_import_net_request,
    __solo_import_net_respond,
    __solo_import_net_peer_score,
    __solo_import_time_now,
    __solo_import_timer_set,
    __solo_import_timer_cancel,
    __solo_import_persist_set,
    __solo_import_persist_get,
    __solo_import_log_emit,
    __solo_import_metric_emit,
);

/// The two result registers of a host function that returns `a0` and `a1`:
/// a struct of two `u64` comes back in exactly those registers (RISC-V
/// LP64 calling convention).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pair {
    /// `a0`.
    pub a0: u64,
    /// `a1`.
    pub a1: u64,
}

/// Raw host functions (spec 05 §4). Pointers are guest addresses.
pub mod host {
    unsafe extern "C" {
        /// Ends the instance with `Halt`; `a0`, `a1` are the return values.
        pub fn __solo_halt(a0: u64, a1: u64) -> !;
        /// Ends the instance with `Trap`.
        pub fn __solo_trap() -> !;
        /// Grows the heap by `bytes` (rounded up to pages); returns the old heap
        /// end, or 0 if the heap is full.
        pub fn __solo_sbrk(bytes: u64) -> u64;
        pub fn __solo_import_abi_version() -> u64;
        pub fn __solo_import_input_len() -> u64;
        pub fn __solo_import_input_read(dst: *mut u8, offset: u32, len: u32) -> u64;
        pub fn __solo_import_output_write(src: *const u8, len: u32) -> u64;
        pub fn __solo_import_gas_remaining() -> u64;
        pub fn __solo_import_storage_get(key: *const u8, key_len: u32, dst: *mut u8, cap: u32) -> u64;
        pub fn __solo_import_storage_set(key: *const u8, key_len: u32, val: *const u8, val_len: u32) -> u64;
        pub fn __solo_import_storage_delete(key: *const u8, key_len: u32) -> u64;
        pub fn __solo_import_storage_commit(dst: *mut u8) -> u64;
        pub fn __solo_import_storage_iter_open(prefix: *const u8, prefix_len: u32) -> u64;
        pub fn __solo_import_storage_iter_next(handle: u64, key: *mut u8, key_cap: u32, val: *mut u8, val_cap: u32) -> super::Pair;
        /// `a0` = status, `a1` = callee gas used (spec 05 §4.4).
        pub fn __solo_import_invoke(code_hash: *const u8, namespace: *const u8, input: *const u8, input_len: u32, gas_limit: u64, flags: u64) -> super::Pair;
        pub fn __solo_import_invoke_output_len() -> u64;
        pub fn __solo_import_invoke_output_read(dst: *mut u8, offset: u32, len: u32) -> u64;
        pub fn __solo_import_secp256k1_recover(msg: *const u8, sig: *const u8, dst: *mut u8) -> u64;
        pub fn __solo_import_hash_keccak256(src: *const u8, len: u32, dst: *mut u8) -> u64;
        pub fn __solo_import_hash_sha256(src: *const u8, len: u32, dst: *mut u8) -> u64;
        pub fn __solo_import_p256_verify(msg: *const u8, sig: *const u8, pubkey: *const u8) -> u64;
        pub fn __solo_import_bls12381_verify(
            msg: *const u8,
            msg_len: u32,
            sig: *const u8,
            pubkey: *const u8,
            dst: *const u8,
            dst_len: u32,
        ) -> u64;
        pub fn __solo_import_bls12381_pairing_check(pairs: *const u8, count: u32) -> u64;
        pub fn __solo_import_bls12381_fast_aggregate_verify(keys: *const u8, count: u32, msg: *const u8, msg_len: u32, sig: *const u8) -> u64;
        pub fn __solo_import_sign(key_role: u64, msg: *const u8, msg_len: u32, dst: *mut u8, cap: u32) -> u64;
        pub fn __solo_import_time_now() -> u64;
        pub fn __solo_import_persist_set(key: *const u8, key_len: u32, val: *const u8, val_len: u32) -> u64;
        pub fn __solo_import_persist_get(key: *const u8, key_len: u32, dst: *mut u8, cap: u32) -> u64;
        pub fn __solo_import_log_emit(level: u32, msg: *const u8, len: u32) -> u64;
        pub fn __solo_import_metric_emit(name: *const u8, name_len: u32, value: i64, kind: u32) -> u64;
    }
}

/// Reads the whole input blob into `buf`, returning the number of bytes
/// available (which may exceed `buf.len()`).
#[must_use]
pub fn input(buf: &mut [u8]) -> usize {
    // SAFETY: the pointer and length describe `buf`, which is valid guest memory.
    unsafe {
        let len = host::__solo_import_input_len() as usize;
        let n = len.min(buf.len());
        host::__solo_import_input_read(buf.as_mut_ptr(), 0, n as u32);
        len
    }
}

/// Replaces the output blob with `bytes`.
pub fn output(bytes: &[u8]) {
    // SAFETY: the pointer and length describe `bytes`.
    unsafe {
        host::__solo_import_output_write(bytes.as_ptr(), bytes.len() as u32);
    }
}

/// Emits a log line (ignored by consensus).
pub fn log(level: u32, msg: &str) {
    // SAFETY: the pointer and length describe `msg`.
    unsafe {
        host::__solo_import_log_emit(level, msg.as_ptr(), msg.len() as u32);
    }
}

/// Ends the instance with `Trap`.
pub fn trap() -> ! {
    // SAFETY: the stub never returns.
    unsafe { host::__solo_trap() }
}

/// Ends the instance with `Halt` and the given return values.
pub fn halt(a0: u64, a1: u64) -> ! {
    // SAFETY: the stub never returns.
    unsafe { host::__solo_halt(a0, a1) }
}

/// Reads the whole input blob.
#[must_use]
pub fn input_vec() -> alloc::vec::Vec<u8> {
    // SAFETY: host functions with valid pointers into our own buffer.
    unsafe {
        let len = host::__solo_import_input_len() as usize;
        let mut buf = alloc::vec![0u8; len];
        host::__solo_import_input_read(buf.as_mut_ptr(), 0, len as u32);
        buf
    }
}

/// Defines an export named `solo_export_<name>` whose handler receives the
/// input blob and returns the output blob; the instance halts with `(0, 0)`.
#[macro_export]
macro_rules! solo_export {
    ($name:ident, $handler:expr) => {
        $crate::__paste_export!($name, $handler);
    };
}

/// Implementation detail of [`solo_export!`]: the export symbol is spelled
/// `solo_export_` followed by the name through `concat_idents`-free linking
/// via `export_name`.
#[doc(hidden)]
#[macro_export]
macro_rules! __paste_export {
    ($name:ident, $handler:expr) => {
        const _: () = {
            #[unsafe(export_name = concat!("solo_export_", stringify!($name)))]
            pub extern "C" fn entry() -> ! {
                let handler: fn(&[u8]) -> alloc::vec::Vec<u8> = $handler;
                let input = $crate::input_vec();
                let out = handler(&input);
                $crate::output(&out);
                $crate::halt(0, 0)
            }
        };
    };
}

/// Defines the `main` export. The function receives `a0`–`a5` and returns the
/// pair placed in `a0`, `a1` at `Halt`.
#[macro_export]
macro_rules! solo_main {
    ($f:path) => {
        #[unsafe(no_mangle)]
        pub extern "C" fn solo_export_main(a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> ! {
            let (r0, r1): (u64, u64) = $f(a0, a1, a2, a3, a4, a5);
            $crate::halt(r0, r1)
        }
    };
}

#[cfg(feature = "allocator")]
#[global_allocator]
static ALLOCATOR: heap::Pool = heap::Pool::new();

#[cfg(feature = "panic-handler")]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // SAFETY: the stub never returns.
    unsafe { host::__solo_trap() }
}
