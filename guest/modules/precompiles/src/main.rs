//! The precompile module (spec 19 §3.2): the only code that imports the
//! precompile host functions behind feature gate 2 (spec 05 §4.8), so that
//! the kernel itself loads on every host. The kernel invokes it, static, with
//! the input `op ‖ operands`, `op` indexing the functions in the order of
//! spec 05 §4.8, and it writes `a0 ‖ result`: the function's status byte and
//! the bytes it wrote, if any. An input of the wrong length for its `op`, or
//! an unknown `op`, traps. Before gate 2 is active the module does not load.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use core::arch::global_asm;

/// Declares the import stubs of the gate-2 functions as `solo-guest` declares
/// those of the ungated ones: the recompiler replaces each call with an
/// `ecall` (spec 03 §8). They live here so that no other program changes.
macro_rules! stubs {
    ($($name:ident),* $(,)?) => {
        global_asm!(
            ".section .text.solo_stubs_precompiles,\"ax\",@progbits",
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
    __solo_import_evm_modexp,
    __solo_import_evm_bn254_add,
    __solo_import_evm_bn254_mul,
    __solo_import_evm_bn254_pairing,
    __solo_import_evm_blake2f,
    __solo_import_evm_kzg_point_evaluation,
    __solo_import_evm_bls12381_g1_add,
    __solo_import_evm_bls12381_g1_msm,
    __solo_import_evm_bls12381_g2_add,
    __solo_import_evm_bls12381_g2_msm,
    __solo_import_evm_bls12381_pairing,
    __solo_import_evm_bls12381_map_fp_to_g1,
    __solo_import_evm_bls12381_map_fp2_to_g2,
);

/// The precompile functions behind gate 2 (spec 05 §4.8).
mod host {
    unsafe extern "C" {
        pub fn __solo_import_evm_modexp(input: *const u8, base_len: u32, exp_len: u32, mod_len: u32, dst: *mut u8) -> u64;
        pub fn __solo_import_evm_bn254_add(input: *const u8, dst: *mut u8) -> u64;
        pub fn __solo_import_evm_bn254_mul(input: *const u8, dst: *mut u8) -> u64;
        pub fn __solo_import_evm_bn254_pairing(pairs: *const u8, count: u32) -> u64;
        pub fn __solo_import_evm_blake2f(input: *const u8, dst: *mut u8) -> u64;
        pub fn __solo_import_evm_kzg_point_evaluation(input: *const u8) -> u64;
        pub fn __solo_import_evm_bls12381_g1_add(input: *const u8, dst: *mut u8) -> u64;
        pub fn __solo_import_evm_bls12381_g1_msm(pairs: *const u8, count: u32, dst: *mut u8) -> u64;
        pub fn __solo_import_evm_bls12381_g2_add(input: *const u8, dst: *mut u8) -> u64;
        pub fn __solo_import_evm_bls12381_g2_msm(pairs: *const u8, count: u32, dst: *mut u8) -> u64;
        pub fn __solo_import_evm_bls12381_pairing(pairs: *const u8, count: u32) -> u64;
        pub fn __solo_import_evm_bls12381_map_fp_to_g1(input: *const u8, dst: *mut u8) -> u64;
        pub fn __solo_import_evm_bls12381_map_fp2_to_g2(input: *const u8, dst: *mut u8) -> u64;
    }
}

/// Operand and result sizes of the fixed-size operations, by `op`; `None`
/// for those that take a count of pairs or, for `modexp`, lengths.
const FIXED: [Option<(usize, usize)>; 13] = [
    None,
    Some((128, 64)),
    Some((96, 64)),
    None,
    Some((213, 64)),
    Some((160, 0)),
    Some((192, 96)),
    None,
    Some((384, 192)),
    None,
    None,
    Some((48, 96)),
    Some((96, 192)),
];

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    let word: [u8; 4] = bytes.get(at..at + 4).and_then(|b| b.try_into().ok()).unwrap_or_else(|| solo_guest::trap());
    u32::from_le_bytes(word)
}

/// The number of `size`-byte items in `bytes`, which must be a whole number of them.
fn count(bytes: &[u8], size: usize) -> u32 {
    if bytes.len() % size != 0 {
        solo_guest::trap();
    }
    (bytes.len() / size) as u32
}

/// Runs operation `op` on `x`: the status and the result.
fn run(op: u8, x: &[u8]) -> (u64, Vec<u8>) {
    let (p, n) = (x.as_ptr(), x.len());
    if let Some((len, out)) = FIXED.get(op as usize).copied().flatten() {
        if n != len {
            solo_guest::trap();
        }
        let mut dst = vec![0u8; out];
        let d = dst.as_mut_ptr();
        // SAFETY: `x` holds the operands the function reads and `dst` has room
        // for the result it writes, at the sizes of spec 05 §4.8.
        let status = unsafe {
            match op {
                1 => host::__solo_import_evm_bn254_add(p, d),
                2 => host::__solo_import_evm_bn254_mul(p, d),
                4 => host::__solo_import_evm_blake2f(p, d),
                5 => host::__solo_import_evm_kzg_point_evaluation(p),
                6 => host::__solo_import_evm_bls12381_g1_add(p, d),
                8 => host::__solo_import_evm_bls12381_g2_add(p, d),
                11 => host::__solo_import_evm_bls12381_map_fp_to_g1(p, d),
                _ => host::__solo_import_evm_bls12381_map_fp2_to_g2(p, d),
            }
        };
        return (status, dst);
    }
    match op {
        0 => {
            let (base, exp, modulus) = (u32_at(x, 0), u32_at(x, 4), u32_at(x, 8));
            if n != 12 + base as usize + exp as usize + modulus as usize {
                solo_guest::trap();
            }
            let mut dst = vec![0u8; modulus as usize];
            // SAFETY: the operands follow the lengths, and `dst` holds `modulus` bytes.
            let status = unsafe { host::__solo_import_evm_modexp(p.wrapping_add(12), base, exp, modulus, dst.as_mut_ptr()) };
            (status, dst)
        }
        // SAFETY: `x` holds `count` whole pairs.
        3 => (unsafe { host::__solo_import_evm_bn254_pairing(p, count(x, 192)) }, Vec::new()),
        // SAFETY: as above.
        10 => (unsafe { host::__solo_import_evm_bls12381_pairing(p, count(x, 288)) }, Vec::new()),
        7 | 9 => {
            let (size, out) = if op == 7 { (128, 96) } else { (224, 192) };
            let mut dst = vec![0u8; out];
            let pairs = count(x, size);
            // SAFETY: `x` holds `pairs` whole pairs and `dst` has room for the sum.
            let status = unsafe {
                if op == 7 {
                    host::__solo_import_evm_bls12381_g1_msm(p, pairs, dst.as_mut_ptr())
                } else {
                    host::__solo_import_evm_bls12381_g2_msm(p, pairs, dst.as_mut_ptr())
                }
            };
            (status, dst)
        }
        _ => solo_guest::trap(),
    }
}

solo_guest::solo_main!(entry);

fn entry(_: u64, _: u64, _: u64, _: u64, _: u64, _: u64) -> (u64, u64) {
    let input = solo_guest::input_vec();
    let Some((&op, operands)) = input.split_first() else { solo_guest::trap() };
    let (status, result) = run(op, operands);
    let mut out = Vec::with_capacity(1 + result.len());
    out.push(status as u8);
    out.extend_from_slice(&result);
    solo_guest::output(&out);
    (0, 0)
}
