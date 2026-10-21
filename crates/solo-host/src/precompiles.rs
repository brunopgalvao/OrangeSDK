//! The precompile host functions behind feature gate 2 (spec 05 §4.8, spec
//! 19): the arithmetic of the EVM precompiles that the interpreted guest
//! computes far more slowly than Ethereum's gas assumes. Each takes the
//! operands exactly as revm's `Crypto` trait hands them to its backend and
//! runs that trait's default implementation, which is the code the guest
//! runs when the gate is not active, so both paths give the same bytes.
//!
//! Every function costs [`PRECOMPILE_BASE_GAS`] plus [`PRECOMPILE_RATE`]
//! times the Ethereum (Osaka) gas of the operation it performs, charged
//! before any range is read except the at most 32 exponent bytes `modexp`
//! prices by.

use revm_precompile::bls12_381::{G1Point, G2Point};
use revm_precompile::bls12_381_const::{DISCOUNT_TABLE_G1_MSM, DISCOUNT_TABLE_G2_MSM};
use revm_precompile::bls12_381_utils::msm_required_gas;
use revm_precompile::primitives::U256;
use revm_precompile::utilities::left_pad_vec_be;
use revm_precompile::{Crypto, PrecompileHalt};
use solo_vm::host::{Capability, HostContext};
use solo_vm::isa::Reg;
use solo_vm::status::{HostStatus, Termination};

use crate::abi::{fault, read};
use crate::executor::Extension;
use crate::storage::{Overlay, Storage};

/// Handle of the first function in [`FUNCTIONS`] as a node serves them; the
/// others follow in order.
pub const HANDLE_BASE: u32 = 202;

/// An extension that serves the functions of gate 2 and nothing else, as a
/// host does once the gate is active: for harnesses that run the kernel's
/// code outside a node (the conformance runner).
#[derive(Debug, Clone, Copy, Default)]
pub struct Gate2;

impl<S: Storage> Extension<S> for Gate2 {
    fn resolve(&self, name: &str, _: Capability) -> Option<u32> {
        handle(name)
    }

    fn call(
        &mut self,
        handle: u32,
        ctx: &mut HostContext<'_>,
        _: &mut Overlay<S>,
    ) -> Result<(), Termination> {
        dispatch(handle, ctx)
    }
}

/// The handle of the function named `name`, if it is one of [`FUNCTIONS`].
#[must_use]
pub fn handle(name: &str) -> Option<u32> {
    FUNCTIONS
        .iter()
        .position(|(n, _)| *n == name)
        .map(|i| HANDLE_BASE + u32::try_from(i).unwrap_or(u32::MAX))
}

/// Performs the function with `handle`; `Unavailable` if it names none of them.
///
/// # Errors
/// The function's terminations.
pub fn dispatch(handle: u32, ctx: &mut HostContext<'_>) -> Result<(), Termination> {
    let function = handle
        .checked_sub(HANDLE_BASE)
        .and_then(|i| FUNCTIONS.get(i as usize))
        .map_or(unknown as PrecompileFn, |(_, f)| *f);
    function(ctx)
}

/// What a handle that names no function does: what the executor does for
/// an unknown handle.
fn unknown(_: &mut HostContext<'_>) -> Result<(), Termination> {
    Err(Termination::HostError(HostStatus::Unavailable.code()))
}

/// VM gas every precompile host function costs before its operation.
pub const PRECOMPILE_BASE_GAS: u64 = 200;

/// VM gas per unit of Ethereum gas of the operation.
pub const PRECOMPILE_RATE: u64 = 2;

/// Largest base, exponent or modulus `evm_modexp` takes, in bytes (EIP-7823).
pub const MODEXP_MAX_LEN: u32 = 1024;

/// Ethereum gas of the bn254 operations (EIP-1108).
pub const BN254_ADD_GAS: u64 = 150;
/// bn254 scalar multiplication.
pub const BN254_MUL_GAS: u64 = 6_000;
/// bn254 pairing check, before its pairs.
pub const BN254_PAIRING_GAS: u64 = 45_000;
/// bn254 pairing check, per pair.
pub const BN254_PAIR_GAS: u64 = 34_000;
/// KZG point evaluation (EIP-4844).
pub const KZG_GAS: u64 = 50_000;
/// Ethereum gas of the BLS12-381 operations (EIP-2537): G1 addition.
pub const BLS_G1_ADD_GAS: u64 = 375;
/// G1 multi-scalar multiplication, per pair before the discount.
pub const BLS_G1_MSM_GAS: u64 = 12_000;
/// G2 addition.
pub const BLS_G2_ADD_GAS: u64 = 600;
/// G2 multi-scalar multiplication, per pair before the discount.
pub const BLS_G2_MSM_GAS: u64 = 22_500;
/// Pairing check, before its pairs.
pub const BLS_PAIRING_GAS: u64 = 37_700;
/// Pairing check, per pair.
pub const BLS_PAIR_GAS: u64 = 32_600;
/// Mapping a base-field element to G1.
pub const BLS_MAP_FP_GAS: u64 = 5_500;
/// Mapping an element of the quadratic extension to G2.
pub const BLS_MAP_FP2_GAS: u64 = 23_800;

/// Bytes of one bn254 pairing pair: a G1 point and a G2 point.
const BN254_PAIR_LEN: u32 = 192;
/// Bytes of a BLS12-381 base-field element.
const FP: usize = 48;
/// Bytes of a G1 point, `x ‖ y`.
const G1: usize = 2 * FP;
/// Bytes of a G2 point, `x0 ‖ x1 ‖ y0 ‖ y1`.
const G2: usize = 4 * FP;
/// Bytes of a scalar.
const SCALAR: usize = 32;
/// Bytes of two G1 points.
const G1_PAIR: u32 = 192;
/// Bytes of two G2 points.
const G2_PAIR: u32 = 384;

/// revm's backends, as the guest runs them without a host.
#[derive(Debug)]
struct Arithmetic;

impl Crypto for Arithmetic {}

/// A precompile host function.
pub type PrecompileFn = fn(&mut HostContext<'_>) -> Result<(), Termination>;

/// The import names of the precompile host functions, in handle order, and
/// their implementations; all are `Sandboxed` once gate 2 is active.
pub const FUNCTIONS: [(&str, PrecompileFn); 13] = [
    ("evm_modexp", evm_modexp),
    ("evm_bn254_add", evm_bn254_add),
    ("evm_bn254_mul", evm_bn254_mul),
    ("evm_bn254_pairing", evm_bn254_pairing),
    ("evm_blake2f", evm_blake2f),
    ("evm_kzg_point_evaluation", evm_kzg_point_evaluation),
    ("evm_bls12381_g1_add", evm_bls12381_g1_add),
    ("evm_bls12381_g1_msm", evm_bls12381_g1_msm),
    ("evm_bls12381_g2_add", evm_bls12381_g2_add),
    ("evm_bls12381_g2_msm", evm_bls12381_g2_msm),
    ("evm_bls12381_pairing", evm_bls12381_pairing),
    ("evm_bls12381_map_fp_to_g1", evm_bls12381_map_fp_to_g1),
    ("evm_bls12381_map_fp2_to_g2", evm_bls12381_map_fp2_to_g2),
];

/// The VM gas of an operation whose Ethereum gas is `gas`.
#[must_use]
pub const fn cost(gas: u64) -> u64 {
    PRECOMPILE_BASE_GAS + PRECOMPILE_RATE * gas
}

fn charge(ctx: &mut HostContext<'_>, gas: u64) -> Result<(), Termination> {
    ctx.charge(cost(gas))
}

fn write(ctx: &mut HostContext<'_>, ptr: u32, data: &[u8]) -> Result<(), Termination> {
    ctx.memory.write(ptr, data).map_err(|_| fault())
}

/// Sets `a0` from a result: 0 and the output written to `dst` on success,
/// 1 and nothing written on a halt.
fn finish(
    ctx: &mut HostContext<'_>,
    dst: u32,
    result: Result<Vec<u8>, PrecompileHalt>,
) -> Result<(), Termination> {
    match result {
        Ok(out) => {
            write(ctx, dst, &out)?;
            ctx.set(Reg::A0, 0);
        }
        Err(_) => ctx.set(Reg::A0, 1),
    }
    Ok(())
}

/// Sets `a0` from a check: 0 if it holds, 1 if not, 2 for invalid input.
fn verdict(ctx: &mut HostContext<'_>, result: Result<bool, PrecompileHalt>) {
    ctx.set(Reg::A0, result.map_or(2, |holds| u64::from(!holds)));
}

/// The bytes of `count` items of `size` bytes, or a fault for a length past
/// the address space.
fn items(ctx: &HostContext<'_>, ptr: u32, count: u32, size: usize) -> Result<Vec<u8>, Termination> {
    let len = u32::try_from(u64::from(count) * size as u64)
        .ok()
        .ok_or_else(fault)?;
    read(ctx, ptr, len)
}

fn fp(bytes: &[u8]) -> [u8; FP] {
    bytes[..FP].try_into().expect("a field element")
}

fn g1(bytes: &[u8]) -> G1Point {
    (fp(bytes), fp(&bytes[FP..]))
}

fn g2(bytes: &[u8]) -> G2Point {
    (
        fp(bytes),
        fp(&bytes[FP..]),
        fp(&bytes[2 * FP..]),
        fp(&bytes[3 * FP..]),
    )
}

fn scalar(bytes: &[u8]) -> [u8; SCALAR] {
    bytes[..SCALAR].try_into().expect("a scalar")
}

/// The Ethereum gas of a modular exponentiation (EIP-2565 as EIP-7883
/// changes it), `head` being the exponent's first 32 bytes, left-padded.
#[must_use]
pub fn modexp_gas(base_len: u32, exp_len: u32, mod_len: u32, head: &[u8; 32]) -> u64 {
    revm_precompile::modexp::osaka_gas_calc(
        u64::from(base_len),
        u64::from(exp_len),
        u64::from(mod_len),
        &U256::from_be_bytes(*head),
    )
}

/// `evm_modexp(input, base_len, exp_len, mod_len, dst)`: reads
/// `base ‖ exp ‖ mod` at `input` and writes `base^exp mod mod`, `mod_len`
/// bytes big-endian, to `dst`; `a0` = 0, or 1 with nothing read or written
/// when a length exceeds [`MODEXP_MAX_LEN`] (which costs the base only).
///
/// # Errors
/// `OutOfGas` and `MemoryFault` terminations.
pub fn evm_modexp(ctx: &mut HostContext<'_>) -> Result<(), Termination> {
    let (input, base_len, exp_len, mod_len, dst) = (
        ctx.arg32(Reg::A0),
        ctx.arg32(Reg::A1),
        ctx.arg32(Reg::A2),
        ctx.arg32(Reg::A3),
        ctx.arg32(Reg::A4),
    );
    if base_len.max(exp_len).max(mod_len) > MODEXP_MAX_LEN {
        ctx.charge(PRECOMPILE_BASE_GAS)?;
        ctx.set(Reg::A0, 1);
        return Ok(());
    }
    let head_len = exp_len.min(32);
    let mut head = [0u8; 32];
    let exp_at = input.checked_add(base_len).ok_or_else(fault)?;
    head[32 - head_len as usize..].copy_from_slice(&read(ctx, exp_at, head_len)?);
    charge(ctx, modexp_gas(base_len, exp_len, mod_len, &head))?;
    let bytes = read(ctx, input, base_len + exp_len + mod_len)?;
    let (base, rest) = bytes.split_at(base_len as usize);
    let (exp, modulus) = rest.split_at(exp_len as usize);
    let out = Arithmetic
        .modexp(base, exp, modulus)
        .map(|out| left_pad_vec_be(&out, mod_len as usize).into_owned());
    finish(ctx, dst, out)
}

/// `evm_bn254_add(input, dst)`: adds the two bn254 G1 points `p ‖ q` (64
/// bytes each, EIP-196) at `input` and writes the sum (64 bytes) to `dst`;
/// `a0` = 0, or 1 when a point is invalid.
///
/// # Errors
/// `OutOfGas` and `MemoryFault` terminations.
pub fn evm_bn254_add(ctx: &mut HostContext<'_>) -> Result<(), Termination> {
    let (input, dst) = (ctx.arg32(Reg::A0), ctx.arg32(Reg::A1));
    charge(ctx, BN254_ADD_GAS)?;
    let bytes = read(ctx, input, 128)?;
    let sum = Arithmetic.bn254_g1_add(&bytes[..64], &bytes[64..]);
    finish(ctx, dst, sum.map(|p| p.to_vec()))
}

/// `evm_bn254_mul(input, dst)`: multiplies the bn254 G1 point (64 bytes) at
/// `input` by the 32-byte big-endian scalar after it and writes the product
/// (64 bytes) to `dst`; `a0` = 0, or 1 when the point is invalid.
///
/// # Errors
/// `OutOfGas` and `MemoryFault` terminations.
pub fn evm_bn254_mul(ctx: &mut HostContext<'_>) -> Result<(), Termination> {
    let (input, dst) = (ctx.arg32(Reg::A0), ctx.arg32(Reg::A1));
    charge(ctx, BN254_MUL_GAS)?;
    let bytes = read(ctx, input, 96)?;
    let product = Arithmetic.bn254_g1_mul(&bytes[..64], &bytes[64..]);
    finish(ctx, dst, product.map(|p| p.to_vec()))
}

/// `evm_bn254_pairing(pairs, count)`: reads `count` pairs of a G1 point (64
/// bytes) and a G2 point (128 bytes, EIP-197); `a0` = 0 when the product of
/// their pairings is one (always for `count` 0), 1 when it is not, 2 when
/// a point is invalid.
///
/// # Errors
/// `OutOfGas` and `MemoryFault` terminations.
pub fn evm_bn254_pairing(ctx: &mut HostContext<'_>) -> Result<(), Termination> {
    let (pairs, count) = (ctx.arg32(Reg::A0), ctx.arg32(Reg::A1));
    charge(ctx, BN254_PAIRING_GAS + BN254_PAIR_GAS * u64::from(count))?;
    let bytes = items(ctx, pairs, count, BN254_PAIR_LEN as usize)?;
    let pairs: Vec<(&[u8], &[u8])> = bytes
        .chunks_exact(BN254_PAIR_LEN as usize)
        .map(|pair| pair.split_at(64))
        .collect();
    verdict(ctx, Arithmetic.bn254_pairing_check(&pairs));
    Ok(())
}

/// `evm_blake2f(input, dst)`: the `BLAKE2b` compression function on the 213
/// bytes of EIP-152 at `input` (rounds, big-endian `u32`; state, message and
/// offset as little-endian words; final flag), writing the new state (64
/// bytes) to `dst`; `a0` = 0, or 1 when the flag is neither 0 nor 1.
///
/// # Errors
/// `OutOfGas` and `MemoryFault` terminations.
///
/// # Panics
/// Never: the slices are of the lengths read.
pub fn evm_blake2f(ctx: &mut HostContext<'_>) -> Result<(), Termination> {
    let (input, dst) = (ctx.arg32(Reg::A0), ctx.arg32(Reg::A1));
    let rounds = read(ctx, input, 4)?;
    let rounds = u32::from_be_bytes(rounds.try_into().expect("four bytes"));
    charge(ctx, u64::from(rounds))?;
    let bytes = read(ctx, input, 213)?;
    let flag = bytes[212];
    if flag > 1 {
        ctx.set(Reg::A0, 1);
        return Ok(());
    }
    let word = |i: usize| u64::from_le_bytes(bytes[i..i + 8].try_into().expect("eight bytes"));
    let mut h: [u64; 8] = core::array::from_fn(|i| word(4 + 8 * i));
    let m: [u64; 16] = core::array::from_fn(|i| word(68 + 8 * i));
    let t = [word(196), word(204)];
    Arithmetic.blake2_compress(rounds, &mut h, &m, &t, flag == 1);
    let out: Vec<u8> = h.iter().flat_map(|w| w.to_le_bytes()).collect();
    finish(ctx, dst, Ok(out))
}

/// `evm_kzg_point_evaluation(input)`: checks the KZG proof at `input`,
/// `z(32) ‖ y(32) ‖ commitment(48) ‖ proof(48)`, against Ethereum's trusted
/// setup (EIP-4844, without the versioned-hash check the precompile makes
/// first); `a0` = 0 when it verifies, 1 otherwise.
///
/// # Errors
/// `OutOfGas` and `MemoryFault` terminations.
///
/// # Panics
/// Never: the slices are of the lengths read.
pub fn evm_kzg_point_evaluation(ctx: &mut HostContext<'_>) -> Result<(), Termination> {
    let input = ctx.arg32(Reg::A0);
    charge(ctx, KZG_GAS)?;
    let b = read(ctx, input, 160)?;
    let valid = Arithmetic.verify_kzg_proof(
        b[..32].try_into().expect("z"),
        b[32..64].try_into().expect("y"),
        b[64..112].try_into().expect("commitment"),
        b[112..].try_into().expect("proof"),
    );
    ctx.set(Reg::A0, u64::from(valid.is_err()));
    Ok(())
}

/// `evm_bls12381_g1_add(input, dst)`: adds the two G1 points at `input`
/// (96 bytes each, coordinates as 48-byte big-endian field elements, the
/// EIP-2537 encoding without its padding) and writes the sum (96 bytes);
/// `a0` = 0, or 1 when a point is invalid.
///
/// # Errors
/// `OutOfGas` and `MemoryFault` terminations.
pub fn evm_bls12381_g1_add(ctx: &mut HostContext<'_>) -> Result<(), Termination> {
    let (input, dst) = (ctx.arg32(Reg::A0), ctx.arg32(Reg::A1));
    charge(ctx, BLS_G1_ADD_GAS)?;
    let b = read(ctx, input, G1_PAIR)?;
    let sum = Arithmetic.bls12_381_g1_add(g1(&b), g1(&b[G1..]));
    finish(ctx, dst, sum.map(|p| p.to_vec()))
}

/// `evm_bls12381_g1_msm(pairs, count, dst)`: the sum of `count` G1 points
/// times 32-byte big-endian scalars, each pair `point(96) ‖ scalar(32)`,
/// written to `dst` (96 bytes; for `count` 0 the empty sum, the point at
/// infinity, all zeros); `a0` = 0, or 1 when a point is invalid.
///
/// # Errors
/// `OutOfGas` and `MemoryFault` terminations.
pub fn evm_bls12381_g1_msm(ctx: &mut HostContext<'_>) -> Result<(), Termination> {
    let (pairs, count, dst) = (ctx.arg32(Reg::A0), ctx.arg32(Reg::A1), ctx.arg32(Reg::A2));
    charge(
        ctx,
        msm_required_gas(count as usize, &DISCOUNT_TABLE_G1_MSM, BLS_G1_MSM_GAS),
    )?;
    let bytes = items(ctx, pairs, count, G1 + SCALAR)?;
    let mut iter = bytes
        .chunks_exact(G1 + SCALAR)
        .map(|p| Ok((g1(p), scalar(&p[G1..]))));
    let sum = Arithmetic.bls12_381_g1_msm(&mut iter);
    finish(ctx, dst, sum.map(|p| p.to_vec()))
}

/// `evm_bls12381_g2_add(input, dst)`: adds the two G2 points at `input`
/// (192 bytes each, `x0 ‖ x1 ‖ y0 ‖ y1`) and writes the sum (192 bytes);
/// `a0` = 0, or 1 when a point is invalid.
///
/// # Errors
/// `OutOfGas` and `MemoryFault` terminations.
pub fn evm_bls12381_g2_add(ctx: &mut HostContext<'_>) -> Result<(), Termination> {
    let (input, dst) = (ctx.arg32(Reg::A0), ctx.arg32(Reg::A1));
    charge(ctx, BLS_G2_ADD_GAS)?;
    let b = read(ctx, input, G2_PAIR)?;
    let sum = Arithmetic.bls12_381_g2_add(g2(&b), g2(&b[G2..]));
    finish(ctx, dst, sum.map(|p| p.to_vec()))
}

/// `evm_bls12381_g2_msm(pairs, count, dst)`: as [`evm_bls12381_g1_msm`] in
/// G2, each pair `point(192) ‖ scalar(32)`, the sum 192 bytes.
///
/// # Errors
/// `OutOfGas` and `MemoryFault` terminations.
pub fn evm_bls12381_g2_msm(ctx: &mut HostContext<'_>) -> Result<(), Termination> {
    let (pairs, count, dst) = (ctx.arg32(Reg::A0), ctx.arg32(Reg::A1), ctx.arg32(Reg::A2));
    charge(
        ctx,
        msm_required_gas(count as usize, &DISCOUNT_TABLE_G2_MSM, BLS_G2_MSM_GAS),
    )?;
    let bytes = items(ctx, pairs, count, G2 + SCALAR)?;
    let mut iter = bytes
        .chunks_exact(G2 + SCALAR)
        .map(|p| Ok((g2(p), scalar(&p[G2..]))));
    let sum = Arithmetic.bls12_381_g2_msm(&mut iter);
    finish(ctx, dst, sum.map(|p| p.to_vec()))
}

/// `evm_bls12381_pairing(pairs, count)`: reads `count` pairs of a G1 point
/// (96 bytes) and a G2 point (192 bytes); `a0` = 0 when the product of their
/// pairings is one (always for `count` 0), 1 when it is not, 2 when a point
/// is invalid.
///
/// # Errors
/// `OutOfGas` and `MemoryFault` terminations.
pub fn evm_bls12381_pairing(ctx: &mut HostContext<'_>) -> Result<(), Termination> {
    let (pairs, count) = (ctx.arg32(Reg::A0), ctx.arg32(Reg::A1));
    charge(ctx, BLS_PAIRING_GAS + BLS_PAIR_GAS * u64::from(count))?;
    let bytes = items(ctx, pairs, count, G1 + G2)?;
    let pairs: Vec<(G1Point, G2Point)> = bytes
        .chunks_exact(G1 + G2)
        .map(|p| (g1(p), g2(&p[G1..])))
        .collect();
    verdict(ctx, Arithmetic.bls12_381_pairing_check(&pairs));
    Ok(())
}

/// `evm_bls12381_map_fp_to_g1(input, dst)`: maps the base-field element
/// (48 bytes) at `input` to G1 and writes the point (96 bytes); `a0` = 0,
/// or 1 when the element is not below the modulus.
///
/// # Errors
/// `OutOfGas` and `MemoryFault` terminations.
pub fn evm_bls12381_map_fp_to_g1(ctx: &mut HostContext<'_>) -> Result<(), Termination> {
    let (input, dst) = (ctx.arg32(Reg::A0), ctx.arg32(Reg::A1));
    charge(ctx, BLS_MAP_FP_GAS)?;
    let b = read(ctx, input, 48)?;
    let point = Arithmetic.bls12_381_fp_to_g1(&fp(&b));
    finish(ctx, dst, point.map(|p| p.to_vec()))
}

/// `evm_bls12381_map_fp2_to_g2(input, dst)`: maps the element `c0 ‖ c1`
/// (96 bytes) of the quadratic extension at `input` to G2 and writes the
/// point (192 bytes); `a0` = 0, or 1 when a coefficient is not below the
/// modulus.
///
/// # Errors
/// `OutOfGas` and `MemoryFault` terminations.
pub fn evm_bls12381_map_fp2_to_g2(ctx: &mut HostContext<'_>) -> Result<(), Termination> {
    let (input, dst) = (ctx.arg32(Reg::A0), ctx.arg32(Reg::A1));
    charge(ctx, BLS_MAP_FP2_GAS)?;
    let b = read(ctx, input, 96)?;
    let point = Arithmetic.bls12_381_fp2_to_g2((fp(&b), fp(&b[FP..])));
    finish(ctx, dst, point.map(|p| p.to_vec()))
}
