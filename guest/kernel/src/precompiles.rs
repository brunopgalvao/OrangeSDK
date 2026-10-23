//! Host-accelerated precompiles (spec 19).
//!
//! revm hands the arithmetic of the Ethereum precompiles to the installed
//! `Crypto` (`evm::HostCrypto`). Once feature gate 2 is active for the block,
//! the operations behind the precompile host functions (spec 05 §4.8) run on
//! the host: the kernel invokes the precompile module, which alone imports
//! those functions, so the kernel loads on every host whatever the gate. The
//! module's bytes are embedded here and written under `code/` ‖ their hash in
//! the first block with the gate active.
//!
//! Before that, the guest computes them with revm's own backends, the code
//! the host functions run, so both paths agree byte for byte. Those whose
//! in-guest cost per EVM gas is above the bound of spec 19 §2 run only while
//! the kernel gas the block (or query) has used, plus the operation's bound,
//! stays within [`PRECOMPILE_BUDGET`]; past it they halt out of gas, so a
//! block of them cannot exhaust the node's kernel gas (spec 19 §5).

use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use revm::precompile::bls12_381::{G1Point, G1PointScalar, G2Point, G2PointScalar};
use revm::precompile::{Crypto, PrecompileHalt};
use solo_abi::types::Hash;
use solo_guest::host;

use crate::state;

/// The precompile module, `guest/modules/precompiles` as `tools/build-guest.sh`
/// recompiles it.
pub const MODULE: &[u8] = include_bytes!("../precompiles.solo");

/// The operations, by the index the module takes (spec 05 §4.8 order).
pub mod op {
    /// `evm_modexp`.
    pub const MODEXP: u8 = 0;
    /// `evm_bn254_add`.
    pub const BN254_ADD: u8 = 1;
    /// `evm_bn254_mul`.
    pub const BN254_MUL: u8 = 2;
    /// `evm_bn254_pairing`.
    pub const BN254_PAIRING: u8 = 3;
    /// `evm_blake2f`.
    pub const BLAKE2F: u8 = 4;
    /// `evm_kzg_point_evaluation`.
    pub const KZG: u8 = 5;
    /// `evm_bls12381_g1_add`.
    pub const G1_ADD: u8 = 6;
    /// `evm_bls12381_g1_msm`.
    pub const G1_MSM: u8 = 7;
    /// `evm_bls12381_g2_add`.
    pub const G2_ADD: u8 = 8;
    /// `evm_bls12381_g2_msm`.
    pub const G2_MSM: u8 = 9;
    /// `evm_bls12381_pairing`.
    pub const PAIRING: u8 = 10;
    /// `evm_bls12381_map_fp_to_g1`.
    pub const MAP_FP: u8 = 11;
    /// `evm_bls12381_map_fp2_to_g2`.
    pub const MAP_FP2: u8 = 12;
}

/// Kernel gas a block (or a query) may have used for an in-guest precompile
/// above the bound to start (spec 19 §5).
pub const PRECOMPILE_BUDGET: u64 = 1 << 34;

/// Kernel gas per EVM gas each in-guest operation is assumed to cost when
/// checked against the budget, by op; 0 for those within the bound of
/// spec 19 §2, which run unchecked (spec 19 table 5.1).
const GUEST_RATIO: [u64; 13] = [0, 0, 600, 500, 0, 2_200, 0, 800, 800, 1_200, 900, 800, 600];

/// Fewest BLAKE2F rounds that run on the host: below it the guest's
/// compression costs less than invoking the module (spec 19 §3.3).
pub const BLAKE2F_HOST_ROUNDS: u32 = 64;

/// Gas left to the kernel instance when the guard below must leave it.
const INVOKE_RESERVE: u64 = 100_000;

static ACCELERATED: AtomicBool = AtomicBool::new(false);
static START: AtomicU64 = AtomicU64::new(0);
static HASH: [AtomicU64; 4] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];
static HASHED: AtomicBool = AtomicBool::new(false);

/// The `keccak256` that `alloy-primitives` calls with its `native-keccak`
/// feature, and so revm for `KECCAK256`, `CREATE2` and code hashes: the
/// host's `hash_keccak256` (spec 05 §4.3, spec 19 §4), the same function for
/// a small fraction of the VM gas of hashing in the guest.
///
/// # Safety
/// `bytes` points to `len` readable bytes and `output` to 32 writable ones,
/// as `alloy-primitives` guarantees.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn native_keccak256(bytes: *const u8, len: usize, output: *mut u8) {
    // SAFETY: the caller's pointers; the host checks the ranges anyway.
    unsafe {
        host::__solo_import_hash_keccak256(bytes, len as u32, output);
    }
}

/// revm's backends, which the guest runs before gate 2.
#[derive(Debug)]
pub struct Guest;

impl Crypto for Guest {}

fn gas_remaining() -> u64 {
    // SAFETY: no arguments.
    unsafe { host::__solo_import_gas_remaining() }
}

/// Starts a block (or query): the precompiles run on the host if
/// `accelerated` (gate 2 is active for it), and the budget counts from here.
/// With the gate active, the module is written to state if it is not there.
pub fn begin(accelerated: bool) {
    ACCELERATED.store(accelerated, Ordering::Relaxed);
    START.store(gas_remaining(), Ordering::Relaxed);
    if accelerated {
        let key = state::code_key(&code_hash());
        if state::get_raw(&key).is_none() {
            state::set_raw(&key, MODULE);
        }
    }
}

/// Whether the precompiles run on the host.
pub fn accelerated() -> bool {
    ACCELERATED.load(Ordering::Relaxed)
}

/// The module's code hash.
pub fn code_hash() -> Hash {
    if !HASHED.load(Ordering::Relaxed) {
        let hash = state::keccak256(MODULE);
        for (i, word) in hash.chunks_exact(8).enumerate() {
            HASH[i].store(
                u64::from_le_bytes(word.try_into().unwrap_or_default()),
                Ordering::Relaxed,
            );
        }
        HASHED.store(true, Ordering::Relaxed);
    }
    let mut hash = [0u8; 32];
    for (i, word) in hash.chunks_exact_mut(8).enumerate() {
        word.copy_from_slice(&HASH[i].load(Ordering::Relaxed).to_le_bytes());
    }
    hash
}

/// Checks an in-guest operation whose Ethereum gas is `gas` against the
/// budget.
fn guard(op: u8, gas: u64) -> Result<(), PrecompileHalt> {
    let ratio = GUEST_RATIO[op as usize];
    let used = START
        .load(Ordering::Relaxed)
        .saturating_sub(gas_remaining());
    match used.checked_add(gas.saturating_mul(ratio)) {
        Some(total) if total <= PRECOMPILE_BUDGET => Ok(()),
        _ => Err(PrecompileHalt::OutOfGas),
    }
}

/// Runs `op` on `operands` through the precompile module: its status and
/// result. A module that does not run to completion leaves the kernel
/// nothing correct to do, so it traps: the host cannot serve gate 2, which
/// spec 13 §8.6 makes a loud failure, or the kernel is out of gas.
fn accelerate(op: u8, operands: &[u8]) -> (u8, Vec<u8>) {
    let hash = code_hash();
    let mut input = Vec::with_capacity(1 + operands.len());
    input.push(op);
    input.extend_from_slice(operands);
    let limit = gas_remaining().saturating_sub(INVOKE_RESERVE);
    // SAFETY: valid pointers into our own buffers of the stated sizes; flag 2 is `static`.
    let result = unsafe {
        host::__solo_import_invoke(
            hash.as_ptr(),
            [0u8; 32].as_ptr(),
            input.as_ptr(),
            input.len() as u32,
            limit,
            2,
        )
    };
    if result.a0 != 0 {
        solo_guest::trap();
    }
    // SAFETY: no arguments, then a buffer of the reported length.
    let out = unsafe {
        let len = host::__solo_import_invoke_output_len() as usize;
        let mut buf = vec![0u8; len];
        host::__solo_import_invoke_output_read(buf.as_mut_ptr(), 0, len as u32);
        buf
    };
    match out.split_first() {
        Some((&status, result)) => (status, result.to_vec()),
        None => solo_guest::trap(),
    }
}

/// A result the host wrote, or `halt` for status 1.
fn output<const N: usize>(
    op: u8,
    operands: &[u8],
    halt: PrecompileHalt,
) -> Result<[u8; N], PrecompileHalt> {
    let (status, out) = accelerate(op, operands);
    match <[u8; N]>::try_from(out.as_slice()) {
        Ok(out) if status == 0 => Ok(out),
        _ => Err(halt),
    }
}

/// A check the host made: status 0 holds, 1 does not, anything else halts.
fn check(op: u8, operands: &[u8], halt: PrecompileHalt) -> Result<bool, PrecompileHalt> {
    match accelerate(op, operands).0 {
        0 => Ok(true),
        1 => Ok(false),
        _ => Err(halt),
    }
}

fn g1(point: &G1Point, out: &mut Vec<u8>) {
    out.extend_from_slice(&point.0);
    out.extend_from_slice(&point.1);
}

fn g2(point: &G2Point, out: &mut Vec<u8>) {
    for fp in [&point.0, &point.1, &point.2, &point.3] {
        out.extend_from_slice(fp);
    }
}

/// `modexp` (EIP-198): within the bound in the guest.
pub fn modexp(base: &[u8], exp: &[u8], modulus: &[u8]) -> Result<Vec<u8>, PrecompileHalt> {
    if !accelerated() {
        return Guest.modexp(base, exp, modulus);
    }
    let mut operands = Vec::with_capacity(12 + base.len() + exp.len() + modulus.len());
    for len in [base.len(), exp.len(), modulus.len()] {
        operands.extend_from_slice(&(len as u32).to_le_bytes());
    }
    operands.extend_from_slice(base);
    operands.extend_from_slice(exp);
    operands.extend_from_slice(modulus);
    let (status, out) = accelerate(op::MODEXP, &operands);
    if status != 0 {
        return Err(PrecompileHalt::ModexpEip7823LimitSize);
    }
    Ok(out)
}

/// bn254 addition (EIP-196): within the bound in the guest.
pub fn bn254_add(p1: &[u8], p2: &[u8]) -> Result<[u8; 64], PrecompileHalt> {
    if !accelerated() {
        return Guest.bn254_g1_add(p1, p2);
    }
    output(
        op::BN254_ADD,
        &[p1, p2].concat(),
        PrecompileHalt::Bn254AffineGFailedToCreate,
    )
}

/// bn254 scalar multiplication (EIP-196).
pub fn bn254_mul(point: &[u8], scalar: &[u8]) -> Result<[u8; 64], PrecompileHalt> {
    if !accelerated() {
        guard(op::BN254_MUL, 6_000)?;
        return Guest.bn254_g1_mul(point, scalar);
    }
    output(
        op::BN254_MUL,
        &[point, scalar].concat(),
        PrecompileHalt::Bn254AffineGFailedToCreate,
    )
}

/// bn254 pairing check (EIP-197).
pub fn bn254_pairing(pairs: &[(&[u8], &[u8])]) -> Result<bool, PrecompileHalt> {
    if !accelerated() {
        guard(op::BN254_PAIRING, 45_000 + 34_000 * pairs.len() as u64)?;
        return Guest.bn254_pairing_check(pairs);
    }
    let operands: Vec<u8> = pairs
        .iter()
        .flat_map(|(a, b)| a.iter().chain(b.iter()).copied())
        .collect();
    check(
        op::BN254_PAIRING,
        &operands,
        PrecompileHalt::Bn254PairLength,
    )
}

/// BLAKE2 compression (EIP-152): within the bound in the guest, and cheaper
/// there below [`BLAKE2F_HOST_ROUNDS`] rounds.
pub fn blake2f(rounds: u32, h: &mut [u64; 8], m: &[u64; 16], t: &[u64; 2], f: bool) {
    if !accelerated() || rounds < BLAKE2F_HOST_ROUNDS {
        return Guest.blake2_compress(rounds, h, m, t, f);
    }
    let mut operands = Vec::with_capacity(213);
    operands.extend_from_slice(&rounds.to_be_bytes());
    for w in h.iter().chain(m.iter()).chain(t.iter()) {
        operands.extend_from_slice(&w.to_le_bytes());
    }
    operands.push(u8::from(f));
    let (_, out) = accelerate(op::BLAKE2F, &operands);
    for (word, bytes) in h.iter_mut().zip(out.chunks_exact(8)) {
        *word = u64::from_le_bytes(bytes.try_into().unwrap_or_default());
    }
}

/// KZG point evaluation (EIP-4844), after the versioned-hash check.
pub fn kzg(
    z: &[u8; 32],
    y: &[u8; 32],
    commitment: &[u8; 48],
    proof: &[u8; 48],
) -> Result<(), PrecompileHalt> {
    if !accelerated() {
        guard(op::KZG, 50_000)?;
        return Guest.verify_kzg_proof(z, y, commitment, proof);
    }
    let operands = [&z[..], y, commitment, proof].concat();
    match check(op::KZG, &operands, PrecompileHalt::BlobVerifyKzgProofFailed) {
        Ok(true) => Ok(()),
        _ => Err(PrecompileHalt::BlobVerifyKzgProofFailed),
    }
}

/// BLS12-381 G1 addition (EIP-2537): within the bound in the guest.
pub fn g1_add(a: G1Point, b: G1Point) -> Result<[u8; 96], PrecompileHalt> {
    if !accelerated() {
        return Guest.bls12_381_g1_add(a, b);
    }
    let mut operands = Vec::with_capacity(192);
    g1(&a, &mut operands);
    g1(&b, &mut operands);
    output(op::G1_ADD, &operands, PrecompileHalt::Bls12381G1NotOnCurve)
}

/// The Ethereum gas of a multi-scalar multiplication of `k` pairs.
fn msm_gas(k: usize, table: &[u16], per_pair: u64) -> u64 {
    revm::precompile::bls12_381_utils::msm_required_gas(k, table, per_pair)
}

/// BLS12-381 G1 multi-scalar multiplication (EIP-2537).
pub fn g1_msm(
    pairs: &mut dyn Iterator<Item = Result<G1PointScalar, PrecompileHalt>>,
) -> Result<[u8; 96], PrecompileHalt> {
    let items: Vec<Result<G1PointScalar, PrecompileHalt>> = pairs.collect();
    if !accelerated() {
        guard(
            op::G1_MSM,
            msm_gas(
                items.len(),
                &revm::precompile::bls12_381_const::DISCOUNT_TABLE_G1_MSM,
                12_000,
            ),
        )?;
        return Guest.bls12_381_g1_msm(&mut items.into_iter());
    }
    let mut operands = Vec::with_capacity(items.len() * 128);
    for item in items {
        let (point, scalar) = item?;
        g1(&point, &mut operands);
        operands.extend_from_slice(&scalar);
    }
    output(
        op::G1_MSM,
        &operands,
        PrecompileHalt::Bls12381G1NotInSubgroup,
    )
}

/// BLS12-381 G2 addition (EIP-2537).
pub fn g2_add(a: G2Point, b: G2Point) -> Result<[u8; 192], PrecompileHalt> {
    if !accelerated() {
        guard(op::G2_ADD, 600)?;
        return Guest.bls12_381_g2_add(a, b);
    }
    let mut operands = Vec::with_capacity(384);
    g2(&a, &mut operands);
    g2(&b, &mut operands);
    output(op::G2_ADD, &operands, PrecompileHalt::Bls12381G2NotOnCurve)
}

/// BLS12-381 G2 multi-scalar multiplication (EIP-2537).
pub fn g2_msm(
    pairs: &mut dyn Iterator<Item = Result<G2PointScalar, PrecompileHalt>>,
) -> Result<[u8; 192], PrecompileHalt> {
    let items: Vec<Result<G2PointScalar, PrecompileHalt>> = pairs.collect();
    if !accelerated() {
        guard(
            op::G2_MSM,
            msm_gas(
                items.len(),
                &revm::precompile::bls12_381_const::DISCOUNT_TABLE_G2_MSM,
                22_500,
            ),
        )?;
        return Guest.bls12_381_g2_msm(&mut items.into_iter());
    }
    let mut operands = Vec::with_capacity(items.len() * 224);
    for item in items {
        let (point, scalar) = item?;
        g2(&point, &mut operands);
        operands.extend_from_slice(&scalar);
    }
    output(
        op::G2_MSM,
        &operands,
        PrecompileHalt::Bls12381G2NotInSubgroup,
    )
}

/// BLS12-381 pairing check (EIP-2537).
pub fn pairing(pairs: &[(G1Point, G2Point)]) -> Result<bool, PrecompileHalt> {
    if !accelerated() {
        guard(op::PAIRING, 37_700 + 32_600 * pairs.len() as u64)?;
        return Guest.bls12_381_pairing_check(pairs);
    }
    let mut operands = Vec::with_capacity(pairs.len() * 288);
    for (a, b) in pairs {
        g1(a, &mut operands);
        g2(b, &mut operands);
    }
    check(
        op::PAIRING,
        &operands,
        PrecompileHalt::Bls12381G1NotInSubgroup,
    )
}

/// Mapping a base-field element to G1 (EIP-2537).
pub fn map_fp(fp: &[u8; 48]) -> Result<[u8; 96], PrecompileHalt> {
    if !accelerated() {
        guard(op::MAP_FP, 5_500)?;
        return Guest.bls12_381_fp_to_g1(fp);
    }
    output(op::MAP_FP, fp, PrecompileHalt::NonCanonicalFp)
}

/// Mapping an element of the quadratic extension to G2 (EIP-2537).
pub fn map_fp2(fp2: ([u8; 48], [u8; 48])) -> Result<[u8; 192], PrecompileHalt> {
    if !accelerated() {
        guard(op::MAP_FP2, 23_800)?;
        return Guest.bls12_381_fp2_to_g2(fp2);
    }
    output(
        op::MAP_FP2,
        &[fp2.0, fp2.1].concat(),
        PrecompileHalt::NonCanonicalFp,
    )
}
