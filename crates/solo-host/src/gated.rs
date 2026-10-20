//! Host functions that arrive behind a feature gate (spec 05 §7, spec 13
//! §8). Their semantics and costs live here, beside the ungated ones, so
//! that every host computes them identically; a node resolves each only
//! while its gate is active and serves it through its extension.

use solo_vm::host::HostContext;
use solo_vm::isa::Reg;
use solo_vm::status::Termination;

use crate::abi::{fault, per_32, read};

/// Base cost of `bls12381_fast_aggregate_verify` in VM gas: hashing the
/// message to G2 and a two-pair pairing check.
pub const FAST_AGGREGATE_VERIFY_GAS: u64 = 125_000;

/// Cost per public key: decoding, the subgroup check and the addition.
pub const FAST_AGGREGATE_VERIFY_KEY_GAS: u64 = 5_500;

/// Cost per started 32 bytes of the message, which is hashed.
pub const FAST_AGGREGATE_VERIFY_WORD_GAS: u64 = 6;

/// `bls12381_fast_aggregate_verify(keys, count, msg, msg_len, sig)` (spec
/// 05 §4.3): `a0` = 0 if the compressed G2 signature `sig` (96 bytes) is a
/// valid Ethereum consensus-layer signature over `msg` by the `count`
/// compressed G1 keys at `keys` (48 bytes each), 1 otherwise; see
/// [`solo_bls::eth::fast_aggregate_verify`]. Gas is charged before any
/// range is read, so a `count` whose keys would not fit in memory ends the
/// instance with `OutOfGas` or `MemoryFault`, never with work done.
///
/// # Errors
/// `OutOfGas` and `MemoryFault` terminations.
///
/// # Panics
/// Never: the signature read is exactly 96 bytes.
pub fn bls12381_fast_aggregate_verify(ctx: &mut HostContext<'_>) -> Result<(), Termination> {
    let (keys, count, msg, msg_len, sig) = (
        ctx.arg32(Reg::A0),
        ctx.arg32(Reg::A1),
        ctx.arg32(Reg::A2),
        ctx.arg32(Reg::A3),
        ctx.arg32(Reg::A4),
    );
    ctx.charge(
        FAST_AGGREGATE_VERIFY_GAS
            + FAST_AGGREGATE_VERIFY_KEY_GAS * u64::from(count)
            + FAST_AGGREGATE_VERIFY_WORD_GAS * per_32(msg_len),
    )?;
    let len = u32::try_from(u64::from(count) * 48)
        .ok()
        .ok_or_else(fault)?;
    let keys = read(ctx, keys, len)?;
    let msg = read(ctx, msg, msg_len)?;
    let sig: [u8; 96] = read(ctx, sig, 96)?.try_into().expect("96 bytes read");
    let valid = solo_bls::eth::fast_aggregate_verify(&keys, &msg, &sig);
    ctx.set(Reg::A0, u64::from(!valid));
    Ok(())
}
