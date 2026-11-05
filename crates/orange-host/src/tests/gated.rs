//! `bls12381_fast_aggregate_verify` through real modules, served by an
//! extension as a node serves it once its gate is active: results, memory
//! checks, and the costs of spec 05 §4.3 pinned.

use orange_bls::curve::{G1Affine, G2Affine, G2Projective, Scalar};
use orange_bls::{eth, hash};
use orange_vm::host::{Capability, HostContext};
use orange_vm::isa::{Instruction, Reg};
use orange_vm::status::{HostStatus, Termination};

use super::{li, module, regs, report};
use crate::executor::{CallResult, Executor, Extension, Flags};
use crate::gated::{
    FAST_AGGREGATE_VERIFY_GAS, FAST_AGGREGATE_VERIFY_KEY_GAS, FAST_AGGREGATE_VERIFY_WORD_GAS,
    bls12381_fast_aggregate_verify,
};
use crate::storage::{MemStorage, Overlay};
use crate::{MemStorage as Mem, ModuleCache};

const RO: i64 = 0x1_0000;
const NAME: &str = "bls12381_fast_aggregate_verify";

/// Serves the function at handle 200, as the node's gated extension does.
struct Gated;

impl Extension<MemStorage> for Gated {
    fn resolve(&self, name: &str, _: Capability) -> Option<u32> {
        (name == NAME).then_some(200)
    }

    fn call(
        &mut self,
        _: u32,
        ctx: &mut HostContext<'_>,
        _: &mut Overlay<MemStorage>,
    ) -> Result<(), Termination> {
        bls12381_fast_aggregate_verify(ctx)
    }
}

fn executor() -> Executor<Mem> {
    let mut exec = Executor::new(ModuleCache::default(), Mem::default());
    exec.set_extension(Box::new(Gated));
    exec
}

fn secret(i: u64) -> Scalar {
    Scalar::from(i * 104_729 + 3)
}

fn keys(signers: &[u64]) -> Vec<u8> {
    signers
        .iter()
        .flat_map(|i| G1Affine::from(G1Affine::generator() * secret(*i)).to_compressed())
        .collect()
}

fn sign(signers: &[u64], msg: &[u8]) -> [u8; 96] {
    let h = G2Projective::from(hash::to_g2(msg, eth::DST));
    let sum: G2Projective = signers.iter().map(|i| h * secret(*i)).sum();
    G2Affine::from(sum).to_compressed()
}

/// Rodata `sig(96) ‖ msg ‖ keys`; calls import 1 with `count` and reports `a0`.
fn verify_module(import: &str, keys: &[u8], count: i64, msg: &[u8], sig: &[u8; 96]) -> Vec<u8> {
    let ro = [sig.as_slice(), msg, keys].concat();
    let msg_len = i64::try_from(msg.len()).unwrap();
    let mut body = vec![
        li(Reg::A0, RO + 96 + msg_len),
        li(Reg::A1, count),
        li(Reg::A2, RO + 96),
        li(Reg::A3, msg_len),
        li(Reg::A4, RO),
        Instruction::Ecall { import: 1 },
    ];
    body.extend(report());
    module(&["output_write", import], &body, &ro)
}

fn run(exec: &mut Executor<Mem>, bytes: &[u8], gas: i64) -> CallResult {
    let hash = exec.load(bytes, Capability::Sandboxed).unwrap();
    exec.call(
        &hash,
        [0; 32],
        b"",
        gas,
        Capability::Sandboxed,
        Flags::default(),
    )
}

#[test]
fn verifies_aggregates_and_charges_per_key_and_word() {
    assert_eq!(
        (
            FAST_AGGREGATE_VERIFY_GAS,
            FAST_AGGREGATE_VERIFY_KEY_GAS,
            FAST_AGGREGATE_VERIFY_WORD_GAS
        ),
        (125_000, 5_500, 6)
    );
    let mut exec = executor();
    for (signers, msg) in [
        (vec![1], &[0x11; 32][..]),
        (vec![1, 2, 3], &[0x22; 33][..]),
        ((1..=16).collect::<Vec<_>>(), &b""[..]),
    ] {
        let k = keys(&signers);
        let count = i64::try_from(signers.len()).unwrap();
        let sig = sign(&signers, msg);
        let valid = run(
            &mut exec,
            &verify_module(NAME, &k, count, msg, &sig),
            1 << 30,
        );
        assert_eq!(regs(&valid).0, 0, "{} signers", signers.len());
        let baseline = run(
            &mut exec,
            &verify_module("abi_version", &k, count, msg, &sig),
            1 << 30,
        );
        let words = u64::try_from(msg.len().div_ceil(32)).unwrap();
        let n = u64::try_from(signers.len()).unwrap();
        assert_eq!(
            valid.gas_used - baseline.gas_used,
            125_000 + 5_500 * n + 6 * words - 10
        );
    }
    // Wrong message, missing signer, bad signature, infinity key, no keys.
    let k = keys(&[1, 2]);
    let sig = sign(&[1, 2], b"m");
    let mut infinity = k.clone();
    infinity[48..].copy_from_slice(&G1Affine::identity().to_compressed());
    for (keys, count, msg, sig) in [
        (k.clone(), 2, &b"n"[..], sig),
        (k.clone(), 1, b"m", sig),
        (k.clone(), 2, b"m", [0xFF; 96]),
        (infinity, 2, b"m", sig),
        (k.clone(), 0, b"m", sig),
    ] {
        let r = run(
            &mut exec,
            &verify_module(NAME, &keys, count, msg, &sig),
            1 << 30,
        );
        assert_eq!(regs(&r).0, 1);
    }
    // Gas is charged before anything is read: 2^32 - 1 keys run out of gas.
    let r = run(
        &mut exec,
        &verify_module(NAME, &k, i64::from(u32::MAX), b"m", &sig),
        1 << 30,
    );
    assert_eq!(r.status, Termination::OutOfGas);
}

#[test]
fn every_range_is_checked() {
    let k = keys(&[1]);
    let sig = sign(&[1], b"m");
    let mut exec = executor();
    // Keys, message and signature each pointed at unmapped memory, and a key
    // count whose bytes exceed the address space.
    for (reg, value) in [
        (Reg::A0, 0x10),
        (Reg::A2, 0x10),
        (Reg::A4, 0x10),
        (Reg::A1, 0x1000_0000),
    ] {
        let ro = [sig.as_slice(), b"m", &k].concat();
        let body = vec![
            li(Reg::A0, RO + 97),
            li(Reg::A1, 1),
            li(Reg::A2, RO + 96),
            li(Reg::A3, 1),
            li(Reg::A4, RO),
            li(reg, value),
            Instruction::Ecall { import: 1 },
        ];
        let r = run(
            &mut exec,
            &module(&["output_write", NAME], &body, &ro),
            i64::MAX >> 2,
        );
        assert_eq!(
            r.status,
            Termination::HostError(HostStatus::MemoryFault.code()),
            "{reg:?}"
        );
    }
}
