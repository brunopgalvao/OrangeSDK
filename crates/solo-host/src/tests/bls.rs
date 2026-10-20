//! `bls12381_verify` and `bls12381_pairing_check` through real modules:
//! results, memory checks, and the costs of spec 05 §4.3 pinned.

use solo_bls::curve::{G1Affine, G2Affine};
use solo_bls::sig::DST_SIGNATURE;
use solo_bls::{SecretKey, hash};

use super::{executor, li, module, regs, report, run};
use crate::abi;
use solo_vm::host::Capability;
use solo_vm::isa::{Instruction, Reg};
use solo_vm::status::{HostStatus, Termination};

const RO: i64 = 0x1_0000;

fn ecall(import: u32) -> Instruction {
    Instruction::Ecall { import }
}

/// Rodata `sig(48) ‖ key(96) ‖ dst ‖ msg` and a body calling import 1 with
/// the `bls12381_verify` arguments, then reporting `a0`.
fn verify_module(import: &str, sig: &[u8; 48], key: &[u8; 96], dst: &[u8], msg: &[u8]) -> Vec<u8> {
    let ro = [sig.as_slice(), key, dst, msg].concat();
    let dst_at = RO + 144;
    let msg_at = dst_at + i64::try_from(dst.len()).unwrap();
    let mut body = vec![
        li(Reg::A0, msg_at),
        li(Reg::A1, i64::try_from(msg.len()).unwrap()),
        li(Reg::A2, RO),
        li(Reg::A3, RO + 48),
        li(Reg::A4, dst_at),
        li(Reg::A5, i64::try_from(dst.len()).unwrap()),
        ecall(1),
    ];
    body.extend(report());
    module(&["output_write", import], &body, &ro)
}

#[test]
fn both_functions_resolve_for_sandboxed_modules() {
    assert_eq!(
        abi::resolve("bls12381_verify", Capability::Sandboxed),
        Some(25)
    );
    assert_eq!(
        abi::resolve("bls12381_pairing_check", Capability::Sandboxed),
        Some(26)
    );
}

#[test]
fn verify_reports_validity_and_charges_100000_plus_6_per_word() {
    let sk = SecretKey::generate(&[3; 32], b"").unwrap();
    let key = sk.public_key().to_bytes();
    let mut exec = executor();
    for msg in [&b""[..], b"x", &[0x5a; 33], &[0x5a; 64]] {
        let sig = sk.sign(msg).to_bytes();
        let valid = run(
            &mut exec,
            &verify_module("bls12381_verify", &sig, &key, DST_SIGNATURE, msg),
            b"",
            1_000_000,
        );
        assert_eq!(
            regs(&valid).0,
            0,
            "valid signature over {} bytes",
            msg.len()
        );
        // The same instructions calling a 10-gas function instead.
        let baseline = run(
            &mut exec,
            &verify_module("abi_version", &sig, &key, DST_SIGNATURE, msg),
            b"",
            1_000_000,
        );
        let words = u64::try_from(msg.len().div_ceil(32)).unwrap();
        assert_eq!(valid.gas_used - baseline.gas_used, 100_000 + 6 * words - 10);
    }
    // A wrong message, another tag, an empty tag: invalid, status 1.
    let sig = sk.sign(b"m").to_bytes();
    for (dst, msg) in [
        (DST_SIGNATURE, &b"n"[..]),
        (b"other".as_slice(), b"m"),
        (b"".as_slice(), b"m"),
    ] {
        let r = run(
            &mut exec,
            &verify_module("bls12381_verify", &sig, &key, dst, msg),
            b"",
            1_000_000,
        );
        assert_eq!(regs(&r).0, 1);
    }
    // Too little gas for the call ends the instance.
    let r = run(
        &mut exec,
        &verify_module("bls12381_verify", &sig, &key, DST_SIGNATURE, b"m"),
        b"",
        99_000,
    );
    assert_eq!(r.status, Termination::OutOfGas);
}

#[test]
fn verify_checks_every_range_before_reading() {
    let sk = SecretKey::generate(&[4; 32], b"").unwrap();
    let key = sk.public_key().to_bytes();
    let sig = sk.sign(b"m").to_bytes();
    let mut exec = executor();
    // Each of message, signature, key and tag pointed at unmapped memory.
    for reg in [Reg::A0, Reg::A2, Reg::A3, Reg::A4] {
        let ro = [sig.as_slice(), &key, DST_SIGNATURE, b"m"].concat();
        let body = vec![
            li(Reg::A0, RO + 144 + 50),
            li(Reg::A1, 1),
            li(Reg::A2, RO),
            li(Reg::A3, RO + 48),
            li(Reg::A4, RO + 144),
            li(Reg::A5, 50),
            li(reg, 0x10),
            ecall(1),
        ];
        let r = run(
            &mut exec,
            &module(&["output_write", "bls12381_verify"], &body, &ro),
            b"",
            1_000_000,
        );
        assert_eq!(
            r.status,
            Termination::HostError(HostStatus::MemoryFault.code()),
            "{reg:?}"
        );
    }
}

/// A body calling `bls12381_pairing_check(RO, count)` and reporting `a0`.
fn pairing_module(import: &str, pairs: &[u8], count: i64) -> Vec<u8> {
    let mut body = vec![li(Reg::A0, RO), li(Reg::A1, count), ecall(1)];
    body.extend(report());
    module(&["output_write", import], &body, pairs)
}

fn pair(p: &G1Affine, q: &G2Affine) -> Vec<u8> {
    [p.to_compressed().as_slice(), &q.to_compressed()].concat()
}

#[test]
fn pairing_check_reports_and_charges_70000_plus_50000_per_pair() {
    let sk = SecretKey::generate(&[5; 32], b"").unwrap();
    let sig = sk.sign(b"m");
    let h = hash::to_g1(b"m", DST_SIGNATURE);
    let pairs = [
        pair(sig.point(), &-G2Affine::generator()),
        pair(&h, sk.public_key().point()),
    ]
    .concat();
    let mut exec = executor();
    let holds = run(
        &mut exec,
        &pairing_module("bls12381_pairing_check", &pairs, 2),
        b"",
        1_000_000,
    );
    assert_eq!(regs(&holds).0, 0);
    let baseline = run(
        &mut exec,
        &pairing_module("abi_version", &pairs, 2),
        b"",
        1_000_000,
    );
    assert_eq!(holds.gas_used - baseline.gas_used, 70_000 + 2 * 50_000 - 10);
    // One pair alone does not hold; no pairs do not hold; bad points do not.
    let one = run(
        &mut exec,
        &pairing_module("bls12381_pairing_check", &pairs, 1),
        b"",
        1_000_000,
    );
    assert_eq!(regs(&one).0, 1);
    let none = run(
        &mut exec,
        &pairing_module("bls12381_pairing_check", &pairs, 0),
        b"",
        1_000_000,
    );
    assert_eq!(regs(&none).0, 1);
    let mut bad = pairs.clone();
    bad[..48].fill(0xFF);
    let r = run(
        &mut exec,
        &pairing_module("bls12381_pairing_check", &bad, 2),
        b"",
        1_000_000,
    );
    assert_eq!(regs(&r).0, 1);
    // Reading past the module's memory faults.
    let r = run(
        &mut exec,
        &pairing_module("bls12381_pairing_check", &pairs, 1000),
        b"",
        100_000_000,
    );
    assert_eq!(
        r.status,
        Termination::HostError(HostStatus::MemoryFault.code())
    );
    // A count whose input would exceed 4 GiB faults once the gas is paid.
    let huge = i64::from(u32::MAX / 144 + 1);
    let r = run(
        &mut exec,
        &pairing_module("bls12381_pairing_check", &pairs, huge),
        b"",
        2_000_000_000_000,
    );
    assert_eq!(
        r.status,
        Termination::HostError(HostStatus::MemoryFault.code())
    );
    let r = run(
        &mut exec,
        &pairing_module("bls12381_pairing_check", &pairs, huge),
        b"",
        1_000_000,
    );
    assert_eq!(r.status, Termination::OutOfGas);
}
