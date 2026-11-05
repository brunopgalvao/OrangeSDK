//! The precompile host functions of gate 2 through real modules, served by
//! the [`Gate2`] extension: each result against revm's own precompile on the
//! same operands (the EVM encoding, which pads BLS12-381 field elements to 64
//! bytes), the invalid inputs, memory checks, and the costs of spec 05 §4.8.

use orange_vm::host::Capability;
use orange_vm::isa::{Instruction, Reg};
use orange_vm::status::{HostStatus, Termination};
use revm_precompile::Precompiles;
use revm_precompile::primitives::Address;

use super::{BUF, li, module, sd};
use crate::executor::{CallResult, Executor, Extension, Flags};
use crate::precompiles::{
    self, BLS_G1_ADD_GAS, BLS_G1_MSM_GAS, BLS_G2_ADD_GAS, BLS_G2_MSM_GAS, BLS_MAP_FP_GAS,
    BLS_MAP_FP2_GAS, BLS_PAIR_GAS, BLS_PAIRING_GAS, BN254_ADD_GAS, BN254_MUL_GAS, BN254_PAIR_GAS,
    BN254_PAIRING_GAS, FUNCTIONS, Gate2, HANDLE_BASE, KZG_GAS, MODEXP_MAX_LEN, PRECOMPILE_BASE_GAS,
    PRECOMPILE_RATE, cost, modexp_gas,
};
use crate::storage::{MemStorage, Overlay};
use crate::{MemStorage as Mem, ModuleCache};

const RO: i64 = 0x1_0000;

fn hex(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(char::is_ascii_hexdigit).collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

const BN_G1: &str = "0000000000000000000000000000000000000000000000000000000000000001\
                     0000000000000000000000000000000000000000000000000000000000000002";
const BN_G1_NEG: &str = "0000000000000000000000000000000000000000000000000000000000000001\
                         30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd45";
/// Not on the curve.
const BN_BAD: &str = "0000000000000000000000000000000000000000000000000000000000000001\
                      0000000000000000000000000000000000000000000000000000000000000003";
const BN_G2: &str = "198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2\
                     1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed\
                     090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b\
                     12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa";
const BLS_G1: &str = "17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb\
                      08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1";
const BLS_G1_NEG: &str = "17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb\
                          114d1d6855d545a8aa7d76c8cf2e21f267816aef1db507c96655b9d5caac42364e6f38ba0ecb751bad54dcd6b939c2ca";
const BLS_G2: &str = "024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8\
                      13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e\
                      0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801\
                      0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be";
const SCALAR: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
const FP: &str = "0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801";
/// The modulus itself: not a canonical field element.
const P: &str = "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab";

/// The EVM encoding of unpadded BLS12-381 field elements: each padded to 64 bytes.
fn pad(unpadded: &[u8]) -> Vec<u8> {
    unpadded
        .chunks(48)
        .flat_map(|fp| [vec![0; 16], fp.to_vec()].concat())
        .collect()
}

/// `pad` for EIP-2537 MSM pairs (`point ‖ scalar`), `point` being `fps` field elements.
fn pad_pairs(pairs: &[u8], fps: usize) -> Vec<u8> {
    pairs
        .chunks(fps * 48 + 32)
        .flat_map(|p| [pad(&p[..fps * 48]), p[fps * 48..].to_vec()].concat())
        .collect()
}

/// `pad` for EIP-2537 pairing pairs (a G1 and a G2 point).
fn unpad(padded: &[u8]) -> Vec<u8> {
    padded.chunks(64).flat_map(|fp| fp[16..].to_vec()).collect()
}

/// What revm's Osaka precompile at `address` returns for `input`: its output, or `None` for a halt.
fn revm(address: u8, input: &[u8]) -> Option<Vec<u8>> {
    let precompile = Precompiles::osaka()
        .get(&Address::with_last_byte(address))
        .unwrap();
    let out = precompile.execute(input, u64::MAX, 0).unwrap();
    out.is_success().then(|| out.bytes.to_vec())
}

fn executor() -> Executor<Mem> {
    let mut exec = Executor::new(ModuleCache::default(), Mem::default());
    exec.set_extension(Box::new(Gate2));
    exec
}

/// Calls `name` with `args` (each a value, or an offset into `rodata` for
/// `Ro`, or into the result buffer for `Dst`), and returns `a0`, the first
/// `out` bytes written at `Dst`, and the gas the call used beyond the same
/// module calling `abi_version` instead.
#[derive(Clone, Copy)]
enum Arg {
    Ro(i64),
    Dst,
    Val(i64),
}

fn call_module(name: &str, rodata: &[u8], args: &[Arg], out: usize) -> Vec<u8> {
    let regs = [Reg::A0, Reg::A1, Reg::A2, Reg::A3, Reg::A4, Reg::A5];
    let mut body: Vec<Instruction> = args
        .iter()
        .zip(regs)
        .map(|(arg, r)| match *arg {
            Arg::Ro(off) => li(r, RO + off),
            Arg::Dst => li(r, BUF + 8),
            Arg::Val(v) => li(r, v),
        })
        .collect();
    body.extend([
        Instruction::Ecall { import: 1 },
        li(Reg::A7, BUF),
        sd(Reg::A7, Reg::A0, 0),
        li(Reg::A0, BUF),
        li(Reg::A1, 8 + i64::try_from(out).unwrap()),
        Instruction::Ecall { import: 0 },
    ]);
    let ro = if rodata.is_empty() {
        &[0u8][..]
    } else {
        rodata
    };
    module(&["output_write", name], &body, ro)
}

fn exec_module(exec: &mut Executor<Mem>, bytes: &[u8], gas: i64) -> CallResult {
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

struct Called {
    a0: u64,
    out: Vec<u8>,
    gas: u64,
}

fn call(name: &str, rodata: &[u8], args: &[Arg], out: usize) -> Called {
    let mut exec = executor();
    let r = exec_module(&mut exec, &call_module(name, rodata, args, out), 1 << 40);
    assert_eq!(r.status, Termination::Halt, "{name}");
    let base = exec_module(
        &mut exec,
        &call_module("abi_version", rodata, args, out),
        1 << 40,
    );
    Called {
        a0: u64::from_le_bytes(r.output[..8].try_into().unwrap()),
        out: r.output[8..].to_vec(),
        gas: r.gas_used + 10 - base.gas_used,
    }
}

fn two(name: &str, input: &[u8], out: usize) -> Called {
    call(name, input, &[Arg::Ro(0), Arg::Dst], out)
}

#[test]
fn constants_and_names() {
    assert_eq!(
        (
            PRECOMPILE_BASE_GAS,
            PRECOMPILE_RATE,
            MODEXP_MAX_LEN,
            HANDLE_BASE
        ),
        (200, 2, 1024, 202)
    );
    assert_eq!(
        [
            BN254_ADD_GAS,
            BN254_MUL_GAS,
            BN254_PAIRING_GAS,
            BN254_PAIR_GAS,
            KZG_GAS
        ],
        [150, 6_000, 45_000, 34_000, 50_000]
    );
    assert_eq!(
        [
            BLS_G1_ADD_GAS,
            BLS_G1_MSM_GAS,
            BLS_G2_ADD_GAS,
            BLS_G2_MSM_GAS,
            BLS_PAIRING_GAS,
            BLS_PAIR_GAS,
            BLS_MAP_FP_GAS,
            BLS_MAP_FP2_GAS
        ],
        [375, 12_000, 600, 22_500, 37_700, 32_600, 5_500, 23_800]
    );
    assert_eq!(cost(150), 500);
    let names: Vec<&str> = FUNCTIONS.iter().map(|(n, _)| *n).collect();
    assert_eq!(
        names,
        [
            "evm_modexp",
            "evm_bn254_add",
            "evm_bn254_mul",
            "evm_bn254_pairing",
            "evm_blake2f",
            "evm_kzg_point_evaluation",
            "evm_bls12381_g1_add",
            "evm_bls12381_g1_msm",
            "evm_bls12381_g2_add",
            "evm_bls12381_g2_msm",
            "evm_bls12381_pairing",
            "evm_bls12381_map_fp_to_g1",
            "evm_bls12381_map_fp2_to_g2",
        ]
    );
    for (i, (name, _)) in FUNCTIONS.iter().enumerate() {
        assert_eq!(
            precompiles::handle(name),
            Some(HANDLE_BASE + u32::try_from(i).unwrap())
        );
        assert_eq!(
            <Gate2 as Extension<MemStorage>>::resolve(&Gate2, name, Capability::Sandboxed),
            precompiles::handle(name)
        );
    }
    assert_eq!(precompiles::handle("evm_sha256"), None);
}

#[test]
fn an_unknown_handle_is_unavailable() {
    let layout = orange_vm::builder::ModuleBuilder::new().layout;
    let mut memory = orange_vm::memory::Memory::new(layout, &[], &[]);
    let mut regs = [0u64; Reg::COUNT];
    let mut gas = 1_000;
    let mut ctx = orange_vm::host::HostContext {
        regs: &mut regs,
        memory: &mut memory,
        gas: &mut gas,
    };
    let mut overlay = Overlay::new(MemStorage::default());
    for handle in [HANDLE_BASE - 1, HANDLE_BASE + 13] {
        assert_eq!(
            <Gate2 as Extension<MemStorage>>::call(&mut Gate2, handle, &mut ctx, &mut overlay),
            Err(Termination::HostError(HostStatus::Unavailable.code()))
        );
    }
}

fn modexp_input(base: &[u8], exp: &[u8], modulus: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    for len in [base.len(), exp.len(), modulus.len()] {
        let mut w = [0u8; 32];
        w[24..].copy_from_slice(&(len as u64).to_be_bytes());
        v.extend(w);
    }
    [v, base.to_vec(), exp.to_vec(), modulus.to_vec()].concat()
}

#[test]
fn modexp_matches_revm_and_charges_by_eip_7883() {
    let mut big = vec![0xEE; 1024];
    big[1023] = 0xED;
    for (base, exp, modulus) in [
        (vec![0xFF; 32], vec![0xFF; 32], vec![0xEE; 32]),
        (vec![3], vec![0xFF; 33], vec![0xED]),
        (vec![0xFF; 1024], vec![0x01], big.clone()),
        (vec![], vec![], vec![0x07]),
        (vec![2], vec![5], vec![]),
        (vec![0x10; 40], vec![], vec![0x77; 3]),
    ] {
        let (bl, el, ml) = (base.len(), exp.len(), modulus.len());
        let input = [base.clone(), exp.clone(), modulus.clone()].concat();
        let c = call(
            "evm_modexp",
            &input,
            &[
                Arg::Ro(0),
                Arg::Val(i64::try_from(bl).unwrap()),
                Arg::Val(i64::try_from(el).unwrap()),
                Arg::Val(i64::try_from(ml).unwrap()),
                Arg::Dst,
            ],
            ml,
        );
        assert_eq!(c.a0, 0);
        let expected = revm(5, &modexp_input(&base, &exp, &modulus)).unwrap();
        assert_eq!(c.out, expected, "{bl} {el} {ml}");
        let mut head = [0u8; 32];
        let h = el.min(32);
        head[32 - h..].copy_from_slice(&exp[..h]);
        let gas = modexp_gas(
            u32::try_from(bl).unwrap(),
            u32::try_from(el).unwrap(),
            u32::try_from(ml).unwrap(),
            &head,
        );
        assert_eq!(c.gas, cost(gas), "{bl} {el} {ml}");
    }
    assert_eq!(modexp_gas(32, 32, 32, &[0xFF; 32]), 4_080);
    assert_eq!(modexp_gas(1, 1, 1, &[0; 32]), 500);
    // A length over the EIP-7823 bound: status 1, nothing read, the base cost.
    for lens in [(1025, 0, 1), (1, 1025, 1), (1, 0, 1025)] {
        let c = call(
            "evm_modexp",
            &[],
            &[
                Arg::Val(0),
                Arg::Val(lens.0),
                Arg::Val(lens.1),
                Arg::Val(lens.2),
                Arg::Val(0),
            ],
            0,
        );
        assert_eq!((c.a0, c.gas), (1, PRECOMPILE_BASE_GAS));
    }
}

#[test]
fn bn254_matches_revm() {
    let g1 = hex(BN_G1);
    let neg = hex(BN_G1_NEG);
    let bad = hex(BN_BAD);
    let scalar = hex(SCALAR);
    // Addition: valid, the identity as a sum, an invalid point.
    for (input, ok) in [
        ([g1.clone(), g1.clone()].concat(), true),
        ([g1.clone(), neg.clone()].concat(), true),
        ([g1.clone(), bad.clone()].concat(), false),
    ] {
        let c = two("evm_bn254_add", &input, 64);
        assert_eq!(c.gas, cost(150));
        match revm(6, &input) {
            Some(out) => assert_eq!((c.a0, c.out), (0, out)),
            None => assert_eq!((c.a0, ok), (1, false)),
        }
    }
    for (input, ok) in [
        ([g1.clone(), scalar.clone()].concat(), true),
        ([bad.clone(), scalar.clone()].concat(), false),
    ] {
        let c = two("evm_bn254_mul", &input, 64);
        assert_eq!(c.gas, cost(6_000));
        match revm(7, &input) {
            Some(out) => assert_eq!((c.a0, c.out), (0, out)),
            None => assert_eq!((c.a0, ok), (1, false)),
        }
    }
    let g2 = hex(BN_G2);
    // Pairings: e(g1, g2) e(-g1, g2) = 1, e(g1, g2) alone is not, an invalid point, no pairs.
    for (pairs, a0) in [
        (vec![(g1.clone(), g2.clone()), (neg.clone(), g2.clone())], 0),
        (vec![(g1.clone(), g2.clone())], 1),
        (vec![(bad.clone(), g2.clone())], 2),
        (vec![], 0),
    ] {
        let input: Vec<u8> = pairs
            .iter()
            .flat_map(|(a, b)| [a.clone(), b.clone()].concat())
            .collect();
        let n = pairs.len();
        let c = call(
            "evm_bn254_pairing",
            &input,
            &[Arg::Ro(0), Arg::Val(i64::try_from(n).unwrap())],
            0,
        );
        assert_eq!(c.a0, a0, "{n} pairs");
        assert_eq!(c.gas, cost(45_000 + 34_000 * n as u64));
        let expected = revm(8, &input).map(|out| out[31]);
        assert_eq!(
            expected,
            [Some(1), Some(0), None][usize::try_from(a0).unwrap()],
            "revm agrees"
        );
    }
}

fn blake2f_input(rounds: u32, flag: u8) -> Vec<u8> {
    let mut input = rounds.to_be_bytes().to_vec();
    input.extend((0..208u32).map(|i| u8::try_from(i * 7 % 251).unwrap()));
    input.push(flag);
    input
}

#[test]
fn blake2f_matches_revm_and_charges_per_round() {
    for rounds in [0, 1, 12, 1_000] {
        let input = blake2f_input(rounds, 1);
        let c = two("evm_blake2f", &input, 64);
        assert_eq!((c.a0, c.out), (0, revm(9, &input).unwrap()));
        assert_eq!(c.gas, cost(u64::from(rounds)));
    }
    let input = blake2f_input(12, 0);
    assert_eq!(two("evm_blake2f", &input, 64).out, revm(9, &input).unwrap());
    let c = two("evm_blake2f", &blake2f_input(12, 2), 64);
    assert_eq!((c.a0, c.out), (1, vec![0; 64]));
}

#[test]
fn kzg_verifies_the_eip_4844_vector() {
    let z = hex("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000");
    let y = hex("1522a4a7f34e1ea350ae07c29c96c7e79655aa926122e95fe69fcbd932ca49e9");
    let commitment = hex(
        "8f59a8d2a1a625a17f3fea0fe5eb8c896db3764f3185481bc22f91b4aaffcca25f26936857bc3a7c2539ea8ec3a952b7",
    );
    let proof = hex(
        "a62ad71d14c5719385c0686f1871430475bf3a00f0aa3f7b8dd99a9abc2160744faf0070725e00b60ad9a026a15b1a8c",
    );
    let valid = [z.clone(), y.clone(), commitment.clone(), proof.clone()].concat();
    let c = call("evm_kzg_point_evaluation", &valid, &[Arg::Ro(0)], 0);
    assert_eq!((c.a0, c.gas), (0, cost(50_000)));
    let mut wrong = valid.clone();
    wrong[63] ^= 1;
    assert_eq!(
        call("evm_kzg_point_evaluation", &wrong, &[Arg::Ro(0)], 0).a0,
        1
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn bls12381_operations_match_revm() {
    let (g1, neg, g2) = (hex(BLS_G1), hex(BLS_G1_NEG), hex(BLS_G2));
    let mut off_curve = g1.clone();
    off_curve[95] ^= 1;
    let scalar = hex(SCALAR);
    // Additions.
    for (input, address, name, out) in [
        (
            [g1.clone(), neg.clone()].concat(),
            11,
            "evm_bls12381_g1_add",
            96,
        ),
        (
            [g1.clone(), g1.clone()].concat(),
            11,
            "evm_bls12381_g1_add",
            96,
        ),
        (
            [g1.clone(), off_curve.clone()].concat(),
            11,
            "evm_bls12381_g1_add",
            96,
        ),
        (
            [g2.clone(), g2.clone()].concat(),
            13,
            "evm_bls12381_g2_add",
            192,
        ),
    ] {
        let c = two(name, &input, out);
        let gas = if address == 11 { 375 } else { 600 };
        assert_eq!(c.gas, cost(gas));
        match revm(address, &pad(&input)) {
            Some(expected) => assert_eq!((c.a0, c.out), (0, unpad(&expected))),
            None => assert_eq!(c.a0, 1),
        }
    }
    let mut g2_off = g2.clone();
    g2_off[191] ^= 1;
    assert_eq!(
        two(
            "evm_bls12381_g2_add",
            &[g2.clone(), g2_off.clone()].concat(),
            192
        )
        .a0,
        1
    );
    // Multi-scalar multiplications of 0, 1, 2 and 3 pairs, and an invalid point.
    for (point, fps, address, name, out, table, per) in [
        (
            &g1,
            2,
            12,
            "evm_bls12381_g1_msm",
            96,
            &revm_precompile::bls12_381_const::DISCOUNT_TABLE_G1_MSM,
            12_000,
        ),
        (
            &g2,
            4,
            14,
            "evm_bls12381_g2_msm",
            192,
            &revm_precompile::bls12_381_const::DISCOUNT_TABLE_G2_MSM,
            22_500,
        ),
    ] {
        for k in 0..4usize {
            let pairs: Vec<u8> = (0..k)
                .flat_map(|i| {
                    [
                        point.clone(),
                        if i == 1 { vec![0; 32] } else { scalar.clone() },
                    ]
                    .concat()
                })
                .collect();
            let c = call(
                name,
                &pairs,
                &[Arg::Ro(0), Arg::Val(i64::try_from(k).unwrap()), Arg::Dst],
                out,
            );
            assert_eq!(
                c.gas,
                cost(revm_precompile::bls12_381_utils::msm_required_gas(
                    k, table, per
                ))
            );
            assert_eq!(c.a0, 0);
            if k == 0 {
                assert_eq!(c.out, vec![0; out], "the empty sum");
            } else {
                assert_eq!(
                    c.out,
                    unpad(&revm(address, &pad_pairs(&pairs, fps)).unwrap()),
                    "{name} {k}"
                );
            }
        }
        let mut bad = point.clone();
        bad[fps * 48 - 1] ^= 1;
        let pairs = [bad, scalar.clone()].concat();
        assert_eq!(
            call(name, &pairs, &[Arg::Ro(0), Arg::Val(1), Arg::Dst], out).a0,
            1
        );
    }
    // Pairings: holds, does not, an invalid point, no pairs.
    for (pairs, a0) in [
        (vec![(g1.clone(), g2.clone()), (neg.clone(), g2.clone())], 0),
        (vec![(g1.clone(), g2.clone())], 1),
        (vec![(off_curve.clone(), g2.clone())], 2),
        (vec![], 0),
    ] {
        let input: Vec<u8> = pairs
            .iter()
            .flat_map(|(a, b)| [a.clone(), b.clone()].concat())
            .collect();
        let n = pairs.len();
        let c = call(
            "evm_bls12381_pairing",
            &input,
            &[Arg::Ro(0), Arg::Val(i64::try_from(n).unwrap())],
            0,
        );
        assert_eq!(
            (c.a0, c.gas),
            (a0, cost(37_700 + 32_600 * n as u64)),
            "{n} pairs"
        );
        if n > 0 {
            let expected = revm(15, &pad(&input)).map(|out| out[31]);
            assert_eq!(
                expected,
                [Some(1), Some(0), None][usize::try_from(a0).unwrap()]
            );
        }
    }
    // Maps, with a valid element and the modulus.
    for (input, address, name, out, gas) in [
        (hex(FP), 16, "evm_bls12381_map_fp_to_g1", 96, 5_500),
        (hex(P), 16, "evm_bls12381_map_fp_to_g1", 96, 5_500),
        (
            hex(&format!("{FP}{FP}")),
            17,
            "evm_bls12381_map_fp2_to_g2",
            192,
            23_800,
        ),
        (
            hex(&format!("{FP}{P}")),
            17,
            "evm_bls12381_map_fp2_to_g2",
            192,
            23_800,
        ),
    ] {
        let c = two(name, &input, out);
        assert_eq!(c.gas, cost(gas));
        match revm(address, &pad(&input)) {
            Some(expected) => assert_eq!((c.a0, c.out), (0, unpad(&expected))),
            None => assert_eq!(c.a0, 1),
        }
    }
}

#[test]
fn gas_comes_first_and_every_range_is_checked() {
    let fault = Termination::HostError(HostStatus::MemoryFault.code());
    let mut exec = executor();
    // Counts whose operands exceed the address space run out of gas, or fault
    // when the gas is there.
    for name in ["evm_bn254_pairing", "evm_bls12381_pairing"] {
        let body = call_module(name, &[], &[Arg::Ro(0), Arg::Val(i64::from(u32::MAX))], 0);
        assert_eq!(
            exec_module(&mut exec, &body, 1 << 30).status,
            Termination::OutOfGas,
            "{name}"
        );
        assert_eq!(
            exec_module(&mut exec, &body, i64::MAX >> 2).status,
            fault,
            "{name}"
        );
    }
    for name in ["evm_bls12381_g1_msm", "evm_bls12381_g2_msm"] {
        let body = call_module(name, &[], &[Arg::Ro(0), Arg::Val(1 << 28), Arg::Dst], 0);
        assert_eq!(
            exec_module(&mut exec, &body, 1 << 30).status,
            Termination::OutOfGas,
            "{name}"
        );
        assert_eq!(
            exec_module(&mut exec, &body, i64::MAX >> 2).status,
            fault,
            "{name}"
        );
    }
    // Operands in unmapped memory, a destination that is not writable, and a
    // modexp whose exponent lies past the end of the address space.
    for (name, args) in [
        ("evm_bn254_add", vec![Arg::Val(0x10), Arg::Dst]),
        ("evm_bn254_add", vec![Arg::Ro(0), Arg::Val(RO)]),
        ("evm_blake2f", vec![Arg::Val(0x10), Arg::Dst]),
        ("evm_kzg_point_evaluation", vec![Arg::Val(0x10)]),
        (
            "evm_modexp",
            vec![
                Arg::Val(0x10),
                Arg::Val(1),
                Arg::Val(1),
                Arg::Val(1),
                Arg::Dst,
            ],
        ),
        (
            "evm_modexp",
            vec![
                Arg::Val(i64::from(u32::MAX)),
                Arg::Val(2),
                Arg::Val(1),
                Arg::Val(1),
                Arg::Dst,
            ],
        ),
        ("evm_bls12381_map_fp_to_g1", vec![Arg::Ro(0), Arg::Val(RO)]),
    ] {
        let body = call_module(name, &[0u8; 512], &args, 0);
        assert_eq!(
            exec_module(&mut exec, &body, 1 << 30).status,
            fault,
            "{name}"
        );
    }
    // Too little gas for the operation.
    let body = call_module("evm_kzg_point_evaluation", &[0u8; 160], &[Arg::Ro(0)], 0);
    assert_eq!(
        exec_module(&mut exec, &body, 50_000).status,
        Termination::OutOfGas
    );
}
