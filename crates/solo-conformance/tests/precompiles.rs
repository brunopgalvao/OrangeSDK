//! The precompiles as the kernel's EVM runs them (spec 19): on the host
//! through the precompile module once feature gate 2 is active, in the guest
//! before. Both paths give the same results on every precompile, valid
//! input or not; no precompile and no ordinary opcode costs the kernel more
//! than the bound of spec 19 §2 per EVM gas once the gate is active; and
//! before it, the in-guest precompiles above the bound halt out of gas once
//! the budget of spec 19 §5 is spent.
//!
//! `measure_precompiles` and `measure_ordinary` print the tables of spec 19
//! §2: `cargo test -p solo-conformance --test precompiles -- --ignored --nocapture`.

mod common;

use std::time::Instant;

use common::case;
use solo_abi::chain::call_status;
use solo_conformance::{Executed, GUEST, Runner};
use solo_host::Backend;
use solo_host::hash::sha256;

/// The bound of spec 19 §2: kernel gas per EVM gas.
const BOUND: u64 = 256;

/// The budget of spec 19 §5.
const BUDGET: u64 = 1 << 34;

fn hex(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(char::is_ascii_hexdigit).collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn word(v: u64) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&v.to_be_bytes());
    w
}

/// Copies the calldata to memory and `STATICCALL`s `address` with it
/// `calls` times, each with `gas` (all there is for 0); then stores the
/// number of calls that succeeded in slot 0, the last call's return data
/// size in slot 1 and its `keccak256` in slot 2.
fn caller(address: u16, calls: usize, gas: u32) -> Vec<u8> {
    let mut code = vec![0x36, 0x5F, 0x5F, 0x37, 0x5F];
    let [hi, lo] = address.to_be_bytes();
    let [_, g2, g1, g0] = gas.to_be_bytes();
    for _ in 0..calls {
        code.extend_from_slice(&[0x5F, 0x5F, 0x36, 0x5F, 0x61, hi, lo]);
        if gas == 0 {
            code.push(0x5A);
        } else {
            code.extend_from_slice(&[0x62, g2, g1, g0]);
        }
        code.extend_from_slice(&[0xFA, 0x01]);
    }
    code.extend_from_slice(&[
        0x5F, 0x55, 0x3D, 0x60, 0x01, 0x55, 0x3D, 0x5F, 0x5F, 0x3E, 0x3D, 0x5F, 0x20, 0x60, 0x02,
        0x55, 0x00,
    ]);
    code
}

/// A legacy call with `data` to a contract running `code`.
fn call_case(code: Vec<u8>, data: &[u8]) -> solo_abi::conformance::Case {
    let mut c = case(code, common::TX_GAS, Vec::new());
    c.tx = common::signed_call_with(common::CONTRACT, common::TX_GAS, data).0;
    c
}

fn execute(runner: &mut Runner, code: Vec<u8>, data: &[u8]) -> Executed {
    let executed = runner.run(&call_case(code, data)).unwrap();
    assert_eq!(executed.outcome.status, call_status::SUCCESS);
    executed
}

fn slot(executed: &Executed, n: u64) -> [u8; 32] {
    executed.post[&common::CONTRACT]
        .storage
        .get(&word(n))
        .copied()
        .unwrap_or_default()
}

/// VM gas and EVM gas of one call to `address` with `input`: two calls less one.
fn per_call(runner: &mut Runner, address: u16, input: &[u8]) -> (u64, u64) {
    let one = execute(runner, caller(address, 1, 0), input);
    let vm_one = runner.gas_used();
    let two = execute(runner, caller(address, 2, 0), input);
    (
        runner.gas_used() - vm_one,
        two.outcome.gas_used - one.outcome.gas_used,
    )
}

/// A precompile input.
struct Shape {
    name: &'static str,
    address: u16,
    input: Vec<u8>,
    /// Whether the guest computes it within the bound, so the guard never
    /// checks it (spec 19 table 2.1).
    bounded: bool,
}

fn shape(name: &'static str, address: u16, input: Vec<u8>, bounded: bool) -> Shape {
    Shape {
        name,
        address,
        input,
        bounded,
    }
}

const BN_G1: &str = "0000000000000000000000000000000000000000000000000000000000000001\
                     0000000000000000000000000000000000000000000000000000000000000002";
const BN_G1_NEG: &str = "0000000000000000000000000000000000000000000000000000000000000001\
                         30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd45";
const BN_BAD: &str = "0000000000000000000000000000000000000000000000000000000000000001\
                      0000000000000000000000000000000000000000000000000000000000000003";
const BN_G2: &str = "198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2\
                     1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed\
                     090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b\
                     12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa";
const BLS_G1: &str = "0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb\
                      0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1";
const BLS_G1_NEG: &str = "0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb\
                          00000000000000000000000000000000114d1d6855d545a8aa7d76c8cf2e21f267816aef1db507c96655b9d5caac42364e6f38ba0ecb751bad54dcd6b939c2ca";
/// `BLS_G1` with its `y` changed: not on the curve.
const BLS_G1_BAD: &str = "0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb\
                          0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e0";
const BLS_G2: &str = "00000000000000000000000000000000024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8\
                      0000000000000000000000000000000013e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e\
                      000000000000000000000000000000000ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801\
                      000000000000000000000000000000000606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be";
/// `BLS_G2` with its last coordinate changed: not on the curve.
const BLS_G2_BAD: &str = "00000000000000000000000000000000024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8\
                          0000000000000000000000000000000013e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e\
                          000000000000000000000000000000000ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801\
                          000000000000000000000000000000000606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79bf";
const BLS_FP: &str = "000000000000000000000000000000000ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801";
/// The base field's modulus, padded: not a canonical element.
const BLS_P: &str = "000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab";
const SCALAR: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

fn modexp(base: &[u8], exp: &[u8], modulus: &[u8]) -> Vec<u8> {
    let mut input = Vec::new();
    for len in [base.len(), exp.len(), modulus.len()] {
        input.extend_from_slice(&word(len as u64));
    }
    [input, base.to_vec(), exp.to_vec(), modulus.to_vec()].concat()
}

/// The EIP-4844 point evaluation with a real proof, or with `y` changed.
fn kzg(valid: bool) -> Vec<u8> {
    let commitment = hex(
        "8f59a8d2a1a625a17f3fea0fe5eb8c896db3764f3185481bc22f91b4aaffcca25f26936857bc3a7c2539ea8ec3a952b7",
    );
    let mut versioned = sha256(&commitment);
    versioned[0] = 1;
    let mut y = hex("1522a4a7f34e1ea350ae07c29c96c7e79655aa926122e95fe69fcbd932ca49e9");
    if !valid {
        y[31] ^= 1;
    }
    [
        versioned.to_vec(),
        hex("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000"),
        y,
        commitment,
        hex(
            "a62ad71d14c5719385c0686f1871430475bf3a00f0aa3f7b8dd99a9abc2160744faf0070725e00b60ad9a026a15b1a8c",
        ),
    ]
    .concat()
}

fn blake2f(rounds: u32, flag: u8) -> Vec<u8> {
    let mut input = rounds.to_be_bytes().to_vec();
    input.extend((0..208u32).map(|i| u8::try_from(i * 13 % 251).unwrap()));
    input.push(flag);
    input
}

fn pairs(g1: &[&str], g2: &str) -> Vec<u8> {
    g1.iter().flat_map(|p| [hex(p), hex(g2)].concat()).collect()
}

fn msm(point: &str, k: usize) -> Vec<u8> {
    hex(&format!("{point}{SCALAR}").repeat(k))
}

/// Worst-case inputs of every precompile (spec 19 §2): the most work per
/// EVM gas each admits.
#[allow(clippy::too_many_lines)]
fn worst() -> Vec<Shape> {
    let ff32 = [0xFF; 32];
    let mut odd32 = [0xEE; 32];
    odd32[31] = 0xED;
    let bls = [BLS_G1, BLS_G1_NEG];
    vec![
        shape(
            "ecrecover",
            1,
            hex(
                "ce0677bb30baa8cf067c88db9811f4333d131bf8bcf12fe7065d211dce971008\
                 000000000000000000000000000000000000000000000000000000000000001c\
                 90f27b8b488db00b00606796d2987f6a5f59ae62ea05effe84fef5b8b0e54998\
                 4a691139ad57a3f0b906637673aa2f63d1f55cb1a69199d4009eea23ceaddc93",
            ),
            true,
        ),
        shape("sha256 1 KiB", 2, vec![0x5A; 1024], true),
        shape("ripemd160 64 B", 3, vec![0x5A; 64], true),
        shape("ripemd160 1 KiB", 3, vec![0x5A; 1024], true),
        shape(
            "modexp 32 B, exp 2^256-1, odd",
            5,
            modexp(&ff32, &ff32, &odd32),
            true,
        ),
        shape(
            "modexp 32 B, exp 2^256-1, even",
            5,
            modexp(&ff32, &ff32, &[0xEE; 32]),
            true,
        ),
        shape(
            "modexp 64 B, exp 2^256-1",
            5,
            modexp(&[0xFF; 64], &ff32, &[0xEF; 64]),
            true,
        ),
        shape(
            "modexp 1 KiB, exp 255",
            5,
            modexp(&[0xFF; 1024], &[0xFF], &[0xEF; 1024]),
            true,
        ),
        shape("bn254 add", 6, [hex(BN_G1), hex(BN_G1_NEG)].concat(), true),
        shape("bn254 mul", 7, [hex(BN_G1), hex(SCALAR)].concat(), false),
        shape("bn254 pairing, 1 pair", 8, pairs(&[BN_G1], BN_G2), false),
        shape(
            "bn254 pairing, 2 pairs",
            8,
            pairs(&[BN_G1, BN_G1_NEG], BN_G2),
            false,
        ),
        shape(
            "bn254 pairing, 8 pairs",
            8,
            pairs(&[BN_G1, BN_G1_NEG].repeat(4), BN_G2),
            false,
        ),
        shape("blake2f 12 rounds", 9, blake2f(12, 1), true),
        shape("blake2f 63 rounds", 9, blake2f(63, 1), true),
        shape("blake2f 64 rounds", 9, blake2f(64, 1), true),
        shape("blake2f 10 000 rounds", 9, blake2f(10_000, 1), true),
        shape("point evaluation", 10, kzg(true), false),
        shape(
            "bls12-381 G1 add",
            11,
            [hex(BLS_G1), hex(BLS_G1_NEG)].concat(),
            true,
        ),
        shape("bls12-381 G1 MSM, 1", 12, msm(BLS_G1, 1), false),
        shape("bls12-381 G1 MSM, 16", 12, msm(BLS_G1, 16), false),
        shape(
            "bls12-381 G2 add",
            13,
            [hex(BLS_G2), hex(BLS_G2)].concat(),
            false,
        ),
        shape("bls12-381 G2 MSM, 1", 14, msm(BLS_G2, 1), false),
        shape("bls12-381 G2 MSM, 16", 14, msm(BLS_G2, 16), false),
        shape(
            "bls12-381 pairing, 1 pair",
            15,
            pairs(&bls[..1], BLS_G2),
            false,
        ),
        shape("bls12-381 pairing, 2 pairs", 15, pairs(&bls, BLS_G2), false),
        shape(
            "bls12-381 pairing, 8 pairs",
            15,
            pairs(&bls.repeat(4), BLS_G2),
            false,
        ),
        shape("bls12-381 map fp to G1", 16, hex(BLS_FP), false),
        shape(
            "bls12-381 map fp2 to G2",
            17,
            hex(&format!("{BLS_FP}{BLS_FP}")),
            false,
        ),
        shape("p256verify", 0x100, vec![0; 160], true),
    ]
}

/// Inputs every precompile refuses, or answers without its main work: both
/// paths must refuse or answer them identically.
fn odd_inputs() -> Vec<Shape> {
    let mut wrong_hash = kzg(true);
    wrong_hash[5] ^= 1;
    let mut bad_padding = pairs(&[BLS_G1], BLS_G2);
    bad_padding[0] = 1;
    vec![
        shape("modexp, zero modulus", 5, modexp(&[3], &[5], &[0]), true),
        shape("modexp, empty", 5, modexp(&[], &[], &[]), true),
        shape(
            "modexp, short input",
            5,
            modexp(&[3, 4], &[0xFF; 40], &[0x99; 33])[..150].to_vec(),
            true,
        ),
        shape(
            "modexp, over EIP-7823",
            5,
            modexp(&[1; 1025], &[1], &[7]),
            true,
        ),
        shape(
            "bn254 add, invalid point",
            6,
            [hex(BN_G1), hex(BN_BAD)].concat(),
            true,
        ),
        shape("bn254 add, short", 6, hex(BN_G1), true),
        shape(
            "bn254 mul, invalid point",
            7,
            [hex(BN_BAD), hex(SCALAR)].concat(),
            true,
        ),
        shape(
            "bn254 pairing, invalid point",
            8,
            pairs(&[BN_BAD], BN_G2),
            true,
        ),
        shape(
            "bn254 pairing, fails",
            8,
            pairs(&[BN_G1, BN_G1], BN_G2),
            true,
        ),
        shape("bn254 pairing, empty", 8, Vec::new(), true),
        shape("bn254 pairing, bad length", 8, vec![1; 100], true),
        shape("blake2f 0 rounds", 9, blake2f(0, 0), true),
        shape("blake2f, bad flag", 9, blake2f(64, 2), true),
        shape("blake2f, bad length", 9, vec![0; 212], true),
        shape("point evaluation, wrong y", 10, kzg(false), true),
        shape("point evaluation, wrong hash", 10, wrong_hash, true),
        shape(
            "bls12-381 G1 add, off curve",
            11,
            [hex(BLS_G1), hex(BLS_G1_BAD)].concat(),
            true,
        ),
        shape("bls12-381 G1 MSM, off curve", 12, msm(BLS_G1_BAD, 2), true),
        shape(
            "bls12-381 G1 MSM, zero scalar",
            12,
            [hex(BLS_G1), vec![0; 32]].concat(),
            true,
        ),
        shape("bls12-381 G1 MSM, empty", 12, Vec::new(), true),
        shape(
            "bls12-381 G2 add, off curve",
            13,
            [hex(BLS_G2), hex(BLS_G2_BAD)].concat(),
            true,
        ),
        shape("bls12-381 G2 MSM, off curve", 14, msm(BLS_G2_BAD, 1), true),
        shape(
            "bls12-381 pairing, off curve",
            15,
            pairs(&[BLS_G1_BAD], BLS_G2),
            true,
        ),
        shape(
            "bls12-381 pairing, fails",
            15,
            pairs(&[BLS_G1], BLS_G2),
            true,
        ),
        shape("bls12-381 pairing, bad padding", 15, bad_padding, true),
        shape(
            "bls12-381 map fp to G1, not canonical",
            16,
            hex(BLS_P),
            true,
        ),
        shape(
            "bls12-381 map fp2 to G2, not canonical",
            17,
            hex(&format!("{BLS_FP}{BLS_P}")),
            true,
        ),
    ]
}

#[test]
fn host_and_guest_paths_agree_on_every_precompile() {
    let mut guest = Runner::new(GUEST, Backend::Native).unwrap();
    let mut hosts = [
        Runner::gated(GUEST, Backend::Native).unwrap(),
        Runner::gated(GUEST, Backend::Interpreter).unwrap(),
    ];
    let mut succeeded = Vec::new();
    for s in worst().into_iter().chain(odd_inputs()) {
        let expected = execute(&mut guest, caller(s.address, 1, 0), &s.input);
        for host in &mut hosts {
            let executed = execute(host, caller(s.address, 1, 0), &s.input);
            assert_eq!(executed, expected, "{} on the {}", s.name, host.label());
        }
        if slot(&expected, 0) == word(1) {
            succeeded.push(s.name);
        }
    }
    // Every worst case succeeds; of the others, those that answer without
    // refusing (a short bn254 input is padded with zeros: the point at
    // infinity).
    let answered: Vec<&str> = worst()
        .iter()
        .map(|s| s.name)
        .chain([
            "modexp, zero modulus",
            "modexp, empty",
            "modexp, short input",
            "bn254 add, short",
            "bn254 pairing, fails",
            "bn254 pairing, empty",
            "blake2f 0 rounds",
            "bls12-381 G1 MSM, zero scalar",
            "bls12-381 pairing, fails",
        ])
        .collect();
    assert_eq!(succeeded, answered);
}

#[test]
fn kernel_gas_per_evm_gas_stays_within_the_bound() {
    let mut gated = Runner::gated(GUEST, Backend::Native).unwrap();
    let mut guest = Runner::new(GUEST, Backend::Native).unwrap();
    for s in worst() {
        let (vm, evm) = per_call(&mut gated, s.address, &s.input);
        assert!(
            vm <= BOUND * evm,
            "{} with gate 2: {vm} VM gas for {evm} EVM gas",
            s.name
        );
        let (vm, evm) = per_call(&mut guest, s.address, &s.input);
        assert_eq!(
            vm <= BOUND * evm,
            s.bounded,
            "{} in the guest: {vm} VM gas for {evm} EVM gas",
            s.name
        );
    }
    for (name, body) in ordinary() {
        let (vm, evm) = per_iteration(&mut guest, &body);
        assert!(vm <= BOUND * evm, "{name}: {vm} VM gas for {evm} EVM gas");
    }
}

#[test]
fn in_guest_precompiles_halt_past_the_budget() {
    // Point evaluations with 60 000 gas each, 250 of them: in the guest the
    // budget lets fewer through; on the host all succeed.
    let input = kzg(true);
    let code = caller(10, 250, 60_000);
    let mut guest = Runner::new(GUEST, Backend::Native).unwrap();
    let executed = execute(&mut guest, code.clone(), &input);
    let passed = u64::from(slot(&executed, 0)[31]);
    assert!((100..250).contains(&passed), "{passed} passed");
    assert!(
        guest.gas_used() < BUDGET + (BUDGET >> 3),
        "{} VM gas",
        guest.gas_used()
    );
    let mut host = Runner::gated(GUEST, Backend::Native).unwrap();
    assert_eq!(slot(&execute(&mut host, code, &input), 0), word(250));
    // The precompiles within the bound are never checked: 40 large modular
    // exponentiations pass in the guest, at 17 million kernel gas each.
    let input = modexp(&[0xFF; 1024], &[0xFF], &[0xEF; 1024]);
    let executed = execute(&mut guest, caller(5, 40, 240_000), &input);
    assert_eq!(slot(&executed, 0), word(40));
    assert!(guest.gas_used() > 40 * 17_000_000);
}

/// A loop running `body`, which must leave the stack as it found it,
/// `iterations` times.
fn looped(body: &[u8], iterations: u16) -> Vec<u8> {
    let [hi, lo] = iterations.to_be_bytes();
    let mut code = vec![0x61, hi, lo, 0x5B];
    code.extend_from_slice(body);
    code.extend_from_slice(&[0x60, 0x01, 0x90, 0x03, 0x80, 0x60, 0x03, 0x57, 0x00]);
    code
}

/// VM gas and EVM gas of 100 iterations of `body`.
fn per_iteration(runner: &mut Runner, body: &[u8]) -> (u64, u64) {
    let short = execute(runner, looped(body, 100), &[]);
    let vm = runner.gas_used();
    let long = execute(runner, looped(body, 200), &[]);
    (
        runner.gas_used() - vm,
        long.outcome.gas_used - short.outcome.gas_used,
    )
}

/// Loops of ordinary opcodes (spec 19 table 2.2), including the costliest
/// per EVM gas found.
fn ordinary() -> Vec<(&'static str, Vec<u8>)> {
    let mut exp = vec![0x7F];
    exp.extend([0xFF; 32]);
    exp.extend([0x60, 0x03, 0x0A, 0x50]);
    vec![
        ("loop control", vec![]),
        ("JUMPDEST x16", vec![0x5B; 16]),
        ("PUSH0 POP x8", [0x5F, 0x50].repeat(8)),
        ("ADD", vec![0x60, 0x01, 0x60, 0x02, 0x01, 0x50]),
        (
            "MULMOD",
            vec![0x60, 0x07, 0x60, 0x05, 0x60, 0x03, 0x09, 0x50],
        ),
        ("EXP 3^(2^256-1)", exp),
        ("KECCAK256 32 B", vec![0x60, 0x20, 0x5F, 0x20, 0x50]),
        ("KECCAK256 1 KiB", vec![0x61, 0x04, 0x00, 0x5F, 0x20, 0x50]),
        (
            "MSTORE MLOAD",
            vec![0x60, 0x2A, 0x5F, 0x52, 0x5F, 0x51, 0x50],
        ),
        (
            "MCOPY 1 KiB",
            vec![0x61, 0x04, 0x00, 0x5F, 0x61, 0x04, 0x00, 0x5E],
        ),
        ("SLOAD warm", vec![0x5F, 0x54, 0x50]),
        ("SSTORE warm", vec![0x5A, 0x5F, 0x55]),
        ("TSTORE TLOAD", vec![0x5A, 0x5F, 0x5D, 0x5F, 0x5C, 0x50]),
        ("BALANCE cold", vec![0x5A, 0x31, 0x50]),
        ("EXTCODEHASH cold", vec![0x5A, 0x3F, 0x50]),
        ("BLOCKHASH, no such block", vec![0x60, 0x00, 0x40, 0x50]),
        ("SELFBALANCE", vec![0x47, 0x50]),
        (
            "STATICCALL empty account",
            vec![0x5F, 0x5F, 0x5F, 0x5F, 0x61, 0x12, 0x34, 0x5A, 0xFA, 0x50],
        ),
        (
            "STATICCALL identity",
            vec![0x5F, 0x5F, 0x5F, 0x5F, 0x60, 0x04, 0x5A, 0xFA, 0x50],
        ),
        (
            "STATICCALL self",
            vec![0x5F, 0x5F, 0x5F, 0x5F, 0x30, 0x61, 0x10, 0x00, 0xFA, 0x50],
        ),
        ("LOG0 empty", vec![0x5F, 0x5F, 0xA0]),
        ("CREATE empty", vec![0x5F, 0x5F, 0x5F, 0xF0, 0x50]),
    ]
}

fn ratio(vm: u64, evm: u64) -> String {
    format!("{}.{}", vm * 10 / evm / 10, vm * 10 / evm % 10)
}

#[test]
#[ignore = "a measurement: cargo test -p solo-conformance --test precompiles -- --ignored --nocapture"]
fn measure_precompiles() {
    for backend in [Backend::Interpreter, Backend::Native] {
        let mut guest = Runner::new(GUEST, backend).unwrap();
        let mut gated = Runner::gated(GUEST, backend).unwrap();
        println!("{backend:?}: EVM gas; VM gas and per EVM gas in the guest, then with gate 2");
        for s in worst() {
            let start = Instant::now();
            let (vm, evm) = per_call(&mut guest, s.address, &s.input);
            let guest_ms = start.elapsed().as_millis();
            let start = Instant::now();
            let (host_vm, charged) = per_call(&mut gated, s.address, &s.input);
            assert_eq!(evm, charged);
            println!(
                "| {} | {evm} | {vm} | {} | {host_vm} | {} | {guest_ms} ms | {} ms |",
                s.name,
                ratio(vm, evm),
                ratio(host_vm, evm),
                start.elapsed().as_millis()
            );
        }
    }
}

#[test]
#[ignore = "a measurement: cargo test -p solo-conformance --test precompiles -- --ignored --nocapture"]
fn measure_ordinary() {
    let mut runner = Runner::new(GUEST, Backend::Native).unwrap();
    for (name, body) in ordinary() {
        let (vm, evm) = per_iteration(&mut runner, &body);
        println!("| {name} | {evm} | {vm} | {} |", ratio(vm, evm));
    }
}

/// Storage holding block 0 with `txs` transaction hashes, and its hash
/// beside it if `hashed`, as the kernel stores blocks.
fn with_block(txs: usize, hashed: bool) -> (solo_host::MemStorage, [u8; 32]) {
    use solo_abi::Encode;
    use solo_host::Storage;
    let header = solo_abi::chain::BlockHeader {
        tx_hashes: solo_abi::codec::Seq(vec![[7; 32]; txs]),
        ..Default::default()
    }
    .to_bytes();
    let hash = solo_host::hash::keccak256(&header);
    let mut storage = solo_host::MemStorage::default();
    storage.set(&[&b"block/"[..], &0u64.to_be_bytes()].concat(), &header);
    if hashed {
        storage.set(&[&b"bnum/"[..], &0u64.to_be_bytes()].concat(), &hash);
    }
    (storage, hash)
}

#[test]
fn blockhash_reads_the_stored_hash_whatever_the_header() {
    let mut runner = Runner::new(GUEST, Backend::Native).unwrap();
    // SSTORE(0, BLOCKHASH(0)): the stored hash; the header alone is never read.
    for hashed in [true, false] {
        let (storage, hash) = with_block(3, hashed);
        let executed = runner
            .run_on(&call_case(vec![0x5F, 0x40, 0x5F, 0x55, 0x00], &[]), storage)
            .unwrap();
        assert_eq!(slot(&executed, 0), if hashed { hash } else { [0; 32] });
    }
    // A thousand transaction hashes in the header cost nothing more.
    let mut gas = Vec::new();
    for n in [100u16, 200] {
        let (storage, _) = with_block(1_000, true);
        let executed = runner
            .run_on(&call_case(looped(&[0x5F, 0x40, 0x50], n), &[]), storage)
            .unwrap();
        gas.push((runner.gas_used(), executed.outcome.gas_used));
    }
    let (vm, evm) = (gas[1].0 - gas[0].0, gas[1].1 - gas[0].1);
    println!(
        "| BLOCKHASH, 1 000 transactions | {evm} | {vm} | {} |",
        ratio(vm, evm)
    );
    assert!(vm <= BOUND * evm, "{vm} VM gas for {evm} EVM gas");
}
