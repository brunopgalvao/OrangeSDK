//! Calibration of the precompile host functions' costs (spec 05 §4.8,
//! spec 19 §3) against `bls12381_verify`'s: each operation is timed natively
//! with the arithmetic the host functions run, in the same run as
//! `bls12381_verify`, and converted to VM gas at that function's rate,
//! 100 000 gas for one verification, so the result does not depend on the
//! machine or its load as long as both share it. The cost of each function
//! is its Ethereum gas times `PRECOMPILE_RATE`; the test prints the rate each
//! shape needs.
//!
//! `cargo test --release -p orange-host --test precompile_calibration -- --ignored --nocapture`

use std::time::{Duration, Instant};

use orange_bls::{SecretKey, host, sig};
use revm_precompile::Precompiles;
use revm_precompile::primitives::Address;

/// `bls12381_verify`'s cost for a message of one word, the reference rate.
const VERIFY_GAS: f64 = 100_006.0;

fn best_of(runs: usize, mut f: impl FnMut()) -> Duration {
    let mut best = Duration::MAX;
    for _ in 0..runs {
        let start = Instant::now();
        f();
        best = best.min(start.elapsed());
    }
    best
}

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

fn modexp(base: &[u8], exp: &[u8], modulus: &[u8]) -> Vec<u8> {
    let mut input = Vec::new();
    for len in [base.len(), exp.len(), modulus.len()] {
        input.extend_from_slice(&word(len as u64));
    }
    [input, base.to_vec(), exp.to_vec(), modulus.to_vec()].concat()
}

const BN_G1: &str = "0000000000000000000000000000000000000000000000000000000000000001\
                     0000000000000000000000000000000000000000000000000000000000000002";
const BN_G1_NEG: &str = "0000000000000000000000000000000000000000000000000000000000000001\
                         30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd45";
const BN_G2: &str = "198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2\
                     1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed\
                     090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b\
                     12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa";
const BLS_G1: &str = "0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb\
                      0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1";
const BLS_G1_NEG: &str = "0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb\
                          00000000000000000000000000000000114d1d6855d545a8aa7d76c8cf2e21f267816aef1db507c96655b9d5caac42364e6f38ba0ecb751bad54dcd6b939c2ca";
const BLS_G2: &str = "00000000000000000000000000000000024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8\
                      0000000000000000000000000000000013e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e\
                      000000000000000000000000000000000ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801\
                      000000000000000000000000000000000606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be";
const BLS_FP: &str = "000000000000000000000000000000000ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801";
const SCALAR: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

fn kzg() -> Vec<u8> {
    use sha2::Digest;
    let commitment = hex(
        "8f59a8d2a1a625a17f3fea0fe5eb8c896db3764f3185481bc22f91b4aaffcca25f26936857bc3a7c2539ea8ec3a952b7",
    );
    let mut versioned: [u8; 32] = sha2::Sha256::digest(&commitment).into();
    versioned[0] = 1;
    [
        versioned.to_vec(),
        hex("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000"),
        hex("1522a4a7f34e1ea350ae07c29c96c7e79655aa926122e95fe69fcbd932ca49e9"),
        commitment,
        hex("a62ad71d14c5719385c0686f1871430475bf3a00f0aa3f7b8dd99a9abc2160744faf0070725e00b60ad9a026a15b1a8c"),
    ]
    .concat()
}

fn blake2f(rounds: u32) -> Vec<u8> {
    let mut input = rounds.to_be_bytes().to_vec();
    input.extend([0x11; 208]);
    input.push(1);
    input
}

fn pairs(g1: [&str; 2], g2: &str, k: usize) -> Vec<u8> {
    (0..k)
        .flat_map(|i| [hex(g1[i % 2]), hex(g2)].concat())
        .collect()
}

fn shapes() -> Vec<(&'static str, u8, Vec<u8>)> {
    let ff32 = [0xFF; 32];
    let mut odd32 = [0xEE; 32];
    odd32[31] = 0xED;
    let msm = |p: &str, k: usize| hex(&format!("{p}{SCALAR}").repeat(k));
    vec![
        ("modexp 32 B, exp 2^256-1", 5, modexp(&ff32, &ff32, &odd32)),
        (
            "modexp 32 B, exp 2^256-1, even",
            5,
            modexp(&ff32, &ff32, &[0xEE; 32]),
        ),
        ("modexp 1 B, exp 2^256-1", 5, modexp(&[3], &ff32, &[0xED])),
        (
            "modexp 64 B, exp 2^256-1",
            5,
            modexp(&[0xFF; 64], &ff32, &[0xEF; 64]),
        ),
        (
            "modexp 256 B, exp 2^256-1",
            5,
            modexp(&[0xFF; 256], &ff32, &[0xEF; 256]),
        ),
        (
            "modexp 1 KiB, exp 255",
            5,
            modexp(&[0xFF; 1024], &[0xFF], &[0xEF; 1024]),
        ),
        (
            "modexp 1 KiB even, exp 255",
            5,
            modexp(&[0xFF; 1024], &[0xFF], &[0xEE; 1024]),
        ),
        (
            "modexp 1 KiB, exp 1",
            5,
            modexp(&[0xFF; 1024], &[1], &[0xEF; 1024]),
        ),
        (
            "modexp 1 KiB, 33-byte exp",
            5,
            modexp(&[0xFF; 1024], &[0xFF; 33], &[0xEF; 1024]),
        ),
        ("bn254 add", 6, [hex(BN_G1), hex(BN_G1_NEG)].concat()),
        ("bn254 mul", 7, [hex(BN_G1), hex(SCALAR)].concat()),
        (
            "bn254 pairing, 1 pair",
            8,
            pairs([BN_G1, BN_G1_NEG], BN_G2, 1),
        ),
        (
            "bn254 pairing, 2 pairs",
            8,
            pairs([BN_G1, BN_G1_NEG], BN_G2, 2),
        ),
        (
            "bn254 pairing, 8 pairs",
            8,
            pairs([BN_G1, BN_G1_NEG], BN_G2, 8),
        ),
        ("blake2f 1 round", 9, blake2f(1)),
        ("blake2f 12 rounds", 9, blake2f(12)),
        ("blake2f 100 000 rounds", 9, blake2f(100_000)),
        ("point evaluation", 10, kzg()),
        (
            "bls12-381 G1 add",
            11,
            [hex(BLS_G1), hex(BLS_G1_NEG)].concat(),
        ),
        ("bls12-381 G1 MSM, 1", 12, msm(BLS_G1, 1)),
        ("bls12-381 G1 MSM, 2", 12, msm(BLS_G1, 2)),
        ("bls12-381 G1 MSM, 16", 12, msm(BLS_G1, 16)),
        ("bls12-381 G1 MSM, 128", 12, msm(BLS_G1, 128)),
        ("bls12-381 G2 add", 13, [hex(BLS_G2), hex(BLS_G2)].concat()),
        ("bls12-381 G2 MSM, 1", 14, msm(BLS_G2, 1)),
        ("bls12-381 G2 MSM, 2", 14, msm(BLS_G2, 2)),
        ("bls12-381 G2 MSM, 16", 14, msm(BLS_G2, 16)),
        ("bls12-381 G2 MSM, 128", 14, msm(BLS_G2, 128)),
        (
            "bls12-381 pairing, 1 pair",
            15,
            pairs([BLS_G1, BLS_G1_NEG], BLS_G2, 1),
        ),
        (
            "bls12-381 pairing, 2 pairs",
            15,
            pairs([BLS_G1, BLS_G1_NEG], BLS_G2, 2),
        ),
        (
            "bls12-381 pairing, 8 pairs",
            15,
            pairs([BLS_G1, BLS_G1_NEG], BLS_G2, 8),
        ),
        ("bls12-381 map fp to G1", 16, hex(BLS_FP)),
        (
            "bls12-381 map fp2 to G2",
            17,
            hex(&format!("{BLS_FP}{BLS_FP}")),
        ),
    ]
}

#[test]
#[ignore = "timing; run explicitly in release mode"]
fn precompiles_at_bls12381_verify_rate() {
    let msg = [7u8; 32];
    let sk = SecretKey::generate(&[1; 32], b"calibration").unwrap();
    let pk = sk.public_key().to_bytes();
    let signature = sk.sign(&msg).to_bytes();
    let verify = best_of(20, || {
        assert!(host::verify(&msg, sig::DST_SIGNATURE, &signature, &pk));
    });
    let rate = VERIFY_GAS / verify.as_secs_f64();
    println!(
        "bls12381_verify {:.0} us, {:.1} VM gas per us",
        verify.as_secs_f64() * 1e6,
        rate / 1e6
    );
    let osaka = Precompiles::osaka();
    let mut worst: f64 = 0.0;
    for (name, address, input) in shapes() {
        let precompile = osaka.get(&Address::with_last_byte(address)).unwrap();
        let output = precompile.execute(&input, u64::MAX, 0).unwrap();
        assert!(output.is_success(), "{name}");
        let gas = output.gas_used;
        let time = best_of(10, || {
            assert!(
                precompile
                    .execute(&input, u64::MAX, 0)
                    .unwrap()
                    .is_success()
            );
        });
        let vm = time.as_secs_f64() * rate;
        let per_gas = vm / f64::from(u32::try_from(gas).unwrap());
        worst = worst.max(per_gas);
        println!(
            "{name:<32} evm {gas:>9} {:>9.1} us {vm:>11.0} VM gas {per_gas:>6.2} per EVM gas",
            time.as_secs_f64() * 1e6
        );
    }
    println!("worst: {worst:.2} VM gas per EVM gas");
}
