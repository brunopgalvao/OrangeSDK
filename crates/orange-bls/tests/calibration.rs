//! Calibration of `bls12381_fast_aggregate_verify`'s cost (spec 05 §4.3)
//! against `bls12381_verify`'s: both are timed in the same run, and the
//! fast-aggregate times are converted to gas at `bls12381_verify`'s rate,
//! 100 000 gas for one verification, so the result does not depend on the
//! machine or its load as long as both share it.
//!
//! cargo test --release -p orange-bls --test calibration -- --ignored --nocapture

use std::time::{Duration, Instant};

use orange_bls::SecretKey;
use orange_bls::curve::{G1Affine, G2Affine, G2Projective, Scalar};
use orange_bls::{eth, hash, host, sig};

/// `bls12381_verify`'s cost for a message of one word, the reference rate.
const VERIFY_GAS: f64 = 100_006.0;

fn best_of(runs: usize, mut f: impl FnMut() -> bool) -> Duration {
    let mut best = Duration::MAX;
    for _ in 0..runs {
        let start = Instant::now();
        assert!(f());
        best = best.min(start.elapsed());
    }
    best
}

fn secret(i: u64) -> Scalar {
    Scalar::from(i * 7919 + 13)
}

#[test]
#[ignore = "timing; run explicitly in release mode"]
fn fast_aggregate_verify_at_bls12381_verify_rate() {
    let msg = [7u8; 32];
    let sk = SecretKey::generate(&[1; 32], b"calibration").unwrap();
    let pk = sk.public_key().to_bytes();
    let sig = sk.sign(&msg).to_bytes();
    let verify = best_of(20, || host::verify(&msg, sig::DST_SIGNATURE, &sig, &pk));

    let h = G2Projective::from(hash::to_g2(&msg, eth::DST));
    let mut keys = Vec::new();
    let mut sum = G2Projective::identity();
    let mut times = Vec::new();
    for n in 1..=512u64 {
        keys.extend_from_slice(&G1Affine::from(G1Affine::generator() * secret(n)).to_compressed());
        sum += h * secret(n);
        if n == 1 || n == 512 {
            let sig = G2Affine::from(sum).to_compressed();
            times.push(best_of(20, || {
                eth::fast_aggregate_verify(&keys, &msg, &sig)
            }));
        }
    }
    let rate = VERIFY_GAS / verify.as_secs_f64();
    let per_key = (times[1].as_secs_f64() - times[0].as_secs_f64()) / 511.0 * rate;
    let base = times[0].as_secs_f64() * rate - per_key;
    println!(
        "bls12381_verify {:.0} us ({:.1} gas/us); fast_aggregate_verify 1 key {:.0} us, 512 keys {:.0} us\n  base {base:.0} gas, per key {per_key:.0} gas, 512 keys {:.0} gas",
        verify.as_secs_f64() * 1e6,
        rate / 1e6,
        times[0].as_secs_f64() * 1e6,
        times[1].as_secs_f64() * 1e6,
        base + 512.0 * per_key,
    );
}
