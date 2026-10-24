//! Timing of a recipient's share checks at the end of the dealing phase
//! (spec 12 §5.1) and of finding the invalid partial signatures among those
//! a combiner holds (spec 12 §4.1), and of computing every public key share
//! of a run's outcome (spec 12 §4.2). The checks are batched and the shares
//! computed together; this measures what each costs, against doing it one
//! by one, for the sizes the reference kernel deals (spec 15 §6.1).
//!
//! `cargo test --release -p solo-bls --test batch_timing -- --ignored --nocapture`
//!
//! `SOLO_FULL_DKG=1` adds the largest run the kernel can schedule: 256
//! members, 1 024 shares, threshold 683 (it takes a few minutes to deal).

use std::time::{Duration, Instant};

use solo_bls::dkg::{Config, Dealer, DecryptionKey, Dkg, Message, Recipient, Step};
use solo_bls::{PartialSignature, SecretKey, threshold};

const SESSION: [u8; 32] = [0x5e; 32];

fn key(j: u32) -> DecryptionKey {
    let mut ikm = [0u8; 32];
    ikm[..4].copy_from_slice(&j.to_be_bytes());
    DecryptionKey::generate(&ikm).unwrap()
}

fn config(t: u32, shares: &[u32]) -> Config {
    let n = u32::try_from(shares.len()).unwrap();
    Config {
        session: SESSION,
        threshold: t,
        dealers: n,
        recipients: (1..=n).map(|j| key(j).encryption_key()).collect(),
        shares: shares.to_vec(),
        weights: shares.to_vec(),
        previous: None,
    }
}

/// Every dealer's dealing, dealt on all cores.
fn dealings(t: u32, shares: &[u32]) -> Vec<Message> {
    let n = u32::try_from(shares.len()).unwrap();
    let threads = std::thread::available_parallelism().map_or(4, usize::from);
    let indices: Vec<u32> = (1..=n).collect();
    let chunk = indices.len().div_ceil(threads);
    std::thread::scope(|s| {
        let handles: Vec<_> = indices
            .chunks(chunk)
            .map(|part| {
                s.spawn(move || {
                    part.iter()
                        .map(|&i| {
                            let mut seed = [7u8; 32];
                            seed[..4].copy_from_slice(&i.to_be_bytes());
                            let dealer = Dealer {
                                index: i,
                                seed,
                                share: None,
                            };
                            Dkg::new(config(t, shares), Some(dealer), None)
                                .unwrap()
                                .1
                                .unwrap()
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        handles
            .into_iter()
            .flat_map(|h| h.join().unwrap())
            .collect()
    })
}

/// The time recipient `j` takes to end the dealing phase on `threads`
/// threads: decrypting and checking its shares from every dealing. Asserts
/// it accuses nobody.
fn complaint_phase(t: u32, shares: &[u32], j: u32, all: &[Message], threads: usize) -> Duration {
    let mut best = Duration::MAX;
    for _ in 0..3 {
        let recipient = Recipient {
            index: j,
            key: key(j),
        };
        let (mut dkg, _) = Dkg::new(config(t, shares), None, Some(recipient)).unwrap();
        dkg.set_threads(threads);
        for m in all {
            dkg.handle(m).unwrap();
        }
        let start = Instant::now();
        let step = dkg.advance().unwrap();
        best = best.min(start.elapsed());
        assert!(matches!(step, Step::Idle));
    }
    best
}

fn run(label: &str, t: u32, shares: &[u32], recipients: &[u32]) {
    let start = Instant::now();
    let all = dealings(t, shares);
    let cores = std::thread::available_parallelism().map_or(1, usize::from);
    eprintln!(
        "{label}: {} dealers, {} shares, threshold {t}, dealt in {:?}",
        shares.len(),
        shares.iter().sum::<u32>(),
        start.elapsed()
    );
    for &j in recipients {
        let m = shares[j as usize - 1];
        let one = complaint_phase(t, shares, j, &all, 1);
        let every = complaint_phase(t, shares, j, &all, cores);
        eprintln!(
            "  recipient {j} with {m} shares checks them in {one:?} on one core, {every:?} on {cores} ({:.1}x)",
            one.as_secs_f64() / every.as_secs_f64()
        );
    }
}

#[test]
#[ignore = "timing; run explicitly in release mode"]
fn share_checks_at_the_end_of_dealing() {
    // 64 members of equal stake: four shares each (spec 15 §6.1).
    run("equal stake, 64 members", 171, &[4; 64], &[1, 32, 64]);
    // One member with a quarter of the stake: 64 shares.
    let mut skewed = vec![3u32; 64];
    skewed[0] = 64;
    run("skewed stake, 64 members", 171, &skewed, &[1, 2, 64]);
    if std::env::var_os("SOLO_FULL_DKG").is_some() {
        run("equal stake, 256 members", 683, &[4; 256], &[1, 128, 256]);
    }
}

#[test]
#[ignore = "timing; run explicitly in release mode"]
fn finding_invalid_partials() {
    let msg = b"finding invalid partials";
    for (t, n) in [(171u32, 256u32), (683, 1024)] {
        let secret = SecretKey::generate(&[9; 32], b"timing").unwrap();
        let (set, shares) = threshold::deal(&secret, t, n, &[3; 32]).unwrap();
        let mut partials: Vec<PartialSignature> = shares[..t as usize + 2]
            .iter()
            .map(|s| s.sign(msg))
            .collect();
        // Two partials signed over another message.
        partials[5] = shares[5].sign(b"other");
        partials[t as usize] = shares[t as usize].sign(b"other");
        let start = Instant::now();
        let one_by_one: Vec<bool> = partials
            .iter()
            .map(|p| set.verify_partial(msg, p))
            .collect();
        let individually = start.elapsed();
        let start = Instant::now();
        let batched = set.verify_partials(msg, &partials, &[1; 32]);
        let in_batch = start.elapsed();
        assert_eq!(batched, one_by_one);
        assert_eq!(batched.iter().filter(|v| !**v).count(), 2);
        eprintln!(
            "threshold {t}, {} partials, 2 invalid: one by one {individually:?}, batched {in_batch:?}",
            partials.len()
        );
    }
}

#[test]
#[ignore = "timing; run explicitly in release mode"]
fn computing_every_public_key_share() {
    // What every node computes for its `KeySetVote` at the end of a run
    // (spec 15 §6.3): the public key share of each of the run's shares.
    for (members, t, n) in [(64, 171u32, 256u32), (256, 683, 1024)] {
        let secret = SecretKey::generate(&[11; 32], b"timing").unwrap();
        let (set, _) = threshold::deal(&secret, t, n, &[5; 32]).unwrap();
        let start = Instant::now();
        let one_by_one: Vec<_> = (1..=n).map(|x| set.public_share(x)).collect();
        let before = start.elapsed();
        // By differences on one thread, and on every core.
        let cores = std::thread::available_parallelism().map_or(1, usize::from);
        let mut after = [Duration::MAX; 2];
        for _ in 0..3 {
            for (i, threads) in [1, cores].into_iter().enumerate() {
                let start = Instant::now();
                let together = set.public_shares_on(n, threads);
                after[i] = after[i].min(start.elapsed());
                assert_eq!(together, one_by_one);
            }
        }
        eprintln!(
            "{members} members, {n} shares, threshold {t}: one by one {before:?}, by differences {:?} ({:.1}x), on {cores} cores {:?} ({:.1}x)",
            after[0],
            before.as_secs_f64() / after[0].as_secs_f64(),
            after[1],
            before.as_secs_f64() / after[1].as_secs_f64()
        );
    }
}
