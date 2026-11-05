//! Batched checks (spec 12 §4.1, §5.1): many Feldman equations, or many
//! partial-signature equations, checked as one random linear combination,
//! and split in halves only when the combination fails, to find the
//! equations that do not hold.
//!
//! Every equation is a statement that some point of a prime-order group is
//! the identity. Weighting the points with independent coefficients `ρ_i`,
//! uniform over `[0, 2^64)` and unknown to whoever chose them, a combination
//! of points not all the identity is the identity with probability at most
//! `2^−64`: for any fixed other coefficients, at most one value of the
//! coefficient of a point that is not the identity cancels the rest. A
//! combination of identities is always the identity, so a batch over valid
//! equations always holds and the halves of a failing batch always contain
//! a failing equation. The coefficients are 64 bits, so the combinations are
//! multi-scalar multiplications over short scalars.
//!
//! Whether a batch pays depends on the sizes: a Feldman check at a small
//! share index costs a few additions, a batch about sixteen per dealer and
//! coefficient. [`search`] estimates both from a cost model in group
//! additions and checks one by one wherever that is cheaper; and once the
//! batches it has tried cost as much as checking everything one by one, it
//! checks the rest one by one, so that dealers or signers who send bad
//! shares or partials cannot make the search cost more than about twice
//! the plain checks. The model decides only how the answer is computed,
//! never the answer.

use alloc::vec::Vec;
use core::ops::Range;

use bls12_381::{G1Affine, G2Affine, G2Projective, Scalar};

use crate::threshold::PartialSignature;
use crate::{hash, par, point, poly, sig};

/// Domain separation tag of a recipient's share-check coefficients.
pub const DST_SHARE_BATCH: &[u8] = b"ORANGE-V01-DKG-BATCH_XMD:SHA-256";

/// Domain separation tag of a combiner's partial-check coefficients.
pub const DST_PARTIAL_BATCH: &[u8] = b"ORANGE-V01-PARTIAL-BATCH_XMD:SHA-256";

/// What one pairing check costs, in group additions, for the cost model.
const PAIRING: u64 = 1_000;

/// A 64-bit coefficient: the first eight bytes, big-endian, of
/// `expand_message_xmd` over the concatenation of `parts`.
pub(crate) fn coefficient(parts: &[&[u8]], dst: &[u8]) -> u64 {
    let mut msg = parts.concat();
    let out = hash::expand_message_xmd(&msg, dst, 8);
    zeroize::Zeroize::zeroize(msg.as_mut_slice());
    u64::from_be_bytes(out.try_into().expect("8 bytes asked for"))
}

/// The additions and doublings of one Horner step at `x` (`point::mul_small`
/// and the coefficient's addition).
fn horner_step(x: u32) -> u64 {
    u64::from(32 - x.leading_zeros() + x.count_ones() + 1)
}

/// The additions and doublings of a multi-scalar multiplication of `n`
/// points with scalars below `2^bits` (`point::msm_g2`).
fn msm_cost(n: usize, bits: usize) -> u64 {
    let c = point::window(n);
    let windows = bits.div_ceil(c);
    (windows * (n + (2 << c)) + windows * c) as u64
}

/// The equations a search runs over, by position.
trait Equations {
    /// What checking positions `range` one by one, and in one batch, cost.
    fn costs(&self, range: Range<usize>) -> (u64, u64);
    /// The positions in `range` whose equations fail, each checked alone.
    fn singles(&mut self, range: Range<usize>) -> Vec<usize>;
    /// Whether the batch over positions `range` holds.
    fn batch(&mut self, range: Range<usize>) -> bool;
}

/// The positions in `range` whose equations fail, ascending: batches where
/// they are cheaper than single checks and the budget lasts, halves of a
/// batch that fails, single checks otherwise.
fn search(range: Range<usize>, budget: &mut u64, eq: &mut dyn Equations, out: &mut Vec<usize>) {
    let n = range.len();
    if n == 0 {
        return;
    }
    let (one_by_one, batched) = eq.costs(range.clone());
    if n == 1 || one_by_one <= batched || *budget < batched {
        out.extend(eq.singles(range));
        return;
    }
    *budget -= batched;
    if eq.batch(range.clone()) {
        return;
    }
    let mid = range.start + n / 2;
    search(range.start..mid, budget, eq, out);
    search(mid..range.end, budget, eq, out);
}

/// [`search`] over every position, with a budget for batches of what
/// checking everything one by one costs.
fn failing(len: usize, eq: &mut dyn Equations) -> Vec<usize> {
    let mut budget = eq.costs(0..len).0;
    let mut out = Vec::new();
    search(0..len, &mut budget, eq, &mut out);
    out
}

/// One dealer's shares to one recipient: the dealer's commitment, the
/// recipient's decrypted shares at consecutive indices, and the dealer's
/// coefficient.
pub(crate) struct DealerShares<'a> {
    pub(crate) commitment: &'a [G2Affine],
    pub(crate) shares: &'a [Scalar],
    pub(crate) rho: u64,
}

struct Feldman<'a, 'b> {
    items: &'b [DealerShares<'a>],
    first: u32,
    /// Threads the aggregate's points are computed on.
    threads: usize,
}

impl Feldman<'_, '_> {
    /// One Horner evaluation of a commitment at each share index.
    fn evaluations(&self) -> u64 {
        let m = self.items.first().map_or(0, |d| d.shares.len());
        (self.first..).take(m).map(horner_step).sum()
    }
}

impl Equations for Feldman<'_, '_> {
    /// Per commitment point: `n` evaluations one by one, against an
    /// aggregate over `n` dealers and one evaluation of it.
    fn costs(&self, range: Range<usize>) -> (u64, u64) {
        let e = self.evaluations();
        (range.len() as u64 * e, msm_cost(range.len(), 64) + e)
    }

    /// The Feldman check of each share of each dealer, the dealers split
    /// over threads.
    fn singles(&mut self, range: Range<usize>) -> Vec<usize> {
        let (items, first) = (self.items, self.first);
        let start = range.start;
        let check = |r: Range<usize>| -> Vec<Option<usize>> {
            r.map(|i| (!feldman(&items[start + i], first)).then_some(start + i))
                .collect()
        };
        par::map(range.len(), self.threads, &check)
            .into_iter()
            .flatten()
            .collect()
    }

    /// The Feldman equations of every share of every dealer in `range`, in
    /// one combination per share index `x`: `(Σ_i ρ_i s_ix) · g2 = Σ_k x^k
    /// A_k` with the aggregate commitment `A_k = Σ_i ρ_i C_ik`.
    fn batch(&mut self, range: Range<usize>) -> bool {
        let items = &self.items[range];
        let scalars: Vec<[u8; 32]> = items.iter().map(|d| point::u64_scalar(d.rho)).collect();
        // Each aggregate point is a multi-scalar multiplication of its own,
        // so the points split over threads with the same result.
        let points = |ks: Range<usize>| -> Vec<G2Projective> {
            let mut column = Vec::with_capacity(items.len());
            ks.map(|k| {
                column.clear();
                column.extend(items.iter().map(|d| d.commitment[k]));
                point::msm_g2(&column, &scalars, 64)
            })
            .collect()
        };
        let aggregate = par::map(items[0].commitment.len(), self.threads, &points);
        let aggregate = poly::normalize(&aggregate);
        // One evaluation of the aggregate per share index, split over threads.
        let first = self.first;
        let holds = |js: Range<usize>| -> Vec<bool> {
            js.map(|j| {
                let combined: Scalar = items
                    .iter()
                    .map(|d| d.shares[j] * Scalar::from(d.rho))
                    .sum();
                let x = first + u32::try_from(j).expect("a share index");
                G2Projective::generator() * combined == poly::evaluate_commitment(&aggregate, x)
            })
            .collect()
        };
        par::map(items[0].shares.len(), self.threads, &holds)
            .into_iter()
            .all(|h| h)
    }
}

/// The Feldman check of each of `d`'s shares, at `first`, `first + 1`, …
fn feldman(d: &DealerShares<'_>, first: u32) -> bool {
    d.shares
        .iter()
        .zip(first..)
        .all(|(s, x)| poly::share_matches(d.commitment, x, s))
}

/// The positions in `items` of the dealers with a share that fails the
/// Feldman check, ascending; the shares sit at indices `first`, `first + 1`,
/// … Every commitment has the same length and every share list the same
/// length. A batch's aggregate is computed on up to `threads` threads; the
/// answer is the same on any number.
pub(crate) fn failing_dealers(
    items: &[DealerShares<'_>],
    first: u32,
    threads: usize,
) -> Vec<usize> {
    failing(
        items.len(),
        &mut Feldman {
            items,
            first,
            threads,
        },
    )
}

struct PartialChecks<'a> {
    commitment: &'a [G2Affine],
    h: &'a G1Affine,
    partials: &'a [PartialSignature],
    rho: &'a [u64],
}

impl PartialChecks<'_> {
    /// Horner evaluations of the commitment at the indices of `range`.
    fn evaluations(&self, range: Range<usize>) -> u64 {
        let t = self.commitment.len() as u64;
        self.partials[range]
            .iter()
            .map(|p| t * horner_step(p.index))
            .sum()
    }

    /// `Σ_j ρ_j pk_{x_j}` over `range`, whichever way is cheaper: one
    /// multi-scalar multiplication over the commitment with scalars
    /// `Σ_j ρ_j x_j^k`, or the key shares evaluated one by one and combined.
    fn combined_key(&self, range: Range<usize>) -> G2Projective {
        let partials = &self.partials[range.clone()];
        let rho = &self.rho[range.clone()];
        let small: Vec<[u8; 32]> = rho.iter().map(|r| point::u64_scalar(*r)).collect();
        if self.evaluations(range.clone()) + msm_cost(range.len(), 64)
            < msm_cost(self.commitment.len(), 255)
        {
            let shares: Vec<G2Projective> = partials
                .iter()
                .map(|p| poly::evaluate_commitment(self.commitment, p.index))
                .collect();
            return point::msm_g2(&poly::normalize(&shares), &small, 64);
        }
        let mut coefficients = alloc::vec![Scalar::zero(); self.commitment.len()];
        for (p, r) in partials.iter().zip(rho) {
            let x = Scalar::from(u64::from(p.index));
            let mut power = Scalar::from(*r);
            for c in &mut coefficients {
                *c += power;
                power *= x;
            }
        }
        let wide: Vec<[u8; 32]> = coefficients.iter().map(Scalar::to_bytes).collect();
        point::msm_g2(self.commitment, &wide, 255)
    }
}

impl Equations for PartialChecks<'_> {
    fn costs(&self, range: Range<usize>) -> (u64, u64) {
        let n = range.len() as u64;
        let e = self.evaluations(range.clone());
        let key = (e + msm_cost(range.len(), 64)).min(msm_cost(self.commitment.len(), 255));
        (e + n * PAIRING, msm_cost(range.len(), 64) + key + PAIRING)
    }

    fn singles(&mut self, range: Range<usize>) -> Vec<usize> {
        range
            .filter(|&i| {
                let p = &self.partials[i];
                !(p.index != 0
                    && sig::verify_hashed(
                        self.h,
                        &p.signature.0,
                        &poly::evaluate_commitment(self.commitment, p.index).into(),
                    ))
            })
            .collect()
    }

    /// `e(Σ_j ρ_j σ_j, −g2) · e(h, Σ_j ρ_j pk_{x_j}) = 1`. A partial naming
    /// index zero fails the batch, so that splitting finds it.
    fn batch(&mut self, range: Range<usize>) -> bool {
        if self.partials[range.clone()].iter().any(|p| p.index == 0) {
            return false;
        }
        let small: Vec<[u8; 32]> = self.rho[range.clone()]
            .iter()
            .map(|r| point::u64_scalar(*r))
            .collect();
        let signatures: Vec<G1Affine> = self.partials[range.clone()]
            .iter()
            .map(|p| p.signature.0)
            .collect();
        let signature = point::msm_g1(&signatures, &small, 64);
        let key = self.combined_key(range);
        sig::verify_hashed(self.h, &signature.into(), &key.into())
    }
}

/// Which partials are valid under `commitment` for the message hash `h`,
/// one flag each, with coefficients `rho`.
pub(crate) fn valid_partials(
    commitment: &[G2Affine],
    h: &G1Affine,
    partials: &[PartialSignature],
    rho: &[u64],
) -> Vec<bool> {
    let mut eq = PartialChecks {
        commitment,
        h,
        partials,
        rho,
    };
    let mut valid = alloc::vec![true; partials.len()];
    for i in failing(partials.len(), &mut eq) {
        valid[i] = false;
    }
    valid
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poly::Polynomial;

    /// Equations that fail at the set bits of `bad`, with fixed costs, that
    /// count how often each kind of check runs.
    struct Mock {
        bad: u32,
        costs: (u64, u64),
        ones: usize,
        batches: usize,
    }

    impl Equations for Mock {
        fn costs(&self, range: Range<usize>) -> (u64, u64) {
            let n = range.len() as u64;
            (n * self.costs.0, self.costs.1)
        }
        fn singles(&mut self, range: Range<usize>) -> Vec<usize> {
            self.ones += range.len();
            range.filter(|i| self.bad >> i & 1 == 1).collect()
        }
        fn batch(&mut self, range: Range<usize>) -> bool {
            self.batches += 1;
            range.clone().all(|i| self.bad >> i & 1 == 0)
        }
    }

    #[test]
    fn the_search_finds_exactly_the_failing_positions_within_its_budget() {
        for len in 0..13usize {
            for bad in [0u32, 0b1, 0b1000_0000_0001, 0b0110_1010_0110, 0xFFF] {
                let expect: Vec<usize> = (0..len).filter(|i| bad >> i & 1 == 1).collect();
                for costs in [(10, 4), (10, 30), (1, 1), (100, 1)] {
                    let mut eq = Mock {
                        bad,
                        costs,
                        ones: 0,
                        batches: 0,
                    };
                    assert_eq!(failing(len, &mut eq), expect, "{len} {bad:b} {costs:?}");
                    // Batches never cost more than checking everything once.
                    assert!(eq.batches as u64 * costs.1 <= len as u64 * costs.0);
                    if expect.is_empty() && len > 1 && costs.0 * len as u64 > costs.1 {
                        assert_eq!((eq.batches, eq.ones), (1, 0));
                    }
                }
            }
        }
    }

    #[test]
    fn a_batch_of_dealers_finds_the_bad_shares() {
        let polys: Vec<Polynomial> = (0..40u8)
            .map(|i| Polynomial::derive(&[i; 32], b"batch", 5, None))
            .collect();
        let commitments: Vec<Vec<G2Affine>> = polys.iter().map(Polynomial::commit).collect();
        // Share indices high enough that a batch is the cheaper check.
        let first = 900u32;
        let mut shares: Vec<Vec<Scalar>> = polys
            .iter()
            .map(|p| (first..first + 3).map(|x| p.evaluate(x)).collect())
            .collect();
        let run = |shares: &[Vec<Scalar>]| -> (Vec<usize>, usize) {
            let list: Vec<DealerShares<'_>> = commitments
                .iter()
                .zip(shares)
                .zip(1u64..)
                .map(|((c, s), i)| DealerShares {
                    commitment: c,
                    shares: s,
                    rho: coefficient(&[&i.to_be_bytes()], DST_SHARE_BATCH),
                })
                .collect();
            let mut eq = Feldman {
                items: &list,
                first,
                threads: 1,
            };
            let (one_by_one, batched) = eq.costs(0..list.len());
            let failing = failing(list.len(), &mut eq);
            // The aggregate's points on several threads give the same answer.
            for threads in [2, 3, 8] {
                assert_eq!(failing_dealers(&list, first, threads), failing);
            }
            (failing, usize::from(batched < one_by_one))
        };
        assert_eq!(run(&shares), (Vec::new(), 1));
        assert_eq!(run(&[]), (Vec::new(), 0));
        // A share off by one from dealer 2, and the last share of dealer 6;
        // then two errors that would cancel under equal weights.
        shares[2][0] += Scalar::one();
        shares[6][2] -= Scalar::one();
        assert_eq!(run(&shares).0, vec![2, 6]);
        shares[3][1] += Scalar::one();
        shares[4][1] -= Scalar::one();
        assert_eq!(run(&shares).0, vec![2, 3, 4, 6]);
        assert_eq!(run(&shares[2..3]).0, vec![0]);
        assert_eq!(run(&shares[..2]).0, Vec::<usize>::new());
    }

    #[test]
    fn the_cost_model_prefers_single_checks_at_small_indices() {
        let c = [G2Affine::generator(); 4];
        let s = [Scalar::one(); 4];
        let items: Vec<DealerShares<'_>> = (0..64)
            .map(|_| DealerShares {
                commitment: &c,
                shares: &s,
                rho: 1,
            })
            .collect();
        let low = Feldman {
            items: &items,
            first: 1,
            threads: 1,
        };
        let (one_by_one, batched) = low.costs(0..64);
        assert!(one_by_one < batched);
        let high = Feldman {
            items: &items,
            first: 700,
            threads: 1,
        };
        let (one_by_one, batched) = high.costs(0..64);
        assert!(one_by_one > 2 * batched);
        assert_eq!(horner_step(1), 3);
        assert_eq!(horner_step(1024), 13);
        assert_eq!(msm_cost(256, 64), 11 * (256 + 128) + 66);
    }

    #[test]
    fn coefficients_depend_on_every_part() {
        let a = coefficient(&[b"a", b"b"], DST_SHARE_BATCH);
        assert_eq!(a, coefficient(&[b"ab"], DST_SHARE_BATCH));
        assert_ne!(a, coefficient(&[b"ab"], DST_PARTIAL_BATCH));
        assert_ne!(a, coefficient(&[b"ac"], DST_SHARE_BATCH));
    }
}
