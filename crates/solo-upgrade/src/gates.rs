//! The feature-gate state machine (spec 13 §8; ADR 0011).
//!
//! A host release ships new behaviour dormant behind a gate, a bit index in
//! a 64-bit feature set. Validators' hosts signal the gates they support
//! once per epoch. At the end of every epoch the stake behind each gate is
//! tallied from the signals carried in that epoch; a gate backed by at least
//! [`THRESHOLD_BPS`] of all stake in [`QUALIFYING_EPOCHS`] consecutive epochs
//! is locked in, and becomes active one full epoch later. Once locked in, a
//! gate never deactivates; before that, one epoch under the threshold resets
//! its streak, which is the revoke path.
//!
//! Epochs are numbered from 0. With `L` blocks per epoch, epoch `e` holds
//! heights `e·L + 1 ..= (e + 1)·L`.

use alloc::vec::Vec;

use solo_abi::codec::Seq;

/// Share of all stake, in basis points, that must back a gate in an epoch.
pub const THRESHOLD_BPS: u64 = 9_500;

/// Consecutive epochs at or above the threshold that lock a gate in.
pub const QUALIFYING_EPOCHS: u32 = 2;

/// Number of gates a feature set can name.
pub const GATES: u8 = 64;

record! {
    /// One gate's progress. Gates with no streak and no activation are not recorded.
    GateRecord {
        /// Bit index of the gate.
        gate: u8,
        /// Consecutive qualifying epochs, up to the one that locked it in.
        streak: u32,
        /// First height at which the gate is active; zero until locked in.
        activation_height: u64,
    }
}

record! {
    /// Every gate's progress, as the kernel keeps it.
    GateBook {
        /// The epoch the next tally is expected for; a tally for any other
        /// epoch restarts every streak that is not locked in.
        next_epoch: u64,
        /// Records in ascending gate order.
        gates: Seq<GateRecord>,
    }
}

/// The epoch of the block at `height` (heights start at 1). An `epoch_blocks`
/// of zero is treated as one.
#[must_use]
pub fn epoch_of(height: u64, epoch_blocks: u64) -> u64 {
    height.saturating_sub(1) / epoch_blocks.max(1)
}

/// The epoch whose last block is `height`, if it is the last block of one.
/// Never, when `epoch_blocks` is zero (gates disabled).
#[must_use]
pub fn ended_epoch(height: u64, epoch_blocks: u64) -> Option<u64> {
    (epoch_blocks != 0 && height != 0 && height.is_multiple_of(epoch_blocks))
        .then(|| height / epoch_blocks - 1)
}

/// The stake behind each gate: the weights of the signals naming it, summed.
/// `signals` holds `(weight, features)` per validator.
#[must_use]
pub fn tally(signals: &[(u64, u64)]) -> [u64; GATES as usize] {
    let mut support = [0u64; GATES as usize];
    for &(weight, features) in signals {
        for (gate, total) in support.iter_mut().enumerate() {
            if features >> gate & 1 == 1 {
                *total = total.saturating_add(weight);
            }
        }
    }
    support
}

/// Whether `support` out of `total` stake meets the threshold. No stake, no gate.
#[must_use]
pub fn qualifies(support: u64, total: u64) -> bool {
    total != 0 && u128::from(support) * 10_000 >= u128::from(total) * u128::from(THRESHOLD_BPS)
}

impl GateBook {
    /// The record of `gate`, if it has one.
    #[must_use]
    pub fn record(&self, gate: u8) -> Option<&GateRecord> {
        self.gates.0.iter().find(|r| r.gate == gate)
    }

    /// The book after tallying `epoch`. `signals` holds `(weight, features)`
    /// of every validator whose signal was carried in `epoch`; `total` is the
    /// stake of the whole validator set. A gate locked in at the end of epoch
    /// `e` activates at the first block of epoch `e + 2`.
    #[must_use]
    pub fn end_epoch(
        &self,
        epoch: u64,
        epoch_blocks: u64,
        signals: &[(u64, u64)],
        total: u64,
    ) -> GateBook {
        let support = tally(signals);
        let consecutive = epoch == self.next_epoch;
        let mut gates = Vec::new();
        for gate in 0..GATES {
            let previous = self.record(gate);
            if let Some(locked) = previous.filter(|r| r.activation_height != 0) {
                gates.push(locked.clone());
                continue;
            }
            if !qualifies(support[usize::from(gate)], total) {
                continue;
            }
            let streak = previous.filter(|_| consecutive).map_or(0, |r| r.streak) + 1;
            let activation_height = if streak >= QUALIFYING_EPOCHS {
                (epoch + 2) * epoch_blocks + 1
            } else {
                0
            };
            gates.push(GateRecord {
                gate,
                streak,
                activation_height,
            });
        }
        GateBook {
            next_epoch: epoch + 1,
            gates: Seq(gates),
        }
    }

    /// The gates active for the block at `height`, one bit per gate.
    #[must_use]
    pub fn active_at(&self, height: u64) -> u64 {
        self.gates
            .0
            .iter()
            .filter(|r| r.activation_height != 0 && r.activation_height <= height)
            .fold(0, |set, r| set | 1 << r.gate)
    }

    /// The gates locked in, active already or scheduled to be.
    #[must_use]
    pub fn locked_in(&self) -> u64 {
        self.active_at(u64::MAX)
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use proptest::prelude::*;
    use solo_abi::{Decode, Encode};

    use super::*;

    const L: u64 = 10;

    #[test]
    fn epochs() {
        assert_eq!(
            (
                epoch_of(0, L),
                epoch_of(1, L),
                epoch_of(10, L),
                epoch_of(11, L)
            ),
            (0, 0, 0, 1)
        );
        assert_eq!(epoch_of(5, 0), 4);
        assert_eq!(
            (ended_epoch(10, L), ended_epoch(20, L), ended_epoch(11, L)),
            (Some(0), Some(1), None)
        );
        assert_eq!((ended_epoch(0, L), ended_epoch(10, 0)), (None, None));
    }

    #[test]
    fn tallies_and_threshold() {
        let support = tally(&[(3, 0b11), (1, 0b10), (u64::MAX, 0b10), (5, 0)]);
        assert_eq!((support[0], support[1], support[2]), (3, u64::MAX, 0));
        assert_eq!(tally(&[(1, 1 << 63)])[63], 1);
        assert!(qualifies(95, 100));
        assert!(!qualifies(94, 100));
        assert!(qualifies(19, 20));
        assert!(!qualifies(3, 4));
        assert!(qualifies(4, 4));
        assert!(!qualifies(0, 0));
        assert!(qualifies(u64::MAX, u64::MAX));
    }

    #[test]
    fn two_qualifying_epochs_lock_a_gate_in_and_it_activates_an_epoch_later() {
        let all = [(1, 0b1), (1, 0b1), (1, 0b1), (1, 0b1)];
        let book = GateBook::default().end_epoch(0, L, &all, 4);
        assert_eq!(
            book.record(0),
            Some(&GateRecord {
                gate: 0,
                streak: 1,
                activation_height: 0
            })
        );
        assert_eq!((book.active_at(u64::MAX), book.next_epoch), (0, 1));
        let book = book.end_epoch(1, L, &all, 4);
        // Locked in at the end of epoch 1; epoch 2 is notice; active from the first block of epoch 3.
        assert_eq!(
            book.record(0),
            Some(&GateRecord {
                gate: 0,
                streak: 2,
                activation_height: 31
            })
        );
        assert_eq!(
            (book.active_at(30), book.active_at(31), book.locked_in()),
            (0, 1, 1)
        );
        // Once locked in, nothing reverses it: not silence, not a gap in the tallies.
        let quiet = book.end_epoch(2, L, &[], 4).end_epoch(7, L, &[], 4);
        assert_eq!(quiet.record(0), book.record(0));
        assert_eq!(quiet.active_at(31), 1);
        assert_eq!(quiet.next_epoch, 8);
    }

    #[test]
    fn falling_short_resets_the_streak() {
        let all = [(1, 0b1), (1, 0b1), (1, 0b1), (1, 0b1)];
        let three = [(1, 0b1), (1, 0b1), (1, 0b1)];
        let book = GateBook::default()
            .end_epoch(0, L, &all, 4)
            .end_epoch(1, L, &three, 4);
        assert_eq!(book.record(0), None);
        let book = book.end_epoch(2, L, &all, 4);
        assert_eq!(book.record(0).unwrap().streak, 1);
        // A tally that skips an epoch restarts the streak instead of extending it.
        let book = book.end_epoch(4, L, &all, 4);
        assert_eq!(book.record(0).unwrap().streak, 1);
        let book = book.end_epoch(5, L, &all, 4);
        assert_eq!(book.record(0).unwrap().activation_height, 71);
    }

    #[test]
    fn stake_not_headcount_decides() {
        // One heavy validator alone carries 95%.
        let book = GateBook::default()
            .end_epoch(0, L, &[(95, 1 << 5)], 100)
            .end_epoch(1, L, &[(95, 1 << 5)], 100);
        assert_eq!(book.locked_in(), 1 << 5);
        let book = GateBook::default().end_epoch(0, L, &[(94, 1 << 5)], 100);
        assert_eq!(book.gates.0, vec![]);
        // Gates progress independently and are kept in gate order.
        let book = GateBook::default().end_epoch(0, L, &[(1, 1 << 9 | 1 << 2)], 1);
        assert_eq!(
            book.gates.0.iter().map(|r| r.gate).collect::<Vec<_>>(),
            vec![2, 9]
        );
        let book = book.end_epoch(1, L, &[(1, 1 << 9)], 1);
        assert_eq!(book.gates.0.len(), 1);
        assert_eq!(book.locked_in(), 1 << 9);
    }

    #[test]
    fn book_roundtrips() {
        let book = GateBook {
            next_epoch: 3,
            gates: Seq(vec![GateRecord {
                gate: 63,
                streak: 2,
                activation_height: 9,
            }]),
        };
        assert_eq!(GateBook::from_bytes(&book.to_bytes()), Ok(book.clone()));
        assert!(alloc::format!("{book:?}").contains("GateBook"));
    }

    proptest! {
        /// Whatever the signals, a locked-in gate stays locked in with the same
        /// activation height, and the active set only grows with height.
        #[test]
        fn locked_in_is_forever(rounds in proptest::collection::vec(proptest::collection::vec((0u64..10, any::<u64>()), 0..6), 1..12)) {
            let mut book = GateBook::default();
            let mut locked: Vec<GateRecord> = Vec::new();
            for (epoch, signals) in rounds.iter().enumerate() {
                let total = signals.iter().map(|s| s.0).sum::<u64>().max(1);
                book = book.end_epoch(epoch as u64, L, signals, total);
                for r in &locked {
                    prop_assert_eq!(book.record(r.gate), Some(r));
                }
                locked = book.gates.0.iter().filter(|r| r.activation_height != 0).cloned().collect();
                for r in &locked {
                    // The first block of an epoch, at least one full epoch after the tally.
                    prop_assert_eq!(r.activation_height % L, 1);
                    prop_assert!(r.activation_height > 2 * L);
                    prop_assert_eq!(r.streak, QUALIFYING_EPOCHS);
                }
                for h in [0, 25, 55, 95] {
                    prop_assert_eq!(book.active_at(h) & !book.active_at(h + L), 0);
                }
            }
        }
    }
}
