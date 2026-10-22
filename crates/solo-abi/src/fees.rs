//! The fee market of the reference kernel (spec 23): the parameters a chain
//! sets at genesis and changes through governance, the base fee of each
//! block under EIP-1559 scaled to slot time, the fee vault that collects
//! priority fees for the stakers, and the `fees` query. Shared by the
//! kernel, the node, the RPC and the `solo` command, so that none of them
//! can compute a different base fee from the same header.

use crate::codec::{Decode, DecodeError, Decoder, Encode, Encoder};
use crate::types::Address;

macro_rules! record {
    ($(#[$meta:meta])* $name:ident { $($(#[$fmeta:meta])* $field:ident : $ty:ty),* $(,)? }) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, Default)]
        pub struct $name {
            $($(#[$fmeta])* pub $field: $ty,)*
        }
        impl Encode for $name {
            fn encode(&self, e: &mut Encoder) {
                $(self.$field.encode(e);)*
            }
        }
        impl Decode for $name {
            fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
                Ok($name { $($field: d.get()?,)* })
            }
        }
    };
}

/// The fee vault, `0x0000000000000000000000000000000000004645`: the block
/// beneficiary of a chain with staking. Priority fees, and whatever a
/// contract sends `block.coinbase`, land here during a block and move to
/// the staking address's reward pool at its end (spec 23 §4). A chain
/// without staking keeps the zero address as its beneficiary.
pub const FEE_VAULT: Address = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x46, 0x45,
];

/// The least base fee change denominator the kernel accepts: a change of at
/// most 1% per block (spec 23 §2).
pub const MIN_DENOMINATOR: u64 = 100;
/// The largest denominator the kernel accepts: 0.8% per block.
pub const MAX_DENOMINATOR: u64 = 125;
/// The least elasticity: the target is half the block gas limit.
pub const MIN_ELASTICITY: u64 = 2;
/// The largest elasticity: the target is a quarter of the block gas limit.
pub const MAX_ELASTICITY: u64 = 4;

/// The production defaults (spec 23 §2.1), which `solo devnet init` writes.
pub const DEFAULT_DENOMINATOR: u64 = 125;
/// See [`DEFAULT_DENOMINATOR`].
pub const DEFAULT_ELASTICITY: u64 = 2;
/// The default floor of the base fee: one gwei.
pub const DEFAULT_MIN_BASE_FEE: u64 = 1_000_000_000;

record! {
    /// The fee market's parameters (spec 23 §2), `GenesisParams::fees` at
    /// genesis and `fees/params` once governance changed them.
    FeeParams {
        /// EIP-1559's base fee change denominator: a block that is full
        /// raises the next base fee by a `denominator`th, an empty one
        /// lowers it as much. Zero turns the market off: every block's base
        /// fee is `min_base_fee`.
        denominator: u64,
        /// EIP-1559's elasticity multiplier: the gas target is the block gas
        /// limit divided by it. Zero with a zero denominator.
        elasticity: u64,
        /// The least base fee, in wei per gas; the base fee of every block
        /// while the market is off.
        min_base_fee: u64,
        /// Where the base fee goes: burned (the zero address, which nothing
        /// credits), or credited to this account every transaction.
        treasury: Address,
    }
}

impl FeeParams {
    /// The production defaults: a denominator of 125, an elasticity of 2, a
    /// floor of one gwei and a burned base fee.
    #[must_use]
    pub const fn production() -> FeeParams {
        FeeParams {
            denominator: DEFAULT_DENOMINATOR,
            elasticity: DEFAULT_ELASTICITY,
            min_base_fee: DEFAULT_MIN_BASE_FEE,
            treasury: [0; 20],
        }
    }

    /// Whether the market is on: the base fee follows demand.
    #[must_use]
    pub const fn market_on(&self) -> bool {
        self.denominator != 0
    }

    /// Whether the parameters can work (spec 23 §2): the market off with
    /// both factors zero, or on with the denominator within 100 to 125 and
    /// the elasticity within 2 to 4. `kernel_init` traps on anything else
    /// and `setFeeParams` fails.
    #[must_use]
    pub const fn workable(&self) -> bool {
        if self.denominator == 0 {
            return self.elasticity == 0;
        }
        self.denominator >= MIN_DENOMINATOR
            && self.denominator <= MAX_DENOMINATOR
            && self.elasticity >= MIN_ELASTICITY
            && self.elasticity <= MAX_ELASTICITY
    }

    /// The gas target of a block with `gas_limit`: the limit over the
    /// elasticity; the whole limit while the market is off.
    #[must_use]
    pub const fn gas_target(&self, gas_limit: u64) -> u64 {
        match gas_limit.checked_div(self.elasticity) {
            Some(target) => target,
            None => gas_limit,
        }
    }

    /// The base fee of the block after one with `parent_base_fee` that
    /// used `parent_gas_used` of `gas_limit` (spec 23 §3): EIP-1559's
    /// update, never below `min_base_fee`. With the market off it is
    /// `min_base_fee`. The genesis counts as a parent at the floor that
    /// used nothing, so block 1 starts at the floor.
    #[must_use]
    pub fn next_base_fee(&self, parent_base_fee: u64, parent_gas_used: u64, gas_limit: u64) -> u64 {
        if !self.market_on() {
            return self.min_base_fee;
        }
        let target = self.gas_target(gas_limit);
        let parent = u128::from(parent_base_fee);
        let denominator = u128::from(self.denominator);
        let fee = match parent_gas_used.cmp(&target) {
            core::cmp::Ordering::Equal => parent,
            core::cmp::Ordering::Greater => {
                let delta =
                    parent * u128::from(parent_gas_used - target) / u128::from(target) / denominator;
                parent + delta.max(1)
            }
            core::cmp::Ordering::Less => {
                let delta =
                    parent * u128::from(target - parent_gas_used) / u128::from(target) / denominator;
                parent - delta
            }
        };
        u64::try_from(fee)
            .unwrap_or(u64::MAX)
            .max(self.min_base_fee)
    }
}

record! {
    /// What the `fees` query returns (spec 23 §7).
    FeeStatus {
        /// The parameters in force.
        params: FeeParams,
        /// The base fee of the next block.
        base_fee: u64,
        /// The reward pool: priority fees collected since the last epoch end
        /// (spec 15 §10), wei held by the staking address.
        pool: u128,
    }
}

/// Query method names.
pub mod query {
    /// `() -> FeeStatus`.
    pub const FEES: &str = "fees";
}

/// Storage keys of the fee market (spec 23 §6).
pub mod keys {
    /// `fees/params` → `FeeParams`, once `setFeeParams` ran.
    pub const PARAMS: &[u8] = b"fees/params";
}

/// The 256-bit product of two `u128`s as `(high, low)`.
const fn widening_mul(a: u128, b: u128) -> (u128, u128) {
    const MASK: u128 = u64::MAX as u128;
    let (a1, a0) = (a >> 64, a & MASK);
    let (b1, b0) = (b >> 64, b & MASK);
    let p00 = a0 * b0;
    let p01 = a0 * b1;
    let p10 = a1 * b0;
    let p11 = a1 * b1;
    let mid = (p00 >> 64) + (p01 & MASK) + (p10 & MASK);
    let low = (mid << 64) | (p00 & MASK);
    let high = p11 + (p01 >> 64) + (p10 >> 64) + (mid >> 64);
    (high, low)
}

/// `⌊a · b / c⌋` exactly, without the product overflowing: the arithmetic
/// of every pro rata share (spec 15 §10). `c` must be non-zero and the
/// quotient must fit a `u128`, which it does whenever `b ≤ c`.
///
/// # Panics
/// If `c` is zero.
#[must_use]
pub fn mul_div(a: u128, b: u128, c: u128) -> u128 {
    assert!(c != 0, "division by zero");
    let (high, low) = widening_mul(a, b);
    let mut remainder = 0u128;
    let mut quotient = 0u128;
    for i in (0..256).rev() {
        let bit = if i >= 128 {
            (high >> (i - 128)) & 1
        } else {
            (low >> i) & 1
        };
        // Twice the remainder plus the bit can pass 2^128; then it certainly
        // passes `c`, and its difference from `c` fits, so wrapping arithmetic
        // gives the right value.
        let overflow = remainder >> 127 != 0;
        let shifted = (remainder << 1) | bit;
        if overflow || shifted >= c {
            remainder = shifted.wrapping_sub(c);
            quotient = (quotient << 1) | 1;
        } else {
            remainder = shifted;
            quotient <<= 1;
        }
    }
    quotient
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip<T: Encode + Decode + PartialEq + core::fmt::Debug>(v: &T) {
        assert_eq!(&T::from_bytes(&v.to_bytes()).unwrap(), v);
    }

    const LIMIT: u64 = 30_000_000;

    #[test]
    fn records_and_constants() {
        let params = FeeParams {
            denominator: 100,
            elasticity: 4,
            min_base_fee: 7,
            treasury: [9; 20],
        };
        roundtrip(&params);
        roundtrip(&FeeStatus {
            params: params.clone(),
            base_fee: 8,
            pool: 1 << 100,
        });
        assert!(alloc::format!("{:?}", FeeStatus::default()).contains("FeeStatus"));
        assert_eq!(FEE_VAULT[18..], [0x46, 0x45]);
        assert!(FEE_VAULT[..18].iter().all(|b| *b == 0));
        assert_eq!(
            (MIN_DENOMINATOR, MAX_DENOMINATOR, MIN_ELASTICITY, MAX_ELASTICITY),
            (100, 125, 2, 4)
        );
        assert_eq!(
            FeeParams::production(),
            FeeParams {
                denominator: 125,
                elasticity: 2,
                min_base_fee: 1_000_000_000,
                treasury: [0; 20],
            }
        );
        assert_eq!(query::FEES, "fees");
        assert_eq!(keys::PARAMS, b"fees/params");
    }

    #[test]
    fn workable_parameters() {
        let with = |denominator, elasticity| FeeParams {
            denominator,
            elasticity,
            ..FeeParams::default()
        };
        assert!(FeeParams::default().workable());
        assert!(FeeParams::production().workable());
        assert!(with(100, 2).workable());
        assert!(with(125, 4).workable());
        assert!(!with(0, 2).workable(), "off needs both factors zero");
        assert!(!with(99, 2).workable());
        assert!(!with(126, 2).workable());
        assert!(!with(100, 1).workable());
        assert!(!with(100, 5).workable());
        assert!(!with(100, 0).workable());
        assert!(!FeeParams::default().market_on());
        assert!(with(100, 2).market_on());
        assert_eq!(FeeParams::default().gas_target(LIMIT), LIMIT);
        assert_eq!(with(100, 2).gas_target(LIMIT), 15_000_000);
        assert_eq!(with(100, 4).gas_target(LIMIT), 7_500_000);
    }

    #[test]
    fn the_base_fee_follows_eip_1559_above_the_floor() {
        let params = FeeParams {
            denominator: 125,
            elasticity: 2,
            min_base_fee: 1_000_000_000,
            treasury: [0; 20],
        };
        let gwei = 1_000_000_000u64;
        // A full block raises the fee by a denominator-th, an empty one lowers
        // it as much, a block at the target leaves it, and nothing goes below
        // the floor.
        assert_eq!(params.next_base_fee(gwei, LIMIT, LIMIT), gwei + gwei / 125);
        assert_eq!(params.next_base_fee(gwei, 15_000_000, LIMIT), gwei);
        assert_eq!(params.next_base_fee(gwei, 0, LIMIT), gwei);
        assert_eq!(params.next_base_fee(2 * gwei, 0, LIMIT), 2 * gwei - 2 * gwei / 125);
        assert_eq!(params.next_base_fee(0, 0, LIMIT), gwei, "the genesis parent");
        // Half way between target and limit: half the largest increase.
        assert_eq!(params.next_base_fee(gwei, 22_500_000, LIMIT), gwei + gwei / 250);
        // The increase is at least one wei, as in EIP-1559.
        let tiny = FeeParams {
            min_base_fee: 0,
            ..params.clone()
        };
        assert_eq!(tiny.next_base_fee(0, LIMIT, LIMIT), 1);
        assert_eq!(tiny.next_base_fee(1, LIMIT, LIMIT), 2);
        assert_eq!(tiny.next_base_fee(1, 0, LIMIT), 1, "and a decrease rounds down");
        assert_eq!(tiny.next_base_fee(0, 0, LIMIT), 0);
        // The fee saturates at the widest the header field holds.
        assert_eq!(tiny.next_base_fee(u64::MAX, LIMIT, LIMIT), u64::MAX);
        // Off: the floor, whatever the parent did.
        let off = FeeParams {
            min_base_fee: 5,
            ..FeeParams::default()
        };
        assert_eq!(off.next_base_fee(9, LIMIT, LIMIT), 5);
        assert_eq!(off.next_base_fee(9, 0, LIMIT), 5);
        assert_eq!(FeeParams::default().next_base_fee(9, LIMIT, LIMIT), 0);
    }

    #[test]
    fn mul_div_is_exact() {
        assert_eq!(mul_div(10, 3, 4), 7);
        assert_eq!(mul_div(0, 3, 4), 0);
        assert_eq!(mul_div(u128::MAX, u128::MAX, u128::MAX), u128::MAX);
        assert_eq!(mul_div(u128::MAX, 1, 2), u128::MAX / 2);
        assert_eq!(mul_div(u128::MAX, u128::MAX - 1, u128::MAX), u128::MAX - 1);
        // A product past 2^128 whose quotient fits: the pool times a weight over the total.
        let pool = 123_456_789_012_345_678_901_234_567_890u128;
        let (weight, total) = (u128::from(u64::MAX), 3 * u128::from(u64::MAX) + 17);
        let share = mul_div(pool, weight, total);
        // Checked by the identity a·b = q·c + r with 0 ≤ r < c, in wide arithmetic.
        let (ph, pl) = widening_mul(pool, weight);
        let (qh, ql) = widening_mul(share, total);
        let (rh, rl) = (ph - qh - u128::from(pl < ql), pl.wrapping_sub(ql));
        assert_eq!(rh, 0);
        assert!(rl < total);
        // Shares of a total add up to at most the pool, short of fewer than the parts.
        let shares: u128 = [5u128, 7, 11].iter().map(|w| mul_div(pool, *w, 23)).sum();
        assert!(pool - shares < 3);
        assert_eq!(widening_mul(1 << 100, 1 << 100), (1 << 72, 0));
    }

    #[test]
    #[should_panic(expected = "division by zero")]
    fn mul_div_refuses_a_zero_divisor() {
        let _ = mul_div(1, 1, 0);
    }
}
