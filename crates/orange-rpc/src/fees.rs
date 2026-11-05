//! The fee methods (spec 23 §7): `eth_gasPrice` and `eth_maxPriorityFeePerGas`
//! from a tip oracle that samples the last [`ORACLE_BLOCKS`] blocks as geth's
//! does, and `eth_feeHistory` with the base fee of every block and the
//! priority fees paid at the requested percentiles of its gas.

use std::collections::BTreeMap;

use orange_abi::chain::{BLOCK_GAS_LIMIT, Receipt};
use serde_json::{Value, json};

use crate::Rpc;
use crate::hex::{parse_quantity, quantity};
use crate::methods::{RpcError, param_str};

/// Most blocks one `eth_feeHistory` request reports, as in geth.
pub const MAX_FEE_HISTORY: u64 = 1024;

/// Blocks the tip oracle samples below the head: geth samples 20, which at
/// twelve-second blocks span four minutes; Orange's blocks are many times
/// shorter, so the oracle looks at 100 (spec 23 §7.1). It looks at up to
/// twice as many when the blocks it finds are empty.
pub const ORACLE_BLOCKS: u64 = 100;
/// The cheapest tips the oracle takes from each block (geth's `sampleNumber`).
pub const ORACLE_SAMPLE: usize = 3;
/// The percentile of the sample the oracle suggests (geth's default).
pub const ORACLE_PERCENTILE: usize = 60;
/// The most the oracle suggests: 500 gwei (geth's `MaxPrice`).
pub const ORACLE_MAX_TIP: u128 = 500_000_000_000;
/// Tips below this are left out of the sample (geth's `IgnorePrice`).
pub const ORACLE_IGNORE_TIP: u128 = 2;

/// The tip oracle's memory between requests.
#[derive(Default)]
pub(crate) struct Oracle {
    /// The head and the default tip the price was last computed for.
    at: Option<(u64, u128)>,
    /// The price last computed.
    price: u128,
    /// The tips sampled from each block, which never change once the
    /// block executed; the blocks a later head looks at again come from here.
    samples: BTreeMap<u64, Vec<u128>>,
}

/// `eth_feeHistory`'s block count: a quantity, a decimal string or a number.
fn block_count(value: Option<&Value>) -> Result<u64, RpcError> {
    let count = match value {
        Some(Value::String(s)) if s.starts_with("0x") => return parse_quantity(s),
        Some(Value::String(s)) => s.parse().ok(),
        Some(Value::Number(n)) => n.as_u64(),
        _ => None,
    };
    count.ok_or(RpcError::invalid_params("invalid block count"))
}

/// `eth_feeHistory`'s reward percentiles: increasing, within 0 to 100.
fn percentiles(value: Option<&Value>) -> Result<Vec<f64>, RpcError> {
    let invalid = || RpcError::invalid_params("invalid reward percentile");
    let list = match value {
        None | Some(Value::Null) => return Ok(Vec::new()),
        Some(Value::Array(list)) => list,
        Some(_) => return Err(invalid()),
    };
    let mut out: Vec<f64> = Vec::with_capacity(list.len());
    for p in list.iter().map(Value::as_f64) {
        match p {
            Some(p) if (0.0..=100.0).contains(&p) && out.last().is_none_or(|last| p > *last) => {
                out.push(p);
            }
            _ => return Err(invalid()),
        }
    }
    Ok(out)
}

/// The priority fees paid at each percentile of a block's gas, as geth
/// computes them: transactions sorted by the tip they paid over the
/// block's `base_fee`, weighted by gas used.
#[allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
fn rewards(receipts: &[Receipt], gas_used: u64, percentiles: &[f64], base_fee: u64) -> Vec<String> {
    let mut sorted: Vec<(u128, u64)> = receipts
        .iter()
        .map(|r| {
            let tip = r.effective_gas_price.saturating_sub(u128::from(base_fee));
            (tip, r.gas_used)
        })
        .collect();
    sorted.sort_by_key(|(tip, _)| *tip);
    let mut index = 0;
    let mut sum = sorted.first().map_or(0, |(_, gas)| *gas);
    let mut out = Vec::with_capacity(percentiles.len());
    for p in percentiles {
        // Gas amounts are far below 2^53, so the float arithmetic is exact
        // enough, and the threshold is non-negative and at most `gas_used`.
        let threshold = (gas_used as f64 * p / 100.0) as u64;
        while sum < threshold && index + 1 < sorted.len() {
            index += 1;
            sum += sorted[index].1;
        }
        out.push(quantity(sorted.get(index).map_or(0, |(tip, _)| *tip)));
    }
    out
}

impl Rpc {
    /// `eth_gasPrice`: the head block's base fee plus the suggested tip, as
    /// geth answers it.
    pub(crate) fn gas_price(&mut self) -> Result<u128, RpcError> {
        let head = self.block_number()?;
        let (header, _) = self.header_at(head)?.unwrap_or_default();
        Ok(u128::from(header.base_fee) + self.suggest_tip()?)
    }

    /// `eth_maxPriorityFeePerGas`: geth's suggestion (spec 23 §7.1). Of each
    /// of the last [`ORACLE_BLOCKS`] blocks it takes the [`ORACLE_SAMPLE`]
    /// cheapest tips paid, at least [`ORACLE_IGNORE_TIP`], by senders other
    /// than the beneficiary; a block without any counts the last suggestion
    /// once and makes the oracle look one block further, up to twice as
    /// many. The suggestion is the [`ORACLE_PERCENTILE`]th percentile of the
    /// sample, at most [`ORACLE_MAX_TIP`]; before any block it is
    /// [`Rpc::gas_price`], the default. It is computed once per head, and
    /// the node's background work runs between the blocks it reads.
    ///
    /// # Errors
    /// A node error while reading blocks or receipts.
    pub fn suggest_tip(&mut self) -> Result<u128, RpcError> {
        let head = self.block_number()?;
        let default = self.gas_price;
        if self.oracle.at == Some((head, default)) {
            return Ok(self.oracle.price);
        }
        // A new default starts the oracle over, as a fresh node's would.
        let last = match self.oracle.at {
            Some((_, d)) if d == default => self.oracle.price,
            _ => default,
        };
        let mut results = Vec::new();
        let mut number = head;
        let mut want = ORACLE_BLOCKS.min(head);
        let mut looked = 0;
        while looked < want && number > 0 {
            let mut values = self.block_tips(number)?;
            looked += 1;
            number -= 1;
            if values.is_empty() {
                values.push(last);
            }
            if values.len() == 1 && want < 2 * ORACLE_BLOCKS && number > 0 {
                want += 1;
            }
            results.extend(values);
        }
        let mut price = last;
        if !results.is_empty() {
            results.sort_unstable();
            price = results[(results.len() - 1) * ORACLE_PERCENTILE / 100];
        }
        price = price.min(ORACLE_MAX_TIP);
        self.oracle.at = Some((head, default));
        self.oracle.price = price;
        let keep = head.saturating_sub(2 * ORACLE_BLOCKS);
        self.oracle.samples = self.oracle.samples.split_off(&keep);
        Ok(price)
    }

    /// The oracle's sample of the block at `height`; from its memory when it
    /// read the block before.
    fn block_tips(&mut self, height: u64) -> Result<Vec<u128>, RpcError> {
        if let Some(values) = self.oracle.samples.get(&height) {
            return Ok(values.clone());
        }
        self.run_background();
        let (header, _) = self.header_at(height)?.unwrap_or_default();
        let base_fee = u128::from(header.base_fee);
        let mut tips: Vec<u128> = self
            .receipts_of(&header)?
            .iter()
            .filter(|r| r.from != header.beneficiary)
            .map(|r| r.effective_gas_price.saturating_sub(base_fee))
            .filter(|tip| *tip >= ORACLE_IGNORE_TIP)
            .collect();
        tips.sort_unstable();
        tips.truncate(ORACLE_SAMPLE);
        self.oracle.samples.insert(height, tips.clone());
        Ok(tips)
    }

    /// The base fee of the block after `height`: its header's, or, after
    /// the head, the one the kernel computed for the next block (spec 23 §3).
    fn base_fee_after(&mut self, height: u64) -> Result<u64, RpcError> {
        match self.header_at(height + 1)? {
            Some((header, _)) => Ok(header.base_fee),
            None => Ok(self.node().fee_status().base_fee),
        }
    }

    /// `eth_feeHistory(blockCount, newestBlock, rewardPercentiles)`.
    #[allow(clippy::cast_precision_loss)]
    pub(crate) fn fee_history(&mut self, params: &[Value]) -> Result<Value, RpcError> {
        let count = block_count(params.first())?;
        let newest = self.resolve_block(param_str(params, 1)?)?;
        let percentiles = percentiles(params.get(2))?;
        let head = self.block_number()?;
        if newest > head {
            return Err(RpcError::server(format!(
                "request beyond head block: requested {newest}, head {head}"
            )));
        }
        if count == 0 {
            return Ok(
                json!({ "oldestBlock": quantity(0), "baseFeePerGas": [], "gasUsedRatio": [] }),
            );
        }
        let count = count.min(MAX_FEE_HISTORY).min(newest + 1);
        let oldest = newest + 1 - count;
        let mut base_fees = Vec::new();
        let mut ratios = Vec::new();
        let mut reward = Vec::new();
        for height in oldest..=newest {
            self.run_background();
            let (header, _) = self.header_at(height)?.unwrap_or_default();
            base_fees.push(quantity(u128::from(header.base_fee)));
            // Gas amounts are far below 2^53: the ratio is exact enough.
            ratios.push(header.gas_used as f64 / BLOCK_GAS_LIMIT as f64);
            let receipts = self.receipts_of(&header)?;
            reward.push(rewards(
                &receipts,
                header.gas_used,
                &percentiles,
                header.base_fee,
            ));
        }
        // The base fee of the block after the newest, which its header decides.
        base_fees.push(quantity(u128::from(self.base_fee_after(newest)?)));
        let blocks = ratios.len();
        let mut history = json!({
            "oldestBlock": quantity(u128::from(oldest)),
            "baseFeePerGas": base_fees,
            "gasUsedRatio": ratios,
            "baseFeePerBlobGas": vec![quantity(0); blocks + 1],
            "blobGasUsedRatio": vec![0.0; blocks],
        });
        if !percentiles.is_empty() {
            history["reward"] = json!(reward);
        }
        Ok(history)
    }
}
