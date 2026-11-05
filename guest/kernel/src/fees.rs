//! The fee market (spec 23): the parameters in force, the base fee of the
//! next block from the head's header, where each part of a fee goes, and
//! the sweep of the fee vault into the reward pool at the end of a block.

use orange_abi::chain::{Account, BLOCK_GAS_LIMIT};
use orange_abi::fees::{FEE_VAULT, FeeParams, FeeStatus, keys};
use orange_abi::staking::STAKING_ADDRESS;
use orange_abi::types::Address;

use crate::evm::BlockFields;
use crate::state;
use crate::tx::Signed;

/// The parameters in force: as `setFeeParams` left them, else genesis's.
pub fn params() -> FeeParams {
    state::get(keys::PARAMS).unwrap_or_else(|| state::params().fees)
}

/// Genesis: traps on parameters that cannot work (spec 23 §2), so the
/// chain never starts with them.
pub fn init() {
    if !params().workable() {
        orange_guest::trap();
    }
}

/// Records new parameters, from the next block on; false, recording
/// nothing, for parameters that cannot work.
pub fn set_params(p: &FeeParams) -> bool {
    if !p.workable() {
        return false;
    }
    state::set(keys::PARAMS, p);
    true
}

/// The base fee of the block after the executed head (spec 23 §3): the
/// update from the head's base fee and gas used, or from the genesis, a
/// parent at the floor that used nothing.
pub fn next_base_fee() -> u64 {
    let p = params();
    let parent = state::height()
        .and_then(state::block_by_number)
        .map_or((p.min_base_fee, 0), |h| (h.base_fee, h.gas_used));
    p.next_base_fee(parent.0, parent.1, BLOCK_GAS_LIMIT)
}

/// The base fee of the executed head: what a call query sees as `BASEFEE`,
/// as geth's `eth_call` at `latest` does; the floor before the first block.
pub fn head_base_fee() -> u64 {
    state::height()
        .and_then(state::block_by_number)
        .map_or_else(|| params().min_base_fee, |h| h.base_fee)
}

/// The block beneficiary (spec 23 §4): the fee vault on a chain with
/// staking, whose balance the end of the block moves to the reward pool;
/// the zero address, where nobody spends, without.
pub fn beneficiary() -> Address {
    if crate::staking::enabled() {
        FEE_VAULT
    } else {
        [0; 20]
    }
}

fn credit(address: &Address, amount: u128) {
    let mut account: Account = state::account(address);
    account.balance += amount;
    state::set_account(address, &account);
}

fn debit(address: &Address, amount: u128) {
    let mut account: Account = state::account(address);
    account.balance -= amount;
    state::set_account(address, &account);
}

/// Charges the sender of `s` a surcharge of `gas` at the transaction's
/// effective price, as the EVM charges its gas: the priority part goes to
/// the beneficiary, the base part is burned, and [`route_base_fee`] then
/// credits the treasury, if any, for the transaction's whole gas.
pub fn pay_surcharge(s: &Signed, gas: u64, block: BlockFields) {
    let base_fee = u128::from(block.base_fee);
    let price = s.tx.effective_gas_price(base_fee).unwrap_or(base_fee);
    debit(&s.from, u128::from(gas) * price);
    let tip = u128::from(gas) * price.saturating_sub(base_fee);
    if tip != 0 {
        credit(&block.beneficiary, tip);
    }
}

/// The base fee of a transaction that used `gas_used` in `block`: credited
/// to the block's treasury, the one the parameters named when the block
/// began, else burned, which the EVM already did by crediting nobody.
pub fn route_base_fee(block: BlockFields, gas_used: u64) {
    if block.treasury != [0; 20] && block.base_fee != 0 && gas_used != 0 {
        credit(
            &block.treasury,
            u128::from(gas_used) * u128::from(block.base_fee),
        );
    }
}

/// The end of a block on a chain with staking: what the fee vault collected
/// moves to the staking address and the reward pool (spec 15 §10.2). The
/// vault holds nothing but a balance, so it leaves state until the next
/// block pays it again.
pub fn sweep() {
    if !crate::staking::enabled() {
        return;
    }
    let amount = state::account(&FEE_VAULT).balance;
    if amount == 0 {
        return;
    }
    state::delete(&state::account_key(&FEE_VAULT));
    credit(&STAKING_ADDRESS, amount);
    crate::staking::add_to_pool(amount);
}

/// The `fees` query (spec 23 §7).
pub fn status() -> FeeStatus {
    FeeStatus {
        params: params(),
        base_fee: next_base_fee(),
        pool: crate::staking::pool(),
    }
}
