//! The validator lifecycle in chain state (spec 15): stake through the
//! staking address, delegation behind a validator, the validator set of
//! each epoch decided at the end of the one before, slashing on recorded
//! evidence, the reward pool that priority fees fill and each epoch end
//! pays out with stake (§10), and the chain-state half of the threshold
//! key: each epoch's DKG run, its messages, and the adoption of the key set
//! that more than two thirds of the stake confirm.

use alloc::vec;
use alloc::vec::Vec;

use solo_abi::chain::consensus::signing_preimage;
use solo_abi::chain::{
    Account, BLOCK_GAS_LIMIT, Evidence, Log, Validator, ValidatorSet, call_status, reason,
};
use solo_abi::codec::Seq;
use solo_abi::fees::mul_div;
use solo_abi::rotation::{HANDOFF_EPOCHS, REPORT_GAS, ThresholdEvidence};
use solo_abi::staking::{
    Delegation, DelegationEntry, DkgEnvelope, DkgRun, G1_LENGTH, G2_LENGTH, GWEI, KIND_DKG,
    KeySetRecord, KeySetVote, MAX_DELEGATIONS, MAX_DELEGATORS, MAX_DKG, MAX_REGISTERED, SLASH_BPS,
    STAKING_ADDRESS, StakeEntry, StakeRecord, StakingAction, StakingParams, StakingStatus,
    address_word, dkg_header, envelope, epoch_of, epoch_start, event, keys, query,
    session_preimage, stake_shares, view_epoch, word,
};
use solo_abi::types::{Address, Genesis, Hash, QueryResult};
use solo_abi::{Decode, Encode};
use solo_guest::host;

use crate::evm::{BlockFields, Message, Outcome};
use crate::tx::{self, Signed};
use crate::{fees, rotation, state};

/// The genesis staking parameters.
pub fn params() -> StakingParams {
    state::params().staking
}

fn concat(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

fn record_key(id: &Hash) -> Vec<u8> {
    concat(&[keys::RECORD, id])
}

fn set_key(epoch: u64) -> Vec<u8> {
    concat(&[keys::SET, &epoch.to_be_bytes()])
}

fn run_key(epoch: u64) -> Vec<u8> {
    concat(&[keys::RUN, &epoch.to_be_bytes()])
}

fn message_key(epoch: u64, phase: u8, index: u32) -> Vec<u8> {
    concat(&[
        keys::MESSAGE,
        &epoch.to_be_bytes(),
        &[phase],
        &index.to_be_bytes(),
    ])
}

fn vote_key(epoch: u64, id: &Hash) -> Vec<u8> {
    concat(&[keys::VOTE, &epoch.to_be_bytes(), id])
}

fn tally_key(epoch: u64, hash: &Hash) -> Vec<u8> {
    concat(&[keys::TALLY, &epoch.to_be_bytes(), hash])
}

fn key_set_key(id: u64) -> Vec<u8> {
    concat(&[keys::KEY_SET, &id.to_be_bytes()])
}

fn delegation_key(id: &Hash, delegator: &Address) -> Vec<u8> {
    concat(&[keys::DELEGATION, id, delegator])
}

fn delegators_key(id: &Hash) -> Vec<u8> {
    concat(&[keys::DELEGATORS, id])
}

fn delegated_to_key(delegator: &Address) -> Vec<u8> {
    concat(&[keys::DELEGATED_TO, delegator])
}

/// Whether staking is on: epochs exist, and with them the reward pool.
pub fn enabled() -> bool {
    params().epoch_blocks != 0
}

/// The reward pool (spec 15 §10.2): priority fees collected since the last
/// epoch end, held by the staking address.
pub fn pool() -> u128 {
    state::get(keys::POOL).unwrap_or(0)
}

fn set_pool(amount: u128) {
    if amount == 0 {
        state::delete(keys::POOL);
    } else {
        state::set(keys::POOL, &amount);
    }
}

/// Adds what a block's fee vault collected to the pool.
pub fn add_to_pool(amount: u128) {
    set_pool(pool() + amount);
}

/// `delegator`'s delegation behind validator `id`, if any.
pub fn delegation(id: &Hash, delegator: &Address) -> Option<Delegation> {
    state::get(&delegation_key(id, delegator))
}

/// A validator's delegators, in the order they first delegated.
fn delegators(id: &Hash) -> Vec<Address> {
    state::get::<Seq<Address>>(&delegators_key(id))
        .map(|s| s.0)
        .unwrap_or_default()
}

/// The validators an account delegates to, in the order it first did.
pub fn delegated_to(delegator: &Address) -> Vec<Hash> {
    state::get::<Seq<Hash>>(&delegated_to_key(delegator))
        .map(|s| s.0)
        .unwrap_or_default()
}

fn set_list<T: Encode + Clone>(key: &[u8], list: &[T]) {
    if list.is_empty() {
        state::delete(key);
    } else {
        state::set(key, &Seq(list.to_vec()));
    }
}

/// Stores a delegation, or removes it with its places in both lists once
/// it holds nothing.
fn put_delegation(id: &Hash, delegator: &Address, d: &Delegation) {
    if d.stake != 0 || d.unbonding != 0 {
        state::set(&delegation_key(id, delegator), d);
        return;
    }
    state::delete(&delegation_key(id, delegator));
    let rest: Vec<Address> = delegators(id)
        .into_iter()
        .filter(|a| a != delegator)
        .collect();
    set_list(&delegators_key(id), &rest);
    let rest: Vec<Hash> = delegated_to(delegator)
        .into_iter()
        .filter(|v| v != id)
        .collect();
    set_list(&delegated_to_key(delegator), &rest);
}

/// A registered validator's record.
pub fn record(id: &Hash) -> Option<StakeRecord> {
    state::get(&record_key(id))
}

fn put_record(id: &Hash, record: &StakeRecord) {
    state::set(&record_key(id), record);
}

/// Registered validator ids, in registration order.
fn ids() -> Vec<Hash> {
    state::get::<Seq<Hash>>(keys::IDS)
        .map(|s| s.0)
        .unwrap_or_default()
}

fn id_of(address: &Address) -> Option<Hash> {
    state::get(&concat(&[keys::BY_ADDRESS, address]))
}

/// The validator set of `epoch`, if decided. Without staking there is one
/// set, the genesis set, whatever the epoch.
pub fn set_of(epoch: u64) -> Option<ValidatorSet> {
    set_in(params().epoch_blocks, epoch)
}

/// [`set_of`] for a caller that already holds `epoch_blocks`.
fn set_in(epoch_blocks: u64, epoch: u64) -> Option<ValidatorSet> {
    if epoch_blocks == 0 {
        return state::get_raw(b"meta/validators").and_then(|b| ValidatorSet::from_bytes(&b).ok());
    }
    state::get(&set_key(epoch))
}

/// The validator set of `epoch` as ids and weights.
pub fn set_entries(epoch: u64) -> Option<Vec<(Hash, u64)>> {
    set_entries_in(params().epoch_blocks, epoch)
}

/// [`set_entries`] for a caller that already holds `epoch_blocks`.
pub fn set_entries_in(epoch_blocks: u64, epoch: u64) -> Option<Vec<(Hash, u64)>> {
    set_in(epoch_blocks, epoch).map(|s| {
        s.validators
            .0
            .into_iter()
            .map(|v| (v.id, v.weight))
            .collect()
    })
}

/// The DKG run of `epoch`, if one was scheduled.
pub fn dkg_run(epoch: u64) -> Option<DkgRun> {
    state::get(&run_key(epoch))
}

/// Whether chain state holds the DKG message of `index` in `phase` of `epoch`.
pub fn has_message(epoch: u64, phase: u8, index: u32) -> bool {
    state::get_raw(&message_key(epoch, phase, index)).is_some()
}

/// Whether validator `id` has confirmed a key set in `epoch`.
pub fn has_vote(epoch: u64, id: &Hash) -> bool {
    state::get_raw(&vote_key(epoch, id)).is_some()
}

/// The DKG messages of `run` recorded in the phases before `upto`, in phase
/// order and by sender within a phase.
pub fn transcript(run: &DkgRun, upto: u8) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for phase in 0..upto.min(3) {
        let senders = if phase == 1 {
            run.recipients.0.len()
        } else {
            run.dealers.0.len()
        };
        for index in 1..=senders as u32 {
            if let Some(m) = state::get_raw(&message_key(run.epoch, phase, index)) {
                out.push(m);
            }
        }
    }
    out
}

/// The key set with id `id`, if it was adopted.
pub fn key_set(id: u64) -> Option<KeySetRecord> {
    state::get(&key_set_key(id))
}

/// The key set validators sign with, if any.
pub fn active() -> Option<KeySetRecord> {
    state::get::<u64>(keys::ACTIVE).and_then(key_set)
}

/// The group public key, once the first key set is adopted.
pub fn group_key() -> Option<Vec<u8>> {
    state::get_raw(keys::GROUP_KEY)
}

/// The compressed G2 identity: `bls12381_pairing_check` with it beside a G1
/// point holds exactly when the point decodes and lies in the subgroup.
fn g2_identity() -> [u8; G2_LENGTH] {
    let mut out = [0u8; G2_LENGTH];
    out[0] = 0xC0;
    out
}

/// Whether `key` is a usable DKG encryption key: a compressed G1 point in
/// the prime-order subgroup other than the identity.
fn valid_key(key: &[u8]) -> bool {
    if key.len() != G1_LENGTH || key[0] & 0x40 != 0 {
        return false;
    }
    let mut pair = key.to_vec();
    pair.extend_from_slice(&g2_identity());
    // SAFETY: a valid pointer to one 144-byte pair.
    unsafe { host::__solo_import_bls12381_pairing_check(pair.as_ptr(), 1) == 0 }
}

fn address_of(id: &Hash) -> Address {
    id[12..].try_into().expect("20 bytes")
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

/// Genesis: every genesis validator is registered with its weight in gwei
/// as stake, the staking address holds that stake, epoch 0's set is the
/// genesis set and epoch 0's DKG run is scheduled. Traps on parameters that
/// cannot work: four DKG phases longer than an epoch, too many validators,
/// an encryption key that is not a point, or, with threshold keys, a key age
/// of zero or an unbonding period that does not outlast the key age and the
/// handoff latency (spec 15 §6.7).
pub fn init(genesis: &Genesis) {
    let p = params();
    if p.epoch_blocks == 0 {
        return;
    }
    if p.dkg_phase_blocks.saturating_mul(4) > p.epoch_blocks {
        solo_guest::trap();
    }
    if p.dkg_phase_blocks != 0
        && (p.max_key_age == 0
            || p.unbonding_epochs <= p.max_key_age.saturating_add(HANDOFF_EPOCHS))
    {
        solo_guest::trap();
    }
    let set = ValidatorSet::from_bytes(&genesis.validators).unwrap_or_else(|_| solo_guest::trap());
    if set.validators.0.len() > MAX_REGISTERED {
        solo_guest::trap();
    }
    if p.keys.0.iter().any(|k| !valid_key(&k.dkg_key)) {
        solo_guest::trap();
    }
    let mut total = 0u128;
    let mut registered = Vec::new();
    for v in &set.validators.0 {
        let dkg_key = p
            .keys
            .0
            .iter()
            .find(|k| k.id == v.id)
            .map(|k| k.dkg_key.clone())
            .unwrap_or_default();
        let stake = u128::from(v.weight) * GWEI;
        total += stake;
        let address = address_of(&v.id);
        put_record(
            &v.id,
            &StakeRecord {
                address,
                stake,
                dkg_key,
                ..StakeRecord::default()
            },
        );
        state::set(&concat(&[keys::BY_ADDRESS, &address]), &v.id);
        registered.push(v.id);
    }
    state::set(keys::IDS, &Seq(registered));
    credit(&STAKING_ADDRESS, total);
    state::set(&set_key(0), &set);
    if p.dkg_phase_blocks != 0 {
        schedule_run(0, &set);
    }
}

/// Gas limits of the staking transactions whose admission check in the
/// block being executed needed a pairing (spec 15 §3.3). Written during the
/// block and deleted at its end, so it is never part of a committed state.
const PAIRING_GAS: &[u8] = b"stake/pairing_gas";

/// Charges `s`'s gas limit to the block's pairing budget before an
/// admission check that needs a pairing; false, charging nothing, once the
/// budget would pass the block gas limit. Only execution charges (`charge`),
/// never admission or selection: a block built by the rules keeps the sum of
/// its gas limits within the block gas limit and never runs out, while a
/// leader who fills a proposal with transactions that fail such a check pays
/// for at most a block's worth of pairings.
fn spend(s: &Signed, charge: bool) -> bool {
    if !charge {
        return true;
    }
    let used: u64 = state::get(PAIRING_GAS).unwrap_or(0);
    let total = used.saturating_add(s.tx.gas_limit);
    if total > BLOCK_GAS_LIMIT {
        return false;
    }
    state::set(PAIRING_GAS, &total);
    true
}

/// Whether `delegator` has released undelegated stake behind `id` at `epoch`.
fn released_delegation(id: &Hash, delegator: &Address, epoch: u64) -> bool {
    delegation(id, delegator).is_some_and(|d| d.unbonding > 0 && epoch >= d.release_epoch)
}

/// The action a transaction to the staking address carries, with the
/// validator it acts for (the zero id for a `withdraw` of delegations
/// alone), if it can run in the block at `height`; `charge` when
/// executing, so a check that needs a pairing spends from the block's
/// pairing budget ([`spend`]).
fn action_of(s: &Signed, height: u64, charge: bool) -> Option<(StakingAction, Hash)> {
    let p = params();
    if p.epoch_blocks == 0 || s.tx.chain_id != Some(state::chain_id()) {
        return None;
    }
    let action = StakingAction::decode(&s.tx.input)?;
    let registered = id_of(&s.from).and_then(|id| record(&id).map(|r| (id, r)));
    let value = s.tx.value;
    let epoch = epoch_of(height, p.epoch_blocks);
    let id = match &action {
        StakingAction::Register { dkg_key } => {
            if !spend(s, charge) || !valid_key(dkg_key) {
                return None;
            }
            match registered {
                Some((_, r)) if r.jailed => return None,
                Some((id, _)) if value == 0 => id,
                Some(_) => return None,
                // A new validator bonds at least the stake selection needs, so a
                // registration slot is never free to take (spec 15 §3.3).
                None if value >= p.min_stake.max(GWEI)
                    && value % GWEI == 0
                    && ids().len() < MAX_REGISTERED =>
                {
                    let pubkey = tx::recover_pubkey(
                        &state::keccak256(&s.tx.signing_payload),
                        &s.tx.signature(),
                    )?;
                    state::keccak256(&pubkey)
                }
                None => return None,
            }
        }
        StakingAction::Bond => {
            let (id, r) = registered?;
            (!r.jailed && value > 0 && value % GWEI == 0).then_some(id)?
        }
        StakingAction::Unbond { amount } => {
            let (id, r) = registered?;
            (value == 0 && *amount > 0 && amount % GWEI == 0 && *amount <= r.stake).then_some(id)?
        }
        StakingAction::Withdraw => {
            // Released stake of its own, or behind any validator it delegates to.
            let own = registered
                .as_ref()
                .filter(|(_, r)| r.unbonding > 0 && epoch >= r.release_epoch)
                .map(|(id, _)| *id);
            let delegated = || {
                delegated_to(&s.from)
                    .iter()
                    .any(|v| released_delegation(v, &s.from, epoch))
                    .then_some([0; 32])
            };
            (value == 0).then(|| own.or_else(delegated))??
        }
        StakingAction::Delegate { validator } => {
            // Behind a registered validator that is not jailed, whole gwei, never
            // behind oneself (a validator bonds), within both bounds for a first
            // delegation (spec 15 §10.1).
            let id = id_of(validator)?;
            let r = record(&id)?;
            if r.jailed || s.from == *validator || value == 0 || value % GWEI != 0 {
                return None;
            }
            let first = delegation(&id, &s.from).is_none();
            if first
                && (delegators(&id).len() >= MAX_DELEGATORS
                    || delegated_to(&s.from).len() >= MAX_DELEGATIONS)
            {
                return None;
            }
            id
        }
        StakingAction::Undelegate { validator, amount } => {
            let id = id_of(validator)?;
            let d = delegation(&id, &s.from)?;
            (value == 0 && *amount > 0 && amount % GWEI == 0 && *amount <= d.stake).then_some(id)?
        }
        StakingAction::Report { evidence } => {
            if value != 0 || s.tx.gas_limit < s.tx.min_gas_limit().saturating_add(REPORT_GAS) {
                return None;
            }
            let evidence = ThresholdEvidence::from_bytes(evidence).ok()?;
            if rotation::on_record(&evidence) || !spend(s, charge) {
                return None;
            }
            rotation::offender(&evidence, height)?
        }
    };
    Some((action, id))
}

/// Admission: a transaction to the staking address must be able to run.
pub fn admit(s: &Signed) -> Result<(), u32> {
    let next = state::height().unwrap_or(0) + 1;
    if s.tx.to == Some(STAKING_ADDRESS) && action_of(s, next, false).is_none() {
        Err(reason::STAKING_ACTION)
    } else {
        Ok(())
    }
}

/// Whether `s` goes to the staking address.
pub fn is_staking(s: &Signed) -> bool {
    s.tx.to == Some(STAKING_ADDRESS)
}

/// Executes a transaction to the staking address: one that cannot run
/// changes nothing; one that can runs through the EVM as a plain call (gas,
/// fees, nonce, and for `bond` the value moving to the staking address),
/// then applies its action.
pub fn run(s: &Signed, height: u64, message: Message, block: BlockFields) -> Outcome {
    let Some((action, id)) = action_of(s, height, true) else {
        return Outcome {
            status: call_status::INVALID,
            gas_used: 0,
            output: Vec::new(),
            logs: Vec::new(),
            contract: None,
        };
    };
    let report = matches!(action, StakingAction::Report { .. });
    let mut outcome = crate::native::run(message, block, true);
    if outcome.status == call_status::SUCCESS {
        outcome.logs.extend(apply(action, &id, s, height, block));
        if report {
            outcome.gas_used += REPORT_GAS;
        }
    }
    outcome
}

fn log(topic: Hash, address: &Address, data: Vec<u8>) -> Log {
    Log {
        address: STAKING_ADDRESS,
        topics: Seq(vec![topic, address_word(address)]),
        data,
    }
}

/// A log with two indexed addresses: a delegator and a validator.
fn log2(topic: Hash, first: &Address, second: &Address, data: Vec<u8>) -> Log {
    Log {
        address: STAKING_ADDRESS,
        topics: Seq(vec![topic, address_word(first), address_word(second)]),
        data,
    }
}

/// Applies a `withdraw` (spec 15 §3.4, §10.1): every released amount, the
/// sender's own and its delegations', moves from the staking address to it.
fn withdraw(s: &Signed, epoch: u64) -> Vec<Log> {
    let mut total = 0u128;
    if let Some(id) = id_of(&s.from)
        && let Some(mut r) = record(&id)
        && r.unbonding > 0
        && epoch >= r.release_epoch
    {
        total += core::mem::take(&mut r.unbonding);
        put_record(&id, &r);
    }
    for id in delegated_to(&s.from) {
        if let Some(mut d) = delegation(&id, &s.from)
            && d.unbonding > 0
            && epoch >= d.release_epoch
        {
            total += core::mem::take(&mut d.unbonding);
            put_delegation(&id, &s.from, &d);
        }
    }
    debit(&STAKING_ADDRESS, total);
    credit(&s.from, total);
    vec![log(event::WITHDRAWN, &s.from, word(total).to_vec())]
}

/// Applies a `delegate` or `undelegate` to the delegation behind `id`.
fn delegate(action: &StakingAction, id: &Hash, s: &Signed, epoch: u64) -> Vec<Log> {
    let mut r = record(id).unwrap_or_default();
    let mut d = delegation(id, &s.from).unwrap_or_default();
    let logs = match action {
        StakingAction::Delegate { validator } => {
            if d == Delegation::default() {
                let mut list = delegators(id);
                list.push(s.from);
                set_list(&delegators_key(id), &list);
                let mut list = delegated_to(&s.from);
                list.push(*id);
                set_list(&delegated_to_key(&s.from), &list);
            }
            d.stake += s.tx.value;
            r.delegated += s.tx.value;
            vec![log2(
                event::DELEGATED,
                &s.from,
                validator,
                word(s.tx.value).to_vec(),
            )]
        }
        StakingAction::Undelegate { validator, amount } => {
            d.stake -= amount;
            d.unbonding += amount;
            d.release_epoch = epoch + 1 + params().unbonding_epochs;
            r.delegated -= amount;
            vec![log2(
                event::UNDELEGATED,
                &s.from,
                validator,
                [word(*amount), word(u128::from(d.release_epoch))].concat(),
            )]
        }
        _ => Vec::new(),
    };
    put_record(id, &r);
    put_delegation(id, &s.from, &d);
    logs
}

fn apply(
    action: StakingAction,
    id: &Hash,
    s: &Signed,
    height: u64,
    block: BlockFields,
) -> Vec<Log> {
    let p = params();
    let epoch = epoch_of(height, p.epoch_blocks);
    match &action {
        StakingAction::Report { evidence } => return report(evidence, id, s, block),
        StakingAction::Withdraw => return withdraw(s, epoch),
        StakingAction::Delegate { .. } | StakingAction::Undelegate { .. } => {
            return delegate(&action, id, s, epoch);
        }
        _ => {}
    }
    let mut r = record(id).unwrap_or_default();
    let logs = match action {
        StakingAction::Register { dkg_key } => {
            let mut logs = vec![log(event::REGISTERED, &s.from, id.to_vec())];
            if r.address == [0; 20] {
                let mut all = ids();
                all.push(*id);
                state::set(keys::IDS, &Seq(all));
                state::set(&concat(&[keys::BY_ADDRESS, &s.from]), id);
                r.address = s.from;
                r.stake = s.tx.value;
                logs.push(log(event::BONDED, &s.from, word(s.tx.value).to_vec()));
            }
            r.dkg_key = dkg_key;
            logs
        }
        StakingAction::Bond => {
            r.stake += s.tx.value;
            vec![log(event::BONDED, &s.from, word(s.tx.value).to_vec())]
        }
        StakingAction::Unbond { amount } => {
            r.stake -= amount;
            r.unbonding += amount;
            r.release_epoch = epoch + 1 + p.unbonding_epochs;
            vec![log(
                event::UNBONDED,
                &s.from,
                [word(amount), word(u128::from(r.release_epoch))].concat(),
            )]
        }
        _ => Vec::new(),
    };
    put_record(id, &r);
    logs
}

/// A `report` that can run (spec 15 §5.2): records the evidence and slashes
/// its offender `id`, and charges the sender `REPORT_GAS` on top of the
/// plain call, routed like every fee (spec 23 §4).
fn report(evidence: &[u8], id: &Hash, s: &Signed, block: BlockFields) -> Vec<Log> {
    let evidence = ThresholdEvidence::from_bytes(evidence).unwrap_or_default();
    rotation::put_evidence(&evidence, id);
    fees::pay_surcharge(s, REPORT_GAS, block);
    let address = record(id).map_or_else(|| address_of(id), |r| r.address);
    vec![log(
        event::REPORTED,
        &address,
        [
            word(u128::from(evidence.kind)),
            word(u128::from(evidence.key_set)),
        ]
        .concat(),
    )]
}

/// `x · SLASH_BPS / 10 000` without overflow.
fn cut(x: u128) -> u128 {
    x / 10_000 * SLASH_BPS + x % 10_000 * SLASH_BPS / 10_000
}

/// The slashing hook of spec 08 §9, called when a new offence is recorded:
/// burns `SLASH_BPS` of the offender's bonded and unbonding stake, and of
/// every delegation behind it (spec 15 §10.1), and jails it, so it is never
/// selected again. A jailed validator is not slashed again, whatever else
/// it signed. An offender whose record was pruned (§3.5) is jailed all the
/// same: its record comes back, jailed and empty, without a registration
/// slot, so it can never register again.
pub fn slash(evidence: &Evidence) {
    if params().epoch_blocks == 0 {
        return;
    }
    let Some(set) = set_of(view_epoch(evidence.view)) else {
        return;
    };
    let Some(v) = set.validators.0.get(evidence.validator as usize) else {
        return;
    };
    slash_id(&v.id);
}

/// Slashes and jails validator `id` unless it is jailed already: the
/// punishment of every recorded offence, equivocation (spec 08 §9) or
/// threshold misbehaviour (spec 15 §5.1).
pub fn slash_id(id: &Hash) {
    let mut r = record(id).unwrap_or_else(|| {
        let address = address_of(id);
        state::set(&concat(&[keys::BY_ADDRESS, &address]), id);
        StakeRecord {
            address,
            ..StakeRecord::default()
        }
    });
    if r.jailed {
        return;
    }
    let (from_stake, from_unbonding) = (cut(r.stake), cut(r.unbonding));
    r.stake -= from_stake;
    r.unbonding -= from_unbonding;
    r.jailed = true;
    let mut burned = from_stake + from_unbonding;
    for delegator in delegators(id) {
        let mut d = delegation(id, &delegator).unwrap_or_default();
        let (from_stake, from_unbonding) = (cut(d.stake), cut(d.unbonding));
        d.stake -= from_stake;
        d.unbonding -= from_unbonding;
        r.delegated -= from_stake;
        burned += from_stake + from_unbonding;
        put_delegation(id, &delegator, &d);
    }
    put_record(id, &r);
    debit(&STAKING_ADDRESS, burned);
    credit(&[0; 20], burned);
}

/// The ids, as a validator set orders them, that the set of `epoch` would
/// verify an evidence index against.
pub fn evidence_set(view: u64) -> Vec<Hash> {
    let blocks = params().epoch_blocks;
    let epoch = if blocks == 0 { 0 } else { view_epoch(view) };
    set_entries_in(blocks, epoch)
        .map(|s| s.into_iter().map(|(id, _)| id).collect())
        .unwrap_or_default()
}

/// The next set: registered validators that are not jailed and whose own
/// stake is at least the minimum stake (and one gwei), the `max_validators`
/// largest total stakes, own and delegated (earlier registration first on
/// a tie), in registration order, each weighted by its total stake in gwei.
/// `None` if nobody qualifies.
fn select(p: &StakingParams) -> Option<ValidatorSet> {
    let floor = p.min_stake.max(GWEI);
    let mut candidates: Vec<(usize, Hash, u128)> = ids()
        .into_iter()
        .enumerate()
        .filter_map(|(i, id)| {
            record(&id)
                .filter(|r| !r.jailed && r.stake >= floor)
                .map(|r| (i, id, r.stake + r.delegated))
        })
        .collect();
    candidates.sort_by(|a, b| b.2.cmp(&a.2).then(a.0.cmp(&b.0)));
    if p.max_validators != 0 {
        candidates.truncate(p.max_validators as usize);
    }
    candidates.sort_by_key(|c| c.0);
    let validators: Vec<Validator> = candidates
        .into_iter()
        .map(|(_, id, stake)| Validator {
            id,
            weight: u64::try_from(stake / GWEI).unwrap_or(u64::MAX),
        })
        .collect();
    (!validators.is_empty()).then_some(ValidatorSet {
        validators: Seq(validators),
    })
}

/// Schedules epoch `epoch`'s DKG run for `set`: always a fresh key among
/// the set (spec 15 §6.1), which the active key hands off to once it is
/// adopted. Shares follow stake: a member with an encryption key gets
/// `⌊w · 4n / W⌋` of them and the threshold is `⌊2 · 4n / 3⌋ + 1`, so any
/// threshold of shares belongs to more than two thirds of the set's weight
/// (spec 15 §6.8). The recipients, who are also the dealers, are the
/// members with a share; when they hold fewer shares than the threshold
/// there is no run.
fn schedule_run(epoch: u64, set: &ValidatorSet) {
    let records: Vec<Option<StakeRecord>> = set
        .validators
        .0
        .iter()
        .map(|v| record(&v.id).filter(|r| !r.dkg_key.is_empty()))
        .collect();
    let members: Vec<(u64, bool)> = set
        .validators
        .0
        .iter()
        .zip(&records)
        .map(|(v, r)| (v.weight, r.is_some()))
        .collect();
    let (counts, threshold) = stake_shares(&members);
    let mut recipients = Vec::new();
    let mut keys_of = Vec::new();
    let mut shares = Vec::new();
    for ((v, r), count) in set.validators.0.iter().zip(records).zip(counts) {
        if let (Some(r), 1..) = (r, count) {
            recipients.push(v.id);
            keys_of.push(r.dkg_key);
            shares.push(count);
        }
    }
    if shares.iter().sum::<u32>() < threshold {
        return;
    }
    let run = DkgRun {
        epoch,
        session: state::keccak256(&session_preimage(state::chain_id(), epoch)),
        threshold,
        dealers: Seq(recipients.clone()),
        recipients: Seq(recipients),
        keys: Seq(keys_of),
        previous: None,
        shares: Seq(shares),
    };
    state::set(&run_key(epoch), &run);
}

/// Frees the registration slots of validators that hold nothing: not
/// jailed, no stake, no unbonding stake, no delegation behind them, and not
/// in `next`, the set just decided. Their records go; they can register
/// again like anyone else.
fn prune(next: &ValidatorSet) {
    let all = ids();
    let before = all.len();
    let kept: Vec<Hash> = all
        .into_iter()
        .filter(|id| {
            let Some(r) = record(id) else { return false };
            let empty = !r.jailed
                && r.stake == 0
                && r.unbonding == 0
                && delegators(id).is_empty()
                && !next.validators.0.iter().any(|v| v.id == *id);
            if empty {
                state::delete(&record_key(id));
                state::delete(&concat(&[keys::BY_ADDRESS, &r.address]));
            }
            !empty
        })
        .collect();
    if kept.len() != before {
        state::set(keys::IDS, &Seq(kept));
    }
}

/// Pays the reward pool out to the set of epoch `epoch`, which is ending
/// (spec 15 §10.2): to its members that are not jailed, each share pro
/// rata to the member's weight among theirs, and within it each
/// delegator's to its bonded stake over the validator's total, the
/// validator keeping the rest. A member jailed during the epoch (every
/// slashed validator is) earns nothing, nor do its delegators: the others
/// share the pool. Every division rounds down and what rounding leaves
/// stays in the pool for the next epoch, so the credits and the pool
/// together always equal what was collected.
fn distribute(epoch: u64) {
    let pool = pool();
    if pool == 0 {
        return;
    }
    let Some(set) = set_of(epoch) else { return };
    let paid_to: Vec<(&Validator, StakeRecord)> = set
        .validators
        .0
        .iter()
        .filter_map(|v| match record(&v.id) {
            Some(r) if r.jailed => None,
            r => Some((v, r.unwrap_or_default())),
        })
        .collect();
    let total: u128 = paid_to.iter().map(|(v, _)| u128::from(v.weight)).sum();
    if total == 0 {
        return;
    }
    let mut paid = 0u128;
    for (v, r) in paid_to {
        let share = mul_div(pool, u128::from(v.weight), total);
        if share == 0 {
            continue;
        }
        let stakes = r.stake + r.delegated;
        let mut rest = share;
        if stakes != 0 {
            for delegator in delegators(&v.id) {
                let part = mul_div(
                    share,
                    delegation(&v.id, &delegator).unwrap_or_default().stake,
                    stakes,
                );
                if part != 0 {
                    credit(&delegator, part);
                    rest -= part;
                }
            }
        }
        if rest != 0 {
            let own = if r.address == [0; 20] {
                address_of(&v.id)
            } else {
                r.address
            };
            credit(&own, rest);
        }
        paid += share;
    }
    debit(&STAKING_ADDRESS, paid);
    set_pool(pool - paid);
}

/// Bookkeeping at the end of the block at `height`: at the end of epoch `e`
/// it pays out the reward pool to the set of `e`, then decides the set of
/// `e + 1` and schedules its DKG run.
pub fn end_block(height: u64) {
    state::delete(PAIRING_GAS);
    let p = params();
    if p.epoch_blocks == 0 || !height.is_multiple_of(p.epoch_blocks) {
        return;
    }
    let next = height / p.epoch_blocks;
    distribute(next - 1);
    let set = select(&p).or_else(|| set_of(next - 1)).unwrap_or_default();
    prune(&set);
    state::set(&set_key(next), &set);
    state::set_raw(b"meta/validators", &set.to_bytes());
    if p.dkg_phase_blocks != 0 {
        schedule_run(next, &set);
    }
}

/// Records the DKG envelopes a block carries (spec 15 §6.2): at most
/// `MAX_DKG`, each kept only when signed by the sender its message names,
/// for the current epoch's run and in its phase. Nothing here can make a
/// block invalid.
pub fn record_dkg(envelopes: &[Vec<u8>], height: u64) {
    let p = params();
    if p.epoch_blocks == 0 || p.dkg_phase_blocks == 0 || envelopes.is_empty() {
        return;
    }
    let epoch = epoch_of(height, p.epoch_blocks);
    let Some(run) = dkg_run(epoch) else { return };
    let phase = ((height - epoch_start(epoch, p.epoch_blocks)) / p.dkg_phase_blocks).min(3);
    let chain_id = state::chain_id();
    for raw in envelopes.iter().take(MAX_DKG) {
        let Ok(env) = DkgEnvelope::from_bytes(raw) else {
            continue;
        };
        if env.epoch != epoch {
            continue;
        }
        let body_hash = state::keccak256(&DkgEnvelope::signed_hash_preimage(env.kind, &env.body));
        let digest = state::keccak256(&signing_preimage(KIND_DKG, chain_id, epoch, &body_hash));
        let Some(pubkey) = tx::recover_pubkey(&digest, &env.signature.0) else {
            continue;
        };
        let signer = state::keccak256(&pubkey);
        match env.kind {
            envelope::MESSAGE => record_message(&run, &env.body, &signer, phase),
            envelope::CONFIRM if phase == 3 => confirm(&run, &env.body, &signer, height),
            envelope::HANDOFF => rotation::record_handoff(&env.body, height),
            envelope::EVIDENCE => rotation::record_evidence_body(&env.body, height),
            _ => {}
        }
    }
}

fn record_message(run: &DkgRun, body: &[u8], signer: &Hash, now: u64) {
    let Some((phase, session, index)) = dkg_header(body) else {
        return;
    };
    if session != run.session || u64::from(phase) != now {
        return;
    }
    let roster = if phase == 1 {
        &run.recipients.0
    } else {
        &run.dealers.0
    };
    if index == 0 || roster.get(index as usize - 1) != Some(signer) {
        return;
    }
    let k = message_key(run.epoch, phase, index);
    if state::get_raw(&k).is_none() {
        state::set_raw(&k, body);
    }
}

fn confirm(run: &DkgRun, body: &[u8], signer: &Hash, height: u64) {
    let epoch = run.epoch;
    if key_set(epoch).is_some() || has_vote(epoch, signer) {
        return;
    }
    let Ok(vote) = KeySetVote::from_bytes(body) else {
        return;
    };
    let Some(set) = set_of(epoch) else { return };
    let total: u128 = set.validators.0.iter().map(|v| u128::from(v.weight)).sum();
    let Some(weight) = set
        .validators
        .0
        .iter()
        .find(|v| v.id == *signer)
        .map(|v| u128::from(v.weight))
    else {
        return;
    };
    let hash = state::keccak256(body);
    state::set(&vote_key(epoch, signer), &hash);
    let k = tally_key(epoch, &hash);
    let tally = state::get::<u128>(&k).unwrap_or(0) + weight;
    state::set(&k, &tally);
    if tally * 3 > total * 2 {
        adopt(run, vote, height);
    }
}

/// Adopts a confirmed key set when its shape fits the run: one public key
/// share per share index. Share `x` is held by `shareholders[x − 1]`, each
/// recipient repeated once per share it holds. The first key set becomes
/// active at once; a later one waits for the active key to hand off to it
/// (spec 15 §6.6).
fn adopt(run: &DkgRun, vote: KeySetVote, height: u64) {
    let shareholders: Vec<Hash> = run
        .recipients
        .0
        .iter()
        .zip(&run.shares.0)
        .flat_map(|(id, &m)| core::iter::repeat_n(*id, m as usize))
        .collect();
    let shaped = vote.key_set.len() == run.threshold as usize * G2_LENGTH
        && vote.public_shares.0.len() == shareholders.len()
        && vote.public_shares.0.iter().all(|s| s.len() == G2_LENGTH);
    if !shaped {
        return;
    }
    let record = KeySetRecord {
        id: run.epoch,
        key_set: vote.key_set,
        public_shares: vote.public_shares,
        shareholders: Seq(shareholders),
    };
    state::set(&key_set_key(run.epoch), &record);
    rotation::adopted(&record, height);
}

fn status() -> StakingStatus {
    let mut p = params();
    p.keys = Seq(Vec::new());
    let epoch = if p.epoch_blocks == 0 {
        0
    } else {
        epoch_of(state::height().unwrap_or(0) + 1, p.epoch_blocks)
    };
    let records = ids()
        .into_iter()
        .filter_map(|id| record(&id).map(|record| StakeEntry { id, record }))
        .collect();
    StakingStatus {
        epoch,
        params: p,
        validators: set_of(epoch).unwrap_or_default(),
        records: Seq(records),
        active: active(),
        group_key: group_key().unwrap_or_default(),
        pool: pool(),
    }
}

/// The `staking_delegations` query: an account's delegations, in order.
fn delegations_of(delegator: &Address) -> Vec<DelegationEntry> {
    delegated_to(delegator)
        .into_iter()
        .filter_map(|validator| {
            delegation(&validator, delegator).map(|delegation| DelegationEntry {
                validator,
                delegation,
            })
        })
        .collect()
}

/// The staking queries; `None` for any other method.
pub fn query(method: &str, params: &[u8]) -> Option<QueryResult> {
    let ok = |body: Vec<u8>| QueryResult { status: 0, body };
    match method {
        query::STAKING => Some(ok(status().to_bytes())),
        query::STAKING_SET => Some(match u64::from_bytes(params) {
            Ok(epoch) => set_of(epoch).map_or(
                QueryResult {
                    status: 1,
                    body: Vec::new(),
                },
                |s| ok(s.to_bytes()),
            ),
            Err(_) => QueryResult {
                status: 2,
                body: Vec::new(),
            },
        }),
        query::DELEGATIONS => Some(match Address::from_bytes(params) {
            Ok(delegator) => ok(Seq(delegations_of(&delegator)).to_bytes()),
            Err(_) => QueryResult {
                status: 2,
                body: Vec::new(),
            },
        }),
        _ => None,
    }
}
