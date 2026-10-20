//! The validator lifecycle in chain state (spec 15): stake through the
//! staking address, the validator set of each epoch decided at the end of
//! the one before, slashing on recorded evidence, and the chain-state half
//! of the threshold key: each epoch's DKG run, its messages, and the
//! adoption of the key set that more than two thirds of the stake confirm.

use alloc::vec;
use alloc::vec::Vec;

use solo_abi::chain::consensus::signing_preimage;
use solo_abi::chain::{Account, Evidence, Log, Validator, ValidatorSet, call_status, reason};
use solo_abi::codec::Seq;
use solo_abi::staking::{
    DkgEnvelope, DkgRun, G1_LENGTH, G2_LENGTH, GWEI, KIND_DKG, KeySetRecord, KeySetVote, MAX_DKG, MAX_REGISTERED, SLASH_BPS, STAKING_ADDRESS,
    StakeEntry, StakeRecord, StakingAction, StakingParams, StakingStatus, dkg_header, dkg_threshold, envelope, epoch_of, epoch_start, event, keys,
    query, session_preimage, view_epoch, word,
};
use solo_abi::types::{Address, Genesis, Hash, QueryResult};
use solo_abi::{Decode, Encode};
use solo_guest::host;

use crate::evm::{self, BlockFields, Message, Outcome};
use crate::state;
use crate::tx::{self, Signed};

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
    concat(&[keys::MESSAGE, &epoch.to_be_bytes(), &[phase], &index.to_be_bytes()])
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

/// A registered validator's record.
pub fn record(id: &Hash) -> Option<StakeRecord> {
    state::get(&record_key(id))
}

fn put_record(id: &Hash, record: &StakeRecord) {
    state::set(&record_key(id), record);
}

/// Registered validator ids, in registration order.
fn ids() -> Vec<Hash> {
    state::get::<Seq<Hash>>(keys::IDS).map(|s| s.0).unwrap_or_default()
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
    set_in(epoch_blocks, epoch).map(|s| s.validators.0.into_iter().map(|v| (v.id, v.weight)).collect())
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
        let senders = if phase == 1 { run.recipients.0.len() } else { run.dealers.0.len() };
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
/// or an encryption key that is not a point.
pub fn init(genesis: &Genesis) {
    let p = params();
    if p.epoch_blocks == 0 {
        return;
    }
    if p.dkg_phase_blocks.saturating_mul(4) > p.epoch_blocks {
        solo_guest::trap();
    }
    let set = ValidatorSet::from_bytes(&genesis.validators).unwrap_or_else(|_| solo_guest::trap());
    if set.validators.0.len() > MAX_REGISTERED {
        solo_guest::trap();
    }
    let mut total = 0u128;
    let mut registered = Vec::new();
    for v in &set.validators.0 {
        let dkg_key = p.keys.0.iter().find(|k| k.id == v.id).map(|k| k.dkg_key.clone()).unwrap_or_default();
        if !dkg_key.is_empty() && !valid_key(&dkg_key) {
            solo_guest::trap();
        }
        let stake = u128::from(v.weight) * GWEI;
        total += stake;
        let address = address_of(&v.id);
        put_record(&v.id, &StakeRecord { address, stake, dkg_key, ..StakeRecord::default() });
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

/// The action a transaction to the staking address carries, with the
/// validator it acts for, if it can run in the block at `height`.
fn action_of(s: &Signed, height: u64) -> Option<(StakingAction, Hash)> {
    let p = params();
    if p.epoch_blocks == 0 || s.tx.chain_id != Some(state::chain_id()) {
        return None;
    }
    let action = StakingAction::decode(&s.tx.input)?;
    let registered = id_of(&s.from).and_then(|id| record(&id).map(|r| (id, r)));
    let value = s.tx.value;
    let id = match &action {
        StakingAction::Register { dkg_key } => {
            if value != 0 || !valid_key(dkg_key) {
                return None;
            }
            match registered {
                Some((_, r)) if r.jailed => return None,
                Some((id, _)) => id,
                None if ids().len() < MAX_REGISTERED => {
                    let pubkey = tx::recover_pubkey(&state::keccak256(&s.tx.signing_payload), &s.tx.signature())?;
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
            let (id, r) = registered?;
            (value == 0 && r.unbonding > 0 && epoch_of(height, p.epoch_blocks) >= r.release_epoch).then_some(id)?
        }
    };
    Some((action, id))
}

/// Admission: a transaction to the staking address must be able to run.
pub fn admit(s: &Signed) -> Result<(), u32> {
    let next = state::height().unwrap_or(0) + 1;
    if s.tx.to == Some(STAKING_ADDRESS) && action_of(s, next).is_none() { Err(reason::STAKING_ACTION) } else { Ok(()) }
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
    let Some((action, id)) = action_of(s, height) else {
        return Outcome { status: call_status::INVALID, gas_used: 0, output: Vec::new(), logs: Vec::new(), contract: None };
    };
    let mut outcome = evm::run(message, block, true);
    if outcome.status == call_status::SUCCESS {
        outcome.logs.push(apply(action, &id, s, height));
    }
    outcome
}

fn log(topic: Hash, address: &Address, data: Vec<u8>) -> Log {
    let mut indexed = [0u8; 32];
    indexed[12..].copy_from_slice(address);
    Log { address: STAKING_ADDRESS, topics: Seq(vec![topic, indexed]), data }
}

fn apply(action: StakingAction, id: &Hash, s: &Signed, height: u64) -> Log {
    let p = params();
    let mut r = record(id).unwrap_or_default();
    let log = match action {
        StakingAction::Register { dkg_key } => {
            if r.address == [0; 20] {
                let mut all = ids();
                all.push(*id);
                state::set(keys::IDS, &Seq(all));
                state::set(&concat(&[keys::BY_ADDRESS, &s.from]), id);
                r.address = s.from;
            }
            r.dkg_key = dkg_key;
            log(event::REGISTERED, &s.from, id.to_vec())
        }
        StakingAction::Bond => {
            r.stake += s.tx.value;
            log(event::BONDED, &s.from, word(s.tx.value).to_vec())
        }
        StakingAction::Unbond { amount } => {
            r.stake -= amount;
            r.unbonding += amount;
            r.release_epoch = epoch_of(height, p.epoch_blocks) + 1 + p.unbonding_epochs;
            log(event::UNBONDED, &s.from, [word(amount), word(u128::from(r.release_epoch))].concat())
        }
        StakingAction::Withdraw => {
            let amount = core::mem::take(&mut r.unbonding);
            debit(&STAKING_ADDRESS, amount);
            credit(&s.from, amount);
            log(event::WITHDRAWN, &s.from, word(amount).to_vec())
        }
    };
    put_record(id, &r);
    log
}

/// `x · SLASH_BPS / 10 000` without overflow.
fn cut(x: u128) -> u128 {
    x / 10_000 * SLASH_BPS + x % 10_000 * SLASH_BPS / 10_000
}

/// The slashing hook of spec 08 §9, called when a new offence is recorded:
/// burns `SLASH_BPS` of the offender's bonded and unbonding stake and jails
/// it, so it is never selected again. A jailed validator is not slashed
/// again, whatever else it signed.
pub fn slash(evidence: &Evidence) {
    if params().epoch_blocks == 0 {
        return;
    }
    let Some(set) = set_of(view_epoch(evidence.view)) else { return };
    let Some(v) = set.validators.0.get(evidence.validator as usize) else { return };
    let Some(mut r) = record(&v.id) else { return };
    if r.jailed {
        return;
    }
    let (from_stake, from_unbonding) = (cut(r.stake), cut(r.unbonding));
    r.stake -= from_stake;
    r.unbonding -= from_unbonding;
    r.jailed = true;
    put_record(&v.id, &r);
    debit(&STAKING_ADDRESS, from_stake + from_unbonding);
    credit(&[0; 20], from_stake + from_unbonding);
}

/// The ids, as a validator set orders them, that the set of `epoch` would
/// verify an evidence index against.
pub fn evidence_set(view: u64) -> Vec<Hash> {
    let blocks = params().epoch_blocks;
    let epoch = if blocks == 0 { 0 } else { view_epoch(view) };
    set_entries_in(blocks, epoch).map(|s| s.into_iter().map(|(id, _)| id).collect()).unwrap_or_default()
}

/// The next set: registered validators that are not jailed and hold at
/// least the minimum stake (and one gwei), the `max_validators` largest
/// stakes (earlier registration first on a tie), in registration order,
/// each weighted by its stake in gwei. `None` if nobody qualifies.
fn select(p: &StakingParams) -> Option<ValidatorSet> {
    let floor = p.min_stake.max(GWEI);
    let mut candidates: Vec<(usize, Hash, u128)> = ids()
        .into_iter()
        .enumerate()
        .filter_map(|(i, id)| record(&id).filter(|r| !r.jailed && r.stake >= floor).map(|r| (i, id, r.stake)))
        .collect();
    candidates.sort_by(|a, b| b.2.cmp(&a.2).then(a.0.cmp(&b.0)));
    if p.max_validators != 0 {
        candidates.truncate(p.max_validators as usize);
    }
    candidates.sort_by_key(|c| c.0);
    let validators: Vec<Validator> =
        candidates.into_iter().map(|(_, id, stake)| Validator { id, weight: u64::try_from(stake / GWEI).unwrap_or(u64::MAX) }).collect();
    (!validators.is_empty()).then_some(ValidatorSet { validators: Seq(validators) })
}

/// Schedules epoch `epoch`'s DKG run for `set`: a resharing of the active
/// key set when there is one, a fresh key otherwise. The recipients are the
/// members with an encryption key; with none there is no run.
fn schedule_run(epoch: u64, set: &ValidatorSet) {
    let mut recipients = Vec::new();
    let mut keys_of = Vec::new();
    for v in &set.validators.0 {
        if let Some(r) = record(&v.id)
            && !r.dkg_key.is_empty()
        {
            recipients.push(v.id);
            keys_of.push(r.dkg_key);
        }
    }
    if recipients.is_empty() {
        return;
    }
    let previous = active();
    let dealers = previous.as_ref().map_or_else(|| recipients.clone(), |k| k.shareholders.0.clone());
    let run = DkgRun {
        epoch,
        session: state::keccak256(&session_preimage(state::chain_id(), epoch)),
        threshold: dkg_threshold(recipients.len()) as u32,
        dealers: Seq(dealers),
        recipients: Seq(recipients),
        keys: Seq(keys_of),
        previous: previous.map(|k| k.id),
    };
    state::set(&run_key(epoch), &run);
}

/// Bookkeeping at the end of the block at `height`: at the end of epoch `e`
/// it decides the set of `e + 1` and schedules its DKG run.
pub fn end_block(height: u64) {
    let p = params();
    if p.epoch_blocks == 0 || !height.is_multiple_of(p.epoch_blocks) {
        return;
    }
    let next = height / p.epoch_blocks;
    let set = select(&p).or_else(|| set_of(next - 1)).unwrap_or_default();
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
        let Ok(env) = DkgEnvelope::from_bytes(raw) else { continue };
        if env.epoch != epoch {
            continue;
        }
        let body_hash = state::keccak256(&DkgEnvelope::signed_hash_preimage(env.kind, &env.body));
        let digest = state::keccak256(&signing_preimage(KIND_DKG, chain_id, epoch, &body_hash));
        let Some(pubkey) = tx::recover_pubkey(&digest, &env.signature.0) else { continue };
        let signer = state::keccak256(&pubkey);
        match env.kind {
            envelope::MESSAGE => record_message(&run, &env.body, &signer, phase),
            envelope::CONFIRM if phase == 3 => confirm(&run, &env.body, &signer),
            _ => {}
        }
    }
}

fn record_message(run: &DkgRun, body: &[u8], signer: &Hash, now: u64) {
    let Some((phase, session, index)) = dkg_header(body) else { return };
    if session != run.session || u64::from(phase) != now {
        return;
    }
    let roster = if phase == 1 { &run.recipients.0 } else { &run.dealers.0 };
    if index == 0 || roster.get(index as usize - 1) != Some(signer) {
        return;
    }
    let k = message_key(run.epoch, phase, index);
    if state::get_raw(&k).is_none() {
        state::set_raw(&k, body);
    }
}

fn confirm(run: &DkgRun, body: &[u8], signer: &Hash) {
    let epoch = run.epoch;
    if key_set(epoch).is_some() || has_vote(epoch, signer) {
        return;
    }
    let Ok(vote) = KeySetVote::from_bytes(body) else { return };
    let Some(set) = set_of(epoch) else { return };
    let total: u128 = set.validators.0.iter().map(|v| u128::from(v.weight)).sum();
    let Some(weight) = set.validators.0.iter().find(|v| v.id == *signer).map(|v| u128::from(v.weight)) else { return };
    let hash = state::keccak256(body);
    state::set(&vote_key(epoch, signer), &hash);
    let k = tally_key(epoch, &hash);
    let tally = state::get::<u128>(&k).unwrap_or(0) + weight;
    state::set(&k, &tally);
    if tally * 3 > total * 2 {
        adopt(run, vote);
    }
}

/// Adopts a confirmed key set when its shape fits the run and, for a
/// resharing, its group key is the one the chain already has.
fn adopt(run: &DkgRun, vote: KeySetVote) {
    let shaped = vote.key_set.len() == run.threshold as usize * G2_LENGTH
        && vote.public_shares.0.len() == run.recipients.0.len()
        && vote.public_shares.0.iter().all(|s| s.len() == G2_LENGTH);
    let group = &vote.key_set[..G2_LENGTH.min(vote.key_set.len())];
    if !shaped || group_key().is_some_and(|g| g != group) {
        return;
    }
    if group_key().is_none() {
        state::set_raw(keys::GROUP_KEY, group);
    }
    let record = KeySetRecord { id: run.epoch, key_set: vote.key_set, public_shares: vote.public_shares, shareholders: run.recipients.clone() };
    state::set(&key_set_key(run.epoch), &record);
    state::set(keys::ACTIVE, &run.epoch);
}

fn status() -> StakingStatus {
    let mut p = params();
    p.keys = Seq(Vec::new());
    let epoch = if p.epoch_blocks == 0 { 0 } else { epoch_of(state::height().unwrap_or(0) + 1, p.epoch_blocks) };
    let records = ids().into_iter().filter_map(|id| record(&id).map(|record| StakeEntry { id, record })).collect();
    StakingStatus {
        epoch,
        params: p,
        validators: set_of(epoch).unwrap_or_default(),
        records: Seq(records),
        active: active(),
        group_key: group_key().unwrap_or_default(),
    }
}

/// The staking queries; `None` for any other method.
pub fn query(method: &str, params: &[u8]) -> Option<QueryResult> {
    let ok = |body: Vec<u8>| QueryResult { status: 0, body };
    match method {
        query::STAKING => Some(ok(status().to_bytes())),
        query::STAKING_SET => Some(match u64::from_bytes(params) {
            Ok(epoch) => set_of(epoch).map_or(QueryResult { status: 1, body: Vec::new() }, |s| ok(s.to_bytes())),
            Err(_) => QueryResult { status: 2, body: Vec::new() },
        }),
        _ => None,
    }
}
