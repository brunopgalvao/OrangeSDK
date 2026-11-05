//! Governance (spec 13): kernel upgrades and host feature-gate signalling
//! through the governance address, module installs through the module
//! address, and the two tracks that authorize them (§9). Under the *key*
//! track the genesis governance key acts alone and at once; under the
//! *stake* track validators vote on proposals weighed by stake, a passed
//! proposal waits out a timelock during which the guardian may veto it, and
//! anyone executes it. Delegators vote beside validators, each vote carrying
//! the bonded stake behind it at the tally, and a proposal may carry a call
//! the governance address makes to any account. Also the bookkeeping at the
//! end of every block, the queries, and this kernel's version and migration
//! rule (spec 06 §7).

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;

use orange_abi::bridge_in::{LIGHT_CLIENT_ADDRESS, VERIFIER_ADDRESS};
use orange_abi::chain::{Account, Log, UpgradeParams, ValidatorSet, call_status, reason};
use orange_abi::codec::Seq;
use orange_abi::governance::{
    self as gov, ACTION_GAS, Ballot, BallotEntry, Call, DelegatorBallot, Execution,
    GOVERNANCE_ADDRESS, GOVERNANCE_GAS, GovernanceParams, GovernanceStatus, MAX_CALL_GAS,
    MAX_OPEN_PROPOSALS, Member, Moved, OpenProposal, Proposal, ProposalView, SWEEP_BALLOTS, Sweep,
    mode, status,
};
use orange_abi::modules::{Install, MODULE_ADDRESS};
use orange_abi::staking::GWEI;
use orange_abi::types::{Address, Genesis, Hash, MigrateArgs, QueryResult};
use orange_abi::{Decode, Encode};
use orange_ethlc::abi as lcabi;
use orange_upgrade::action::{cancelled_log, proposed_log};
use orange_upgrade::gates::{ended_epoch, epoch_of};
use orange_upgrade::{
    Action, EnactedUpgrade, GateBook, MAX_CHUNKS, PendingUpgrade, Signal, UpgradeStatus,
    ValidatorSignal, keys, query,
};

use crate::evm::{BlockFields, Message, Outcome};
use crate::state;
use crate::tx::Signed;

/// This kernel's version (spec 06 §7.1). The `upgrade-test` build reports the
/// next version, so tests can upgrade a running chain to a kernel that differs.
#[cfg(not(feature = "upgrade-test"))]
pub const KERNEL_VERSION: u32 = 1;
/// This kernel's version (spec 06 §7.1), as built for the upgrade tests.
#[cfg(feature = "upgrade-test")]
pub const KERNEL_VERSION: u32 = 2;

fn params() -> UpgradeParams {
    state::params().upgrades
}

/// The governance key of spec 13 §9.1: the one account under the key
/// track, the guardian's default under the stake track; zero for none.
fn key() -> Address {
    params().governance
}

/// The governance mode: as a `setMode` left it, else as genesis set it.
pub fn mode() -> u8 {
    state::get(gov::keys::MODE).unwrap_or_else(|| state::params().governance.mode)
}

/// The proposal rules in force, as a `setParams` left them, else genesis's,
/// under the mode in force.
fn rules() -> GovernanceParams {
    GovernanceParams {
        mode: mode(),
        ..state::get(gov::keys::PARAMS).unwrap_or_else(|| state::params().governance)
    }
}

/// The guardian under the stake track: the account a `setGuardian` named,
/// else the governance key; zero for none. Nobody under the key track.
fn guardian() -> Address {
    if mode() != mode::STAKE {
        return [0; 20];
    }
    state::get(gov::keys::GUARDIAN).unwrap_or_else(key)
}

/// The account on whose behalf the kernel calls a governed bridge module
/// (spec 18 §5): the key under the key track, the governance address under
/// the stake track. It is what the modules' configuration names.
pub fn authority() -> Address {
    if mode() == mode::STAKE {
        GOVERNANCE_ADDRESS
    } else {
        key()
    }
}

/// Whether `from` is the key acting under the key track.
fn key_acts(from: &Address) -> bool {
    let key = key();
    mode() == mode::KEY && key != [0; 20] && *from == key
}

/// Whether proposal rules can work under the stake track (spec 13 §9.1):
/// a voting period, and a quorum that is neither nothing (then a single
/// vote decides and no deposit is ever forfeited) nor more than the whole.
fn workable(voting_blocks: u64, quorum_bps: u64) -> bool {
    voting_blocks != 0 && (1..=10_000).contains(&quorum_bps)
}

/// Genesis (spec 13 §9.1): traps on parameters that cannot work, so the
/// chain never starts with them: an unknown mode, a quorum above the whole,
/// or the stake track with rules that are not workable.
pub fn init(genesis: &Genesis) {
    let Ok(params) = orange_abi::chain::GenesisParams::from_bytes(&genesis.params) else {
        orange_guest::trap()
    };
    let g = &params.governance;
    if g.mode > mode::STAKE
        || g.quorum_bps > 10_000
        || (g.mode == mode::STAKE && !workable(g.voting_blocks, g.quorum_bps))
    {
        orange_guest::trap();
    }
}

/// Validator ids and weights, in validator-set order.
fn validators() -> Vec<(Hash, u64)> {
    state::get_raw(b"meta/validators")
        .and_then(|b| ValidatorSet::from_bytes(&b).ok())
        .map(|set| {
            set.validators
                .0
                .into_iter()
                .map(|v| (v.id, v.weight))
                .collect()
        })
        .unwrap_or_default()
}

/// The validator whose consensus key controls `address`, with its weight: a
/// validator id is the hash an Ethereum address is the last 20 bytes of.
fn validator_of(address: &Address) -> Option<(Hash, u64)> {
    validators()
        .into_iter()
        .find(|(id, _)| id[12..] == address[..])
}

fn pending() -> Option<PendingUpgrade> {
    state::get(keys::PENDING)
}

/// Whether `code_hash` is the code of a kernel this chain has switched to:
/// its staged code stays as it is for good (spec 13 §5).
fn enacted(code_hash: &Hash) -> bool {
    state::get_raw(&keys::kernel(code_hash)).is_some()
}

fn book() -> GateBook {
    state::get(keys::BOOK).unwrap_or_default()
}

/// Whether feature gate `gate` is active for the block at `height` (spec 13 §8.4).
pub fn gate_active(gate: u8, height: u64) -> bool {
    book().active_at(height) >> gate & 1 == 1
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

// ---- Proposals in state ----

fn open() -> Vec<OpenProposal> {
    state::get::<Seq<OpenProposal>>(gov::keys::OPEN)
        .map(|s| s.0)
        .unwrap_or_default()
}

/// Stores `list` under `key`, or deletes the key when it is empty.
fn put_list<T: Encode + Clone>(key: &[u8], list: &[T]) {
    if list.is_empty() {
        state::delete(key);
    } else {
        state::set(key, &Seq(list.to_vec()));
    }
}

fn set_open(list: &[OpenProposal]) {
    put_list(gov::keys::OPEN, list);
}

/// An open proposal by id.
fn proposal(id: u64) -> Option<Proposal> {
    state::get(&gov::keys::proposal(id))
}

fn put_proposal(p: &Proposal) {
    state::set(&gov::keys::proposal(p.id), p);
}

fn vote_of(id: u64, validator: &Hash) -> Option<bool> {
    state::get(&gov::keys::vote(id, validator))
}

fn voters(id: u64) -> Vec<Hash> {
    state::get::<Seq<Hash>>(&gov::keys::voters(id))
        .map(|s| s.0)
        .unwrap_or_default()
}

fn gwei(wei: u128) -> u64 {
    u64::try_from(wei / GWEI).unwrap_or(u64::MAX)
}

/// The members of the current validator set whose stake counts in a tally,
/// with their weights now (spec 13 §9.3): with staking, each member whose
/// record is there and not jailed, weighing its own and its delegators'
/// bonded stake in gwei; without, every member at its weight in the set.
fn members() -> Vec<(Hash, u64)> {
    let set = validators();
    if !crate::staking::enabled() {
        return set;
    }
    set.into_iter()
        .filter_map(|(id, _)| {
            let r = crate::staking::record(&id).filter(|r| !r.jailed)?;
            Some((id, gwei(r.stake.saturating_add(r.delegated))))
        })
        .collect()
}

/// Positions of `members` by validator id.
fn positions(members: &[(Hash, u64)]) -> BTreeMap<Hash, usize> {
    members
        .iter()
        .enumerate()
        .map(|(i, (id, _))| (*id, i))
        .collect()
}

/// `delegator`'s bonded stake, in gwei, behind each member that counts, by
/// the member's position.
fn behind(delegator: &Address, at: &BTreeMap<Hash, usize>) -> Vec<(usize, u64)> {
    crate::staking::delegated_to(delegator)
        .into_iter()
        .filter_map(|v| {
            let i = *at.get(&v)?;
            let w = gwei(crate::staking::delegation(&v, delegator)?.stake);
            (w != 0).then_some((i, w))
        })
        .collect()
}

fn ballot_count(id: u64) -> u32 {
    state::get(&gov::keys::ballots(id)).unwrap_or(0)
}

/// Where `delegator`'s vote on `id` is kept, if it voted.
fn ballot_index(id: u64, delegator: &Address) -> Option<u32> {
    state::get(&gov::keys::ballot(id, delegator))
}

/// The delegators that voted on `id`, in the order they first did, with their votes.
fn ballots(id: u64) -> Vec<(Address, bool)> {
    (0..ballot_count(id))
        .filter_map(|i| state::get::<BallotEntry>(&gov::keys::ballot_at(id, i)))
        .map(|b| (b.delegator, b.support))
        .collect()
}

/// A live tally of `id` with what went into it.
struct Count {
    members: Vec<(Hash, u64)>,
    votes: Vec<Option<bool>>,
    ballots: Vec<(Address, bool)>,
    tally: gov::Tally,
}

/// The tally of `id` now (spec 13 §9.3): the members that count, each
/// validator's vote carrying its member's stake less what its voting
/// delegators took with them, each delegator's vote its bonded stake
/// behind members that count.
fn count(id: u64) -> Count {
    let members = members();
    let at = positions(&members);
    let votes: Vec<Option<bool>> = members.iter().map(|(v, _)| vote_of(id, v)).collect();
    let ballots = ballots(id);
    let list: Vec<Member> = members
        .iter()
        .zip(&votes)
        .map(|((_, weight), vote)| Member {
            weight: *weight,
            vote: *vote,
        })
        .collect();
    let delegators: Vec<gov::Delegator> = ballots
        .iter()
        .map(|(a, support)| gov::Delegator {
            support: *support,
            behind: behind(a, &at),
        })
        .collect();
    Count {
        tally: gov::tally(&list, &delegators),
        members,
        votes,
        ballots,
    }
}

/// The running sums of proposal `id` behind `validator` (spec 13 §9.3).
fn moved(id: u64, validator: &Hash) -> Moved {
    state::get(&gov::keys::moved(id, validator)).unwrap_or_default()
}

/// Replaces `old` gwei with `new` in the sums of proposal `id` behind
/// `validator` on the side `support` names.
fn shift(id: u64, validator: &Hash, support: bool, old: u64, new: u64) {
    let mut m = moved(id, validator);
    m.shift(support, old, new);
    let key = gov::keys::moved(id, validator);
    if m == Moved::default() {
        state::delete(&key);
    } else {
        state::set(&key, &m);
    }
}

/// The staking hook of spec 13 §9.3: `delegator`'s bonded stake behind
/// `validator` changed from `old` to `new` wei (a `delegate` or an
/// `undelegate`), so the running sums of every open proposal it voted on
/// move with it. At most `MAX_OPEN_PROPOSALS` proposals, each one read of
/// where the vote is, and for a vote its entry and its sums.
pub fn delegation_changed(validator: &Hash, delegator: &Address, old: u128, new: u128) {
    let (old, new) = (gwei(old), gwei(new));
    for o in open() {
        if let Some(i) = ballot_index(o.id, delegator)
            && let Some(b) = state::get::<BallotEntry>(&gov::keys::ballot_at(o.id, i))
        {
            shift(o.id, validator, b.support, old, new);
        }
    }
}

/// The tally of `id` from its running sums (spec 13 §9.3): one vote and one
/// sum per member of `members`, whatever the number of delegators' votes.
/// Equal to [`count`]'s from scratch.
fn tally_with(id: u64, members: &[(Hash, u64)]) -> (u64, u64, u64) {
    let staking = crate::staking::enabled();
    let list: Vec<(Member, Moved)> = members
        .iter()
        .map(|(v, weight)| {
            let m = Member {
                weight: *weight,
                vote: vote_of(id, v),
            };
            (
                m,
                if staking {
                    moved(id, v)
                } else {
                    Moved::default()
                },
            )
        })
        .collect();
    gov::running_tally(&list)
}

/// Moves `id`'s entry in the open list to `due`.
fn set_due(id: u64, due: u64) {
    let list: Vec<OpenProposal> = open()
        .into_iter()
        .map(|o| {
            if o.id == id {
                OpenProposal { id, due }
            } else {
                o
            }
        })
        .collect();
    set_open(&list);
}

/// Removes proposal `p` from state with its validators' votes and its
/// running sums, hands its delegators' votes to the sweep (spec 13 §9.3),
/// and settles its deposit: back to the proposer when `refund`, else to the
/// zero address, where fees go and nobody can spend it.
fn prune(p: &Proposal, refund: bool) {
    for validator in voters(p.id) {
        state::delete(&gov::keys::vote(p.id, &validator));
    }
    state::delete(&gov::keys::voters(p.id));
    // Sums are kept only behind registered validators: a delegation needs
    // one, and a record with delegations behind it, or jailed, stays.
    for validator in crate::staking::ids() {
        state::delete(&gov::keys::moved(p.id, &validator));
    }
    let end = ballot_count(p.id);
    if end != 0 {
        let mut list = sweeps();
        list.push(Sweep {
            id: p.id,
            next: 0,
            end,
        });
        put_list(gov::keys::SWEEP, &list);
        state::delete(&gov::keys::ballots(p.id));
    }
    state::delete(&gov::keys::proposal(p.id));
    let rest: Vec<OpenProposal> = open().into_iter().filter(|o| o.id != p.id).collect();
    set_open(&rest);
    if p.deposit > 0 {
        debit(&GOVERNANCE_ADDRESS, p.deposit);
        credit(if refund { &p.proposer } else { &[0; 20] }, p.deposit);
    }
}

fn sweeps() -> Vec<Sweep> {
    state::get::<Seq<Sweep>>(gov::keys::SWEEP)
        .map(|s| s.0)
        .unwrap_or_default()
}

/// Deletes up to [`SWEEP_BALLOTS`] delegators' votes of pruned proposals,
/// oldest first (spec 13 §9.3): a pruned proposal's votes are no longer
/// read, and leave state at this pace, which outruns what a block can cast.
fn sweep() {
    let mut list = sweeps();
    if list.is_empty() {
        return;
    }
    let mut budget = SWEEP_BALLOTS;
    while budget != 0
        && let Some(s) = list.first_mut()
    {
        let upto = s.end.min(s.next.saturating_add(budget));
        for i in s.next..upto {
            let key = gov::keys::ballot_at(s.id, i);
            if let Some(b) = state::get::<BallotEntry>(&key) {
                state::delete(&gov::keys::ballot(s.id, &b.delegator));
            }
            state::delete(&key);
        }
        budget -= upto - s.next;
        s.next = upto;
        if s.next == s.end {
            list.remove(0);
        }
    }
    put_list(gov::keys::SWEEP, &list);
}

/// Records where proposal `id` was executed, in block `height`, at its end
/// (`system`) or by an `execute` transaction (spec 13 §9.7).
fn record_execution(id: u64, height: u64, system: bool) {
    state::set(&gov::keys::executed(id), &Execution { height, system });
}

/// Records the tally of a proposal whose voting ended: passed, it waits for
/// its timelock; otherwise it is pruned, its deposit returned only if the
/// vote reached quorum.
fn close_voting(mut p: Proposal, members: &[(Hash, u64)]) {
    let (yes, no, total) = tally_with(p.id, members);
    let rules = rules();
    if !p.fast_track && gov::passes(yes, no, total, rules.quorum_bps) {
        p.status = status::PASSED;
        (p.yes, p.no, p.total) = (yes, no, total);
        put_proposal(&p);
        set_due(p.id, p.expires_at);
    } else {
        prune(&p, gov::quorum(yes, no, total, rules.quorum_bps));
    }
}

// ---- What an action is ----

/// A proposable action's track.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Track {
    /// Voting, a timelock, then `execute`.
    Normal,
    /// A safety action: a majority of all stake passes and executes it at once.
    Fast,
}

/// The track of the action `data` to `target`, if it is one a proposal may
/// carry (spec 13 §9.2); `switch`, the key track, admits `setMode`, which
/// only the key proposes, and refuses `reject`, which needs proposals.
fn track_of(target: &Address, data: &[u8], switch: bool) -> Option<Track> {
    let selector = data.get(..4)?;
    match *target {
        GOVERNANCE_ADDRESS => match Action::decode(data) {
            Some(Action::Propose { .. }) => Some(Track::Normal),
            Some(Action::Cancel { .. }) => Some(Track::Fast),
            Some(_) => None,
            None => match Call::decode(data)? {
                Call::SetGuardian { .. } | Call::SetParams { .. } | Call::SetFeeParams { .. } => {
                    Some(Track::Normal)
                }
                Call::SetMode { .. } if switch => Some(Track::Normal),
                Call::Reject { .. } if !switch => Some(Track::Fast),
                _ => None,
            },
        },
        MODULE_ADDRESS => Install::decode(data).map(|_| Track::Normal),
        LIGHT_CLIENT_ADDRESS
            if selector == lcabi::SET_CHECKPOINT || selector == lcabi::SET_DELAY =>
        {
            Some(Track::Normal)
        }
        VERIFIER_ADDRESS if selector == lcabi::PAUSE => Some(Track::Fast),
        VERIFIER_ADDRESS if selector == lcabi::UNPAUSE || selector == lcabi::SET_RATE_LIMIT => {
            Some(Track::Normal)
        }
        _ => None,
    }
}

/// Applies the governance action `data` to `target` in `block` (spec 13
/// §9.5), as a passed proposal, the key or the guardian does; `None` if its
/// checks fail, in which case nothing changed. `stager` is the account
/// whose upload a `propose` or an `install` uses: the proposal's proposer,
/// or the key (spec 13 §3).
fn apply_action(
    target: &Address,
    data: &[u8],
    stager: &Address,
    block: BlockFields,
) -> Option<Vec<Log>> {
    let height = block.number;
    match *target {
        GOVERNANCE_ADDRESS => match Action::decode(data) {
            Some(action @ (Action::Propose { .. } | Action::Cancel { .. })) => {
                apply_upgrade(action, stager, height)
            }
            Some(_) => None,
            None => match Call::decode(data)? {
                Call::SetGuardian { guardian } => {
                    state::set(gov::keys::GUARDIAN, &guardian);
                    Some(vec![gov::guardian_log(&guardian)])
                }
                Call::SetMode { mode: m } => switch_to_stake(m),
                Call::SetParams {
                    voting_blocks,
                    timelock_blocks,
                    quorum_bps,
                    deposit,
                } => {
                    if !workable(voting_blocks, quorum_bps) {
                        return None;
                    }
                    let rules = GovernanceParams {
                        mode: mode(),
                        voting_blocks,
                        timelock_blocks,
                        quorum_bps,
                        deposit,
                    };
                    state::set(gov::keys::PARAMS, &rules);
                    Some(vec![gov::params_log(&rules)])
                }
                // The fee market's parameters, from the next block on (spec 23 §5).
                Call::SetFeeParams { params } => {
                    crate::fees::set_params(&params).then(|| vec![gov::fee_params_log(&params)])
                }
                // Withdraws a normal-track proposal before it executes, its
                // deposit returned, as a veto does.
                Call::Reject { id } => {
                    prune(&proposal(id).filter(|p| !p.fast_track)?, true);
                    Some(Vec::new())
                }
                _ => None,
            },
        },
        MODULE_ADDRESS => Install::decode(data)
            .and_then(|install| crate::modules::install_action(&install, stager, height))
            .map(|log| vec![log]),
        LIGHT_CLIENT_ADDRESS | VERIFIER_ADDRESS => {
            crate::bridge::govern(target, data, block, ACTION_GAS).map(|()| Vec::new())
        }
        _ => None,
    }
}

/// `setMode(stake)` under the key track (spec 13 §9.6): from then on the
/// key is the guardian, the bridge modules take the governance address as
/// their governance, and nothing but a kernel upgrade changes the mode again.
fn switch_to_stake(to: u8) -> Option<Vec<Log>> {
    let rules = rules();
    if to != mode::STAKE || mode() != mode::KEY || !workable(rules.voting_blocks, rules.quorum_bps)
    {
        return None;
    }
    state::set(gov::keys::MODE, &mode::STAKE);
    if state::get_raw(gov::keys::PARAMS).is_some() {
        // Rules a `setParams` recorded under the key now read as the stake track's.
        state::set(
            gov::keys::PARAMS,
            &GovernanceParams {
                mode: mode::STAKE,
                ..rules
            },
        );
    }
    if state::get_raw(gov::keys::GUARDIAN).is_none() {
        state::set(gov::keys::GUARDIAN, &key());
    }
    crate::bridge::set_governance(&GOVERNANCE_ADDRESS);
    Some(vec![gov::mode_log(mode::STAKE)])
}

// ---- Admission ----

/// What a transaction to the governance or module address carries, once
/// it is authorized.
enum Request {
    /// An upgrade action or a signal (spec 13 §2).
    Upgrade(Action),
    /// A module install the key sends directly (spec 16 §4.2).
    Install(Install),
    /// A governance call (spec 13 §9.2).
    Call(Call),
}

/// The request a transaction carries, if it can run in the block at
/// `height` (spec 13 §2.3, §9.4): signed for this chain (EIP-155 or a typed
/// transaction, so it cannot be replayed from another chain), calldata that
/// is an action, an install or a call, value only where a deposit is due,
/// and a sender that the action or call authorizes in the current mode.
fn request_of(s: &Signed, height: u64) -> Option<Request> {
    if s.tx.chain_id != Some(state::chain_id()) {
        return None;
    }
    match s.tx.to? {
        MODULE_ADDRESS if s.tx.value == 0 && key_acts(&s.from) => {
            Install::decode(&s.tx.input).map(Request::Install)
        }
        GOVERNANCE_ADDRESS => match Action::decode(&s.tx.input) {
            Some(action) => (s.tx.value == 0 && upgrade_allowed(&action, &s.from))
                .then_some(Request::Upgrade(action)),
            None => {
                let call = Call::decode(&s.tx.input)?;
                let surcharge = surcharge(s.tx.to.as_ref(), &s.tx.input);
                if s.tx.gas_limit < s.tx.min_gas_limit().saturating_add(surcharge) {
                    return None;
                }
                call_allowed(&call, s, height).then_some(Request::Call(call))
            }
        },
        _ => None,
    }
}

/// Who may send an upgrade action (spec 13 §2.2): `stage` the key under
/// the key track and any validator under the stake track; `propose` and
/// `cancel` the key under the key track (under the stake track they are
/// proposals); `signal` any validator while gate epochs exist.
fn upgrade_allowed(action: &Action, from: &Address) -> bool {
    match action {
        Action::Stage { .. } => {
            key_acts(from) || (mode() == mode::STAKE && validator_of(from).is_some())
        }
        Action::Propose { .. } | Action::Cancel { .. } => key_acts(from),
        Action::Signal { .. } => params().epoch_blocks != 0 && validator_of(from).is_some(),
    }
}

/// Who may make a governance call, and when (spec 13 §9.4).
fn call_allowed(call: &Call, s: &Signed, height: u64) -> bool {
    let from = &s.from;
    let value = s.tx.value;
    if mode() == mode::KEY {
        // Under the key: the key submits, and its submission executes at once.
        return match call {
            Call::Submit { target, data } => {
                value == 0 && key_acts(from) && track_of(target, data, true).is_some()
            }
            Call::SubmitCall { target, gas, .. } => {
                value == 0 && key_acts(from) && callable(target, *gas)
            }
            _ => false,
        };
    }
    let bonded = || {
        let deposit = rules().deposit;
        match validator_of(from) {
            Some(_) => value == 0,
            None => deposit != 0 && value == deposit,
        }
    };
    match call {
        Call::Submit { target, data } => {
            bonded() && track_of(target, data, false).is_some() && open().len() < MAX_OPEN_PROPOSALS
        }
        Call::SubmitCall { target, gas, .. } => {
            bonded() && callable(target, *gas) && open().len() < MAX_OPEN_PROPOSALS
        }
        Call::Vote { id, .. } => {
            value == 0
                && proposal(*id)
                    .is_some_and(|p| p.status == status::VOTING && height <= p.voting_end)
                && (validator_of(from).is_some() || may_ballot(from))
        }
        Call::Execute { id } => {
            value == 0
                && proposal(*id).is_some_and(|p| {
                    p.status == status::PASSED && (p.executable_at..=p.expires_at).contains(&height)
                })
        }
        Call::Veto { id } => {
            value == 0 && guardian_acts(from) && proposal(*id).is_some_and(|p| vetoable(&p))
        }
        Call::Pause { target } => {
            value == 0
                && guardian_acts(from)
                && *target == VERIFIER_ADDRESS
                && crate::bridge::governed(target)
        }
        Call::SetGuardian { .. }
        | Call::SetMode { .. }
        | Call::SetParams { .. }
        | Call::SetFeeParams { .. }
        | Call::Reject { .. } => false,
    }
}

/// Whether a governed call may go to `target` with `gas` (spec 13 §9.2):
/// never to a system address, whose actions are proposed as such, and with
/// at most [`MAX_CALL_GAS`].
fn callable(target: &Address, gas: u64) -> bool {
    !gov::is_system(target) && gas <= MAX_CALL_GAS
}

/// Whether `from`, which is no validator's account, may vote as a delegator
/// (spec 13 §9.3): staking is on and it has bonded stake behind a member of
/// the current set that counts. Any such stake, however small: the tally
/// reads running sums, not the votes, so their number bounds nothing.
fn may_ballot(from: &Address) -> bool {
    crate::staking::enabled() && !behind(from, &positions(&members())).is_empty()
}

fn guardian_acts(from: &Address) -> bool {
    let guardian = guardian();
    guardian != [0; 20] && *from == guardian
}

/// Whether the guardian may veto `p` (spec 13 §9.3): a normal-track
/// proposal, unless it names a guardian. So validators always replace a
/// guardian that vetoes, and a guardian never protects what a majority
/// stops on the fast track.
fn vetoable(p: &Proposal) -> bool {
    let names_guardian = p.target == GOVERNANCE_ADDRESS
        && matches!(Call::decode(&p.data), Some(Call::SetGuardian { .. }));
    !p.fast_track && !names_guardian
}

/// The code hash an action runs staged code of: a `propose` or an `install`.
fn code_of(target: &Address, data: &[u8]) -> Option<Hash> {
    match *target {
        GOVERNANCE_ADDRESS => match Action::decode(data)? {
            Action::Propose { code_hash, .. } => Some(code_hash),
            _ => None,
        },
        MODULE_ADDRESS => Install::decode(data).map(|install| install.code_hash),
        _ => None,
    }
}

/// Whether the code an action names is there to run (spec 13 §9.3): the
/// chunks of `stager`'s upload that hash to `code_hash`, or for an install
/// a module already in state under its hash.
fn code_complete(stager: &Address, code_hash: &Hash, module: bool) -> bool {
    (module && state::get_raw(&state::code_key(code_hash)).is_some())
        || assemble(stager, code_hash)
            .is_some_and(|(code, _)| state::keccak256(&code) == *code_hash)
}

/// Whether an open proposal names `code_hash`: its code is frozen while one does.
fn claimed(code_hash: &Hash) -> bool {
    open()
        .into_iter()
        .filter_map(|o| proposal(o.id))
        .any(|p| code_of(&p.target, &p.data) == Some(*code_hash))
}

/// What a message to `to` with calldata `data` pays beyond the plain call
/// (spec 13 §9.9): the surcharge of `orange_abi::governance::surcharge`, and
/// for an `execute` of an open call proposal the call's gas, which the
/// executor gives it.
pub fn surcharge(to: Option<&Address>, data: &[u8]) -> u64 {
    let base = gov::surcharge(to, data);
    match Call::decode(data) {
        Some(Call::Execute { id }) if to == Some(&GOVERNANCE_ADDRESS) => {
            base + proposal(id).filter(Proposal::is_call).map_or(0, |p| p.gas)
        }
        _ => base,
    }
}

/// Admission: a transaction to the governance or module address must be
/// able to run in the next block. A governance call whose gas limit does
/// not cover the surcharge is refused as the gas problem it is (spec 13
/// §9.4), so the sender learns how much to attach.
pub fn admit(s: &Signed) -> Result<(), u32> {
    let system = s.tx.to == Some(GOVERNANCE_ADDRESS) || s.tx.to == Some(MODULE_ADDRESS);
    let next = state::height().unwrap_or(0) + 1;
    if system {
        // Anything without a surcharge has its intrinsic gas already (`well_formed`).
        let surcharge = surcharge(s.tx.to.as_ref(), &s.tx.input);
        if surcharge != 0 && s.tx.gas_limit < s.tx.min_gas_limit().saturating_add(surcharge) {
            return Err(reason::GAS_TOO_LOW);
        }
    }
    if system && request_of(s, next).is_none() {
        Err(reason::SYSTEM_ACTION)
    } else {
        Ok(())
    }
}

// ---- Execution ----

/// Executes a transaction. One to the governance or module address that
/// cannot run changes nothing, like any transaction that should not have
/// been included; one that can runs through the EVM as a plain call (gas,
/// fees, nonce, a deposit's value), then applies its action or call. One
/// whose state checks fail reverts: the transaction keeps its gas and nonce
/// and changes nothing else, the value it carried going back to the
/// sender, except that an executed proposal is pruned whether or not its
/// action's checks passed (spec 13 §9.5).
pub fn run(s: &Signed, height: u64, message: Message, block: BlockFields) -> Outcome {
    if s.tx.to != Some(GOVERNANCE_ADDRESS) && s.tx.to != Some(MODULE_ADDRESS) {
        return crate::native::run(message, block, true);
    }
    let Some(request) = request_of(s, height) else {
        return Outcome {
            status: call_status::INVALID,
            gas_used: 0,
            output: Vec::new(),
            logs: Vec::new(),
            contract: None,
        };
    };
    let mut outcome = crate::native::run(message, block, true);
    if outcome.status == call_status::SUCCESS {
        let applied = match request {
            Request::Upgrade(action) => apply_upgrade(action, &s.from, height),
            Request::Install(install) => {
                crate::modules::install_action(&install, &s.from, height).map(|log| vec![log])
            }
            Request::Call(call) => {
                // The governance surcharge, paid like every fee (spec 13 §9.9).
                outcome.gas_used += GOVERNANCE_GAS;
                crate::fees::pay_surcharge(s, GOVERNANCE_GAS, block);
                let mut called = 0;
                let applied = apply_call(call, s, block, &mut called);
                // A governed call's gas, which it paid the same way.
                outcome.gas_used += called;
                applied
            }
        };
        match applied {
            Some(logs) => outcome.logs.extend(logs),
            None => {
                outcome.status = call_status::REVERT;
                if let Some(to) = s.tx.to
                    && s.tx.value > 0
                {
                    // The deposit of a submission that opened nothing.
                    debit(&to, s.tx.value);
                    credit(&s.from, s.tx.value);
                }
            }
        }
    }
    outcome
}

/// Applies an authorized upgrade action in the block at `height`; `None`
/// if its state checks fail. `from` sends it, or for a `propose` is its
/// stager (spec 13 §3).
fn apply_upgrade(action: Action, from: &Address, height: u64) -> Option<Vec<Log>> {
    match action {
        Action::Stage {
            code_hash,
            index,
            chunk,
        } => {
            // Frozen code: the pending upgrade's, every enacted kernel's, and
            // what an open proposal names. Each sender stages into an upload
            // of its own, so nobody spoils another's by writing chunks under
            // the same code hash (spec 13 §3).
            if pending().is_some_and(|p| p.code_hash == code_hash)
                || enacted(&code_hash)
                || claimed(&code_hash)
            {
                return None;
            }
            state::set_raw(&keys::chunk(from, &code_hash, index), &chunk);
            Some(Vec::new())
        }
        Action::Propose {
            code_hash,
            activation_height,
            required_gates,
        } => {
            let earliest = height.saturating_add(params().min_delay.max(1));
            // Block `H + 1` must exist, and a kernel the chain already ran never comes back.
            if pending().is_some()
                || activation_height < earliest
                || activation_height == u64::MAX
                || enacted(&code_hash)
            {
                return None;
            }
            let (code, chunks) = assemble(from, &code_hash)?;
            if state::keccak256(&code) != code_hash {
                return None;
            }
            let size = u32::try_from(code.len()).ok()?;
            // Hosts read the code of a pending or enacted kernel from here.
            state::set(&keys::source(&code_hash), from);
            state::set(
                keys::PENDING,
                &PendingUpgrade {
                    code_hash,
                    activation_height,
                    required_gates,
                    size,
                    chunks,
                    proposed_at: height,
                },
            );
            Some(vec![proposed_log(
                &code_hash,
                activation_height,
                required_gates,
            )])
        }
        Action::Cancel { code_hash } => {
            pending().filter(|p| p.code_hash == code_hash)?;
            state::delete(keys::PENDING);
            Some(vec![cancelled_log(&code_hash)])
        }
        Action::Signal { features } => {
            let (id, _) = validator_of(from)?;
            state::set(
                &keys::signal(&id),
                &Signal {
                    epoch: epoch_of(height, params().epoch_blocks),
                    features,
                },
            );
            Some(Vec::new())
        }
    }
}

/// Opens a proposal under the stake track (spec 13 §9.3) for the action, or
/// the governed call, `target` and `data` carry.
fn open_proposal(
    s: &Signed,
    target: Address,
    data: Vec<u8>,
    call: Option<(u128, u64)>,
    height: u64,
) -> Proposal {
    let rules = rules();
    let id: u64 = state::get(gov::keys::NEXT).unwrap_or(1);
    let fast = call.is_none() && track_of(&target, &data, false) == Some(Track::Fast);
    let voting_end = height.saturating_add(rules.voting_blocks);
    let (executable_at, expires_at) = if fast {
        (0, voting_end)
    } else {
        let first = voting_end
            .saturating_add(rules.timelock_blocks)
            .saturating_add(1);
        (
            first,
            first.saturating_add(rules.voting_blocks).saturating_sub(1),
        )
    };
    let (value, gas) = call.unwrap_or_default();
    let p = Proposal {
        id,
        proposer: s.from,
        deposit: s.tx.value,
        target,
        data,
        submitted_at: height,
        voting_end,
        executable_at,
        expires_at,
        fast_track: fast,
        status: status::VOTING,
        yes: 0,
        no: 0,
        total: 0,
        value,
        gas,
    };
    put_proposal(&p);
    let mut list = open();
    list.push(OpenProposal {
        id,
        due: voting_end,
    });
    set_open(&list);
    state::set(gov::keys::NEXT, &(id + 1));
    p
}

/// Runs a governed call (spec 13 §9.5): the governance address calls
/// `target` with `value` and `data` and a gas limit of `gas`, at a gas price
/// of zero, its state changes kept if it succeeds; `value` only from what
/// the address holds beyond the deposits of open proposals. The executor of
/// `s` pays the gas it used, which `called` accumulates. Whatever the call
/// does, it returns the logs to record: the call's own on success, then
/// `CallExecuted`.
fn governed_call(
    id: u64,
    p: &Proposal,
    s: &Signed,
    block: BlockFields,
    called: &mut u64,
) -> Vec<Log> {
    let held: u128 = open()
        .into_iter()
        .filter_map(|o| proposal(o.id))
        .map(|o| o.deposit)
        .sum();
    let funds = state::account(&GOVERNANCE_ADDRESS)
        .balance
        .saturating_sub(held);
    let outcome = (p.value <= funds).then(|| {
        crate::native::run(
            Message {
                tx_type: 0,
                caller: GOVERNANCE_ADDRESS,
                to: Some(p.target),
                value: p.value,
                data: p.data.clone(),
                gas_limit: p.gas,
                gas_price: 0,
                priority_fee: None,
                nonce: None,
                access_list: Vec::new(),
                authorization_list: Vec::new(),
            },
            block,
            true,
        )
    });
    let (success, used, output, mut logs) = match outcome {
        Some(o) if o.status == call_status::SUCCESS => (true, o.gas_used, o.output, o.logs),
        Some(o) => (false, o.gas_used, o.output, Vec::new()),
        None => (false, 0, Vec::new(), Vec::new()),
    };
    *called += used;
    crate::fees::pay_surcharge(s, used, block);
    logs.push(gov::call_executed_log(
        id, &p.target, success, used, &output,
    ));
    logs
}

/// Applies an authorized governance call in `block` (spec 13 §9.4–§9.5);
/// `None` if its checks fail. The gas of a governed call it runs adds to
/// `called`.
fn apply_call(call: Call, s: &Signed, block: BlockFields, called: &mut u64) -> Option<Vec<Log>> {
    let height = block.number;
    match call {
        Call::Submit { target, data } if mode() == mode::KEY => {
            enact(&s.from, &target, &data, block)
        }
        Call::SubmitCall {
            target,
            value,
            gas,
            data,
        } if mode() == mode::KEY => {
            let mut logs = vec![gov::enacted_log(&s.from, &target, &data)];
            let p = Proposal {
                target,
                data,
                value,
                gas,
                ..Proposal::default()
            };
            logs.extend(governed_call(0, &p, s, block, called));
            Some(logs)
        }
        Call::Submit { target, data } => {
            // What a proposal runs code of is complete when the proposal
            // opens, and frozen from then on, so validators vote on the code
            // that is there (spec 13 §9.3).
            if let Some(code_hash) = code_of(&target, &data)
                && !code_complete(&s.from, &code_hash, target == MODULE_ADDRESS)
            {
                return None;
            }
            let p = open_proposal(s, target, data, None, height);
            Some(vec![gov::submitted_log(&p)])
        }
        Call::SubmitCall {
            target,
            value,
            gas,
            data,
        } => {
            let p = open_proposal(s, target, data, Some((value, gas)), height);
            Some(vec![gov::submitted_log(&p)])
        }
        Call::Vote { id, support } => {
            let p = proposal(id)?;
            let weight = match validator_of(&s.from) {
                Some((validator, _)) => {
                    if vote_of(id, &validator).is_none() {
                        let mut list = voters(id);
                        list.push(validator);
                        state::set(&gov::keys::voters(id), &Seq(list));
                    }
                    state::set(&gov::keys::vote(id, &validator), &support);
                    members()
                        .into_iter()
                        .find(|(v, _)| *v == validator)
                        .map_or(0, |(_, w)| w)
                }
                None => {
                    let (at, before) = match ballot_index(id, &s.from) {
                        Some(at) => {
                            let entry = state::get::<BallotEntry>(&gov::keys::ballot_at(id, at));
                            (at, entry.map(|b| b.support))
                        }
                        None => {
                            let n = ballot_count(id);
                            state::set(&gov::keys::ballot(id, &s.from), &n);
                            state::set(&gov::keys::ballots(id), &(n + 1));
                            (n, None)
                        }
                    };
                    if before != Some(support) {
                        // The delegator's stake joins its side's running
                        // sums, or moves there from the other side, behind
                        // every validator it delegates to.
                        for v in crate::staking::delegated_to(&s.from) {
                            let w = gwei(
                                crate::staking::delegation(&v, &s.from).map_or(0, |d| d.stake),
                            );
                            if let Some(old) = before {
                                shift(id, &v, old, w, 0);
                            }
                            shift(id, &v, support, 0, w);
                        }
                    }
                    let entry = BallotEntry {
                        delegator: s.from,
                        support,
                    };
                    state::set(&gov::keys::ballot_at(id, at), &entry);
                    behind(&s.from, &positions(&members()))
                        .iter()
                        .fold(0u64, |sum, (_, w)| sum.saturating_add(*w))
                }
            };
            if p.fast_track {
                // Tallied at the end of this block (spec 13 §9.3).
                set_due(id, height);
            }
            Some(vec![gov::voted_log(id, &s.from, support, weight)])
        }
        Call::Execute { id } => {
            let p = proposal(id)?;
            prune(&p, true);
            record_execution(id, height, false);
            let mut logs = vec![gov::executed_log(id)];
            if p.is_call() {
                logs.extend(governed_call(id, &p, s, block, called));
                return Some(logs);
            }
            logs.extend(apply_action(&p.target, &p.data, &p.proposer, block)?);
            Some(logs)
        }
        Call::Veto { id } => {
            prune(&proposal(id)?, true);
            Some(vec![gov::vetoed_log(id)])
        }
        Call::Pause { target } => enact(&s.from, &target, &lcabi::PAUSE, block),
        Call::SetGuardian { .. }
        | Call::SetMode { .. }
        | Call::SetParams { .. }
        | Call::SetFeeParams { .. }
        | Call::Reject { .. } => None,
    }
}

/// Executes an action at once on behalf of `by` (the key, or the guardian
/// pausing), logging that it did before the action's own logs.
fn enact(by: &Address, target: &Address, data: &[u8], block: BlockFields) -> Option<Vec<Log>> {
    let mut logs = vec![gov::enacted_log(by, target, data)];
    logs.extend(apply_action(target, data, by, block)?);
    Some(logs)
}

/// `stager`'s upload of `code_hash`: chunks 0, 1, … up to the first missing
/// one, concatenated, and how many there were; `None` without chunk 0.
fn assemble(stager: &Address, code_hash: &Hash) -> Option<(Vec<u8>, u32)> {
    let mut code = Vec::new();
    let mut chunks = 0;
    while chunks < MAX_CHUNKS {
        let Some(chunk) = state::get_raw(&keys::chunk(stager, code_hash, chunks)) else {
            break;
        };
        code.extend_from_slice(&chunk);
        chunks += 1;
    }
    (chunks > 0).then_some((code, chunks))
}

/// Bookkeeping at the end of `block`, before the state commitment. Returns
/// what the fast-track proposals executed here logged, in order: the
/// block's system logs (spec 20 §3.5).
pub fn end_block(height: u64, block: BlockFields) -> Vec<Log> {
    if pending().is_some_and(|up| height > up.activation_height) {
        // This kernel was superseded at the activation height. A host still
        // running it past there must halt rather than fork the chain.
        orange_guest::trap();
    }
    // What pruning left of delegators' votes leaves state at a bounded pace.
    sweep();
    let mut logs = Vec::new();
    // The members that count, read once for every tally of the block.
    let mut counted: Option<Vec<(Hash, u64)>> = None;
    // Proposals whose voting ends here are tallied, and fast-track ones that
    // took a vote in this block; passed ones left unexecuted through their
    // window expire (spec 13 §9.3).
    for entry in open() {
        if entry.due != height {
            continue;
        }
        let Some(p) = proposal(entry.id) else {
            continue;
        };
        if p.status != status::VOTING {
            prune(&p, true);
            continue;
        }
        let members = counted.get_or_insert_with(members);
        if !p.fast_track {
            close_voting(p, members);
        } else {
            let (yes, no, total) = tally_with(p.id, members);
            if gov::fast_passes(yes, total) {
                // A safety action executes at once; what it logs goes to the
                // block's system receipt, after `ProposalExecuted`.
                prune(&p, true);
                record_execution(p.id, height, true);
                logs.push(gov::executed_log(p.id));
                logs.extend(
                    apply_action(&p.target, &p.data, &p.proposer, block).unwrap_or_default(),
                );
            } else if height >= p.voting_end {
                prune(&p, gov::quorum(yes, no, total, rules().quorum_bps));
            } else {
                set_due(p.id, p.voting_end);
            }
        }
    }
    let p = params();
    if let Some(epoch) = ended_epoch(height, p.epoch_blocks) {
        let mut signals = Vec::new();
        let mut total = 0u64;
        for (id, weight) in validators() {
            total = total.saturating_add(weight);
            if let Some(signal) = state::get::<Signal>(&keys::signal(&id))
                && signal.epoch == epoch
            {
                signals.push((weight, signal.features));
            }
        }
        state::set(
            keys::BOOK,
            &book().end_epoch(epoch, p.epoch_blocks, &signals, total),
        );
    }
    if let Some(up) = pending()
        && up.activation_height == height
        && up.required_gates & !book().active_at(height + 1) != 0
    {
        // The new kernel needs host features that will not be active: it lapses.
        state::delete(keys::PENDING);
    }
    logs
}

// ---- Queries ----

fn upgrade_status() -> UpgradeStatus {
    let validators = validators()
        .into_iter()
        .map(|(id, weight)| ValidatorSignal {
            id,
            weight,
            signal: state::get(&keys::signal(&id)),
        })
        .collect();
    UpgradeStatus {
        version: KERNEL_VERSION,
        params: params(),
        pending: pending(),
        enacted: state::get(keys::ENACTED),
        gates: book(),
        validators: Seq(validators),
    }
}

/// An open proposal with its live tally and every vote that counts.
fn view(p: Proposal) -> ProposalView {
    let c = count(p.id);
    let votes = c
        .members
        .iter()
        .zip(&c.votes)
        .zip(&c.tally.effective)
        .filter_map(|(((validator, _), vote), weight)| {
            vote.map(|support| Ballot {
                validator: *validator,
                support,
                weight: *weight,
            })
        })
        .collect();
    let delegators = c
        .ballots
        .iter()
        .zip(&c.tally.delegators)
        .map(|((delegator, support), weight)| DelegatorBallot {
            delegator: *delegator,
            support: *support,
            weight: *weight,
        })
        .collect();
    ProposalView {
        proposal: p,
        yes: c.tally.yes,
        no: c.tally.no,
        total: c.tally.total,
        votes: Seq(votes),
        delegators: Seq(delegators),
    }
}

fn governance_status() -> GovernanceStatus {
    let proposals = open()
        .into_iter()
        .filter_map(|o| proposal(o.id))
        .map(view)
        .collect();
    GovernanceStatus {
        mode: mode(),
        key: key(),
        guardian: guardian(),
        params: rules(),
        next_id: state::get(gov::keys::NEXT).unwrap_or(1),
        proposals: Seq(proposals),
    }
}

/// The upgrade and governance queries; status 3 for any other method.
pub fn query(method: &str, params: &[u8]) -> QueryResult {
    let ok = |body: Vec<u8>| QueryResult { status: 0, body };
    match method {
        query::KERNEL_VERSION => ok(KERNEL_VERSION.to_bytes()),
        query::STATUS => ok(upgrade_status().to_bytes()),
        // The code of the upload a `propose` of the code hash used.
        query::CODE => match Hash::from_bytes(params) {
            Ok(code_hash) => state::get::<Address>(&keys::source(&code_hash))
                .and_then(|source| assemble(&source, &code_hash))
                .map_or(
                    QueryResult {
                        status: 1,
                        body: Vec::new(),
                    },
                    |(code, _)| ok(code.to_bytes()),
                ),
            Err(_) => QueryResult {
                status: 2,
                body: Vec::new(),
            },
        },
        gov::query::GOVERNANCE => ok(governance_status().to_bytes()),
        gov::query::EXECUTED => match u64::from_bytes(params) {
            Ok(id) => state::get::<Execution>(&gov::keys::executed(id)).map_or(
                QueryResult {
                    status: 1,
                    body: Vec::new(),
                },
                |e| ok(e.to_bytes()),
            ),
            Err(_) => QueryResult {
                status: 2,
                body: Vec::new(),
            },
        },
        gov::query::PROPOSAL => match u64::from_bytes(params) {
            Ok(id) => proposal(id).map_or(
                QueryResult {
                    status: 1,
                    body: Vec::new(),
                },
                |p| ok(view(p).to_bytes()),
            ),
            Err(_) => QueryResult {
                status: 2,
                body: Vec::new(),
            },
        },
        _ => QueryResult {
            status: 3,
            body: Vec::new(),
        },
    }
}

/// The chain-state half of `kernel_migrate` (spec 06 §7.2). Accepts only the
/// version this kernel supersedes, and only at the pending upgrade's
/// activation height; anything else traps so the host halts. Enacts the
/// upgrade in chain state, from chain state alone: the driver state differs
/// between nodes and must not reach the commitment.
pub fn migrate(args: &MigrateArgs) {
    let Some(up) = pending() else {
        orange_guest::trap()
    };
    if args.from_version.checked_add(1) != Some(KERNEL_VERSION)
        || state::height() != Some(up.activation_height)
    {
        orange_guest::trap();
    }
    state::delete(keys::PENDING);
    let enacted = EnactedUpgrade {
        code_hash: up.code_hash,
        height: up.activation_height,
        from_version: args.from_version,
        to_version: KERNEL_VERSION,
    };
    state::set(&keys::kernel(&up.code_hash), &enacted);
    state::set(keys::ENACTED, &enacted);
}
