//! Governance (spec 13): kernel upgrades and host feature-gate signalling
//! through the governance address, module installs through the module
//! address, and the two tracks that authorize them (§9). Under the *key*
//! track the genesis governance key acts alone and at once; under the
//! *stake* track validators vote on proposals weighed by stake, a passed
//! proposal waits out a timelock during which the guardian may veto it, and
//! anyone executes it. Also the bookkeeping at the end of every block, the
//! queries, and this kernel's version and migration rule (spec 06 §7).

use alloc::vec;
use alloc::vec::Vec;

use solo_abi::bridge_in::{LIGHT_CLIENT_ADDRESS, VERIFIER_ADDRESS};
use solo_abi::chain::{Account, Log, UpgradeParams, ValidatorSet, call_status, reason};
use solo_abi::codec::Seq;
use solo_abi::governance::{
    self as gov, ACTION_GAS, Ballot, Call, GOVERNANCE_ADDRESS, GOVERNANCE_GAS, GovernanceParams, GovernanceStatus, MAX_OPEN_PROPOSALS, OpenProposal,
    Proposal, ProposalView, mode, status,
};
use solo_abi::modules::{Install, MODULE_ADDRESS};
use solo_abi::types::{Address, Genesis, Hash, MigrateArgs, QueryResult};
use solo_abi::{Decode, Encode};
use solo_ethlc::abi as lcabi;
use solo_upgrade::action::{cancelled_log, proposed_log};
use solo_upgrade::gates::{ended_epoch, epoch_of};
use solo_upgrade::{Action, EnactedUpgrade, GateBook, MAX_CHUNKS, PendingUpgrade, Signal, UpgradeStatus, ValidatorSignal, keys, query};

use crate::evm::{BASE_FEE, BlockFields, Message, Outcome};
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
    GovernanceParams { mode: mode(), ..state::get(gov::keys::PARAMS).unwrap_or_else(|| state::params().governance) }
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
    if mode() == mode::STAKE { GOVERNANCE_ADDRESS } else { key() }
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
    let Ok(params) = solo_abi::chain::GenesisParams::from_bytes(&genesis.params) else { solo_guest::trap() };
    let g = &params.governance;
    if g.mode > mode::STAKE || g.quorum_bps > 10_000 || (g.mode == mode::STAKE && !workable(g.voting_blocks, g.quorum_bps)) {
        solo_guest::trap();
    }
}

/// Validator ids and weights, in validator-set order.
fn validators() -> Vec<(Hash, u64)> {
    state::get_raw(b"meta/validators")
        .and_then(|b| ValidatorSet::from_bytes(&b).ok())
        .map(|set| set.validators.0.into_iter().map(|v| (v.id, v.weight)).collect())
        .unwrap_or_default()
}

/// The validator whose consensus key controls `address`, with its weight: a
/// validator id is the hash an Ethereum address is the last 20 bytes of.
fn validator_of(address: &Address) -> Option<(Hash, u64)> {
    validators().into_iter().find(|(id, _)| id[12..] == address[..])
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
    state::get::<Seq<OpenProposal>>(gov::keys::OPEN).map(|s| s.0).unwrap_or_default()
}

fn set_open(list: &[OpenProposal]) {
    if list.is_empty() {
        state::delete(gov::keys::OPEN);
    } else {
        state::set(gov::keys::OPEN, &Seq(list.to_vec()));
    }
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
    state::get::<Seq<Hash>>(&gov::keys::voters(id)).map(|s| s.0).unwrap_or_default()
}

/// The stake voting yes and no on `id`, and the stake of the whole current
/// validator set: a vote weighs what its validator weighs now, nothing once
/// it has left the set.
fn tally(id: u64) -> (u64, u64, u64) {
    let (mut yes, mut no, mut total) = (0u64, 0u64, 0u64);
    for (validator, weight) in validators() {
        total = total.saturating_add(weight);
        match vote_of(id, &validator) {
            Some(true) => yes = yes.saturating_add(weight),
            Some(false) => no = no.saturating_add(weight),
            None => {}
        }
    }
    (yes, no, total)
}

/// Removes proposal `p` from state with its votes, and settles its deposit:
/// back to the proposer when `refund`, else to the zero address, where fees
/// go and nobody can spend it.
fn prune(p: &Proposal, refund: bool) {
    for validator in voters(p.id) {
        state::delete(&gov::keys::vote(p.id, &validator));
    }
    state::delete(&gov::keys::voters(p.id));
    state::delete(&gov::keys::proposal(p.id));
    let rest: Vec<OpenProposal> = open().into_iter().filter(|o| o.id != p.id).collect();
    set_open(&rest);
    if p.deposit > 0 {
        debit(&GOVERNANCE_ADDRESS, p.deposit);
        credit(if refund { &p.proposer } else { &[0; 20] }, p.deposit);
    }
}

/// Records the tally of a proposal whose voting ended: passed, it waits for
/// its timelock; otherwise it is pruned, its deposit returned only if the
/// vote reached quorum.
fn close_voting(mut p: Proposal) {
    let (yes, no, total) = tally(p.id);
    let rules = rules();
    if !p.fast_track && gov::passes(yes, no, total, rules.quorum_bps) {
        p.status = status::PASSED;
        (p.yes, p.no, p.total) = (yes, no, total);
        put_proposal(&p);
        let list: Vec<OpenProposal> = open().into_iter().map(|o| if o.id == p.id { OpenProposal { id: o.id, due: p.expires_at } } else { o }).collect();
        set_open(&list);
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
/// carry (spec 13 §9.2); `switch` admits `setMode`, which only the key
/// track proposes.
fn track_of(target: &Address, data: &[u8], switch: bool) -> Option<Track> {
    let selector = data.get(..4)?;
    match *target {
        GOVERNANCE_ADDRESS => match Action::decode(data) {
            Some(Action::Propose { .. }) => Some(Track::Normal),
            Some(Action::Cancel { .. }) => Some(Track::Fast),
            Some(_) => None,
            None => match Call::decode(data)? {
                Call::SetGuardian { .. } | Call::SetParams { .. } => Some(Track::Normal),
                Call::SetMode { .. } if switch => Some(Track::Normal),
                _ => None,
            },
        },
        MODULE_ADDRESS => Install::decode(data).map(|_| Track::Normal),
        LIGHT_CLIENT_ADDRESS if selector == lcabi::SET_CHECKPOINT || selector == lcabi::SET_DELAY => Some(Track::Normal),
        VERIFIER_ADDRESS if selector == lcabi::PAUSE => Some(Track::Fast),
        VERIFIER_ADDRESS if selector == lcabi::UNPAUSE || selector == lcabi::SET_RATE_LIMIT => Some(Track::Normal),
        _ => None,
    }
}

/// Applies the governance action `data` to `target` in `block` (spec 13
/// §9.5), as a passed proposal, the key or the guardian does; `None` if its
/// checks fail, in which case nothing changed.
fn apply_action(target: &Address, data: &[u8], block: BlockFields) -> Option<Vec<Log>> {
    let height = block.number;
    match *target {
        GOVERNANCE_ADDRESS => match Action::decode(data) {
            Some(action @ (Action::Propose { .. } | Action::Cancel { .. })) => apply_upgrade(action, &[0; 20], height),
            Some(_) => None,
            None => match Call::decode(data)? {
                Call::SetGuardian { guardian } => {
                    state::set(gov::keys::GUARDIAN, &guardian);
                    Some(vec![gov::guardian_log(&guardian)])
                }
                Call::SetMode { mode: m } => switch_to_stake(m),
                Call::SetParams { voting_blocks, timelock_blocks, quorum_bps, deposit } => {
                    if !workable(voting_blocks, quorum_bps) {
                        return None;
                    }
                    let rules = GovernanceParams { mode: mode(), voting_blocks, timelock_blocks, quorum_bps, deposit };
                    state::set(gov::keys::PARAMS, &rules);
                    Some(vec![gov::params_log(&rules)])
                }
                _ => None,
            },
        },
        MODULE_ADDRESS => Install::decode(data).and_then(|install| crate::modules::install_action(&install, height)).map(|log| vec![log]),
        LIGHT_CLIENT_ADDRESS | VERIFIER_ADDRESS => crate::bridge::govern(target, data, block, ACTION_GAS).map(|()| Vec::new()),
        _ => None,
    }
}

/// `setMode(stake)` under the key track (spec 13 §9.6): from then on the
/// key is the guardian, the bridge modules take the governance address as
/// their governance, and nothing but a kernel upgrade changes the mode again.
fn switch_to_stake(to: u8) -> Option<Vec<Log>> {
    let rules = rules();
    if to != mode::STAKE || mode() != mode::KEY || !workable(rules.voting_blocks, rules.quorum_bps) {
        return None;
    }
    state::set(gov::keys::MODE, &mode::STAKE);
    if state::get_raw(gov::keys::PARAMS).is_some() {
        // Rules a `setParams` recorded under the key now read as the stake track's.
        state::set(gov::keys::PARAMS, &GovernanceParams { mode: mode::STAKE, ..rules });
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
        MODULE_ADDRESS if s.tx.value == 0 && key_acts(&s.from) => Install::decode(&s.tx.input).map(Request::Install),
        GOVERNANCE_ADDRESS => match Action::decode(&s.tx.input) {
            Some(action) => (s.tx.value == 0 && upgrade_allowed(&action, &s.from)).then_some(Request::Upgrade(action)),
            None => {
                let call = Call::decode(&s.tx.input)?;
                if s.tx.gas_limit < s.tx.min_gas_limit().saturating_add(GOVERNANCE_GAS) {
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
        Action::Stage { .. } => key_acts(from) || (mode() == mode::STAKE && validator_of(from).is_some()),
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
            Call::Submit { target, data } => value == 0 && key_acts(from) && track_of(target, data, true).is_some(),
            _ => false,
        };
    }
    match call {
        Call::Submit { target, data } => {
            let deposit = rules().deposit;
            let bonded = match validator_of(from) {
                Some(_) => value == 0,
                None => deposit != 0 && value == deposit,
            };
            bonded && track_of(target, data, false).is_some() && open().len() < MAX_OPEN_PROPOSALS
        }
        Call::Vote { id, .. } => value == 0 && validator_of(from).is_some() && proposal(*id).is_some_and(|p| p.status == status::VOTING && height <= p.voting_end),
        Call::Execute { id } => value == 0 && proposal(*id).is_some_and(|p| p.status == status::PASSED && (p.executable_at..=p.expires_at).contains(&height)),
        Call::Veto { id } => value == 0 && guardian_acts(from) && proposal(*id).is_some_and(|p| vetoable(&p)),
        Call::Pause { target } => value == 0 && guardian_acts(from) && *target == VERIFIER_ADDRESS && crate::bridge::governed(target),
        Call::SetGuardian { .. } | Call::SetMode { .. } | Call::SetParams { .. } => false,
    }
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
    let names_guardian = p.target == GOVERNANCE_ADDRESS && matches!(Call::decode(&p.data), Some(Call::SetGuardian { .. }));
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

/// Whether the code an action names is there to run (spec 13 §9.3): staged
/// chunks that hash to `code_hash`, or for an install a module already in
/// state under its hash.
fn code_complete(code_hash: &Hash, module: bool) -> bool {
    (module && state::get_raw(&state::code_key(code_hash)).is_some()) || assemble(code_hash).is_some_and(|(code, _)| state::keccak256(&code) == *code_hash)
}

/// Whether an open proposal names `code_hash`: its code is frozen while one does.
fn claimed(code_hash: &Hash) -> bool {
    open().into_iter().filter_map(|o| proposal(o.id)).any(|p| code_of(&p.target, &p.data) == Some(*code_hash))
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
        let surcharge = gov::surcharge(s.tx.to.as_ref(), &s.tx.input);
        if surcharge != 0 && s.tx.gas_limit < s.tx.min_gas_limit().saturating_add(surcharge) {
            return Err(reason::GAS_TOO_LOW);
        }
    }
    if system && request_of(s, next).is_none() { Err(reason::SYSTEM_ACTION) } else { Ok(()) }
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
        return Outcome { status: call_status::INVALID, gas_used: 0, output: Vec::new(), logs: Vec::new(), contract: None };
    };
    let mut outcome = crate::native::run(message, block, true);
    if outcome.status == call_status::SUCCESS {
        let applied = match request {
            Request::Upgrade(action) => apply_upgrade(action, &s.from, height),
            Request::Install(install) => crate::modules::install_action(&install, height).map(|log| vec![log]),
            Request::Call(call) => {
                // The governance surcharge, paid like every fee (spec 13 §9.9).
                outcome.gas_used += GOVERNANCE_GAS;
                let fee = u128::from(GOVERNANCE_GAS) * s.tx.effective_gas_price(u128::from(BASE_FEE)).unwrap_or(0);
                debit(&s.from, fee);
                credit(&[0; 20], fee);
                apply_call(call, s, block)
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
/// if its state checks fail.
fn apply_upgrade(action: Action, from: &Address, height: u64) -> Option<Vec<Log>> {
    match action {
        Action::Stage { code_hash, index, chunk } => {
            // Frozen code: the pending upgrade's, every enacted kernel's, and
            // what an open proposal names. And a code hash belongs to the
            // account that staged its first chunk, so nobody spoils another's
            // upload by writing a chunk of their own under it (spec 13 §3).
            if pending().is_some_and(|p| p.code_hash == code_hash) || enacted(&code_hash) || claimed(&code_hash) {
                return None;
            }
            match state::get::<Address>(&keys::staker(&code_hash)) {
                Some(staker) if staker != *from => return None,
                Some(_) => {}
                None => state::set(&keys::staker(&code_hash), from),
            }
            state::set_raw(&keys::chunk(&code_hash, index), &chunk);
            Some(Vec::new())
        }
        Action::Propose { code_hash, activation_height, required_gates } => {
            let earliest = height.saturating_add(params().min_delay.max(1));
            // Block `H + 1` must exist, and a kernel the chain already ran never comes back.
            if pending().is_some() || activation_height < earliest || activation_height == u64::MAX || enacted(&code_hash) {
                return None;
            }
            let (code, chunks) = assemble(&code_hash)?;
            if state::keccak256(&code) != code_hash {
                return None;
            }
            let size = u32::try_from(code.len()).ok()?;
            state::set(keys::PENDING, &PendingUpgrade { code_hash, activation_height, required_gates, size, chunks, proposed_at: height });
            Some(vec![proposed_log(&code_hash, activation_height, required_gates)])
        }
        Action::Cancel { code_hash } => {
            pending().filter(|p| p.code_hash == code_hash)?;
            state::delete(keys::PENDING);
            Some(vec![cancelled_log(&code_hash)])
        }
        Action::Signal { features } => {
            let (id, _) = validator_of(from)?;
            state::set(&keys::signal(&id), &Signal { epoch: epoch_of(height, params().epoch_blocks), features });
            Some(Vec::new())
        }
    }
}

/// Applies an authorized governance call in `block` (spec 13 §9.4–§9.5);
/// `None` if its checks fail.
fn apply_call(call: Call, s: &Signed, block: BlockFields) -> Option<Vec<Log>> {
    let height = block.number;
    match call {
        Call::Submit { target, data } if mode() == mode::KEY => enact(&s.from, &target, &data, block),
        Call::Submit { target, data } => {
            // What a proposal runs code of is complete when the proposal
            // opens, and frozen from then on, so validators vote on the code
            // that is there (spec 13 §9.3).
            if let Some(code_hash) = code_of(&target, &data)
                && !code_complete(&code_hash, target == MODULE_ADDRESS)
            {
                return None;
            }
            let rules = rules();
            let id: u64 = state::get(gov::keys::NEXT).unwrap_or(1);
            let fast = track_of(&target, &data, false) == Some(Track::Fast);
            let voting_end = height.saturating_add(rules.voting_blocks);
            let (executable_at, expires_at) = if fast {
                (0, voting_end)
            } else {
                let first = voting_end.saturating_add(rules.timelock_blocks).saturating_add(1);
                (first, first.saturating_add(rules.voting_blocks).saturating_sub(1))
            };
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
            };
            put_proposal(&p);
            let mut list = open();
            list.push(OpenProposal { id, due: voting_end });
            set_open(&list);
            state::set(gov::keys::NEXT, &(id + 1));
            Some(vec![gov::submitted_log(&p)])
        }
        Call::Vote { id, support } => {
            let (validator, weight) = validator_of(&s.from)?;
            let p = proposal(id)?;
            if vote_of(id, &validator).is_none() {
                let mut list = voters(id);
                list.push(validator);
                state::set(&gov::keys::voters(id), &Seq(list));
            }
            state::set(&gov::keys::vote(id, &validator), &support);
            let mut logs = vec![gov::voted_log(id, &s.from, support, weight)];
            if p.fast_track {
                let (yes, _, total) = tally(id);
                if gov::fast_passes(yes, total) {
                    prune(&p, true);
                    logs.push(gov::executed_log(id));
                    logs.extend(apply_action(&p.target, &p.data, block)?);
                }
            }
            Some(logs)
        }
        Call::Execute { id } => {
            let p = proposal(id)?;
            prune(&p, true);
            let mut logs = vec![gov::executed_log(id)];
            logs.extend(apply_action(&p.target, &p.data, block)?);
            Some(logs)
        }
        Call::Veto { id } => {
            prune(&proposal(id)?, true);
            Some(vec![gov::vetoed_log(id)])
        }
        Call::Pause { target } => enact(&s.from, &target, &lcabi::PAUSE, block),
        Call::SetGuardian { .. } | Call::SetMode { .. } | Call::SetParams { .. } => None,
    }
}

/// Executes an action at once on behalf of `by` (the key, or the guardian
/// pausing), logging that it did before the action's own logs.
fn enact(by: &Address, target: &Address, data: &[u8], block: BlockFields) -> Option<Vec<Log>> {
    let mut logs = vec![gov::enacted_log(by, target, data)];
    logs.extend(apply_action(target, data, block)?);
    Some(logs)
}

/// The staged code of `code_hash`: chunks 0, 1, … up to the first missing
/// one, concatenated, and how many there were; `None` without chunk 0.
fn assemble(code_hash: &Hash) -> Option<(Vec<u8>, u32)> {
    let mut code = Vec::new();
    let mut chunks = 0;
    while chunks < MAX_CHUNKS {
        let Some(chunk) = state::get_raw(&keys::chunk(code_hash, chunks)) else { break };
        code.extend_from_slice(&chunk);
        chunks += 1;
    }
    (chunks > 0).then_some((code, chunks))
}

/// Bookkeeping at the end of the block at `height`, before the state commitment.
pub fn end_block(height: u64) {
    if pending().is_some_and(|up| height > up.activation_height) {
        // This kernel was superseded at the activation height. A host still
        // running it past there must halt rather than fork the chain.
        solo_guest::trap();
    }
    // Proposals whose voting ends here are tallied; passed ones left
    // unexecuted through their window expire (spec 13 §9.3).
    for entry in open() {
        if entry.due != height {
            continue;
        }
        let Some(p) = proposal(entry.id) else { continue };
        if p.status == status::VOTING {
            close_voting(p);
        } else {
            prune(&p, true);
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
        state::set(keys::BOOK, &book().end_epoch(epoch, p.epoch_blocks, &signals, total));
    }
    if let Some(up) = pending()
        && up.activation_height == height
        && up.required_gates & !book().active_at(height + 1) != 0
    {
        // The new kernel needs host features that will not be active: it lapses.
        state::delete(keys::PENDING);
    }
}

// ---- Queries ----

fn upgrade_status() -> UpgradeStatus {
    let validators = validators().into_iter().map(|(id, weight)| ValidatorSignal { id, weight, signal: state::get(&keys::signal(&id)) }).collect();
    UpgradeStatus { version: KERNEL_VERSION, params: params(), pending: pending(), enacted: state::get(keys::ENACTED), gates: book(), validators: Seq(validators) }
}

/// An open proposal with its live tally and every vote.
fn view(p: Proposal) -> ProposalView {
    let (mut yes, mut no, mut total) = (0u64, 0u64, 0u64);
    let mut votes = Vec::new();
    for (validator, weight) in validators() {
        total = total.saturating_add(weight);
        if let Some(support) = vote_of(p.id, &validator) {
            if support {
                yes = yes.saturating_add(weight);
            } else {
                no = no.saturating_add(weight);
            }
            votes.push(Ballot { validator, support, weight });
        }
    }
    ProposalView { proposal: p, yes, no, total, votes: Seq(votes) }
}

fn governance_status() -> GovernanceStatus {
    let proposals = open().into_iter().filter_map(|o| proposal(o.id)).map(view).collect();
    GovernanceStatus { mode: mode(), key: key(), guardian: guardian(), params: rules(), next_id: state::get(gov::keys::NEXT).unwrap_or(1), proposals: Seq(proposals) }
}

/// The upgrade and governance queries; status 3 for any other method.
pub fn query(method: &str, params: &[u8]) -> QueryResult {
    let ok = |body: Vec<u8>| QueryResult { status: 0, body };
    match method {
        query::KERNEL_VERSION => ok(KERNEL_VERSION.to_bytes()),
        query::STATUS => ok(upgrade_status().to_bytes()),
        query::CODE => match Hash::from_bytes(params) {
            Ok(code_hash) => assemble(&code_hash).map_or(QueryResult { status: 1, body: Vec::new() }, |(code, _)| ok(code.to_bytes())),
            Err(_) => QueryResult { status: 2, body: Vec::new() },
        },
        gov::query::GOVERNANCE => ok(governance_status().to_bytes()),
        gov::query::PROPOSAL => match u64::from_bytes(params) {
            Ok(id) => proposal(id).map_or(QueryResult { status: 1, body: Vec::new() }, |p| ok(view(p).to_bytes())),
            Err(_) => QueryResult { status: 2, body: Vec::new() },
        },
        _ => QueryResult { status: 3, body: Vec::new() },
    }
}

/// The chain-state half of `kernel_migrate` (spec 06 §7.2). Accepts only the
/// version this kernel supersedes, and only at the pending upgrade's
/// activation height; anything else traps so the host halts. Enacts the
/// upgrade in chain state, from chain state alone: the driver state differs
/// between nodes and must not reach the commitment.
pub fn migrate(args: &MigrateArgs) {
    let Some(up) = pending() else { solo_guest::trap() };
    if args.from_version.checked_add(1) != Some(KERNEL_VERSION) || state::height() != Some(up.activation_height) {
        solo_guest::trap();
    }
    state::delete(keys::PENDING);
    let enacted = EnactedUpgrade { code_hash: up.code_hash, height: up.activation_height, from_version: args.from_version, to_version: KERNEL_VERSION };
    state::set(&keys::kernel(&up.code_hash), &enacted);
    state::set(keys::ENACTED, &enacted);
}
