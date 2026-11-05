//! The Altair light-client sync protocol (consensus-specs
//! `altair/light-client/sync-protocol.md`, with the Capella execution
//! header and the Electra generalized indices), restricted to updates the
//! client applies at once: finalized, signed by a supermajority of the
//! sync committee (spec 18 §3).
//!
//! The protocol's `current_slot` checks are left out: the OrangeSDK chain has no clock it
//! could trust to say what slot Ethereum is at, and an update is ordered by
//! its signature slot and authenticated by the committee's signature alone.
//! The best-valid-update bookkeeping and the forced update after a timeout
//! are left out too: a client that falls a whole period behind stalls until
//! governance installs a new checkpoint (spec 18 §3.6).

use alloc::vec::Vec;

use orange_abi::bridge_in::LightClientConfig;

use crate::beacon::{
    Bootstrap, CURRENT_SYNC_COMMITTEE_GINDEX, FINALITY_BRANCH, FINALIZED_ROOT_GINDEX,
    NEXT_SYNC_COMMITTEE_GINDEX, Update,
};
use crate::ssz::{self, ZERO};
use crate::{Crypto, Hash};

/// `DOMAIN_SYNC_COMMITTEE`.
pub const DOMAIN_SYNC_COMMITTEE: [u8; 4] = [7, 0, 0, 0];

/// Largest sync committee a configuration may name.
pub const MAX_COMMITTEE: u32 = 1024;

/// Why an update, a bootstrap or a configuration was refused. The code is
/// the argument of the light client's `UpdateRejected(uint8)` revert.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Rejection {
    /// The bytes do not decode.
    Malformed = 1,
    /// A header or the signature is from before the first configured fork.
    UnsupportedFork = 2,
    /// An execution payload header is not proven by its beacon header.
    BadExecutionBranch = 3,
    /// Not `signature_slot > attested slot >= finalized slot`.
    Slots = 4,
    /// The signature is from a period whose committee the client does not hold.
    WrongPeriod = 5,
    /// The update would change nothing: no newer finalized header and no
    /// next committee the client lacks.
    NotNewer = 6,
    /// The update carries no finality branch.
    NoFinality = 7,
    /// The finalized header is not proven by the attested state.
    BadFinalityBranch = 8,
    /// The next sync committee is not proven by the attested state.
    BadCommitteeBranch = 9,
    /// The next sync committee differs from the one the client holds.
    CommitteeMismatch = 10,
    /// Fewer than two thirds of the committee signed.
    LowParticipation = 11,
    /// The aggregate signature does not verify.
    BadSignature = 12,
    /// The bootstrap's committee is not proven by its header.
    BadBootstrap = 13,
    /// The configuration cannot work: no forks or forks out of order, a
    /// committee size that is zero, not a multiple of 8 or above
    /// [`MAX_COMMITTEE`], or a zero epoch or period length.
    BadConfig = 14,
}

/// The light client's state the protocol reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct State {
    /// Slot of the finalized header.
    pub finalized_slot: u64,
    /// The committee of the finalized header's period.
    pub current: Vec<u8>,
    /// The committee of the next period, once known.
    pub next: Option<Vec<u8>>,
}

/// What a valid update changes.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Applied {
    /// Whether the update's finalized header is newer than the client's
    /// and replaces it.
    pub finalized: bool,
    /// Whether the client moves to the next period, whose committee
    /// becomes the current one.
    pub rotate: bool,
    /// The period whose committee the client learns: the update's next
    /// sync committee.
    pub committee: Option<u64>,
}

/// Checks that a configuration can work.
///
/// # Errors
/// [`Rejection::BadConfig`].
pub fn check_config(cfg: &LightClientConfig) -> Result<(), Rejection> {
    let forks = &cfg.forks.0;
    let ordered = forks.windows(2).all(|w| w[0].epoch < w[1].epoch);
    let size = cfg.sync_committee_size;
    if forks.is_empty()
        || !ordered
        || size == 0
        || !size.is_multiple_of(8)
        || size > MAX_COMMITTEE
        || cfg.slots_per_epoch == 0
        || cfg.epochs_per_period == 0
    {
        return Err(Rejection::BadConfig);
    }
    Ok(())
}

/// The epoch of `slot`.
#[must_use]
pub fn epoch(cfg: &LightClientConfig, slot: u64) -> u64 {
    slot.checked_div(cfg.slots_per_epoch).unwrap_or(0)
}

/// The sync-committee period of `slot`.
#[must_use]
pub fn period(cfg: &LightClientConfig, slot: u64) -> u64 {
    epoch(cfg, slot)
        .checked_div(cfg.epochs_per_period)
        .unwrap_or(0)
}

/// The fork version at `epoch`, if it is not before the first fork.
#[must_use]
pub fn fork_version(cfg: &LightClientConfig, epoch: u64) -> Option<[u8; 4]> {
    cfg.forks
        .0
        .iter()
        .rev()
        .find(|f| f.epoch <= epoch)
        .map(|f| f.version)
}

fn supported(cfg: &LightClientConfig, slot: u64) -> bool {
    fork_version(cfg, epoch(cfg, slot)).is_some()
}

/// `compute_domain(DOMAIN_SYNC_COMMITTEE, version, genesis_validators_root)`.
#[must_use]
pub fn domain(c: &dyn Crypto, version: [u8; 4], genesis_validators_root: &Hash) -> Hash {
    let mut v = ZERO;
    v[..4].copy_from_slice(&version);
    let fork_data_root = ssz::pair(c, &v, genesis_validators_root);
    let mut out = ZERO;
    out[..4].copy_from_slice(&DOMAIN_SYNC_COMMITTEE);
    out[4..].copy_from_slice(&fork_data_root[..28]);
    out
}

/// The root a sync committee signs for `object_root` in the slot before
/// `signature_slot`, if that slot is not before the first fork.
#[must_use]
pub fn signing_root(
    c: &dyn Crypto,
    cfg: &LightClientConfig,
    object_root: &Hash,
    signature_slot: u64,
) -> Option<Hash> {
    let version = fork_version(cfg, epoch(cfg, signature_slot.max(1) - 1))?;
    Some(ssz::pair(
        c,
        object_root,
        &domain(c, version, &cfg.genesis_validators_root),
    ))
}

/// Checks a trusted checkpoint (`initialize_light_client_store` without the
/// trusted block root, which is the checkpoint itself here).
///
/// # Errors
/// The [`Rejection`] that applies.
pub fn bootstrap(c: &dyn Crypto, cfg: &LightClientConfig, b: &Bootstrap) -> Result<(), Rejection> {
    if !supported(cfg, b.header.beacon.slot) {
        return Err(Rejection::UnsupportedFork);
    }
    if !b.header.is_valid(c) {
        return Err(Rejection::BadExecutionBranch);
    }
    let root = b.current_sync_committee.root(c);
    if !ssz::verify_branch(
        c,
        &root,
        &b.current_sync_committee_branch,
        CURRENT_SYNC_COMMITTEE_GINDEX,
        &b.header.beacon.state_root,
    ) {
        return Err(Rejection::BadBootstrap);
    }
    Ok(())
}

/// The checks of an update that need no state beyond the finalized slot:
/// format, participation, slot order, relevance; the cheap part of
/// [`process`], which admission runs (spec 18 §7).
///
/// # Errors
/// The [`Rejection`] that applies.
pub fn precheck(cfg: &LightClientConfig, state: &State, update: &Update) -> Result<(), Rejection> {
    let size = cfg.sync_committee_size as usize;
    if !supported(cfg, update.finalized.beacon.slot) {
        return Err(Rejection::UnsupportedFork);
    }
    if update.sync_aggregate.participants() * 3 < size * 2 {
        return Err(Rejection::LowParticipation);
    }
    let (attested, finalized) = (update.attested.beacon.slot, update.finalized.beacon.slot);
    if update.signature_slot <= attested || attested < finalized {
        return Err(Rejection::Slots);
    }
    let store_period = period(cfg, state.finalized_slot);
    let signature_period = period(cfg, update.signature_slot);
    let known = if state.next.is_some() {
        signature_period == store_period || signature_period == store_period + 1
    } else {
        signature_period == store_period
    };
    if !known {
        return Err(Rejection::WrongPeriod);
    }
    // Altair's relevance rule, then its apply rule: something must change.
    let has_next = update.next_sync_committee.is_some() && state.next.is_none();
    let attested_period = period(cfg, attested);
    if !(attested > state.finalized_slot || has_next && attested_period == store_period) {
        return Err(Rejection::NotNewer);
    }
    if !(finalized > state.finalized_slot || has_next && period(cfg, finalized) == attested_period)
    {
        return Err(Rejection::NotNewer);
    }
    if update.finality_branch == [ZERO; FINALITY_BRANCH] {
        return Err(Rejection::NoFinality);
    }
    Ok(())
}

/// `validate_light_client_update` and `apply_light_client_update` for an
/// update the client applies at once: what it changes.
///
/// # Errors
/// The [`Rejection`] that applies.
pub fn process(
    c: &dyn Crypto,
    cfg: &LightClientConfig,
    state: &State,
    update: &Update,
) -> Result<Applied, Rejection> {
    precheck(cfg, state, update)?;
    let (attested, finalized) = (&update.attested, &update.finalized);
    if !attested.is_valid(c) || !finalized.is_valid(c) {
        return Err(Rejection::BadExecutionBranch);
    }
    if !ssz::verify_branch(
        c,
        &finalized.beacon.root(c),
        &update.finality_branch,
        FINALIZED_ROOT_GINDEX,
        &attested.beacon.state_root,
    ) {
        return Err(Rejection::BadFinalityBranch);
    }
    let store_period = period(cfg, state.finalized_slot);
    let attested_period = period(cfg, attested.beacon.slot);
    if let Some((committee, branch)) = &update.next_sync_committee {
        if attested_period == store_period
            && let Some(next) = &state.next
            && *next != committee.pubkeys
        {
            return Err(Rejection::CommitteeMismatch);
        }
        if !ssz::verify_branch(
            c,
            &committee.root(c),
            branch,
            NEXT_SYNC_COMMITTEE_GINDEX,
            &attested.beacon.state_root,
        ) {
            return Err(Rejection::BadCommitteeBranch);
        }
    }
    let signers = match &state.next {
        Some(next) if period(cfg, update.signature_slot) != store_period => next,
        _ => &state.current,
    };
    let keys = update.sync_aggregate.participant_keys(signers);
    let root = signing_root(c, cfg, &attested.beacon.root(c), update.signature_slot)
        .ok_or(Rejection::UnsupportedFork)?;
    if !c.fast_aggregate_verify(&keys, &root, &update.sync_aggregate.signature) {
        return Err(Rejection::BadSignature);
    }
    // Without a next committee the signature is from the store's period, so
    // [`precheck`] has left only updates finalized in that period, as
    // `apply_light_client_update` asserts.
    let finalized_period = period(cfg, finalized.beacon.slot);
    let learned = update
        .next_sync_committee
        .as_ref()
        .map(|_| attested_period + 1);
    let mut applied = Applied::default();
    if state.next.is_none() {
        applied.committee = learned;
    } else if finalized_period == store_period + 1 {
        applied.rotate = true;
        applied.committee = learned;
    }
    applied.finalized = finalized.beacon.slot > state.finalized_slot;
    Ok(applied)
}
