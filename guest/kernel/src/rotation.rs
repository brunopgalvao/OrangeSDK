//! Rotating threshold keys in chain state (spec 15 §5.1, §6.5–§6.7): which
//! key set is active, the handoffs that move the chain from one key set to
//! the next, and the evidence of threshold misbehaviour that slashes a
//! shareholder. Every signature here is checked with `bls12381_verify`.

use alloc::vec::Vec;

use solo_abi::Decode;
use solo_abi::codec::Seq;
use solo_abi::rotation::{Handoff, MAX_EVIDENCE_QUERY, RotationCertificate, ThresholdEvidence, keys, offence, query, rotation_message};
use solo_abi::staking::{DST_SIGNATURE, G1_LENGTH, G2_LENGTH, KeySetRecord, epoch_of, keys as skeys};
use solo_abi::types::{Hash, QueryResult};
use solo_guest::host;

use crate::{staking, state};

fn id_key(prefix: &[u8], id: u64) -> Vec<u8> {
    [prefix, &id.to_be_bytes()].concat()
}

/// Whether `signature` (48 bytes) verifies over `message` under `key` (96
/// bytes) with the certificate tag.
pub fn verify(message: &[u8], signature: &[u8], key: &[u8]) -> bool {
    if signature.len() != G1_LENGTH || key.len() != G2_LENGTH {
        return false;
    }
    // SAFETY: valid pointers into our own buffers of the sizes the host reads.
    unsafe {
        host::__solo_import_bls12381_verify(message.as_ptr(), message.len() as u32, signature.as_ptr(), key.as_ptr(), DST_SIGNATURE.as_ptr(), DST_SIGNATURE.len() as u32)
            == 0
    }
}

/// The height of the block that made key set `id` active, if one did.
pub fn activated(id: u64) -> Option<u64> {
    state::get(&id_key(keys::ACTIVATED, id))
}

/// The height of the block whose handoff replaced key set `id`, if one did.
pub fn replaced(id: u64) -> Option<u64> {
    state::get(&id_key(keys::REPLACED, id))
}

/// Makes key set `record` the active one from the block at `height` on.
pub fn activate(record: &KeySetRecord, height: u64) {
    state::set(skeys::ACTIVE, &record.id);
    state::set_raw(skeys::GROUP_KEY, record.group_key().unwrap_or_default());
    state::set(&id_key(keys::ACTIVATED, record.id), &height);
}

/// Records an adopted key set as the newest; the first one ever adopted
/// becomes active at once, every later one waits for its handoff.
pub fn adopted(record: &KeySetRecord, height: u64) {
    state::set(keys::ADOPTED, &record.id);
    if state::get_raw(skeys::ACTIVE).is_none() {
        activate(record, height);
    }
}

/// The key set the active one should hand off to: the newest adopted key
/// set, when it is newer than the active one.
pub fn pending() -> Option<KeySetRecord> {
    let active: u64 = state::get(skeys::ACTIVE)?;
    let newest: u64 = state::get(keys::ADOPTED)?;
    (newest > active).then(|| staking::key_set(newest)).flatten()
}

/// Whether `certificate` hands the active key off to the pending target,
/// the newest adopted key set, with a valid group signature of the active
/// key; the target's record. A handoff to an older adopted key set that a
/// newer one superseded before it was recorded is never recorded (spec 15
/// §6.6), so the active key only ever moves to the newest key.
pub fn handoff_target(certificate: &RotationCertificate) -> Option<KeySetRecord> {
    let active = staking::active()?;
    if certificate.from != active.id {
        return None;
    }
    let target = pending().filter(|t| t.id == certificate.to)?;
    let message = rotation_message(state::chain_id(), target.id, target.group_key()?);
    verify(&message, &certificate.signature, active.group_key()?).then_some(target)
}

/// Records the handoff a block at `height` carries, if it is valid: the
/// handoff record, the height that replaced the old key set, and the new
/// active key set (spec 15 §6.6).
pub fn record_handoff(body: &[u8], height: u64) {
    let Ok(certificate) = RotationCertificate::from_bytes(body) else { return };
    let Some(target) = handoff_target(&certificate) else { return };
    let record = Handoff { from: certificate.from, to: target.id, key: target.group_key().unwrap_or_default().to_vec(), signature: certificate.signature, height };
    state::set(&id_key(keys::HANDOFF, record.from), &record);
    state::set(&id_key(keys::REPLACED, record.from), &height);
    activate(&target, height);
}

/// Whether the offence `evidence` names is on record already.
pub fn on_record(evidence: &ThresholdEvidence) -> bool {
    state::get_raw(&[keys::EVIDENCE_SEEN, &evidence.id()[..]].concat()).is_some()
}

/// The validator id of the shareholder that `evidence` shows misbehaving,
/// judged by the state before the block at `height` (spec 15 §5.1): its
/// partial signature verifies under its public share, over a message that
/// no honest shareholder signs.
pub fn offender(evidence: &ThresholdEvidence, height: u64) -> Option<Hash> {
    let record = staking::key_set(evidence.key_set)?;
    let index = (evidence.index as usize).checked_sub(1)?;
    let offender = *record.shareholders.0.get(index)?;
    let share = record.public_shares.0.get(index)?;
    let message = evidence.message(state::chain_id(), &state::keccak256)?;
    let fraud = if let Some((to, key)) = evidence.rotation() {
        match staking::key_set(to) {
            Some(target) => target.group_key() != Some(key),
            None => epoch_of(height, staking::params().epoch_blocks) > to,
        }
    } else {
        let a = evidence.anchored()?;
        a.anchor_height != 0
            && if evidence.kind == offence::ANCHOR {
                a.anchor_height < height && state::block_by_number(a.anchor_height).is_some_and(|b| b.state_root != a.anchor_root)
            } else {
                replaced(evidence.key_set).is_some_and(|r| r <= a.anchor_height)
            }
    };
    (fraud && verify(&message, &evidence.signature, share)).then_some(offender)
}

/// Records `evidence` in the block at `height` if it shows an offence not on
/// record yet, and slashes its offender (spec 15 §5); the offender's id if
/// it did.
pub fn record_evidence(evidence: &ThresholdEvidence, height: u64) -> Option<Hash> {
    if on_record(evidence) {
        return None;
    }
    let offender = offender(evidence, height)?;
    put_evidence(evidence, &offender);
    Some(offender)
}

/// Stores `evidence`, already checked, and slashes `offender` unless it is
/// jailed already.
pub fn put_evidence(evidence: &ThresholdEvidence, offender: &Hash) {
    let index: u64 = state::get(keys::EVIDENCE_COUNT).unwrap_or(0);
    state::set(&id_key(keys::EVIDENCE, index), evidence);
    state::set(&[keys::EVIDENCE_SEEN, &evidence.id()[..]].concat(), &index);
    state::set(keys::EVIDENCE_COUNT, &(index + 1));
    staking::slash_id(offender);
}

/// Records the evidence an envelope of a block at `height` carries.
pub fn record_evidence_body(body: &[u8], height: u64) {
    if let Ok(evidence) = ThresholdEvidence::from_bytes(body) {
        record_evidence(&evidence, height);
    }
}

/// The rotation queries; `None` for any other method.
pub fn query(method: &str, params: &[u8]) -> Option<QueryResult> {
    let found = |body: Option<Vec<u8>>| match body {
        Some(body) => QueryResult { status: 0, body },
        None => QueryResult { status: 1, body: Vec::new() },
    };
    let Ok(first) = u64::from_bytes(params) else {
        return [query::HANDOFF, query::THRESHOLD_EVIDENCE].contains(&method).then(|| QueryResult { status: 2, body: Vec::new() });
    };
    match method {
        query::HANDOFF => Some(found(state::get_raw(&id_key(keys::HANDOFF, first)))),
        query::THRESHOLD_EVIDENCE => {
            let count: u64 = state::get(keys::EVIDENCE_COUNT).unwrap_or(0);
            let end = count.min(first.saturating_add(MAX_EVIDENCE_QUERY as u64));
            let records: Vec<ThresholdEvidence> = (first..end).filter_map(|i| state::get(&id_key(keys::EVIDENCE, i))).collect();
            Some(found(Some(solo_abi::Encode::to_bytes(&Seq(records)))))
        }
        _ => None,
    }
}
