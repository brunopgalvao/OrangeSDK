//! The driver's half of the threshold key (spec 15 §6, spec 08 §4a): what
//! this node sends in each DKG phase, the pool of envelopes leaders put in
//! proposals, partial signatures on finalize votes, and their combination
//! into the certificates of spec 12 §7. Every step that needs a secret is a
//! request to the host's threshold keystore (`sign` with key role 2), so no
//! share or decryption key ever enters the kernel. Keys rotate (spec 15
//! §6.6): the shareholders of the active key sign the rotation message to
//! the newest adopted key set, any node that gathers enough of those
//! partials combines them into a handoff for leaders to propose, and a
//! partial that no honest shareholder signs becomes evidence (spec 15 §5.1).

use alloc::vec;
use alloc::vec::Vec;

use orange_abi::chain::Proposal;
use orange_abi::chain::consensus::{KEY_ROLE, identity_preimage, signing_preimage};
use orange_abi::codec::Seq;
use orange_abi::rotation::{
    RotationCertificate, RotationShare, ThresholdEvidence, certificate_bytes, certificate_message,
    offence, rotation_message, threshold_certificate,
};
use orange_abi::staking::{
    DkgEnvelope, DkgReply, DkgRequest, DkgRun, KEY_ROLE_THRESHOLD, KIND_DKG, KeySetRecord,
    KeystoreRequest, MAX_DKG, PartialShare, dkg_header, envelope, epoch_of,
};
use orange_abi::types::Hash;
use orange_abi::{Decode, Encode};
use orange_guest::host;

use crate::{persist, rotation, staking, state, tx};

/// Envelopes received and not yet on chain, for this node's proposals.
const POOL_KEY: &[u8] = b"dkg/pool";
/// Most envelopes the pool keeps.
const POOL_CAP: usize = 64;
/// What this node sends in a phase, once computed: `dkg/out/` ‖ epoch ‖ phase.
const OUT_KEY: &[u8] = b"dkg/out/";
/// This node's validator id, once learned.
const ID_KEY: &[u8] = b"dkg/id";
/// Rotation shares received for the pending handoff, one partial per share
/// index. Rotation shares carry a list of partials since shares follow stake
/// (spec 15 §6.6); the keys are new so that a node whose driver store holds
/// the earlier single-partial records ignores them rather than misreading them.
const SHARES_KEY: &[u8] = b"dkg/shares2";
/// This node's rotation share, once computed: `dkg/rshare2/` ‖ active ‖ target.
const RSHARE_KEY: &[u8] = b"dkg/rshare2/";
/// The handoff this node combined: `dkg/handoff/` ‖ target.
const HANDOFF_KEY: &[u8] = b"dkg/handoff/";
/// Evidence this node found that chain state does not hold yet.
const EVIDENCE_KEY: &[u8] = b"dkg/evidence";
/// Most pieces of evidence this node keeps to report.
const EVIDENCE_CAP: usize = 16;

/// Sends `request` to the threshold keystore; its answer, if it has one.
pub fn keystore(request: &KeystoreRequest) -> Option<Vec<u8>> {
    let msg = request.to_bytes();
    let call = |buf: &mut Vec<u8>| {
        // SAFETY: valid pointers into our own buffers of the stated sizes.
        unsafe {
            host::__orange_import_sign(
                KEY_ROLE_THRESHOLD,
                msg.as_ptr(),
                msg.len() as u32,
                buf.as_mut_ptr(),
                buf.len() as u32,
            ) as usize
        }
    };
    let mut buf = vec![0u8; 4096];
    let n = call(&mut buf);
    if n == 0 {
        return None;
    }
    if n > buf.len() {
        buf = vec![0u8; n];
        call(&mut buf);
    }
    buf.truncate(n);
    Some(buf)
}

/// This node's validator id (`keccak256` of its consensus public key),
/// whether or not it is in a validator set; `None` without a key.
pub fn my_id(chain_id: u64) -> Option<Hash> {
    if let Some(id) = persist::get(ID_KEY) {
        return Some(id);
    }
    let msg = state::keccak256(&identity_preimage(chain_id));
    let sig = persist::sign(KEY_ROLE, &msg)?;
    let id = state::keccak256(&tx::recover_pubkey(&msg, &sig.0)?);
    persist::set(ID_KEY, &id);
    Some(id)
}

fn index_of(list: &[Hash], id: &Hash) -> u32 {
    list.iter()
        .position(|x| x == id)
        .map_or(0, |i| i as u32 + 1)
}

/// The share indices `id` holds of a key set with these shareholders.
fn indices_of(shareholders: &[Hash], id: &Hash) -> Vec<u32> {
    (1u32..)
        .zip(shareholders)
        .filter(|(_, s)| *s == id)
        .map(|(x, _)| x)
        .collect()
}

/// This node's partial signatures with every share it holds of key set
/// `key_set` (`SignAll`, spec 15 §6.4), installing its shares again first
/// if the keystore lost them; only partials of the share indices chain
/// state gives `me` are kept.
fn sign_all(key_set: u64, me: &Hash, indices: &[u32], message: Vec<u8>) -> Vec<PartialShare> {
    let request = KeystoreRequest::SignAll { key_set, message };
    let reply = keystore(&request).or_else(|| {
        if install(key_set, me) {
            keystore(&request)
        } else {
            None
        }
    });
    let partials = reply
        .and_then(|r| Seq::<PartialShare>::from_bytes(&r).ok())
        .map(|s| s.0)
        .unwrap_or_default();
    partials
        .into_iter()
        .filter(|p| p.key_set == key_set && indices.contains(&p.index))
        .collect()
}

fn signer(chain_id: u64, env: &DkgEnvelope) -> Option<Hash> {
    let body_hash = state::keccak256(&DkgEnvelope::signed_hash_preimage(env.kind, &env.body));
    let digest = state::keccak256(&signing_preimage(KIND_DKG, chain_id, env.epoch, &body_hash));
    tx::recover_pubkey(&digest, &env.signature.0).map(|pubkey| state::keccak256(&pubkey))
}

/// The epoch of the block after the executed head.
fn next_epoch() -> u64 {
    epoch_of(
        state::height().unwrap_or(0) + 1,
        staking::params().epoch_blocks,
    )
}

fn sign_envelope(chain_id: u64, epoch: u64, kind: u8, body: Vec<u8>) -> Option<Vec<u8>> {
    let body_hash = state::keccak256(&DkgEnvelope::signed_hash_preimage(kind, &body));
    let signature = persist::sign(
        KEY_ROLE,
        &state::keccak256(&signing_preimage(KIND_DKG, chain_id, epoch, &body_hash)),
    )?;
    Some(
        DkgEnvelope {
            epoch,
            kind,
            body,
            signature,
        }
        .to_bytes(),
    )
}

fn request(run: &DkgRun, dealer: u32, recipient: u32, upto: u8) -> KeystoreRequest {
    let previous = run.previous.and_then(staking::key_set);
    let request = DkgRequest {
        key_set: run.epoch,
        session: run.session,
        threshold: run.threshold,
        dealers: run.dealers.0.len() as u32,
        recipients: run.keys.clone(),
        previous: previous.map(|k| k.key_set).unwrap_or_default(),
        previous_id: run.previous.unwrap_or(0),
        dealer,
        recipient,
        transcript: Seq(staking::transcript(run, upto)),
        upto,
    };
    KeystoreRequest::WeightedDkg {
        request,
        shares: run.shares.clone(),
    }
}

fn ask(run: &DkgRun, dealer: u32, recipient: u32, upto: u8) -> Option<DkgReply> {
    keystore(&request(run, dealer, recipient, upto)).and_then(|r| DkgReply::from_bytes(&r).ok())
}

/// Installs this node's share of key set `id` again from the run that made
/// it, as after a restart that emptied the keystore; whether it now holds it.
pub fn install(id: u64, me: &Hash) -> bool {
    let Some(run) = staking::dkg_run(id) else {
        return false;
    };
    let recipient = index_of(&run.recipients.0, me);
    recipient != 0 && matches!(ask(&run, 0, recipient, 3), Some(DkgReply::Finished(_)))
}

/// What this node sends after executing the block at `executed`: its DKG
/// message or confirmation of the phase the next block is in, as long as
/// chain state lacks it. Computed once per phase and then repeated.
pub fn duties(chain_id: u64, me: &Hash, executed: u64) -> Option<Vec<u8>> {
    let p = staking::params();
    if p.epoch_blocks == 0 || p.dkg_phase_blocks == 0 {
        return None;
    }
    let next = executed + 1;
    let epoch = epoch_of(next, p.epoch_blocks);
    let run = staking::dkg_run(epoch)?;
    let phase = staking::phase(epoch, next);
    if phase < 3 && staking::phase_complete(&run, phase) {
        // What the next phase sends depends only on what this one recorded,
        // which is all in: the keystore can start on it now.
        let _ = duty(chain_id, me, &run, phase + 1);
    }
    duty(chain_id, me, &run, phase)
}

/// This node's message or confirmation for `phase` of `run`, as long as
/// chain state lacks it, computed once and then repeated. Its inputs, the
/// messages of the earlier phases, must be final.
fn duty(chain_id: u64, me: &Hash, run: &DkgRun, phase: u8) -> Option<Vec<u8>> {
    let epoch = run.epoch;
    let dealer = index_of(&run.dealers.0, me);
    let recipient = index_of(&run.recipients.0, me);
    let pending = match phase {
        0 | 2 => dealer != 0 && !staking::has_message(epoch, phase, dealer),
        1 => recipient != 0 && !staking::has_message(epoch, 1, recipient),
        _ => {
            staking::key_set(epoch).is_none()
                && !staking::has_vote(epoch, me)
                && staking::set_entries(epoch).is_some_and(|set| set.iter().any(|v| v.0 == *me))
        }
    };
    if !pending {
        return None;
    }
    let out_key = [OUT_KEY, &epoch.to_be_bytes(), &[phase]].concat();
    if let Some(cached) = persist::get_raw(&out_key) {
        return (!cached.is_empty()).then_some(cached);
    }
    let (as_dealer, as_recipient) = if phase == 0 || phase == 2 {
        (dealer, 0)
    } else {
        (0, recipient)
    };
    let mut reply = ask(run, as_dealer, as_recipient, phase);
    if reply.is_none()
        && as_dealer != 0
        && let Some(previous) = run.previous
        && install(previous, me)
    {
        // A resharing dealer deals its current share, which a restart may have
        // taken out of the keystore.
        reply = ask(run, as_dealer, as_recipient, phase);
    }
    let envelope = match reply? {
        DkgReply::Message(m) => sign_envelope(chain_id, epoch, envelope::MESSAGE, m),
        DkgReply::Finished(vote) => {
            sign_envelope(chain_id, epoch, envelope::CONFIRM, vote.to_bytes())
        }
        DkgReply::Idle => None,
    };
    persist::set_raw(&out_key, envelope.as_deref().unwrap_or(&[]));
    envelope
}

/// The pool's entries: each envelope's signer followed by the envelope.
fn entries() -> Vec<Vec<u8>> {
    let mut entries = persist::get::<Seq<Vec<u8>>>(POOL_KEY)
        .map(|s| s.0)
        .unwrap_or_default();
    entries.retain(|e| e.len() > 32);
    entries
}

/// The envelopes this node holds for proposals.
pub fn pool() -> Vec<Vec<u8>> {
    entries().into_iter().map(|e| e[32..].to_vec()).collect()
}

/// The slot an envelope takes in the pool and on chain: for a DKG message
/// its phase and sender index, for a confirmation its signer, for a handoff
/// its target, for evidence its offence. The pool keeps one envelope per slot.
fn slot(env: &DkgEnvelope, signer: &Hash) -> Option<(u8, u32, Hash)> {
    match env.kind {
        envelope::MESSAGE => dkg_header(&env.body).map(|(at, _, index)| (at, index, ZERO)),
        envelope::CONFIRM => Some((3, 0, *signer)),
        envelope::HANDOFF => RotationCertificate::from_bytes(&env.body)
            .ok()
            .map(|c| (4, 0, state::keccak256(&c.to.to_be_bytes()))),
        _ => ThresholdEvidence::from_bytes(&env.body)
            .ok()
            .map(|e| (5, 0, state::keccak256(&e.id()))),
    }
}

const ZERO: Hash = [0; 32];

/// Whether the envelope `env`, signed by `signer`, can still be recorded
/// in a block after the one at `executed` (spec 15 §6.2): it names the
/// epoch of the next block, whose run exists; a DKG message is of the run's
/// session, of the current phase or a later one, and from the sender its
/// index names, with nothing recorded for that sender and phase; a
/// confirmation is from a member of the epoch's set that has not
/// confirmed, while no key set of the epoch is adopted; a handoff is from
/// the active key set to the target, the newest adopted one; evidence is of an offence not
/// on record. The signatures of handoffs and evidence are checked once, when
/// they arrive ([`pool_add`]).
fn wanted(env: &DkgEnvelope, signer: &Hash, executed: u64) -> bool {
    let p = staking::params();
    if p.epoch_blocks == 0 || p.dkg_phase_blocks == 0 {
        return false;
    }
    let next = executed + 1;
    let epoch = epoch_of(next, p.epoch_blocks);
    if env.epoch != epoch {
        return false;
    }
    let Some(run) = staking::dkg_run(epoch) else {
        return false;
    };
    let phase = staking::phase(epoch, next);
    if env.kind == envelope::HANDOFF {
        return RotationCertificate::from_bytes(&env.body).is_ok_and(|c| {
            staking::active().is_some_and(|a| a.id == c.from)
                && rotation::pending().is_some_and(|t| t.id == c.to)
        });
    }
    if env.kind == envelope::EVIDENCE {
        return ThresholdEvidence::from_bytes(&env.body).is_ok_and(|e| !rotation::on_record(&e));
    }
    if env.kind == envelope::MESSAGE {
        let Some((at, session, index)) = dkg_header(&env.body) else {
            return false;
        };
        let roster = if at == 1 {
            &run.recipients.0
        } else {
            &run.dealers.0
        };
        session == run.session
            && at >= phase
            && index != 0
            && roster.get(index as usize - 1) == Some(signer)
            && !staking::has_message(epoch, at, index)
    } else {
        env.kind == envelope::CONFIRM
            && staking::key_set(epoch).is_none()
            && !staking::has_vote(epoch, signer)
            && staking::set_entries(epoch).is_some_and(|set| set.iter().any(|v| v.0 == *signer))
    }
}

/// Whether a handoff or evidence envelope is valid as the block after the
/// executed head would record it: its group or partial signature verifies.
fn proven(env: &DkgEnvelope) -> bool {
    let next = state::height().unwrap_or(0) + 1;
    match env.kind {
        envelope::HANDOFF => RotationCertificate::from_bytes(&env.body)
            .is_ok_and(|c| rotation::handoff_target(&c).is_some()),
        envelope::EVIDENCE => ThresholdEvidence::from_bytes(&env.body)
            .is_ok_and(|e| rotation::offender(&e, next).is_some()),
        _ => true,
    }
}

/// Handles an envelope from a peer: a rotation share goes to the shares of
/// the pending handoff (or, if no honest shareholder signs it, becomes
/// evidence), anything else to the pool. Answers the envelopes this node
/// now has to broadcast: a handoff it combined, or evidence it found.
pub fn receive(chain_id: u64, raw: Vec<u8>) -> Vec<Vec<u8>> {
    let Ok(env) = DkgEnvelope::from_bytes(&raw) else {
        return Vec::new();
    };
    if env.kind != envelope::ROTATION_SHARE {
        pool_add(chain_id, raw);
        return Vec::new();
    }
    let Some(signer) = signer(chain_id, &env) else {
        return Vec::new();
    };
    let Ok(share) = RotationShare::from_bytes(&env.body) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if let Some(evidence) = rotation_fraud(&share, &signer) {
        out.extend(report(chain_id, evidence));
    }
    add_share(&share, &signer);
    out.extend(combine(chain_id));
    out
}

/// Keeps an envelope for this node's proposals when it can still be
/// recorded after the executed head, it fills a slot the pool does not hold
/// yet, and the pool has room. Every envelope is checked before it is
/// kept, so a peer can fill the pool only with what the run's own
/// participants signed, one envelope per participant and phase, and with
/// handoffs and evidence whose signatures verify.
pub fn pool_add(chain_id: u64, raw: Vec<u8>) {
    let Ok(env) = DkgEnvelope::from_bytes(&raw) else {
        return;
    };
    let mut pool = entries();
    if pool.len() >= POOL_CAP {
        return;
    }
    let Some(signer) = signer(chain_id, &env) else {
        return;
    };
    if !wanted(&env, &signer, state::height().unwrap_or(0)) {
        return;
    }
    let taken = slot(&env, &signer);
    let occupied = pool.iter().any(|e| {
        let held: Hash = e[..32].try_into().expect("32 bytes");
        DkgEnvelope::from_bytes(&e[32..])
            .ok()
            .and_then(|other| slot(&other, &held))
            == taken
    });
    if occupied || !proven(&env) {
        return;
    }
    pool.push([&signer[..], &raw].concat());
    persist::set(POOL_KEY, &Seq(pool));
}

/// The rotation shares this node holds for the pending handoff.
fn shares() -> Vec<RotationShare> {
    persist::get::<Seq<RotationShare>>(SHARES_KEY)
        .map(|s| s.0)
        .unwrap_or_default()
}

/// The active key set and the pending handoff's target, with the target's
/// group key, while a handoff is due.
fn due() -> Option<(KeySetRecord, KeySetRecord)> {
    let target = rotation::pending()?;
    Some((staking::active()?, target))
}

/// Keeps the partials of `share`, signed by `signer`, that are partials of
/// shares `signer` holds of the active key set over the rotation message
/// to the pending target: one per share index, each kept as a share of its
/// own. Partials for any other handoff are dropped, as are all of them
/// once no handoff is due.
fn add_share(share: &RotationShare, signer: &Hash) {
    let Some((active, target)) = due() else {
        persist::set(SHARES_KEY, &Seq::<RotationShare>(Vec::new()));
        return;
    };
    let mut held: Vec<RotationShare> = shares()
        .into_iter()
        .filter(|s| s.to == target.id && s.partials.0.iter().all(|p| p.key_set == active.id))
        .collect();
    let for_target = share.to == target.id && target.group_key() == Some(share.key.as_slice());
    for p in &share.partials.0 {
        let fits = for_target
            && p.key_set == active.id
            && p.index != 0
            && active.shareholders.0.get(p.index as usize - 1) == Some(signer)
            && !held
                .iter()
                .flat_map(|s| &s.partials.0)
                .any(|q| q.index == p.index);
        if fits {
            held.push(RotationShare {
                to: share.to,
                key: share.key.clone(),
                partials: Seq(vec![p.clone()]),
            });
        }
    }
    persist::set(SHARES_KEY, &Seq(held));
}

/// Evidence of a rotation share that no honest shareholder signs: a partial
/// over the rotation message to a key set with another group key than the
/// one the chain adopted, or to one never adopted whose epoch is over. Of
/// a share's partials, the first that shows an offence.
fn rotation_fraud(share: &RotationShare, signer: &Hash) -> Option<ThresholdEvidence> {
    let honest =
        staking::key_set(share.to).is_some_and(|t| t.group_key() == Some(share.key.as_slice()));
    if honest {
        return None;
    }
    let subject = [&share.to.to_be_bytes()[..], &share.key].concat();
    share.partials.0.iter().find_map(|p| {
        let record = staking::key_set(p.key_set)?;
        if p.index == 0 || record.shareholders.0.get(p.index as usize - 1) != Some(signer) {
            return None;
        }
        let evidence = ThresholdEvidence {
            kind: offence::ROTATION,
            key_set: p.key_set,
            index: p.index,
            signature: p.signature.clone(),
            subject: subject.clone(),
        };
        rotation::offender(&evidence, state::height().unwrap_or(0) + 1).map(|_| evidence)
    })
}

/// Evidence of a finalize vote's partial `partial` over proposal `p` that no
/// honest shareholder signs: its anchor root is not the state root this node
/// executed at the anchored height, or the key set signing it had handed off
/// by then (spec 15 §5.1). Checked only when one of the two holds, so honest
/// partials cost nothing more.
pub fn inspect(chain_id: u64, partial: &PartialShare, p: &Proposal) -> Vec<Vec<u8>> {
    if p.anchor_height == 0 {
        return Vec::new();
    }
    let false_root =
        state::block_by_number(p.anchor_height).is_some_and(|b| b.state_root != p.anchor_root);
    let stale = rotation::replaced(partial.key_set).is_some_and(|r| r <= p.anchor_height);
    let kind = match (false_root, stale) {
        (true, _) => offence::ANCHOR,
        (false, true) => offence::STALE_KEY,
        (false, false) => return Vec::new(),
    };
    let evidence = ThresholdEvidence {
        kind,
        key_set: partial.key_set,
        index: partial.index,
        signature: partial.signature.clone(),
        subject: p.to_bytes(),
    };
    if rotation::on_record(&evidence)
        || rotation::offender(&evidence, state::height().unwrap_or(0) + 1).is_none()
    {
        return Vec::new();
    }
    report(chain_id, evidence)
}

/// Keeps `evidence` to report until chain state holds its offence, and
/// answers its envelope.
fn report(chain_id: u64, evidence: ThresholdEvidence) -> Vec<Vec<u8>> {
    let mut held: Vec<ThresholdEvidence> = persist::get::<Seq<ThresholdEvidence>>(EVIDENCE_KEY)
        .map(|s| s.0)
        .unwrap_or_default();
    if held.len() < EVIDENCE_CAP && !held.iter().any(|e| e.id() == evidence.id()) {
        held.push(evidence.clone());
        persist::set(EVIDENCE_KEY, &Seq(held));
    }
    let Some(env) = sign_envelope(
        chain_id,
        next_epoch(),
        envelope::EVIDENCE,
        evidence.to_bytes(),
    ) else {
        return Vec::new();
    };
    pool_add(chain_id, env.clone());
    alloc::vec![env]
}

/// Combines the shares this node holds into the handoff to the pending
/// target once they reach the active key set's threshold; the handoff's
/// envelope, once per target and epoch.
fn combine(chain_id: u64) -> Option<Vec<u8>> {
    let (active, target) = due()?;
    let epoch = next_epoch();
    let out_key = [HANDOFF_KEY, &target.id.to_be_bytes(), &epoch.to_be_bytes()].concat();
    if persist::get_raw(&out_key).is_some() {
        return None;
    }
    let partials: Vec<PartialShare> = shares()
        .into_iter()
        .filter(|s| s.to == target.id)
        .flat_map(|s| s.partials.0)
        .filter(|p| p.key_set == active.id)
        .collect();
    if partials.len() < active.threshold() {
        return None;
    }
    let message = rotation_message(chain_id, target.id, target.group_key()?);
    let signature = keystore(&KeystoreRequest::Combine {
        key_set: active.key_set.clone(),
        message,
        partials: Seq(partials),
    })?;
    let body = RotationCertificate {
        from: active.id,
        to: target.id,
        signature,
    }
    .to_bytes();
    let env = sign_envelope(chain_id, epoch, envelope::HANDOFF, body)?;
    persist::set_raw(&out_key, &env);
    pool_add(chain_id, env.clone());
    Some(env)
}

/// What this node broadcasts for key rotation after each block: its
/// rotation share, a partial for each share it holds of the active key
/// set, while a handoff is due, the handoff once it can combine one, and
/// the evidence it found that chain state does not hold yet.
pub fn rotation_step(chain_id: u64, me: &Hash) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut held: Vec<ThresholdEvidence> = persist::get::<Seq<ThresholdEvidence>>(EVIDENCE_KEY)
        .map(|s| s.0)
        .unwrap_or_default();
    let before = held.len();
    held.retain(|e| !rotation::on_record(e));
    if held.len() != before {
        persist::set(EVIDENCE_KEY, &Seq(held.clone()));
    }
    for evidence in held {
        if let Some(env) = sign_envelope(
            chain_id,
            next_epoch(),
            envelope::EVIDENCE,
            evidence.to_bytes(),
        ) {
            pool_add(chain_id, env.clone());
            out.push(env);
        }
    }
    let Some((active, target)) = due() else {
        persist::set(SHARES_KEY, &Seq::<RotationShare>(Vec::new()));
        return out;
    };
    let indices = indices_of(&active.shareholders.0, me);
    if !indices.is_empty() {
        // Keyed by both ends: a share is the active key set's partials over
        // the rotation to the target, and is never reused for another pair.
        let out_key = [
            RSHARE_KEY,
            &active.id.to_be_bytes(),
            &target.id.to_be_bytes(),
        ]
        .concat();
        let share = persist::get::<RotationShare>(&out_key).or_else(|| {
            let key = target.group_key()?.to_vec();
            let partials = sign_all(
                active.id,
                me,
                &indices,
                rotation_message(chain_id, target.id, &key),
            );
            if partials.is_empty() {
                return None;
            }
            let share = RotationShare {
                to: target.id,
                key,
                partials: Seq(partials),
            };
            persist::set(&out_key, &share);
            Some(share)
        });
        if let Some(share) = share
            && let Some(env) = sign_envelope(
                chain_id,
                next_epoch(),
                envelope::ROTATION_SHARE,
                share.to_bytes(),
            )
        {
            add_share(&share, me);
            out.push(env);
        }
    }
    let handoff = [
        HANDOFF_KEY,
        &target.id.to_be_bytes(),
        &next_epoch().to_be_bytes(),
    ]
    .concat();
    match persist::get_raw(&handoff) {
        Some(env) => {
            pool_add(chain_id, env.clone());
            out.push(env);
        }
        None => out.extend(combine(chain_id)),
    }
    out
}

/// Drops the envelopes that can no longer be recorded after the block at
/// `executed`: chain state holds them, their epoch or phase is over, or
/// the epoch's key set is already adopted.
pub fn pool_prune(executed: u64) {
    let pool = entries();
    let before = pool.len();
    let kept: Vec<Vec<u8>> = pool
        .into_iter()
        .filter(|e| {
            let held: Hash = e[..32].try_into().expect("32 bytes");
            DkgEnvelope::from_bytes(&e[32..]).is_ok_and(|env| wanted(&env, &held, executed))
        })
        .collect();
    if kept.len() != before {
        persist::set(POOL_KEY, &Seq(kept));
    }
}

/// The envelopes a proposal carries: the first `MAX_DKG` of the pool.
pub fn for_proposal() -> Seq<Vec<u8>> {
    let mut pool = pool();
    pool.truncate(MAX_DKG);
    Seq(pool)
}

/// This node's partial signatures over the version-2 certificate message
/// of the proposal at `height` with `hash`, one with each share it holds of
/// the active key set; empty when it holds none.
pub fn partials(chain_id: u64, me: &Hash, height: u64, hash: &Hash) -> Vec<PartialShare> {
    let Some(active) = staking::active() else {
        return Vec::new();
    };
    let indices = indices_of(&active.shareholders.0, me);
    if indices.is_empty() {
        return Vec::new();
    }
    sign_all(
        active.id,
        me,
        &indices,
        certificate_message(chain_id, active.id, height, hash),
    )
}

/// Whether `partial`, carried by a finalize vote of validator `signer`,
/// names the signer's own share of a key set the chain adopted.
pub fn belongs(partial: &PartialShare, signer: &Hash) -> bool {
    partial.index != 0
        && staking::key_set(partial.key_set)
            .is_some_and(|k| k.shareholders.0.get(partial.index as usize - 1) == Some(signer))
}

/// A version-2 threshold certificate for the proposal at `height` with
/// `hash`, when the partials of some key set that has been active reach its
/// threshold and combine into a signature that verifies under its group key.
pub fn certificate(
    chain_id: u64,
    height: u64,
    hash: &Hash,
    partials: &[PartialShare],
) -> Option<Vec<u8>> {
    let mut ids: Vec<u64> = partials.iter().map(|p| p.key_set).collect();
    ids.sort_unstable();
    ids.dedup();
    for id in ids {
        let Some(record) = staking::key_set(id).filter(|r| rotation::activated(r.id).is_some())
        else {
            continue;
        };
        let of_set: Vec<PartialShare> = partials
            .iter()
            .filter(|p| p.key_set == id)
            .cloned()
            .collect();
        if of_set.len() < record.threshold() {
            continue;
        }
        let request = KeystoreRequest::Combine {
            key_set: record.key_set,
            message: certificate_message(chain_id, id, height, hash),
            partials: Seq(of_set),
        };
        if let Some(signature) = keystore(&request) {
            return Some(certificate_bytes(id, height, hash, &signature));
        }
    }
    None
}

/// Whether `bytes` is a version-2 threshold certificate of proposal `p`,
/// with `hash`, signed by the key in force for it (spec 08 §7a): a key set
/// made active below `p`'s height and not handed off at or below its
/// anchor, which is the key an honest shareholder signs `p` with.
pub fn certifies(chain_id: u64, bytes: &[u8], p: &Proposal, hash: &Hash) -> bool {
    let Some(c) = threshold_certificate(bytes).filter(|c| c.version == 2) else {
        return false;
    };
    let Some(record) = staking::key_set(c.key_id) else {
        return false;
    };
    let in_force = rotation::activated(c.key_id).is_some_and(|a| a < p.height)
        && rotation::replaced(c.key_id).is_none_or(|r| r > p.anchor_height);
    in_force
        && c.height == p.height
        && c.block_hash == *hash
        && rotation::verify(
            &c.message(chain_id),
            c.signature,
            record.group_key().unwrap_or_default(),
        )
}
