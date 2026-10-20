//! The driver's half of the threshold key (spec 15 §6, spec 08 §4a): what
//! this node sends in each DKG phase, the pool of envelopes leaders put in
//! proposals, partial signatures on finalize votes, and their combination
//! into the certificates of spec 12 §7. Every step that needs a secret is a
//! request to the host's threshold keystore (`sign` with key role 2), so no
//! share or decryption key ever enters the kernel.

use alloc::vec;
use alloc::vec::Vec;

use solo_abi::chain::consensus::{KEY_ROLE, identity_preimage, signing_preimage};
use solo_abi::codec::Seq;
use solo_abi::staking::{
    DST_SIGNATURE, DkgEnvelope, DkgReply, DkgRequest, DkgRun, G2_LENGTH, KEY_ROLE_THRESHOLD, KIND_DKG, KeystoreRequest, MAX_DKG, PartialShare,
    certificate_bytes, certificate_message, certificate_parts, dkg_header, envelope, epoch_of, epoch_start,
};
use solo_abi::types::Hash;
use solo_abi::{Decode, Encode};
use solo_guest::host;

use crate::{persist, staking, state, tx};

/// Envelopes received and not yet on chain, for this node's proposals.
const POOL_KEY: &[u8] = b"dkg/pool";
/// Most envelopes the pool keeps.
const POOL_CAP: usize = 64;
/// What this node sends in a phase, once computed: `dkg/out/` ‖ epoch ‖ phase.
const OUT_KEY: &[u8] = b"dkg/out/";
/// This node's validator id, once learned.
const ID_KEY: &[u8] = b"dkg/id";

/// Sends `request` to the threshold keystore; its answer, if it has one.
pub fn keystore(request: &KeystoreRequest) -> Option<Vec<u8>> {
    let msg = request.to_bytes();
    let call = |buf: &mut Vec<u8>| {
        // SAFETY: valid pointers into our own buffers of the stated sizes.
        unsafe { host::__solo_import_sign(KEY_ROLE_THRESHOLD, msg.as_ptr(), msg.len() as u32, buf.as_mut_ptr(), buf.len() as u32) as usize }
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
    list.iter().position(|x| x == id).map_or(0, |i| i as u32 + 1)
}

fn signer(chain_id: u64, env: &DkgEnvelope) -> Option<Hash> {
    let body_hash = state::keccak256(&DkgEnvelope::signed_hash_preimage(env.kind, &env.body));
    let digest = state::keccak256(&signing_preimage(KIND_DKG, chain_id, env.epoch, &body_hash));
    tx::recover_pubkey(&digest, &env.signature.0).map(|pubkey| state::keccak256(&pubkey))
}

fn sign_envelope(chain_id: u64, epoch: u64, kind: u8, body: Vec<u8>) -> Option<Vec<u8>> {
    let body_hash = state::keccak256(&DkgEnvelope::signed_hash_preimage(kind, &body));
    let signature = persist::sign(KEY_ROLE, &state::keccak256(&signing_preimage(KIND_DKG, chain_id, epoch, &body_hash)))?;
    Some(DkgEnvelope { epoch, kind, body, signature }.to_bytes())
}

fn request(run: &DkgRun, dealer: u32, recipient: u32, upto: u8) -> KeystoreRequest {
    let previous = run.previous.and_then(staking::key_set);
    KeystoreRequest::Dkg(DkgRequest {
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
    })
}

fn ask(run: &DkgRun, dealer: u32, recipient: u32, upto: u8) -> Option<DkgReply> {
    keystore(&request(run, dealer, recipient, upto)).and_then(|r| DkgReply::from_bytes(&r).ok())
}

/// Installs this node's share of key set `id` again from the run that made
/// it, as after a restart that emptied the keystore; whether it now holds it.
pub fn install(id: u64, me: &Hash) -> bool {
    let Some(run) = staking::dkg_run(id) else { return false };
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
    let phase = ((next - epoch_start(epoch, p.epoch_blocks)) / p.dkg_phase_blocks).min(3) as u8;
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
    let (as_dealer, as_recipient) = if phase == 0 || phase == 2 { (dealer, 0) } else { (0, recipient) };
    let mut reply = ask(&run, as_dealer, as_recipient, phase);
    if reply.is_none()
        && as_dealer != 0
        && let Some(previous) = run.previous
        && install(previous, me)
    {
        // A resharing dealer deals its current share, which a restart may have
        // taken out of the keystore.
        reply = ask(&run, as_dealer, as_recipient, phase);
    }
    let envelope = match reply? {
        DkgReply::Message(m) => sign_envelope(chain_id, epoch, envelope::MESSAGE, m),
        DkgReply::Finished(vote) => sign_envelope(chain_id, epoch, envelope::CONFIRM, vote.to_bytes()),
        DkgReply::Idle => None,
    };
    persist::set_raw(&out_key, envelope.as_deref().unwrap_or(&[]));
    envelope
}

/// The pool's entries: each envelope's signer followed by the envelope.
fn entries() -> Vec<Vec<u8>> {
    let mut entries = persist::get::<Seq<Vec<u8>>>(POOL_KEY).map(|s| s.0).unwrap_or_default();
    entries.retain(|e| e.len() > 32);
    entries
}

/// The envelopes this node holds for proposals.
pub fn pool() -> Vec<Vec<u8>> {
    entries().into_iter().map(|e| e[32..].to_vec()).collect()
}

/// The slot an envelope takes in the pool and on chain: for a DKG message
/// its phase and sender index, for a confirmation its signer. The pool
/// keeps one envelope per slot.
fn slot(env: &DkgEnvelope, signer: &Hash) -> Option<(u8, u32, Hash)> {
    if env.kind == envelope::MESSAGE { dkg_header(&env.body).map(|(at, _, index)| (at, index, ZERO)) } else { Some((3, 0, *signer)) }
}

const ZERO: Hash = [0; 32];

/// Whether the envelope `env`, signed by `signer`, can still be recorded
/// in a block after the one at `executed` (spec 15 §6.2): it names the
/// epoch of the next block, whose run exists; a DKG message is of the run's
/// session, of the current phase or a later one, and from the sender its
/// index names, with nothing recorded for that sender and phase; a
/// confirmation is from a member of the epoch's set that has not
/// confirmed, while no key set of the epoch is adopted.
fn wanted(env: &DkgEnvelope, signer: &Hash, executed: u64) -> bool {
    let p = staking::params();
    if p.epoch_blocks == 0 || p.dkg_phase_blocks == 0 {
        return false;
    }
    let next = executed + 1;
    let epoch = epoch_of(next, p.epoch_blocks);
    let phase = ((next - epoch_start(epoch, p.epoch_blocks)) / p.dkg_phase_blocks).min(3) as u8;
    if env.epoch != epoch {
        return false;
    }
    let Some(run) = staking::dkg_run(epoch) else { return false };
    if env.kind == envelope::MESSAGE {
        let Some((at, session, index)) = dkg_header(&env.body) else { return false };
        let roster = if at == 1 { &run.recipients.0 } else { &run.dealers.0 };
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

/// Keeps an envelope for this node's proposals when it can still be
/// recorded after the executed head, it fills a slot the pool does not hold
/// yet, and the pool has room. Every envelope is checked before it is
/// kept, so a peer can fill the pool only with what the run's own
/// participants signed, one envelope per participant and phase.
pub fn pool_add(chain_id: u64, raw: Vec<u8>) {
    let Ok(env) = DkgEnvelope::from_bytes(&raw) else { return };
    let mut pool = entries();
    if pool.len() >= POOL_CAP {
        return;
    }
    let Some(signer) = signer(chain_id, &env) else { return };
    if !wanted(&env, &signer, state::height().unwrap_or(0)) {
        return;
    }
    let taken = slot(&env, &signer);
    let occupied = pool.iter().any(|e| {
        let held: Hash = e[..32].try_into().expect("32 bytes");
        DkgEnvelope::from_bytes(&e[32..]).ok().and_then(|other| slot(&other, &held)) == taken
    });
    if occupied {
        return;
    }
    pool.push([&signer[..], &raw].concat());
    persist::set(POOL_KEY, &Seq(pool));
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

/// This node's partial signature over the certificate message of the
/// proposal at `height` with `hash`, with the share of the active key set.
pub fn partial(chain_id: u64, me: &Hash, height: u64, hash: &Hash) -> Option<PartialShare> {
    let active = staking::active()?;
    let index = index_of(&active.shareholders.0, me);
    if index == 0 {
        return None;
    }
    let request = KeystoreRequest::Sign { key_set: active.id, message: certificate_message(chain_id, height, hash) };
    let signature = keystore(&request).or_else(|| if install(active.id, me) { keystore(&request) } else { None })?;
    Some(PartialShare { key_set: active.id, index, signature })
}

/// Whether `partial`, carried by a finalize vote of validator `signer`,
/// names the signer's own share of a key set the chain adopted.
pub fn belongs(partial: &PartialShare, signer: &Hash) -> bool {
    partial.index != 0 && staking::key_set(partial.key_set).is_some_and(|k| k.shareholders.0.get(partial.index as usize - 1) == Some(signer))
}

/// A threshold certificate for the proposal at `height` with `hash`, when
/// the partials of some key set reach its threshold and combine into a
/// signature that verifies under the group key.
pub fn certificate(chain_id: u64, height: u64, hash: &Hash, partials: &[PartialShare]) -> Option<Vec<u8>> {
    let message = certificate_message(chain_id, height, hash);
    let mut ids: Vec<u64> = partials.iter().map(|p| p.key_set).collect();
    ids.sort_unstable();
    ids.dedup();
    for id in ids {
        let Some(record) = staking::key_set(id) else { continue };
        let of_set: Vec<PartialShare> = partials.iter().filter(|p| p.key_set == id).cloned().collect();
        if of_set.len() < record.threshold() {
            continue;
        }
        let request = KeystoreRequest::Combine { key_set: record.key_set, message: message.clone(), partials: Seq(of_set) };
        if let Some(signature) = keystore(&request) {
            return Some(certificate_bytes(height, hash, &signature));
        }
    }
    None
}

/// Whether `bytes` is a threshold certificate of the proposal at `height`
/// with `hash` that verifies under the chain's group key.
pub fn certifies(chain_id: u64, bytes: &[u8], height: u64, hash: &Hash) -> bool {
    let Some((at, block, signature)) = certificate_parts(bytes) else { return false };
    let Some(key) = staking::group_key() else { return false };
    if at != height || block != *hash || key.len() != G2_LENGTH {
        return false;
    }
    let message = certificate_message(chain_id, height, hash);
    // SAFETY: valid pointers into our own buffers of the sizes the host reads.
    unsafe {
        host::__solo_import_bls12381_verify(
            message.as_ptr(),
            message.len() as u32,
            signature.as_ptr(),
            key.as_ptr(),
            DST_SIGNATURE.as_ptr(),
            DST_SIGNATURE.len() as u32,
        ) == 0
    }
}
