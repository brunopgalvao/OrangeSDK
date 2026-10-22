//! The reference driver: Simplex consensus (spec 08). Views rotate through
//! the validator set; a leader proposes a block extending the notarized tip,
//! validators vote, a quorum of stake notarizes, a second quorum of finalize
//! votes finalizes the block and every ancestor. A quorum for any view at or
//! above the current one moves a node past it, and a node that hears from a
//! peer stuck in an older view sends it the certificates that let it catch
//! up, so validators that drifted apart converge. With staking, views belong
//! to epochs: the set of each epoch votes in its views, and a node enters
//! the next epoch's first view once it has executed the epoch's last block.
//! With one validator it degenerates into a paced single-node chain, which
//! is what `solo dev` runs.

use alloc::vec::Vec;

use solo_abi::chain::consensus::{
    EQUIVOCATION_PENALTY, KEY_ROLE, KIND_FINALIZE, KIND_PROPOSE, KIND_VOTE, MAX_BACKOFF, MAX_EVIDENCE, TOPIC, identity_preimage, leader,
    propose_timer, signing_preimage, timeout_timer, timer_view, view_timeout_ms,
};
use solo_abi::chain::{
    BLOCK_GAS_LIMIT, BlockHeader, Certificate, ConsensusMessage, Evidence, GenesisParams, Participation, Proposal, Signature, SignedHash, SignedVote, SimplexState,
    SyncRequest, SyncResponse, keys,
};
use solo_abi::bridge::FinalityProof;
use solo_abi::codec::Seq;
use solo_abi::staking::{MAX_DKG, PartialShare, epoch_end, epoch_of, first_view, view_epoch};
use solo_abi::types::{Block, Effect, Hash, Input, MigrateArgs};
use solo_abi::{Decode, Encode};

use crate::{dkg, persist, staking, state, stf, tx};

const STATE_KEY: &[u8] = b"simplex/state";
/// The certificate that justified entering the current view.
const ENTRY_KEY: &[u8] = b"simplex/entry";
/// The certificate that made the current tip the tip.
const TIP_KEY: &[u8] = b"simplex/tip";
/// Evidence found here that chain state does not hold yet.
const PENDING_EVIDENCE_KEY: &[u8] = b"simplex/evidence";
/// Messages for views of the epoch after this node's, each the delivering
/// peer and the signer followed by the payload.
const FUTURE_KEY: &[u8] = b"simplex/future";
/// Most messages kept for a later epoch.
const FUTURE_CAP: usize = 64;
/// Most messages kept for a later epoch from one signer.
const FUTURE_PER_SIGNER: usize = 4;
/// Whether the outstanding sync request was sent for a message nobody
/// known signed, so any verified trigger may replace it.
const WEAK_SYNC_KEY: &[u8] = b"simplex/weak_sync";
/// The height a restarted node re-executes its own finalized blocks up to
/// (spec 08 §7), while it does; 0 or absent otherwise.
const REPLAY_KEY: &[u8] = b"simplex/replay";
/// The block log (spec 22 §5): per finalized height, under `local/` in chain
/// state so that it reaches the disk with the block it names, the proposal,
/// its finalize certificate and its threshold certificate. A node whose
/// chain state is ahead of its tables takes the heights between from here.
const LOG_PROPOSAL: &[u8] = b"local/log/prop/";
const LOG_CERTIFICATE: &[u8] = b"local/log/cert/";
const LOG_THRESHOLD: &[u8] = b"local/log/bcert/";
/// Heights the block log keeps behind the finalized head.
const LOG_WINDOW: u64 = 64;
const ZERO: Hash = [0; 32];

/// The anchor a leader puts in its proposal (spec 08 §5): its executed
/// head and that block's state root, or none before the first block.
fn anchor() -> (u64, Hash) {
    state::height().and_then(|h| state::block_by_number(h).map(|b| (h, b.state_root))).unwrap_or((0, ZERO))
}

/// Whether a shareholder signs the certificate of `p` (spec 08 §6a): its
/// anchor is none, or names a block below it that this node has executed,
/// with that block's state root. A certificate therefore vouches for the
/// anchor as it does for the proposal (spec 17 §4).
fn anchored(p: &Proposal) -> bool {
    if p.anchor_height == 0 {
        return p.anchor_root == ZERO;
    }
    p.anchor_height < p.height && state::block_by_number(p.anchor_height).is_some_and(|b| b.state_root == p.anchor_root)
}

/// `query::FINALITY_PROOF` (spec 17 §5): the threshold certificate this
/// node stored for `height` and the encoded proposal it certifies.
pub fn finality_proof(height: u64) -> Option<FinalityProof> {
    let certificate = persist::get_raw(&key(b"bcert/", &[&height.to_le_bytes()]))?;
    let hash = solo_abi::rotation::threshold_certificate(&certificate)?.block_hash;
    let proposal = persist::get_raw(&key(b"prop/", &[&hash]))?;
    Some(FinalityProof { certificate, proposal })
}

/// The persisted driver state.
pub fn load() -> SimplexState {
    persist::get(STATE_KEY).unwrap_or(SimplexState { view: 1, ..SimplexState::default() })
}

fn save(s: &SimplexState) {
    persist::set(STATE_KEY, s);
}

/// `kernel_migrate`: adopts the previous kernel's driver state when it decodes.
pub fn migrate(args: &MigrateArgs) {
    match SimplexState::from_bytes(&args.driver_state) {
        Ok(s) => save(&s),
        Err(_) => solo_guest::trap(),
    }
}

fn key(prefix: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let mut k = prefix.to_vec();
    for p in parts {
        k.extend_from_slice(p);
    }
    k
}

/// Most proposals one sync response carries, give or take one batch.
const SYNC_BATCH: u64 = 16;

/// A validator set as ids and weights, in leader-rotation order.
type Set = Vec<(Hash, u64)>;

/// Whether `votes`, with distinct indices into `set`, weigh more than two
/// thirds of the set's total weight (spec 08 §1). Repeated or out-of-range
/// indices count nothing.
fn is_quorum(set: &Set, votes: &[SignedVote]) -> bool {
    let total: u128 = set.iter().map(|v| u128::from(v.1)).sum();
    let mut seen = alloc::vec![false; set.len()];
    let mut weight = 0u128;
    for vote in votes {
        let i = vote.validator as usize;
        if let Some(slot) = seen.get_mut(i)
            && !*slot
        {
            *slot = true;
            weight += u128::from(set[i].1);
        }
    }
    weight * 3 > total * 2
}

/// One driver step's working set.
struct Ctx {
    s: SimplexState,
    chain_id: u64,
    params: GenesisParams,
    /// The epoch of the current view.
    epoch: u64,
    /// The validator set of `epoch`.
    set: Set,
    effects: Vec<Effect>,
    /// The peer the current input came from, if it came from one.
    peer: Option<Hash>,
}

impl Ctx {
    fn open() -> Ctx {
        let mut s = load();
        s.now_ms = persist::time_now();
        let params = state::params();
        let mut c = Ctx { s, chain_id: state::chain_id(), params, epoch: 0, set: Vec::new(), effects: Vec::new(), peer: None };
        c.load_set();
        c
    }

    /// The epoch this node works in: its view's, unless chain state has not
    /// reached that epoch (a node that lost its chain state), then the epoch
    /// of the next block to execute, whose set it knows.
    fn load_set(&mut self) {
        let blocks = self.params.staking.epoch_blocks;
        self.epoch = if blocks == 0 { 0 } else { view_epoch(self.s.view).min(epoch_of(state::height().unwrap_or(0) + 1, blocks)) };
        self.set = staking::set_entries_in(blocks, self.epoch).unwrap_or_default();
    }

    fn n(&self) -> usize {
        self.set.len()
    }

    /// The epoch of `view`: its high 32 bits with staking, always 0 without.
    fn view_epoch(&self, view: u64) -> u64 {
        if self.params.staking.epoch_blocks == 0 { 0 } else { view_epoch(view) }
    }

    /// The last height of `epoch`, with staking.
    fn epoch_end(&self, epoch: u64) -> Option<u64> {
        let blocks = self.params.staking.epoch_blocks;
        (blocks != 0).then(|| epoch_end(epoch, blocks))
    }

    /// Whether `p` extends its epoch's last block: a suffix proposal, which
    /// only finalizes that block and is never executed (spec 08 §3a).
    fn is_suffix(&self, p: &Proposal) -> bool {
        self.epoch_end(self.view_epoch(p.view)).is_some_and(|end| p.height > end)
    }

    /// The validator set of the epoch of `view`, if this node knows it.
    fn set_for(&self, view: u64) -> Option<Set> {
        let epoch = self.view_epoch(view);
        if epoch == self.epoch { Some(self.set.clone()) } else { staking::set_entries_in(self.params.staking.epoch_blocks, epoch) }
    }

    fn quorum(&self, view: u64, votes: &[SignedVote]) -> bool {
        self.set_for(view).is_some_and(|set| is_quorum(&set, votes))
    }

    fn is_leader(&self, view: u64) -> bool {
        self.n() > 0 && self.view_epoch(view) == self.epoch && self.s.me == Some(leader(view, self.n()) as u32)
    }

    fn message_hash(&self, kind: u8, view: u64, hash: &Hash) -> Hash {
        state::keccak256(&signing_preimage(kind, self.chain_id, view, hash))
    }

    fn signer(&self, kind: u8, view: u64, hash: &Hash, sig: &Signature) -> Option<Hash> {
        tx::recover_pubkey(&self.message_hash(kind, view, hash), &sig.0).map(|pubkey| state::keccak256(&pubkey))
    }

    /// Who signed `kind(view, hash)`, as an index into the set of the view's epoch.
    fn verify(&self, kind: u8, view: u64, hash: &Hash, sig: &Signature) -> Option<u32> {
        let set = self.set_for(view)?;
        let id = self.signer(kind, view, hash, sig)?;
        set.iter().position(|v| v.0 == id).map(|i| i as u32)
    }

    fn sign(&self, kind: u8, view: u64, hash: &Hash) -> Option<Signature> {
        persist::sign(KEY_ROLE, &self.message_hash(kind, view, hash))
    }

    /// Learns this node's validator index by signing a fixed message; none
    /// while its view is in an epoch whose set it does not know yet.
    fn identify(&self) -> Option<u32> {
        if self.view_epoch(self.s.view) != self.epoch {
            return None;
        }
        let msg = state::keccak256(&identity_preimage(self.chain_id));
        let sig = persist::sign(KEY_ROLE, &msg)?;
        let pubkey = tx::recover_pubkey(&msg, &sig.0)?;
        let id = state::keccak256(&pubkey);
        self.set.iter().position(|v| v.0 == id).map(|i| i as u32)
    }

    fn broadcast(&mut self, m: &ConsensusMessage) {
        self.effects.push(Effect::Broadcast { topic: TOPIC, payload: m.to_bytes() });
    }

    fn proposal(hash: &Hash) -> Option<Proposal> {
        persist::get(&key(b"prop/", &[hash]))
    }

    fn store_proposal(hash: &Hash, proposal: &Proposal) {
        persist::set(&key(b"prop/", &[hash]), proposal);
    }

    /// Records a vote under `prefix` for `(view, hash)`.
    fn add_vote(prefix: &[u8], view: u64, hash: &Hash, vote: SignedVote) {
        let k = key(prefix, &[&view.to_le_bytes(), hash]);
        let mut votes: Seq<SignedVote> = persist::get(&k).unwrap_or_default();
        if !votes.0.iter().any(|v| v.validator == vote.validator) {
            votes.0.push(vote);
            persist::set(&k, &votes);
        }
    }

    fn votes(prefix: &[u8], view: u64, hash: &Hash) -> Seq<SignedVote> {
        persist::get(&key(prefix, &[&view.to_le_bytes(), hash])).unwrap_or_default()
    }

    /// Keeps a threshold partial signature for `(view, hash)`, one per key
    /// set and shareholder.
    fn add_partial(view: u64, hash: &Hash, partial: PartialShare) {
        let k = key(b"part/", &[&view.to_le_bytes(), hash]);
        let mut partials: Seq<PartialShare> = persist::get(&k).unwrap_or_default();
        if !partials.0.iter().any(|p| (p.key_set, p.index) == (partial.key_set, partial.index)) {
            partials.0.push(partial);
            persist::set(&k, &partials);
        }
    }

    fn enter_view(&mut self, view: u64) {
        if view > self.s.view {
            // The old view's timers are stale; the host need not keep them.
            self.effects.push(Effect::CancelTimer { timer_id: timeout_timer(self.s.view) });
            self.effects.push(Effect::CancelTimer { timer_id: propose_timer(self.s.view) });
        }
        self.s.view = view;
        self.s.voted = false;
        self.s.timed_out = false;
        self.arm();
    }

    /// Enters the first view of `epoch` once this node has executed the last
    /// block of the epoch before (spec 08 §3a): that block is the finalized
    /// head and becomes the tip, its finalize certificate the tip and entry
    /// certificate, and messages kept for the new epoch are taken up again.
    /// A node whose view is already past the first view keeps it.
    fn enter_epoch(&mut self, epoch: u64) {
        let Some(set) = staking::set_entries_in(self.params.staking.epoch_blocks, epoch) else { return };
        self.epoch = epoch;
        self.set = set;
        let height = self.s.finalized_height;
        // A tip of an earlier epoch is the last block or a suffix proposal on it; a tip
        // of this epoch or a later one (a restarted node catching up) stays.
        if self.view_epoch(self.s.tip_view) < epoch
            && let Some(head) = persist::get::<Hash>(&key(b"final/", &[&height.to_le_bytes()])).and_then(|h| Self::proposal(&h))
            && let Some(certificate) = persist::get::<Certificate>(&key(b"cert/", &[&height.to_le_bytes()]))
        {
            persist::set(TIP_KEY, &certificate);
            persist::set(ENTRY_KEY, &certificate);
            self.s.tip_view = head.view;
            self.s.tip_height = head.height;
            self.s.tip_hash = state::keccak256(&head.to_bytes());
            self.s.tip_timestamp_ms = head.timestamp_ms;
        }
        let view = first_view(epoch);
        if view > self.s.view {
            self.effects.push(Effect::CancelTimer { timer_id: timeout_timer(self.s.view) });
            self.effects.push(Effect::CancelTimer { timer_id: propose_timer(self.s.view) });
            self.s.view = view;
            self.s.me = self.identify();
            self.s.voted = false;
            self.s.timed_out = false;
            self.arm();
        } else {
            self.s.me = self.identify();
        }
        let future: Seq<Vec<u8>> = persist::get(FUTURE_KEY).unwrap_or_default();
        persist::set(FUTURE_KEY, &Seq::<Vec<u8>>(Vec::new()));
        let peer = self.peer;
        for entry in future.0.iter().filter(|e| e.len() > 64) {
            self.peer = Some(entry[..32].try_into().expect("32 bytes"));
            if let Ok(m) = ConsensusMessage::from_bytes(&entry[64..]) {
                self.on_message(m);
            }
        }
        self.peer = peer;
    }

    /// Enters the epoch of the next block to execute, if this node is still
    /// in an earlier one.
    fn catch_up_epoch(&mut self) {
        let blocks = self.params.staking.epoch_blocks;
        if blocks == 0 {
            return;
        }
        let epoch = epoch_of(state::height().unwrap_or(0) + 1, blocks);
        if epoch > self.epoch {
            self.enter_epoch(epoch);
        }
    }

    /// A message for an epoch this node has not entered, in a view of
    /// `epoch`. Its set is not known yet, so the most this node can check is
    /// that a registered validator that is not jailed signed it (for a
    /// certificate, its first vote). Such a message is kept when `epoch` is
    /// the next one, at most `FUTURE_PER_SIGNER` per signer, and its peer
    /// is asked for the blocks that lead there. Any other one only asks,
    /// and never in place of a request a verified message sent (spec 08 §3a).
    fn keep_for_later(&mut self, m: &ConsensusMessage, epoch: u64) {
        let Some(peer) = self.peer else { return };
        let Some(signer) = self.future_signer(m).filter(|id| staking::record(id).is_some_and(|r| !r.jailed)) else {
            self.send_sync(true);
            return;
        };
        let mut future: Seq<Vec<u8>> = persist::get(FUTURE_KEY).unwrap_or_default();
        let held = future.0.iter().filter(|e| e.get(32..64) == Some(&signer[..])).count();
        if epoch == self.epoch + 1 && future.0.len() < FUTURE_CAP && held < FUTURE_PER_SIGNER {
            future.0.push([&peer[..], &signer[..], &m.to_bytes()].concat());
            persist::set(FUTURE_KEY, &future);
        }
        self.request_sync();
    }

    /// Who signed `m`: the proposer, the voter, or a certificate's first voter.
    fn future_signer(&self, m: &ConsensusMessage) -> Option<Hash> {
        match m {
            ConsensusMessage::Propose { proposal, signature } => {
                self.signer(KIND_PROPOSE, proposal.view, &state::keccak256(&proposal.to_bytes()), signature)
            }
            ConsensusMessage::Vote { view, hash, signature } => self.signer(KIND_VOTE, *view, hash, signature),
            ConsensusMessage::Finalize { view, hash, signature } | ConsensusMessage::FinalizeShare { view, hash, signature, .. } => {
                self.signer(KIND_FINALIZE, *view, hash, signature)
            }
            ConsensusMessage::Certificate { certificate, .. } => {
                let first = certificate.votes.0.first()?;
                self.signer(certificate.kind, certificate.view, &certificate.hash, &first.signature)
            }
            ConsensusMessage::Dkg { .. } => None,
        }
    }

    /// Arms the current view's timers: the timeout, and the leader's proposal
    /// time unless it already voted or timed out in this view. A restarted
    /// node arms its view without forgetting what it did there, so it never
    /// votes twice in one view.
    fn arm(&mut self) {
        let view = self.s.view;
        // A sync that never answered is retried on the next trigger.
        self.s.sync_pending = false;
        self.s.proposing = false;
        self.s.answered = Seq(Vec::new());
        self.s.view_started_ms = self.s.now_ms;
        let slot = self.params.slot_ms;
        self.effects.push(Effect::SetTimer { timer_id: timeout_timer(view), deadline_ms: self.s.now_ms + self.timeout_ms() });
        if self.is_leader(view) && !self.s.voted && !self.s.timed_out {
            let at = self.s.tip_timestamp_ms + slot;
            if at <= self.s.now_ms {
                self.request_mempool();
            } else {
                self.effects.push(Effect::SetTimer { timer_id: propose_timer(view), deadline_ms: at });
            }
        }
    }

    fn timeout_ms(&self) -> u64 {
        view_timeout_ms(self.params.slot_ms, self.s.backoff)
    }

    fn request_mempool(&mut self) {
        self.s.proposing = true;
        let skip = Seq(self.carried());
        self.effects.push(Effect::MempoolTake { max_bytes: 1 << 20, max_gas: BLOCK_GAS_LIMIT, skip });
    }

    fn on_timer(&mut self, timer_id: u64, now_ms: u64) {
        self.s.now_ms = now_ms;
        let view = timer_view(timer_id);
        if view != self.s.view {
            return;
        }
        if timer_id == timeout_timer(view) {
            // The first firing times the view out; every later one repeats the
            // same timeout vote, which peers may have missed, and lets peers
            // that lag ask for certificates again.
            self.s.answered = Seq(Vec::new());
            self.s.timed_out = true;
            self.cast(KIND_VOTE, view, ZERO);
            self.check_timeout(view);
            if self.s.view == view {
                self.effects.push(Effect::SetTimer { timer_id, deadline_ms: now_ms + self.timeout_ms() });
            }
        } else if self.is_leader(view) && !self.s.proposing && !self.s.voted && !self.s.timed_out {
            self.request_mempool();
        }
    }

    fn on_mempool(&mut self, txs: &[Vec<u8>]) {
        let view = self.s.view;
        if !(self.s.proposing && self.is_leader(view) && !self.s.voted && !self.s.timed_out) {
            return;
        }
        self.s.proposing = false;
        let mut proposal = Proposal {
            view,
            height: self.s.tip_height + 1,
            parent: self.s.tip_hash,
            timestamp_ms: self.s.now_ms.max(self.s.tip_timestamp_ms + 1),
            anchor_height: 0,
            anchor_root: ZERO,
            txs: Seq(Vec::new()),
            evidence: Seq(Vec::new()),
            dkg: Seq(Vec::new()),
        };
        // A suffix proposal carries nothing: it only finalizes the epoch's last block.
        if !self.is_suffix(&proposal) {
            proposal.txs = Seq(self.select(txs));
            proposal.evidence = Self::pending_evidence();
            proposal.dkg = dkg::for_proposal();
            (proposal.anchor_height, proposal.anchor_root) = anchor();
        }
        let hash = state::keccak256(&proposal.to_bytes());
        let Some(signature) = self.sign(KIND_PROPOSE, view, &hash) else { return };
        self.broadcast(&ConsensusMessage::Propose { proposal: proposal.clone(), signature });
        self.handle_proposal(proposal, hash);
    }

    /// The hashes of the transactions that the unexecuted ancestors of the tip
    /// carry. A leader can extend a block it has not executed yet (it executes
    /// on finalization, a message delay after notarization), and until then
    /// its mempool still holds that block's transactions; the take skips them
    /// so that they do not use up the next block's budget.
    fn carried(&self) -> Vec<[u8; 32]> {
        let executed = state::height().unwrap_or(0);
        let mut carried = Vec::new();
        let mut cursor = (self.s.tip_height > executed).then_some(self.s.tip_hash);
        while let Some(hash) = cursor {
            let Some(p) = Self::proposal(&hash) else { break };
            carried.extend(p.txs.0.iter().map(|raw| state::keccak256(raw)));
            cursor = (p.height > executed + 1).then_some(p.parent);
        }
        carried
    }

    /// The mempool transactions to propose, at most `max_txs`, leaving out any
    /// that an unexecuted ancestor of the tip carries (should the host have
    /// handed them out anyway) or that has already run.
    fn select(&self, txs: &[Vec<u8>]) -> Vec<Vec<u8>> {
        let carried = self.carried();
        let mut selected = Vec::new();
        for raw in txs {
            if selected.len() >= self.params.max_txs as usize {
                break;
            }
            let hash = state::keccak256(raw);
            if !carried.contains(&hash) && !stf::has_run(&hash) {
                selected.push(raw.clone());
            }
        }
        selected
    }

    /// Evidence this node found that chain state does not record yet, as
    /// much as one proposal carries.
    fn pending_evidence() -> Seq<Evidence> {
        let mut pending: Seq<Evidence> = persist::get(PENDING_EVIDENCE_KEY).unwrap_or_default();
        let before = pending.0.len();
        pending.0.retain(|e| state::get_raw(&key(keys::EVIDENCE_SEEN, &[&e.id()])).is_none());
        if pending.0.len() != before {
            persist::set(PENDING_EVIDENCE_KEY, &pending);
        }
        pending.0.truncate(MAX_EVIDENCE);
        pending
    }

    fn on_message(&mut self, m: ConsensusMessage) {
        let view = match &m {
            ConsensusMessage::Propose { proposal, .. } => Some(proposal.view),
            ConsensusMessage::Vote { view, .. } | ConsensusMessage::Finalize { view, .. } | ConsensusMessage::FinalizeShare { view, .. } => Some(*view),
            ConsensusMessage::Certificate { certificate, .. } => Some(certificate.view),
            ConsensusMessage::Dkg { .. } => None,
        };
        if let Some(epoch) = view.map(|v| self.view_epoch(v)).filter(|e| *e > self.epoch) {
            self.keep_for_later(&m, epoch);
            return;
        }
        match m {
            ConsensusMessage::Propose { proposal, signature } => {
                let view = proposal.view;
                if self.n() == 0 || view == 0 {
                    return;
                }
                let Some(set) = self.set_for(view) else { return };
                let hash = state::keccak256(&proposal.to_bytes());
                let proposer = leader(view, set.len()) as u32;
                if self.verify(KIND_PROPOSE, view, &hash, &signature) != Some(proposer) {
                    return;
                }
                self.observe(KIND_PROPOSE, view, proposer, SignedHash { hash, signature });
                if view < self.s.view {
                    self.forward_certificates(view, proposer);
                    if self.view_epoch(view) == self.epoch {
                        self.late_proposal(proposal, hash);
                    }
                } else {
                    self.handle_proposal(proposal, hash);
                }
            }
            ConsensusMessage::Vote { view, hash, signature } => {
                if view < self.s.view {
                    self.late_vote(view, hash, signature);
                    return;
                }
                let Some(validator) = self.verify(KIND_VOTE, view, &hash, &signature) else { return };
                self.observe(KIND_VOTE, view, validator, SignedHash { hash, signature });
                Self::add_vote(b"votes/", view, &hash, SignedVote { validator, signature });
                if hash == ZERO {
                    self.check_timeout(view);
                } else {
                    self.check_notarization(view, &hash);
                }
            }
            ConsensusMessage::Finalize { view, hash, signature } => self.on_finalize(view, hash, signature, None),
            ConsensusMessage::FinalizeShare { view, hash, signature, partial } => self.on_finalize(view, hash, signature, Some(partial)),
            ConsensusMessage::Certificate { certificate, proposal } => self.on_certificate(certificate, proposal),
            ConsensusMessage::Dkg { envelope } => {
                for envelope in dkg::receive(self.chain_id, envelope) {
                    self.broadcast(&ConsensusMessage::Dkg { envelope });
                }
            }
        }
    }

    /// A finalize vote, with the voter's partial signature when it holds a
    /// share. Finalize votes of an epoch this node has left only matter as
    /// evidence.
    fn on_finalize(&mut self, view: u64, hash: Hash, signature: Signature, partial: Option<PartialShare>) {
        let Some(validator) = self.verify(KIND_FINALIZE, view, &hash, &signature) else { return };
        self.observe(KIND_FINALIZE, view, validator, SignedHash { hash, signature });
        if self.view_epoch(view) < self.epoch {
            return;
        }
        if let Some(partial) = partial
            && dkg::belongs(&partial, &self.set[validator as usize].0)
        {
            // A partial no honest shareholder signs is evidence (spec 15 §5.1).
            if let Some(p) = Self::proposal(&hash) {
                for envelope in dkg::inspect(self.chain_id, &partial, &p) {
                    self.broadcast(&ConsensusMessage::Dkg { envelope });
                }
            }
            Self::add_partial(view, &hash, partial);
        }
        Self::add_vote(b"fin/", view, &hash, SignedVote { validator, signature });
        self.check_finalization(view, &hash);
    }

    fn handle_proposal(&mut self, proposal: Proposal, hash: Hash) {
        Self::store_proposal(&hash, &proposal);
        if proposal.height > self.s.tip_height + 1 {
            self.request_sync();
        }
        let extends_tip = proposal.parent == self.s.tip_hash && proposal.height == self.s.tip_height + 1;
        let bounded = proposal.evidence.0.len() <= MAX_EVIDENCE && proposal.dkg.0.len() <= MAX_DKG;
        let empty = proposal.txs.0.is_empty() && proposal.evidence.0.is_empty() && proposal.dkg.0.is_empty();
        let fits = !self.is_suffix(&proposal) || empty;
        if proposal.view == self.s.view && extends_tip && bounded && fits && !self.s.voted && !self.s.timed_out {
            self.s.voted = true;
            self.cast(KIND_VOTE, proposal.view, hash);
        }
        self.check_notarization(proposal.view, &hash);
    }

    /// A proposal for a view this node has left matters only when this node
    /// holds a quorum for it and lacks the proposal itself.
    fn late_proposal(&mut self, proposal: Proposal, hash: Hash) {
        let view = proposal.view;
        let certified = self.quorum(view, &Self::votes(b"votes/", view, &hash).0) || self.quorum(view, &Self::votes(b"fin/", view, &hash).0);
        if !certified || Self::proposal(&hash).is_some() {
            return;
        }
        Self::store_proposal(&hash, &proposal);
        self.check_notarization(view, &hash);
        self.check_finalization(view, &hash);
    }

    /// A vote for a view this node has left: its sender may be stuck there.
    fn late_vote(&mut self, view: u64, hash: Hash, signature: Signature) {
        // A block vote for what this node notarized in the previous view is
        // routine: its sender is about to notarize the same proposal itself.
        let routine = hash != ZERO && view + 1 == self.s.view && persist::get::<Hash>(&key(b"notar/", &[&view.to_le_bytes()])) == Some(hash);
        if routine || self.peer.is_some_and(|p| self.s.answered.0.contains(&p)) {
            return;
        }
        let Some(validator) = self.verify(KIND_VOTE, view, &hash, &signature) else { return };
        self.observe(KIND_VOTE, view, validator, SignedHash { hash, signature });
        self.forward_certificates(view, validator);
    }

    /// Sends the peer of the current input what it needs to reach this
    /// node's view: the certificate of the tip, with its proposal, and the
    /// certificate that justified entering the current view. Only when the
    /// stale message's `signer` (an index into the set of `view`'s epoch) is
    /// that peer itself, since an old signed message proves nothing about
    /// whoever replays it, and at most once per peer until the view changes
    /// or its timeout fires again. That bounds what stale messages can draw
    /// out of this node to two certificates and one proposal per validator
    /// per view and timeout period; it does not make the answer smaller than
    /// the message that asked for it.
    fn forward_certificates(&mut self, view: u64, signer: u32) {
        let Some(peer) = self.peer else { return };
        let signer_id = self.set_for(view).and_then(|set| set.get(signer as usize).map(|v| v.0));
        if signer_id != Some(peer) || self.s.answered.0.contains(&peer) {
            return;
        }
        self.s.answered.0.push(peer);
        let entry: Option<Certificate> = persist::get(ENTRY_KEY);
        if let Some(tip) = persist::get::<Certificate>(TIP_KEY)
            && entry.as_ref().is_none_or(|e| (e.view, e.hash) != (tip.view, tip.hash))
        {
            self.send_certificate(peer, tip);
        }
        if let Some(entry) = entry {
            self.send_certificate(peer, entry);
        }
    }

    fn send_certificate(&mut self, peer: Hash, certificate: Certificate) {
        let proposal = if certificate.hash == ZERO { None } else { Self::proposal(&certificate.hash) };
        let m = ConsensusMessage::Certificate { certificate, proposal };
        self.effects.push(Effect::Send { peer, topic: TOPIC, payload: m.to_bytes() });
    }

    /// A certificate from a peer: it must pass [`Ctx::verified`], or it is
    /// dropped whole. Certificates of an epoch this node has left teach it
    /// nothing.
    fn on_certificate(&mut self, certificate: Certificate, proposal: Option<Proposal>) {
        let Certificate { kind, view, hash, votes } = certificate;
        if self.view_epoch(view) < self.epoch {
            return;
        }
        // Below the current view only a proposal this node lacks can still matter.
        if view < self.s.view && proposal.is_none() {
            return;
        }
        let names_proposal = hash != ZERO;
        if !(kind == KIND_VOTE || (kind == KIND_FINALIZE && names_proposal)) {
            return;
        }
        if let Some(p) = &proposal
            && (!names_proposal || p.view != view || state::keccak256(&p.to_bytes()) != hash)
        {
            return;
        }
        let prefix: &[u8] = if kind == KIND_FINALIZE { b"fin/" } else { b"votes/" };
        // A quorum this node already holds, with its proposal, teaches it nothing.
        if self.quorum(view, &Self::votes(prefix, view, &hash).0) && (!names_proposal || Self::proposal(&hash).is_some()) {
            return;
        }
        if !self.verified(kind, view, &hash, &votes.0) {
            return;
        }
        if let Some(p) = &proposal {
            Self::store_proposal(&hash, p);
        }
        for vote in votes.0 {
            Self::add_vote(prefix, view, &hash, vote);
        }
        if kind == KIND_FINALIZE {
            self.check_finalization(view, &hash);
        } else if names_proposal {
            self.check_notarization(view, &hash);
        } else {
            self.check_timeout(view);
        }
    }

    /// Whether `votes` certify `kind(view, hash)`: at most `n` votes, with
    /// distinct validator indices in range, weighing more than two thirds of
    /// the stake of the view's epoch, each signed by the validator it names.
    /// The shape is checked before any signature, so a certificate costs at
    /// most `n` recoveries however large its message. Every vote that
    /// verifies is observed (§9), even when the certificate as a whole fails.
    fn verified(&mut self, kind: u8, view: u64, hash: &Hash, votes: &[SignedVote]) -> bool {
        let Some(set) = self.set_for(view) else { return false };
        let n = set.len();
        if votes.len() > n {
            return false;
        }
        let mut named = alloc::vec![false; n];
        for vote in votes {
            match named.get_mut(vote.validator as usize) {
                Some(seen) if !*seen => *seen = true,
                _ => return false,
            }
        }
        if !is_quorum(&set, votes) {
            return false;
        }
        for vote in votes {
            if self.verify(kind, view, hash, &vote.signature) != Some(vote.validator) {
                return false;
            }
            self.observe(kind, view, vote.validator, SignedHash { hash: *hash, signature: vote.signature });
        }
        true
    }

    /// Remembers the first hash `validator` signed of `kind` in `view`; a
    /// different one later is equivocation (spec 08 §9). Timeout votes are
    /// all alike and never conflict.
    fn observe(&mut self, kind: u8, view: u64, validator: u32, signed: SignedHash) {
        if kind == KIND_VOTE && signed.hash == ZERO {
            return;
        }
        let k = key(b"sig/", &[&[kind], &view.to_le_bytes(), &validator.to_le_bytes()]);
        let Some(first) = persist::get::<SignedHash>(&k) else {
            persist::set(&k, &signed);
            return;
        };
        if first.hash == signed.hash {
            return;
        }
        let evidence = Evidence::new(kind, view, validator, first, signed);
        let ek = key(b"evidence/", &[&evidence.id()]);
        if persist::get_raw(&ek).is_some() {
            return;
        }
        persist::set(&ek, &evidence);
        let mut pending: Seq<Evidence> = persist::get(PENDING_EVIDENCE_KEY).unwrap_or_default();
        pending.0.push(evidence);
        persist::set(PENDING_EVIDENCE_KEY, &pending);
        self.effects.push(Effect::Metric { name: b"equivocations".to_vec(), value: 1 });
        if let Some(peer) = self.peer {
            self.effects.push(Effect::PeerScore { peer, delta: EQUIVOCATION_PENALTY });
        }
    }

    /// Signs and broadcasts a vote of `kind`, counting it locally. Signing is
    /// deterministic, so casting the same vote again repeats one message. A
    /// finalize vote carries this node's partial signature when it holds a
    /// share of the active key set and the proposal is not a suffix.
    fn cast(&mut self, kind: u8, view: u64, hash: Hash) {
        let Some(me) = self.s.me else { return };
        let Some(signature) = self.sign(kind, view, &hash) else { return };
        let vote = SignedVote { validator: me, signature };
        if kind != KIND_FINALIZE {
            self.broadcast(&ConsensusMessage::Vote { view, hash, signature });
            Self::add_vote(b"votes/", view, &hash, vote);
            return;
        }
        let partial = Self::proposal(&hash)
            .filter(|p| !self.is_suffix(p) && anchored(p))
            .zip(dkg::my_id(self.chain_id))
            .and_then(|(p, id)| dkg::partial(self.chain_id, &id, p.height, &hash));
        match partial {
            Some(partial) => {
                Self::add_partial(view, &hash, partial.clone());
                self.broadcast(&ConsensusMessage::FinalizeShare { view, hash, signature, partial });
            }
            None => self.broadcast(&ConsensusMessage::Finalize { view, hash, signature }),
        }
        Self::add_vote(b"fin/", view, &hash, vote);
    }

    /// Records `certificate` as what justified leaving its view, and enters
    /// the next. Views that time out lengthen the next timeout, so a network
    /// or a node slower than the base timeout still gets views notarized;
    /// views notarized well within the timeout shorten it again.
    fn advance(&mut self, certificate: &Certificate) {
        persist::set(ENTRY_KEY, certificate);
        if certificate.hash == ZERO {
            self.s.backoff = (self.s.backoff + 1).min(MAX_BACKOFF);
        } else if self.s.now_ms.saturating_sub(self.s.view_started_ms).saturating_mul(2) < self.timeout_ms() {
            self.s.backoff = self.s.backoff.saturating_sub(1);
        }
        self.enter_view(certificate.view + 1);
    }

    /// A quorum of timeout votes for this view or a later one skips past it,
    /// with the tip unchanged.
    fn check_timeout(&mut self, view: u64) {
        if view < self.s.view {
            return;
        }
        let votes = Self::votes(b"votes/", view, &ZERO);
        if self.quorum(view, &votes.0) {
            self.advance(&Certificate { kind: KIND_VOTE, view, hash: ZERO, votes });
        }
    }

    fn check_notarization(&mut self, view: u64, hash: &Hash) {
        let votes = Self::votes(b"votes/", view, hash);
        if self.quorum(view, &votes.0) {
            self.notarized(&Certificate { kind: KIND_VOTE, view, hash: *hash, votes });
        }
    }

    /// `certificate`, a quorum of block votes or of finalize votes, shows its
    /// proposal notarized. A known proposal from a view above the tip's
    /// becomes the tip. A certificate for this view or a later one moves the
    /// node past it, with a finalize vote when the node holds the proposal
    /// (so its tip is that proposal) and has not timed out in that view.
    /// Notarizations of an epoch this node has left change nothing.
    fn notarized(&mut self, certificate: &Certificate) {
        let (view, hash) = (certificate.view, certificate.hash);
        if self.view_epoch(view) < self.epoch {
            return;
        }
        let proposal = Self::proposal(&hash);
        if let Some(p) = &proposal {
            persist::set(&key(b"notar/", &[&view.to_le_bytes()]), &hash);
            if view > self.s.tip_view {
                self.set_tip(certificate, p);
            }
        }
        if view < self.s.view {
            return;
        }
        let finalize = proposal.is_some() && !(view == self.s.view && self.s.timed_out);
        self.advance(certificate);
        if finalize {
            self.cast(KIND_FINALIZE, view, hash);
            self.check_finalization(view, &hash);
        } else if proposal.is_none() {
            self.request_sync();
        }
    }

    fn set_tip(&mut self, certificate: &Certificate, proposal: &Proposal) {
        persist::set(TIP_KEY, certificate);
        self.s.tip_view = certificate.view;
        self.s.tip_height = proposal.height;
        self.s.tip_hash = certificate.hash;
        self.s.tip_timestamp_ms = proposal.timestamp_ms;
    }

    /// Finalizes the proposal notarized in `view` and every unexecuted
    /// ancestor, oldest first, once a quorum of finalize votes is in. Such a
    /// quorum also implies the notarization, which moves a node that is
    /// behind past `view`. When the finalize votes carry enough partial
    /// signatures, the blocks also get a threshold certificate.
    fn check_finalization(&mut self, view: u64, hash: &Hash) {
        let votes = Self::votes(b"fin/", view, hash);
        if !self.quorum(view, &votes.0) {
            return;
        }
        let certificate = Certificate { kind: KIND_FINALIZE, view, hash: *hash, votes };
        if view >= self.s.view || view > self.s.tip_view {
            self.notarized(&certificate);
        }
        let Some(head) = Self::proposal(hash) else {
            self.request_sync();
            return;
        };
        if head.height <= self.s.finalized_height {
            return;
        }
        let mut chain = Vec::new();
        let mut cursor = Some(head.clone());
        while let Some(p) = cursor {
            if p.height <= self.s.finalized_height {
                break;
            }
            cursor = if p.height == 1 { None } else { Self::proposal(&p.parent) };
            chain.push(p);
        }
        if chain.last().map(|p| p.height) != Some(self.s.finalized_height + 1) {
            self.request_sync();
            return;
        }
        let threshold = if self.is_suffix(&head) {
            None
        } else {
            let partials: Seq<PartialShare> = persist::get(&key(b"part/", &[&view.to_le_bytes(), hash])).unwrap_or_default();
            dkg::certificate(self.chain_id, head.height, hash, &partials.0)
        };
        self.adopt(chain.into_iter().rev().collect(), &certificate, threshold.as_deref());
    }

    /// Records `chain` (consecutive, lowest first, extending the finalized
    /// head) as finalized under `certificate`, and `threshold` if there is
    /// one, and asks the host to execute it. Suffix proposals are kept but
    /// never finalized as blocks.
    fn adopt(&mut self, chain: Vec<Proposal>, certificate: &Certificate, threshold: Option<&[u8]>) {
        for p in chain {
            let hash = state::keccak256(&p.to_bytes());
            Self::store_proposal(&hash, &p);
            if self.is_suffix(&p) || self.epoch_end(self.view_epoch(certificate.view)).is_some_and(|end| p.height > end) {
                continue;
            }
            persist::set(&key(b"final/", &[&p.height.to_le_bytes()]), &hash);
            persist::set(&key(b"cert/", &[&p.height.to_le_bytes()]), certificate);
            if let Some(bytes) = threshold {
                persist::set_raw(&key(b"bcert/", &[&p.height.to_le_bytes()]), bytes);
            }
            Self::log_block(&p, certificate, threshold);
            self.s.finalized_height = p.height;
            self.execute(p);
        }
    }

    /// Writes the block log entry of `p` (spec 22 §5) and drops the one
    /// `LOG_WINDOW` heights behind it.
    fn log_block(p: &Proposal, certificate: &Certificate, threshold: Option<&[u8]>) {
        let height = p.height.to_le_bytes();
        state::set_raw(&key(LOG_PROPOSAL, &[&height]), &p.to_bytes());
        state::set(&key(LOG_CERTIFICATE, &[&height]), certificate);
        if let Some(bytes) = threshold {
            state::set_raw(&key(LOG_THRESHOLD, &[&height]), bytes);
        }
        if p.height > LOG_WINDOW {
            let old = (p.height - LOG_WINDOW).to_le_bytes();
            for prefix in [LOG_PROPOSAL, LOG_CERTIFICATE, LOG_THRESHOLD] {
                state::delete(&key(prefix, &[&old]));
            }
        }
    }

    /// Takes the heights `from` to `to` from the block log into the tables
    /// (spec 22 §5): chain state holds them executed, so they were
    /// finalized, whatever the tables remember. The last one becomes the
    /// tip when the tip is behind it.
    fn recover_log(&mut self, from: u64, to: u64) {
        for height in from..=to {
            let h = height.to_le_bytes();
            let Some(bytes) = state::get_raw(&key(LOG_PROPOSAL, &[&h])) else { continue };
            let hash = state::keccak256(&bytes);
            persist::set_raw(&key(b"prop/", &[&hash]), &bytes);
            persist::set(&key(b"final/", &[&h]), &hash);
            let certificate = state::get::<Certificate>(&key(LOG_CERTIFICATE, &[&h]));
            if let Some(certificate) = &certificate {
                persist::set(&key(b"cert/", &[&h]), certificate);
            }
            if let Some(threshold) = state::get_raw(&key(LOG_THRESHOLD, &[&h])) {
                persist::set_raw(&key(b"bcert/", &[&h]), &threshold);
            }
            if height == to
                && self.s.tip_height < height
                && let Ok(p) = Proposal::from_bytes(&bytes)
                && let Some(certificate) = certificate
            {
                self.set_tip(&certificate, &p);
                persist::set(ENTRY_KEY, &certificate);
            }
        }
    }

    /// Asks the host to execute finalized proposal `p`.
    fn execute(&mut self, p: Proposal) {
        let header = BlockHeader { height: p.height, parent_hash: p.parent, timestamp_ms: p.timestamp_ms, ..BlockHeader::default() };
        let participation = Participation { evidence: p.evidence, dkg: p.dkg }.to_bytes();
        self.effects.push(Effect::ExecuteBlock { block: Block { header: header.to_bytes(), txs: p.txs, participation } });
    }

    /// Begins re-executing, from the proposals and certificates this node
    /// persisted, the blocks it had finalized up to `remembered` above the
    /// `executed` height its chain state holds: a node that lost its chain
    /// state but kept its tables needs no peer to come back (spec 08 §7).
    /// One block per step, so that no step outgrows its budget however long
    /// the chain; the target outlives a restart in the middle.
    fn start_replay(&mut self, executed: u64, remembered: u64) {
        if remembered > executed {
            persist::set(REPLAY_KEY, &remembered);
        }
        self.replay_next();
    }

    /// The next block of a replay, the one above the chain state (the truth
    /// about what was executed, whichever kernel did it), when it is within
    /// the target and the tables hold it; the target, or a gap, ends the
    /// replay, and what the tables lack the node syncs (spec 08 §7a).
    fn replay_next(&mut self) {
        let target: u64 = persist::get(REPLAY_KEY).unwrap_or(0);
        if target == 0 {
            return;
        }
        let next = state::height().unwrap_or(0) + 1;
        match Self::finalized_proposal(next).filter(|_| next <= target) {
            Some(p) => {
                self.s.finalized_height = self.s.finalized_height.max(next);
                self.execute(p);
            }
            None => persist::set(REPLAY_KEY, &0u64),
        }
    }

    /// The proposal this node finalized at `height`, when its tables hold
    /// it with the certificate the host finalizes it under.
    fn finalized_proposal(height: u64) -> Option<Proposal> {
        let hash: Hash = persist::get(&key(b"final/", &[&height.to_le_bytes()]))?;
        persist::get_raw(&key(b"cert/", &[&height.to_le_bytes()]))?;
        Self::proposal(&hash).filter(|p| p.height == height)
    }

    fn finalized_hash(&self) -> Hash {
        if self.s.finalized_height == 0 {
            return ZERO;
        }
        persist::get(&key(b"final/", &[&self.s.finalized_height.to_le_bytes()])).unwrap_or(ZERO)
    }

    /// Asks the peer of the current input for finalized blocks past ours.
    fn request_sync(&mut self) {
        self.send_sync(false);
    }

    /// [`Ctx::request_sync`] for a message this node could verify (`weak`
    /// false) or not. One request is outstanding at a time, but a verified
    /// trigger replaces a request a weak one sent, so a peer that sends
    /// unverifiable messages and never answers cannot hold up catch-up.
    fn send_sync(&mut self, weak: bool) {
        let Some(peer) = self.peer else { return };
        if self.s.sync_pending && (weak || !persist::get::<bool>(WEAK_SYNC_KEY).unwrap_or(false)) {
            return;
        }
        persist::set(WEAK_SYNC_KEY, &weak);
        self.s.sync_pending = true;
        self.s.sync_request_id += 1;
        self.s.sync_peer = peer;
        let payload = SyncRequest { from_height: self.s.finalized_height + 1 }.to_bytes();
        self.effects.push(Effect::Request { peer, request_id: self.s.sync_request_id, payload });
    }

    /// Serves finalized proposals from the requested height, never past the
    /// last block of that height's epoch, so the requester knows the set
    /// that certified them; a batch ends at the head of its certificate,
    /// which can be a suffix proposal.
    fn on_request(&mut self, request_id: u64, payload: &[u8]) {
        let Ok(request) = SyncRequest::from_bytes(payload) else { return };
        let fin = self.s.finalized_height;
        let mut response = SyncResponse { finalized_height: fin, proposals: Seq(Vec::new()), certificate: None, threshold: Vec::new() };
        let from = request.from_height;
        if from >= 1 && from <= fin {
            let mut top = (from + SYNC_BATCH - 1).min(fin);
            let blocks = self.params.staking.epoch_blocks;
            if blocks != 0 {
                top = top.min(epoch_end(epoch_of(from, blocks), blocks));
            }
            if let Some(certificate) = persist::get::<Certificate>(&key(b"cert/", &[&top.to_le_bytes()]))
                && let Some(head) = Self::proposal(&certificate.hash)
            {
                let mut proposals = Vec::new();
                let mut cursor = Some(head);
                while let Some(p) = cursor {
                    let height = p.height;
                    cursor = if height > from { Self::proposal(&p.parent) } else { None };
                    proposals.push(p);
                    if height == from {
                        break;
                    }
                }
                if proposals.last().is_some_and(|p| p.height == from) {
                    proposals.reverse();
                    response.proposals = Seq(proposals);
                    response.certificate = Some(certificate);
                    response.threshold = persist::get_raw(&key(b"bcert/", &[&top.to_le_bytes()])).unwrap_or_default();
                }
            }
        }
        self.effects.push(Effect::Respond { request_id, payload: response.to_bytes() });
    }

    /// Verifies and adopts a sync response; asks for more if the peer is
    /// further ahead. The finalize votes must verify against the set of
    /// their view's epoch, always: a threshold certificate counts
    /// shareholders, not stake, so it never stands in for them (spec 08
    /// §7a). One that also verifies under the group key is kept, for this
    /// node to pass on. Only votes of its current epoch move its tip and view.
    fn on_response(&mut self, request_id: u64, payload: &[u8]) {
        if !self.s.sync_pending || request_id != self.s.sync_request_id {
            return;
        }
        self.s.sync_pending = false;
        let Ok(response) = SyncResponse::from_bytes(payload) else { return };
        let Some(certificate) = response.certificate else { return };
        let proposals = response.proposals.0;
        let Some(last) = proposals.last() else { return };
        if certificate.kind != KIND_FINALIZE || state::keccak256(&last.to_bytes()) != certificate.hash {
            return;
        }
        if !self.verified(KIND_FINALIZE, certificate.view, &certificate.hash, &certificate.votes.0) {
            return;
        }
        let threshold = !self.is_suffix(last) && dkg::certifies(self.chain_id, &response.threshold, last, &certificate.hash);
        let current = self.view_epoch(certificate.view) == self.epoch;
        let mut parent = self.finalized_hash();
        let mut height = self.s.finalized_height;
        for p in &proposals {
            if p.parent != parent || p.height != height + 1 {
                return;
            }
            parent = state::keccak256(&p.to_bytes());
            height = p.height;
        }
        let head = last.clone();
        self.adopt(proposals, &certificate, threshold.then_some(response.threshold.as_slice()));
        // A finalized head from a later view than the tip's replaces it; a
        // tip from a later view already extends the head.
        if current {
            if certificate.view > self.s.tip_view {
                self.set_tip(&certificate, &head);
            }
            if self.s.view <= certificate.view {
                self.advance(&certificate);
            }
        }
        if response.finalized_height > height {
            self.peer = Some(self.s.sync_peer);
            self.request_sync();
        }
    }

    /// After executing `height`: the block's finalization effect, with its
    /// threshold certificate when it has one; this node's DKG duties and the
    /// envelopes it still holds; and, at the end of an epoch, the next one.
    fn on_executed(&mut self, height: u64) {
        if let Some(certificate) = persist::get::<Certificate>(&key(b"cert/", &[&height.to_le_bytes()])) {
            let bytes = persist::get_raw(&key(b"bcert/", &[&height.to_le_bytes()])).unwrap_or_else(|| certificate.to_bytes());
            self.effects.push(Effect::FinalizeBlock { height, certificate: bytes });
            self.effects.push(Effect::Metric { name: b"blocks".to_vec(), value: 1 });
        }
        self.dkg_step(height);
        if self.epoch_end(self.epoch).is_some_and(|end| height >= end) {
            self.catch_up_epoch();
        }
        self.rejoin();
        self.replay_next();
    }

    /// A node whose chain state has just reached its view's epoch, by
    /// re-executing its own blocks or by syncing (spec 08 §3a, §7), learns
    /// its index in that epoch's set and arms its view again, so that as
    /// leader it proposes now rather than after a timeout; its flags still
    /// say what it did in the view. The epoch itself it took up at `open`
    /// ([`Ctx::load_set`]), its view being there already. A node outside
    /// the set finds no index.
    fn rejoin(&mut self) {
        if self.s.me.is_none() && self.view_epoch(self.s.view) == self.epoch {
            self.s.me = self.identify();
            if self.s.me.is_some() {
                self.arm();
            }
        }
    }

    /// Prunes the envelope pool and sends this node's DKG message for the
    /// phase after the block at `executed`, if it has one, and what it has
    /// for key rotation: its rotation share, a handoff, evidence.
    fn dkg_step(&mut self, executed: u64) {
        if self.params.staking.epoch_blocks == 0 || self.params.staking.dkg_phase_blocks == 0 {
            return;
        }
        dkg::pool_prune(executed);
        let Some(me) = dkg::my_id(self.chain_id) else { return };
        if let Some(envelope) = dkg::duties(self.chain_id, &me, executed) {
            dkg::pool_add(self.chain_id, envelope.clone());
            self.broadcast(&ConsensusMessage::Dkg { envelope });
        }
        for envelope in dkg::rotation_step(self.chain_id, &me) {
            self.broadcast(&ConsensusMessage::Dkg { envelope });
        }
    }
}

/// `kernel_driver_step`.
pub fn step(input: &Input) -> Seq<Effect> {
    let mut c = Ctx::open();
    match input {
        Input::Started { now_ms, resumed_state } => {
            if let Some(bytes) = resumed_state
                && let Ok(restored) = SimplexState::from_bytes(bytes)
            {
                c.s = restored;
            }
            c.s.now_ms = *now_ms;
            // Chain state is the truth about what has been executed. A node that
            // lost it re-executes what it had finalized from its own tables and
            // syncs the rest, instead of executing on the wrong parent; a replay
            // a restart cut short goes on to where it was headed.
            let executed = state::height().unwrap_or(0);
            let remembered = c.s.finalized_height.max(persist::get(REPLAY_KEY).unwrap_or(0));
            if remembered > executed {
                c.s.finalized_height = executed;
            } else if executed > c.s.finalized_height {
                // Chain state is ahead of what the tables remember (a restart
                // between a block's write and the driver's, or a snapshot): the
                // blocks were finalized, and the block log says by what.
                c.recover_log(c.s.finalized_height + 1, executed);
                c.s.finalized_height = executed;
            }
            c.load_set();
            if c.s.tip_height == 0 {
                // Pace the first block one slot after start, like every later one.
                c.s.tip_timestamp_ms = *now_ms;
            }
            c.s.me = c.identify();
            c.catch_up_epoch();
            c.arm();
            c.dkg_step(executed);
            c.start_replay(executed, remembered);
        }
        Input::TimerFired { timer_id, now_ms } => c.on_timer(*timer_id, *now_ms),
        Input::MempoolContents { txs } => c.on_mempool(&txs.0),
        Input::NetworkMessage { peer, topic, payload } if *topic == TOPIC => {
            c.peer = Some(*peer);
            if let Ok(m) = ConsensusMessage::from_bytes(payload) {
                c.on_message(m);
            }
        }
        Input::Request { peer, request_id, payload } => {
            c.peer = Some(*peer);
            c.on_request(*request_id, payload);
        }
        Input::Response { request_id, payload } => c.on_response(*request_id, payload),
        Input::BlockExecuted { height, .. } => c.on_executed(*height),
        _ => {}
    }
    save(&c.s);
    c.effects.push(Effect::PersistState { state: c.s.to_bytes() });
    Seq(c.effects)
}
