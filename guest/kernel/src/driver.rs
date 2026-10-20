//! The reference driver: Simplex consensus (spec 08). Views rotate through
//! the validator set; a leader proposes a block extending the notarized tip,
//! validators vote, a quorum notarizes, a second quorum of finalize votes
//! finalizes the block and every ancestor. A quorum for any view at or above
//! the current one moves a node past it, and a node that hears from a peer
//! stuck in an older view sends it the certificates that let it catch up, so
//! validators that drifted apart converge. With one validator it degenerates
//! into a paced single-node chain, which is what `solo dev` runs.

use alloc::vec::Vec;

use solo_abi::chain::consensus::{
    EQUIVOCATION_PENALTY, KEY_ROLE, KIND_FINALIZE, KIND_PROPOSE, KIND_VOTE, MAX_BACKOFF, MAX_EVIDENCE, TOPIC, identity_preimage, leader,
    propose_timer, quorum, signing_preimage, timeout_timer, timer_view, view_timeout_ms,
};
use solo_abi::chain::{
    BlockHeader, Certificate, ConsensusMessage, Evidence, GenesisParams, Participation, Proposal, Signature, SignedHash, SignedVote, SimplexState,
    SyncRequest, SyncResponse, keys,
};
use solo_abi::codec::Seq;
use solo_abi::types::{Block, Effect, Hash, Input, MigrateArgs};
use solo_abi::{Decode, Encode};

use crate::{persist, state, tx};

const STATE_KEY: &[u8] = b"simplex/state";
/// The certificate that justified entering the current view.
const ENTRY_KEY: &[u8] = b"simplex/entry";
/// The certificate that made the current tip the tip.
const TIP_KEY: &[u8] = b"simplex/tip";
/// Evidence found here that chain state does not hold yet.
const PENDING_EVIDENCE_KEY: &[u8] = b"simplex/evidence";
const ZERO: Hash = [0; 32];

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

/// One driver step's working set.
struct Ctx {
    s: SimplexState,
    chain_id: u64,
    params: GenesisParams,
    validators: Vec<Hash>,
    effects: Vec<Effect>,
    /// The peer the current input came from, if it came from one.
    peer: Option<Hash>,
}

impl Ctx {
    fn open() -> Ctx {
        let mut s = load();
        s.now_ms = persist::time_now();
        Ctx { s, chain_id: state::chain_id(), params: state::params(), validators: state::validators(), effects: Vec::new(), peer: None }
    }

    fn n(&self) -> usize {
        self.validators.len()
    }

    fn is_leader(&self, view: u64) -> bool {
        self.n() > 0 && self.s.me == Some(leader(view, self.n()) as u32)
    }

    fn message_hash(&self, kind: u8, view: u64, hash: &Hash) -> Hash {
        state::keccak256(&signing_preimage(kind, self.chain_id, view, hash))
    }

    /// Who signed `kind(view, hash)`, as a validator index.
    fn verify(&self, kind: u8, view: u64, hash: &Hash, sig: &Signature) -> Option<u32> {
        let pubkey = tx::recover_pubkey(&self.message_hash(kind, view, hash), &sig.0)?;
        let id = state::keccak256(&pubkey);
        self.validators.iter().position(|v| *v == id).map(|i| i as u32)
    }

    fn sign(&self, kind: u8, view: u64, hash: &Hash) -> Option<Signature> {
        persist::sign(KEY_ROLE, &self.message_hash(kind, view, hash))
    }

    /// Learns this node's validator index by signing a fixed message.
    fn identify(&self) -> Option<u32> {
        let msg = state::keccak256(&identity_preimage(self.chain_id));
        let sig = persist::sign(KEY_ROLE, &msg)?;
        let pubkey = tx::recover_pubkey(&msg, &sig.0)?;
        let id = state::keccak256(&pubkey);
        self.validators.iter().position(|v| *v == id).map(|i| i as u32)
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

    /// Records a vote under `prefix` for `(view, hash)`; returns the count.
    fn add_vote(prefix: &[u8], view: u64, hash: &Hash, vote: SignedVote) -> usize {
        let k = key(prefix, &[&view.to_le_bytes(), hash]);
        let mut votes: Seq<SignedVote> = persist::get(&k).unwrap_or_default();
        if !votes.0.iter().any(|v| v.validator == vote.validator) {
            votes.0.push(vote);
            persist::set(&k, &votes);
        }
        votes.0.len()
    }

    fn votes(prefix: &[u8], view: u64, hash: &Hash) -> Seq<SignedVote> {
        persist::get(&key(prefix, &[&view.to_le_bytes(), hash])).unwrap_or_default()
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
        self.effects.push(Effect::MempoolTake { max_bytes: 1 << 20, max_gas: u64::from(self.params.max_txs) * 21_000 });
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
        let mut selected = txs.to_vec();
        selected.truncate(self.params.max_txs as usize);
        let proposal = Proposal {
            view,
            height: self.s.tip_height + 1,
            parent: self.s.tip_hash,
            timestamp_ms: self.s.now_ms.max(self.s.tip_timestamp_ms + 1),
            txs: Seq(selected),
            evidence: Self::pending_evidence(),
        };
        let hash = state::keccak256(&proposal.to_bytes());
        let Some(signature) = self.sign(KIND_PROPOSE, view, &hash) else { return };
        self.broadcast(&ConsensusMessage::Propose { proposal: proposal.clone(), signature });
        self.handle_proposal(proposal, hash);
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
        match m {
            ConsensusMessage::Propose { proposal, signature } => {
                let view = proposal.view;
                if self.n() == 0 || view == 0 {
                    return;
                }
                let hash = state::keccak256(&proposal.to_bytes());
                let proposer = leader(view, self.n()) as u32;
                if self.verify(KIND_PROPOSE, view, &hash, &signature) != Some(proposer) {
                    return;
                }
                self.observe(KIND_PROPOSE, view, proposer, SignedHash { hash, signature });
                if view < self.s.view {
                    self.forward_certificates(proposer);
                    self.late_proposal(proposal, hash);
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
            ConsensusMessage::Finalize { view, hash, signature } => {
                let Some(validator) = self.verify(KIND_FINALIZE, view, &hash, &signature) else { return };
                self.observe(KIND_FINALIZE, view, validator, SignedHash { hash, signature });
                Self::add_vote(b"fin/", view, &hash, SignedVote { validator, signature });
                self.check_finalization(view, &hash);
            }
            ConsensusMessage::Certificate { certificate, proposal } => self.on_certificate(certificate, proposal),
        }
    }

    fn handle_proposal(&mut self, proposal: Proposal, hash: Hash) {
        Self::store_proposal(&hash, &proposal);
        if proposal.height > self.s.tip_height + 1 {
            self.request_sync();
        }
        let extends_tip = proposal.parent == self.s.tip_hash && proposal.height == self.s.tip_height + 1;
        let bounded = proposal.evidence.0.len() <= MAX_EVIDENCE;
        if proposal.view == self.s.view && extends_tip && bounded && !self.s.voted && !self.s.timed_out {
            self.s.voted = true;
            self.cast(KIND_VOTE, proposal.view, hash);
        }
        self.check_notarization(proposal.view, &hash);
    }

    /// A proposal for a view this node has left matters only when this node
    /// holds a quorum for it and lacks the proposal itself.
    fn late_proposal(&mut self, proposal: Proposal, hash: Hash) {
        let view = proposal.view;
        let q = quorum(self.n());
        let certified = Self::votes(b"votes/", view, &hash).0.len() >= q || Self::votes(b"fin/", view, &hash).0.len() >= q;
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
        self.forward_certificates(validator);
    }

    /// Sends the peer of the current input what it needs to reach this
    /// node's view: the certificate of the tip, with its proposal, and the
    /// certificate that justified entering the current view. Only when the
    /// stale message's `signer` is that peer itself, since an old signed
    /// message proves nothing about whoever replays it, and at most once per
    /// peer until the view changes or its timeout fires again. That bounds
    /// what stale messages can draw out of this node to two certificates and
    /// one proposal per validator per view and timeout period; it does not
    /// make the answer smaller than the message that asked for it.
    fn forward_certificates(&mut self, signer: u32) {
        let Some(peer) = self.peer else { return };
        if self.validators.get(signer as usize) != Some(&peer) || self.s.answered.0.contains(&peer) {
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
    /// dropped whole.
    fn on_certificate(&mut self, certificate: Certificate, proposal: Option<Proposal>) {
        let Certificate { kind, view, hash, votes } = certificate;
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
        if Self::votes(prefix, view, &hash).0.len() >= quorum(self.n()) && (!names_proposal || Self::proposal(&hash).is_some()) {
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
    /// distinct validator indices in range, each signed by the validator it
    /// names, and at least a quorum of them. The shape is checked before any
    /// signature, so a certificate costs at most `n` recoveries however
    /// large its message. Every vote that verifies is observed (§9), even
    /// when the certificate as a whole fails.
    fn verified(&mut self, kind: u8, view: u64, hash: &Hash, votes: &[SignedVote]) -> bool {
        let n = self.n();
        if votes.len() > n || votes.len() < quorum(n) {
            return false;
        }
        let mut named = alloc::vec![false; n];
        for vote in votes {
            match named.get_mut(vote.validator as usize) {
                Some(seen) if !*seen => *seen = true,
                _ => return false,
            }
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
    /// deterministic, so casting the same vote again repeats one message.
    fn cast(&mut self, kind: u8, view: u64, hash: Hash) {
        let Some(me) = self.s.me else { return };
        let Some(signature) = self.sign(kind, view, &hash) else { return };
        let (prefix, m) = if kind == KIND_FINALIZE {
            (&b"fin/"[..], ConsensusMessage::Finalize { view, hash, signature })
        } else {
            (&b"votes/"[..], ConsensusMessage::Vote { view, hash, signature })
        };
        self.broadcast(&m);
        Self::add_vote(prefix, view, &hash, SignedVote { validator: me, signature });
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
        if votes.0.len() >= quorum(self.n()) {
            self.advance(&Certificate { kind: KIND_VOTE, view, hash: ZERO, votes });
        }
    }

    fn check_notarization(&mut self, view: u64, hash: &Hash) {
        let votes = Self::votes(b"votes/", view, hash);
        if votes.0.len() >= quorum(self.n()) {
            self.notarized(&Certificate { kind: KIND_VOTE, view, hash: *hash, votes });
        }
    }

    /// `certificate`, a quorum of block votes or of finalize votes, shows its
    /// proposal notarized. A known proposal from a view above the tip's
    /// becomes the tip. A certificate for this view or a later one moves the
    /// node past it, with a finalize vote when the node holds the proposal
    /// (so its tip is that proposal) and has not timed out in that view.
    fn notarized(&mut self, certificate: &Certificate) {
        let (view, hash) = (certificate.view, certificate.hash);
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
    /// behind past `view`.
    fn check_finalization(&mut self, view: u64, hash: &Hash) {
        let votes = Self::votes(b"fin/", view, hash);
        if votes.0.len() < quorum(self.n()) {
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
        self.adopt(chain.into_iter().rev().collect(), &certificate);
    }

    /// Records `chain` (consecutive, lowest first, extending the finalized
    /// head) as finalized under `certificate` and asks the host to execute it.
    fn adopt(&mut self, chain: Vec<Proposal>, certificate: &Certificate) {
        for p in chain {
            let hash = state::keccak256(&p.to_bytes());
            Self::store_proposal(&hash, &p);
            persist::set(&key(b"final/", &[&p.height.to_le_bytes()]), &hash);
            persist::set(&key(b"cert/", &[&p.height.to_le_bytes()]), certificate);
            self.s.finalized_height = p.height;
            let header = BlockHeader { height: p.height, parent_hash: p.parent, timestamp_ms: p.timestamp_ms, ..BlockHeader::default() };
            let participation = Participation { evidence: p.evidence }.to_bytes();
            self.effects.push(Effect::ExecuteBlock { block: Block { header: header.to_bytes(), txs: p.txs, participation } });
        }
    }

    fn finalized_hash(&self) -> Hash {
        if self.s.finalized_height == 0 {
            return ZERO;
        }
        persist::get(&key(b"final/", &[&self.s.finalized_height.to_le_bytes()])).unwrap_or(ZERO)
    }

    /// Asks the peer of the current input for finalized blocks past ours.
    fn request_sync(&mut self) {
        let Some(peer) = self.peer else { return };
        if self.s.sync_pending {
            return;
        }
        self.s.sync_pending = true;
        self.s.sync_request_id += 1;
        self.s.sync_peer = peer;
        let payload = SyncRequest { from_height: self.s.finalized_height + 1 }.to_bytes();
        self.effects.push(Effect::Request { peer, request_id: self.s.sync_request_id, payload });
    }

    /// Serves finalized proposals from the requested height.
    fn on_request(&mut self, request_id: u64, payload: &[u8]) {
        let Ok(request) = SyncRequest::from_bytes(payload) else { return };
        let fin = self.s.finalized_height;
        let mut response = SyncResponse { finalized_height: fin, proposals: Seq(Vec::new()), certificate: None };
        if request.from_height >= 1 && request.from_height <= fin {
            let top = (request.from_height + SYNC_BATCH - 1).min(fin);
            if let Some(certificate) = persist::get::<Certificate>(&key(b"cert/", &[&top.to_le_bytes()]))
                && let Some(head) = Self::proposal(&certificate.hash)
            {
                let mut proposals = Vec::new();
                for h in request.from_height..=head.height {
                    let Some(p) = persist::get::<Hash>(&key(b"final/", &[&h.to_le_bytes()])).and_then(|x| Self::proposal(&x)) else {
                        proposals.clear();
                        break;
                    };
                    proposals.push(p);
                }
                if !proposals.is_empty() {
                    response.proposals = Seq(proposals);
                    response.certificate = Some(certificate);
                }
            }
        }
        self.effects.push(Effect::Respond { request_id, payload: response.to_bytes() });
    }

    /// Verifies and adopts a sync response; asks for more if the peer is further ahead.
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
        self.adopt(proposals, &certificate);
        // A finalized head from a later view than the tip's replaces it; a
        // tip from a later view already extends the head.
        if certificate.view > self.s.tip_view {
            self.set_tip(&certificate, &head);
        }
        if self.s.view <= certificate.view {
            self.advance(&certificate);
        }
        if response.finalized_height > height {
            self.peer = Some(self.s.sync_peer);
            self.request_sync();
        }
    }

    fn on_executed(&mut self, height: u64) {
        let Some(certificate) = persist::get::<Certificate>(&key(b"cert/", &[&height.to_le_bytes()])) else { return };
        self.effects.push(Effect::FinalizeBlock { height, certificate: certificate.to_bytes() });
        self.effects.push(Effect::Metric { name: b"blocks".to_vec(), value: 1 });
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
            // Chain state is the truth about what has been executed; a node that
            // lost it syncs the rest instead of executing on the wrong parent.
            let executed = state::height().unwrap_or(0);
            if c.s.finalized_height > executed {
                c.s.finalized_height = executed;
            }
            if c.s.tip_height == 0 {
                // Pace the first block one slot after start, like every later one.
                c.s.tip_timestamp_ms = *now_ms;
            }
            c.s.me = c.identify();
            c.arm();
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
