//! The reference driver: Simplex consensus (spec 08). Views rotate through
//! the validator set; a leader proposes a block extending the notarized tip,
//! validators vote, a quorum notarizes, a second quorum of finalize votes
//! finalizes the block and every ancestor. With one validator it degenerates
//! into a paced single-node chain, which is what `solo dev` runs.

use alloc::vec::Vec;

use solo_abi::chain::consensus::{
    KEY_ROLE, KIND_FINALIZE, KIND_PROPOSE, KIND_VOTE, TIMEOUT_SLOTS, TOPIC, identity_preimage, leader,
    propose_timer, quorum, signing_preimage, timeout_timer, timer_view,
};
use solo_abi::chain::{BlockHeader, Certificate, ConsensusMessage, GenesisParams, Proposal, Signature, SignedVote, SimplexState, ValidatorSet};
use solo_abi::codec::Seq;
use solo_abi::types::{Block, Effect, Hash, Input, MigrateArgs};
use solo_abi::{Decode, Encode};

use crate::{persist, state, tx};

const STATE_KEY: &[u8] = b"simplex/state";
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

/// One driver step's working set.
struct Ctx {
    s: SimplexState,
    chain_id: u64,
    params: GenesisParams,
    validators: Vec<Hash>,
    effects: Vec<Effect>,
}

impl Ctx {
    fn open() -> Ctx {
        let validators = state::get_raw(b"meta/validators")
            .and_then(|b| ValidatorSet::from_bytes(&b).ok())
            .map(|set| set.validators.0.into_iter().map(|v| v.id).collect())
            .unwrap_or_default();
        let mut s = load();
        s.now_ms = persist::time_now();
        Ctx { s, chain_id: state::chain_id(), params: state::params(), validators, effects: Vec::new() }
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
        self.s.proposing = false;
        let slot = self.params.slot_ms;
        self.effects.push(Effect::SetTimer { timer_id: timeout_timer(view), deadline_ms: self.s.now_ms + TIMEOUT_SLOTS * slot });
        if self.is_leader(view) {
            let at = self.s.tip_timestamp_ms + slot;
            if at <= self.s.now_ms {
                self.request_mempool();
            } else {
                self.effects.push(Effect::SetTimer { timer_id: propose_timer(view), deadline_ms: at });
            }
        }
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
            if !self.s.timed_out {
                self.s.timed_out = true;
                self.cast(KIND_VOTE, view, ZERO);
                self.check_timeout(view);
            }
        } else if self.is_leader(view) && !self.s.proposing && !self.s.voted {
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
        };
        let hash = state::keccak256(&proposal.to_bytes());
        let Some(signature) = self.sign(KIND_PROPOSE, view, &hash) else { return };
        self.broadcast(&ConsensusMessage::Propose { proposal: proposal.clone(), signature });
        self.handle_proposal(proposal, hash);
    }

    fn on_message(&mut self, m: ConsensusMessage) {
        match m {
            ConsensusMessage::Propose { proposal, signature } => {
                let hash = state::keccak256(&proposal.to_bytes());
                if self.n() == 0 || self.verify(KIND_PROPOSE, proposal.view, &hash, &signature) != Some(leader(proposal.view, self.n()) as u32) {
                    return;
                }
                self.handle_proposal(proposal, hash);
            }
            ConsensusMessage::Vote { view, hash, signature } => {
                if view < self.s.view {
                    return;
                }
                let Some(validator) = self.verify(KIND_VOTE, view, &hash, &signature) else { return };
                Self::add_vote(b"votes/", view, &hash, SignedVote { validator, signature });
                if hash == ZERO {
                    self.check_timeout(view);
                } else {
                    self.check_notarization(view, &hash);
                }
            }
            ConsensusMessage::Finalize { view, hash, signature } => {
                let Some(validator) = self.verify(KIND_FINALIZE, view, &hash, &signature) else { return };
                Self::add_vote(b"fin/", view, &hash, SignedVote { validator, signature });
                self.check_finalization(view, &hash);
            }
        }
    }

    fn handle_proposal(&mut self, proposal: Proposal, hash: Hash) {
        if proposal.view < self.s.view {
            return;
        }
        persist::set(&key(b"prop/", &[&hash]), &proposal);
        let extends_tip = proposal.parent == self.s.tip_hash && proposal.height == self.s.tip_height + 1;
        if proposal.view == self.s.view && extends_tip && !self.s.voted && !self.s.timed_out {
            self.s.voted = true;
            self.cast(KIND_VOTE, proposal.view, hash);
        }
        self.check_notarization(proposal.view, &hash);
    }

    /// Signs and broadcasts a vote of `kind`, counting it locally.
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

    fn check_timeout(&mut self, view: u64) {
        if view == self.s.view && Self::votes(b"votes/", view, &ZERO).0.len() >= quorum(self.n()) {
            self.enter_view(view + 1);
        }
    }

    fn check_notarization(&mut self, view: u64, hash: &Hash) {
        if view != self.s.view || Self::votes(b"votes/", view, hash).0.len() < quorum(self.n()) {
            return;
        }
        let Some(proposal) = Self::proposal(hash) else { return };
        persist::set(&key(b"notar/", &[&view.to_le_bytes()]), hash);
        self.s.tip_view = view;
        self.s.tip_height = proposal.height;
        self.s.tip_hash = *hash;
        self.s.tip_timestamp_ms = proposal.timestamp_ms;
        let finalize = !self.s.timed_out;
        self.enter_view(view + 1);
        if finalize {
            self.cast(KIND_FINALIZE, view, *hash);
            self.check_finalization(view, hash);
        }
    }

    /// Finalizes the proposal notarized in `view` and every unexecuted
    /// ancestor, oldest first, once a quorum of finalize votes is in.
    fn check_finalization(&mut self, view: u64, hash: &Hash) {
        let votes = Self::votes(b"fin/", view, hash);
        if votes.0.len() < quorum(self.n()) {
            return;
        }
        let Some(head) = Self::proposal(hash) else { return };
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
            return;
        }
        let certificate = Certificate { kind: KIND_FINALIZE, view, hash: *hash, votes };
        for p in chain.into_iter().rev() {
            persist::set(&key(b"cert/", &[&p.height.to_le_bytes()]), &certificate);
            let header = BlockHeader { height: p.height, parent_hash: p.parent, timestamp_ms: p.timestamp_ms, ..BlockHeader::default() };
            self.effects.push(Effect::ExecuteBlock { block: Block { header: header.to_bytes(), txs: p.txs, participation: Vec::new() } });
        }
        self.s.finalized_height = head.height;
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
            if c.s.tip_height == 0 {
                // Pace the first block one slot after start, like every later one.
                c.s.tip_timestamp_ms = *now_ms;
            }
            c.s.me = c.identify();
            let view = c.s.view;
            c.enter_view(view);
        }
        Input::TimerFired { timer_id, now_ms } => c.on_timer(*timer_id, *now_ms),
        Input::MempoolContents { txs } => c.on_mempool(&txs.0),
        Input::NetworkMessage { topic, payload, .. } if *topic == TOPIC => {
            if let Ok(m) = ConsensusMessage::from_bytes(payload) {
                c.on_message(m);
            }
        }
        Input::BlockExecuted { height, .. } => c.on_executed(*height),
        _ => {}
    }
    save(&c.s);
    c.effects.push(Effect::PersistState { state: c.s.to_bytes() });
    Seq(c.effects)
}
