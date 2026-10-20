# 08 — The reference driver: Simplex consensus

## 1. Overview

This document specifies the consensus protocol of the reference kernel's driver (06 §3): a Simplex-family BFT protocol with fused finality. It is the protocol `solo dev` runs with one validator and what multi-validator chains run until governance installs another kernel. It fixes the messages, the voting rules, how nodes that drifted into different views meet again, the certificate carried by `FinalizeBlock`, equivocation evidence, and what the driver persists. Networking, timers and keys are the host's (05 §4.5–4.6); execution is the state-transition group's (06 §5).

Tolerance: with `n` validators the protocol is safe and live with fewer than `n/3` faulty ones; a quorum is `⌊2n/3⌋ + 1` votes. Validators are counted, not weighted, in this version.

## 2. Validators and identity

`Genesis.validators` is a `ValidatorSet { validators: vec<Validator { id: [32], weight: u64 }> }` in canonical encoding. A validator's `id` is `keccak256` of its uncompressed secp256k1 public key (64 bytes). The order of the vector is the leader rotation; the leader of view `v` is `validators[(v − 1) mod n]`.

A node learns whether it is a validator by signing the identity message (§4) with key role 0 through `sign`, recovering the public key with `secp256k1_recover`, and looking the id up. A node without a key, or with a key outside the set, is an observer: it follows the protocol's messages, executes and finalizes exactly as validators do, and never votes.

## 3. Views and the notarized tip

The driver runs in views `v = 1, 2, …`. Every node keeps a *notarized tip*: the proposal with the highest view that it has seen notarized (§5), initially the empty tip at height 0 with hash zero. A proposal in view `v` extends the proposer's tip: its `parent` is the tip's hash and its `height` is the tip's height plus one. Views only increase; a node may enter a view several above its current one (§5).

Entering view `v`, a node:

1. clears its `voted`, `timed_out` and `proposing` flags;
2. *arms* the view: sets the *timeout timer* of `v` (id `2v`) to `now + T`, where the *view timeout* `T` is `3 × slot_ms × 2^b` and `b` is its backoff (§5a); if it is the leader of `v` and has neither voted nor timed out in `v`, it proposes at `max(now, tip.timestamp_ms + slot_ms)`: immediately, or when the *proposal timer* of `v` (id `2v + 1`) fires. Arming also abandons an outstanding sync request (§7a) and forgets which peers were answered (§5a).

A node that restarts (`Started`) arms its current view without clearing `voted` or `timed_out`, so it never votes twice in one view and a leader never proposes twice in one view.

Timers of other views are ignored when they fire. `slot_ms` is `GenesisParams.slot_ms`.

## 4. Messages

All consensus traffic is on topic 1 with a `ConsensusMessage` payload. `Propose`, `Vote` and `Finalize` are `Broadcast`; `Certificate` is `Send` to one peer (§5a).

```
enum ConsensusMessage {
  0 Propose     { proposal: Proposal, signature: [65] }
  1 Vote        { view: u64, hash: [32], signature: [65] }   // hash zero: timeout vote
  2 Finalize    { view: u64, hash: [32], signature: [65] }
  3 Certificate { certificate: Certificate, proposal: option<Proposal> }
}
struct Proposal { view: u64, height: u64, parent: [32], timestamp_ms: u64, txs: vec<bytes>, evidence: vec<Evidence> }
```

The *proposal hash* is `keccak256` of the encoded `Proposal`. Signatures are recoverable secp256k1 signatures (`r ‖ s ‖ recovery id`) over `keccak256(kind ‖ chain_id ‖ view ‖ hash)` with every integer little-endian and `kind` one byte: 0 for a proposal, 1 for a vote, 2 for a finalize vote. The identity message of §2 is a vote (`kind` 1) in view 0 on the zero hash. Signing is deterministic (RFC 6979), so a node that signs the same message twice produces the same bytes.

A message whose signature does not recover to a validator is dropped. A `Propose` must be signed by the leader of its view; one for view 0 is dropped. `Certificate` is checked as §5a says.

## 5. Rules

Let `q` be the quorum and `v` the node's current view. A node:

- **Proposes** (leader only) by taking the mempool (`MempoolTake` with `max_bytes` 2^20, `max_gas` the block gas limit, 30 000 000, and `skip` the hashes of the transactions that the ancestors of the tip above the executed height carry, so that a block on an unexecuted parent gets a full budget of new transactions), building `Proposal { view, height: tip.height + 1, parent: tip.hash, timestamp_ms: max(now, tip.timestamp_ms + 1), txs, evidence }` with at most `max_txs` transactions and the pending evidence of §9 (at most 8 records), broadcasting `Propose`, and then handling its own proposal as below. `txs` are the mempool's in the order the host gave them, leaving out every transaction that an ancestor of the tip above the executed height carries, and every transaction that has run (its receipt records gas used). A leader extends its tip before executing it, since blocks execute on finalization, and until then its mempool still holds the tip's transactions.
- **Votes** for the first valid proposal it sees in view `v` that extends its tip and carries at most 8 evidence records, provided it has neither voted nor timed out in `v`; it sets `voted` and broadcasts `Vote { view, hash }`. Its own vote counts.
- **Times out** when the timeout timer of `v` fires: it sets `timed_out`, broadcasts `Vote { view: v, hash: zero }` and re-arms the timer to `now + T`. Every later firing in the same view repeats the same timeout vote, which peers may have missed, and forgets which peers were answered (§5a). A node may both vote for a proposal and time out in the same view.
- **Notarizes** a proposal when it holds, for some view `w`, `q` votes for `(w, hash)` or `q` finalize votes for it (a finalize quorum implies a notarization). If it knows the proposal and `w` is above its tip's view, the proposal becomes its tip. If `w ≥ v`, it enters view `w + 1`; it then broadcasts `Finalize { view: w, hash }` (its own finalize vote counts) when it knows the proposal and did not time out in `w`, and otherwise, when it lacks the proposal, sends a sync request (§7a) to the peer that delivered the quorum.
- **Skips** when it holds `q` timeout votes for some view `w ≥ v`: it enters `w + 1` with its tip unchanged.
- **Finalizes** the proposal at `(view, hash)` when it holds `q` finalize votes for it and knows the proposal and every ancestor down to its finalized height: it emits `ExecuteBlock` for each unexecuted ancestor and the proposal, lowest height first, stores the finalize certificate for each, and records the new finalized height. On each `BlockExecuted` it emits `FinalizeBlock { height, certificate }` and a `blocks` metric.

Votes and proposals for views at or above `v` are kept, whether or not they complete a quorum yet; finalize votes are kept for any view. A vote or proposal for a view below `v` is not counted. It is *stale*: its sender may be stuck in that view, and the node answers it as §5a says. The one exception is a proposal below `v` that the node holds a vote or finalize quorum for but lacked: it is kept, may become the tip, and may complete a finalization.

`ExecuteBlock` carries `Block { header, txs, participation }` where `participation` is the encoded `Participation { evidence }` of the proposal (§9).

## 5a. View synchronization

Validators that start at different times, restart, or lose messages drift into different views; a quorum then never forms in any one view unless they meet. The first three rules make them meet; the fourth keeps views notarizing when the network or the nodes are slower than the base timeout:

1. A quorum for any view at or above the current one moves a node past that view (§5, notarizes and skips).
2. A node stuck in a view repeats its timeout vote every view timeout (§5, times out).
3. **Certificate forwarding.** Every node remembers its *entry certificate*, the quorum that brought it into its current view (timeout votes, block votes, or finalize votes, as `Certificate { kind, view, hash, votes }` with `kind` 1 or 2), and its *tip certificate*, the quorum that made its tip the tip. When a node receives a stale `Propose` or `Vote` from a peer, it sends that peer, point to point, `Certificate { certificate: tip certificate, proposal: tip }` unless the tip certificate is also the entry certificate, then `Certificate { certificate: entry certificate, proposal }` with the proposal the entry certificate names, if it names one the node holds. It answers only when the stale message's signature verifies and its signer's validator id is the delivering peer's id (the `Hello` id of 09), because any validator's old signed message stays valid forever and proves nothing about whoever replays it. It answers at most once per peer until it enters another view or its timeout fires again. Stale messages can therefore draw at most two certificates and one proposal per validator per view and timeout period out of a node; that bounds the amplification but does not remove it, since the answer is far larger than the stale message (§8). A stale vote is not answered at all when it is a block vote, in the view just before the current one, for the proposal the node notarized there: its sender is about to notarize the same proposal itself.
4. **Backoff.** A node's backoff `b` starts at 0. Leaving a view by a timeout certificate raises it by one, to at most 4. Leaving a view by a notarization, a finalize quorum or a sync response less than `T / 2` after entering (or resuming) it lowers it by one, to at least 0. Views that keep timing out therefore wait up to 16 times longer, until the timeout exceeds what the network and the nodes actually need to notarize a view; the timeout stays there while views take more than half of it, and comes back down once they notarize well within it. A single faulty leader among honest ones still costs only `3 × slot_ms`.

A node that receives `Certificate` drops it unless: its view is at or above the node's current view, or it carries a proposal; the node does not already hold that quorum together with any proposal it names; `kind` is 1, or 2 with a non-zero hash; a carried proposal hashes to `hash` and names the same view, and `hash` is non-zero; and `votes` verifies as §6 says. The count and the indices are checked before any signature is recovered, so a certificate costs at most `n` recoveries however large its message. It then keeps the proposal and the votes as if they had arrived one by one, and applies §5: a timeout certificate skips, a vote or finalize certificate notarizes (and may finalize).

## 6. Certificates

`FinalizeBlock.certificate` is a `Certificate { kind: 2, view, hash, votes: vec<SignedVote { validator: u32, signature: [65] }> }` holding the finalize votes that finalized the block or one of its descendants. Verifying it means checking that `votes` holds at least a quorum and at most `n` entries whose `validator` indices are distinct and index the validator set, then that each signature recovers, over the finalize message of `(view, hash)`, to the validator its entry names. One entry that fails rejects the whole certificate. The same structure with `kind: 1` carries the block votes of a notarization, or with `hash` zero the timeout votes of a skipped view (§5a). Threshold BLS certificates (codex ADR 0008) will replace this format; `kind` and the message structure are versioned so that they can.

## 7. Persistence and restart

Everything the driver keeps between steps is node-local (`persist_*`), never chain state: its `SimplexState` (view, tip, finalized height, flags, validator index, clock, sync bookkeeping, the peers answered in this view, the backoff and when the view began), proposals by hash, votes and finalize votes by `(view, hash)`, the notarized hash per view, the certificate per finalized height, the entry and tip certificates, the first hash each validator signed per kind and view, and equivocation evidence (§9). The host also receives the `SimplexState` as `PersistState` after every step and hands it back at `Started`, so a restarted node resumes in the view it left with what it did there (§3); a node whose persisted tables are gone still follows from its state record. Garbage `resumed_state` is ignored and the driver starts from view 1.

## 7a. Catch-up

A node that sees a valid proposal more than one height above its tip, a finalize quorum for a proposal it cannot connect to its finalized head, or a notarization of a view at or above its own for a proposal it lacks, sends the peer that delivered the message a `Request` with `SyncRequest { from_height: finalized + 1 }`, unless a sync request is already outstanding (an outstanding request is abandoned on entering a new view). The peer answers with `Respond` carrying `SyncResponse { finalized_height, proposals, certificate }`: consecutive finalized proposals starting at the requested height, ending at the head of the certificate that finalized `from_height + 15` (or its own finalized head if lower), and that certificate. The requester checks that the certificate is a finalize certificate for the last proposal that verifies as §6 says and that the proposals link to its finalized head, then executes them and finalizes them under that certificate. The head becomes its tip if the certificate's view is above the tip's (a tip from a later view already extends the head), and the node enters the view after the certificate's if it is not past it, with the certificate as its entry certificate. It asks again while the responder reported a higher finalized height. Anything that fails a check is dropped.

On `Started`, the driver lowers its finalized height to the height of the chain state, so a node that kept its driver record but lost its chain state syncs instead of executing on the wrong parent.

## 8. Properties and limits of this version

- Safety: two conflicting proposals cannot both be notarized in one view (each honest validator votes at most once per view, across restarts), and a finalized proposal is on every later honest tip. A validator that finalized `B` in view `w` had `B` as its tip and only moves its tip to proposals notarized in later views, so it votes only for descendants of `B`; those are at least `q − f` validators, which leaves at most `f + n − q < q` votes for anything conflicting, however other validators jumped between views. A validator that timed out in `w` never finalizes `w`, and a finalize quorum and a timeout quorum for one view cannot both exist.
- Liveness: after the network delivers within `slot_ms`, every honest validator reaches the highest view any honest validator is in within one view timeout plus two message delays (by forwarding or by quorums of repeated timeout votes); from then on, a view with an honest leader whose tip the others hold finalizes within about two message delays after the proposal, and a faulty leader costs one view timeout, `3 × slot_ms` when the views before it notarized. When messages and processing take longer than the base timeout, backoff (§5a) lengthens the timeout until views notarize, up to `48 × slot_ms`; a network slower than that is not live.
- Finality for a block proposed in view `v` arrives in view `v` or `v + 1`; `latest`, `safe` and `finalized` coincide for RPC.
- Not in this version: slashing (no staking exists; §9 is the hook), weighted voting, asynchronous execution with lag `k`, transaction re-admission after a proposal that was not notarized, pruning of the driver's persisted tables, a bound on the votes and evidence a validator can make others store by signing messages for views far ahead, and authenticated peer ids. Certificate forwarding (§5a) amplifies: a stale vote of about 106 bytes can draw two certificates and a proposal of up to a block's size, once per validator per view and timeout period. Because `Hello` ids are self-declared (09), a peer that claims a validator's id and replays that validator's old vote draws the answer meant for it, and uses up that validator's answer for the period.

## 9. Equivocation evidence

An honest validator signs at most one hash per kind and view: one proposal (as leader), one block vote, one finalize vote. Timeout votes all carry the zero hash and never conflict, and a timeout vote beside a block vote in the same view is allowed (§5).

**Detection.** For every proposal, block vote and finalize vote whose signature it verifies, including each vote of a `Certificate` or of a sync response's certificate (§7a) that verifies, even when the certificate as a whole is then dropped, a node records the first hash the signer signed for that kind and view. A second, different hash is an equivocation. The node keeps both signed messages node-locally as

```
struct SignedHash { hash: [32], signature: [65] }
struct Evidence   { kind: u8, view: u64, validator: u32, first: SignedHash, second: SignedHash }   // first.hash < second.hash
```

once per offence (validator, view, kind), adds it to its pending evidence, emits `Metric { name: "equivocations", value: 1 }`, and emits `PeerScore { peer, delta: −100 }` for the peer that delivered the second message.

**Recording.** A leader puts up to 8 pending records that chain state does not yet hold into its proposal's `evidence`; a record leaves the pending list once chain state holds its offence. Executing a block, before its transactions, decodes `Block.participation` as `Participation { evidence: vec<Evidence> }` and takes at most 8 records. A record is kept when it is well formed (`kind` ≤ 2, `first.hash < second.hash`, and for `kind` 1 `first.hash` non-zero), `validator` indexes the validator set, both signatures recover to that validator over the messages of `(kind, view, hash)`, and its offence is not yet on record. Kept records are stored in chain state:

| Key | Value |
|---|---|
| `evidence/` + index (big-endian u64) | `Evidence`, indices from 0 in the order recorded |
| `meta/evidence_count` | `u64`, the number of records |
| `evseen/` + validator (big-endian u32) ‖ view (big-endian u64) ‖ kind | `u64` index of the record for that offence |

Anything else in `participation` is ignored, so evidence never makes a block invalid. The query `evidence` takes a `u64` first index and returns `vec<Evidence>`: the records from that index on, at most 64.

**Slashing hook.** Recording a record is the point where a staking kernel cuts the offender's stake, in the same state transition and therefore identically on every node. No staking exists in this version, so recording is all that happens.
