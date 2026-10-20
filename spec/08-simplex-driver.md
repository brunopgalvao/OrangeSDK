# 08 — The reference driver: Simplex consensus

## 1. Overview

This document specifies the consensus protocol of the reference kernel's driver (06 §3): a Simplex-family BFT protocol with fused finality. It is the protocol `solo dev` runs with one validator and what multi-validator chains run until governance installs another kernel. It fixes the messages, the voting rules, the certificate carried by `FinalizeBlock`, and what the driver persists. Networking, timers and keys are the host's (05 §4.5–4.6); execution is the state-transition group's (06 §5).

Tolerance: with `n` validators the protocol is safe and live with fewer than `n/3` faulty ones; a quorum is `⌊2n/3⌋ + 1` votes. Validators are counted, not weighted, in this version.

## 2. Validators and identity

`Genesis.validators` is a `ValidatorSet { validators: vec<Validator { id: [32], weight: u64 }> }` in canonical encoding. A validator's `id` is `keccak256` of its uncompressed secp256k1 public key (64 bytes). The order of the vector is the leader rotation; the leader of view `v` is `validators[(v − 1) mod n]`.

A node learns whether it is a validator by signing the identity message (§4) with key role 0 through `sign`, recovering the public key with `secp256k1_recover`, and looking the id up. A node without a key, or with a key outside the set, is an observer: it follows the protocol's messages, executes and finalizes exactly as validators do, and never votes.

## 3. Views and the notarized tip

The driver runs in views `v = 1, 2, …`. Every node keeps a *notarized tip*: the proposal with the highest view that it has seen notarized (§5), initially the empty tip at height 0 with hash zero. A proposal in view `v` extends the proposer's tip: its `parent` is the tip's hash and its `height` is the tip's height plus one.

Entering view `v`, a node:

1. clears its `voted`, `timed_out` and `proposing` flags;
2. sets the *timeout timer* of `v` (id `2v`) to `now + 3 × slot_ms`;
3. if it is the leader of `v`, proposes at `max(now, tip.timestamp_ms + slot_ms)`: immediately, or when the *proposal timer* of `v` (id `2v + 1`) fires.

Timers of other views are ignored when they fire. `slot_ms` is `GenesisParams.slot_ms`.

## 4. Messages

All consensus traffic is `Broadcast` on topic 1 with a `ConsensusMessage` payload:

```
enum ConsensusMessage {
  0 Propose  { proposal: Proposal, signature: [65] }
  1 Vote     { view: u64, hash: [32], signature: [65] }   // hash zero: timeout vote
  2 Finalize { view: u64, hash: [32], signature: [65] }
}
struct Proposal { view: u64, height: u64, parent: [32], timestamp_ms: u64, txs: vec<bytes> }
```

The *proposal hash* is `keccak256` of the encoded `Proposal`. Signatures are recoverable secp256k1 signatures (`r ‖ s ‖ recovery id`) over `keccak256(kind ‖ chain_id ‖ view ‖ hash)` with every integer little-endian and `kind` one byte: 0 for a proposal, 1 for a vote, 2 for a finalize vote. The identity message of §2 is a vote (`kind` 1) in view 0 on the zero hash.

A message whose signature does not recover to a validator is dropped. A `Propose` must be signed by the leader of its view.

## 5. Rules

Let `q` be the quorum. A node:

- **Proposes** (leader only) by taking the mempool (`MempoolTake`), building `Proposal { view, height: tip.height + 1, parent: tip.hash, timestamp_ms: max(now, tip.timestamp_ms + 1), txs }` with at most `max_txs` transactions, broadcasting `Propose`, and then handling its own proposal as below. `txs` are the mempool's in the order the host gave them, leaving out every transaction that an ancestor of the tip above the executed height carries, and every transaction that has run (its receipt records gas used). A leader extends its tip before executing it, since blocks execute on finalization, and until then its mempool still holds the tip's transactions.
- **Votes** for the first valid proposal it sees in its current view that extends its tip, provided it has neither voted nor timed out in that view; it sets `voted` and broadcasts `Vote { view, hash }`. Its own vote counts.
- **Times out** when the timeout timer of its current view fires and it has not already done so: it sets `timed_out` and broadcasts `Vote { view, hash: zero }`. A node may both vote for a proposal and time out in the same view.
- **Notarizes** a proposal when it holds `q` votes for `(view, hash)` and knows the proposal. If the view is its current view, the proposal becomes its tip and it enters view `v + 1`. If it had not timed out in `v`, it broadcasts `Finalize { view, hash }`; its own finalize vote counts.
- **Skips** its current view when it holds `q` timeout votes for it: it enters `v + 1` with its tip unchanged.
- **Finalizes** the proposal at `(view, hash)` when it holds `q` finalize votes for it and knows the proposal and every ancestor down to its finalized height: it emits `ExecuteBlock` for each unexecuted ancestor and the proposal, lowest height first, stores the finalize certificate for each, and records the new finalized height. On each `BlockExecuted` it emits `FinalizeBlock { height, certificate }` and a `blocks` metric.

Votes for views below the current one are ignored, except finalize votes, which are counted for any view. Proposals for views below the current one are ignored.

## 6. Certificates

`FinalizeBlock.certificate` is a `Certificate { kind: 2, view, hash, votes: vec<SignedVote { validator: u32, signature: [65] }> }` holding the finalize votes that finalized the block or one of its descendants. Verifying it means recovering each signature over the finalize message of `(view, hash)` and checking that at least a quorum of distinct validator indices match. Threshold BLS certificates (codex ADR 0008) will replace this format; `kind` and the message structure are versioned so that they can.

## 7. Persistence and restart

Everything the driver keeps between steps is node-local (`persist_*`), never chain state: its `SimplexState` (view, tip, finalized height, flags, validator index, clock), proposals by hash, votes and finalize votes by `(view, hash)`, the notarized hash per view, and the certificate per finalized height. The host also receives the `SimplexState` as `PersistState` after every step and hands it back at `Started`, so a restarted node resumes in the view it left; a node whose persisted tables are gone still follows from its state record. Garbage `resumed_state` is ignored and the driver starts from view 1.

## 7a. Catch-up

A node that sees a valid proposal more than one height above its tip, or a finalize quorum for a proposal it cannot connect to its finalized head, sends the peer that delivered the message a `Request` with `SyncRequest { from_height: finalized + 1 }`, unless a sync request is already outstanding (an outstanding request is abandoned on entering a new view). The peer answers with `Respond` carrying `SyncResponse { finalized_height, proposals, certificate }`: consecutive finalized proposals starting at the requested height, ending at the head of the certificate that finalized `from_height + 15` (or its own finalized head if lower), and that certificate. The requester checks that the certificate is a quorum of finalize votes for the last proposal and that the proposals link to its finalized head, then executes them, finalizes them under that certificate, moves its tip and view forward if they are behind, and asks again while the responder reported a higher finalized height. Anything that fails a check is dropped.

On `Started`, the driver lowers its finalized height to the height of the chain state, so a node that kept its driver record but lost its chain state syncs instead of executing on the wrong parent.

## 8. Properties and limits of this version

- Safety: two conflicting proposals cannot both be notarized in one view (each honest validator votes at most once per view), and a finalized proposal is on every later honest tip because a validator that timed out in `v` never finalizes `v` while one that finalized never voted to skip it.
- Liveness: after the network delivers within `slot_ms`, a view with an honest leader finalizes within about two message delays after the proposal; a faulty leader costs `3 × slot_ms`.
- Finality for a block proposed in view `v` arrives in view `v` or `v + 1`; `latest`, `safe` and `finalized` coincide for RPC.
- Not in this version: equivocation evidence and slashing, weighted voting, asynchronous execution with lag `k`, and transaction re-admission after a proposal that was not notarized.
