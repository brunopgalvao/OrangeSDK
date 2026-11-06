# 17 — Bridge to Ethereum: outbox, light client and inbox

## 1. Overview

This document specifies the OrangeSDK-to-Ethereum half of the tier-2 bridge of codex ADR 0013: a message that any account or contract on an OrangeSDK chain hands to the *outbox* is recorded in chain state, a relayer proves it on Ethereum against a state root that a *light client* there accepted from a threshold certificate (spec 12), and an *inbox* delivers it to its recipient once, after a delay, within rate limits, unless a guardian stops it. The Ethereum-to-OrangeSDK half, a sync-committee light client of Ethereum as a kernel module, is specified separately. The decisions behind this document are recorded in codex ADRs 0029 and 0031; the second replaced the constant group key with one that rotates every epoch, and the version-1 contracts with version-2 ones that follow it.

The pieces, and where they live:

| Piece | Where | Section |
|---|---|---|
| Outbox, the system address `0x…4f42` | reference kernel (`guest/kernel/src/outbox.rs`), `orange_abi::bridge` | §2, §3 |
| Proposal anchor, the state root a certificate vouches for | reference driver (spec 08 §4, §5, §6a) | §4 |
| `OrangeFinalityVerifierV1`, `OrangeLightClient` (a key that never changes) | `contracts/` | §5.1, §5.2 |
| `OrangeFinalityVerifierV2`, `OrangeLightClientV2` (a key that rotates) | `contracts/` | §5.3 |
| `OrangeInbox` | `contracts/` | §6 |
| Relayer library, node queries, RPC methods | `crates/orange-bridge`, the kernel's `finality_proof` and `handoff` queries, `crates/orange-rpc` | §7 |

Integers inside a message, a certificate message or an Ethereum ABI word are big-endian. Integers inside an OrangeSDK canonical encoding (06 §2), such as a proposal, are little-endian.

## 2. The outbox

### 2.1 Interface

The *outbox address* is `0x0000000000000000000000000000000000004f42` (ASCII `OB`), in the system range of 16 §4. A message call to it carries the Solidity ABI encoding of a call to

```solidity
interface IOrangeOutbox {
    function send(uint64 destChainId, address recipient, bytes calldata payload)
        external payable returns (uint64 nonce);                   // 0x67914f6e
    event MessageSent(uint64 indexed nonce, address indexed sender, uint64 indexed destChainId,
                      address recipient, uint256 value, bytes32 messageHash, bytes payload);
                      // topic 0x8fabcda9a3d55fe5b04af509473a7e85e18d39ae5e91b739a48a647ca26f1017
}
```

`contracts/IOrangeOutbox.sol` is this interface. A contract calls the outbox like any contract (`IOrangeOutbox(0x…4F42).send(...)`), at any depth; an account calls it with a transaction, so `cast send 0x0000000000000000000000000000000000004f42 "send(uint64,address,bytes)" 1 0x… 0x…` works as is.

### 2.2 Acceptable sends and admission

Calldata is a *send* only if it is exactly the canonical encoding: the selector, a `uint64` word whose high 24 bytes are zero, an address word whose high 12 bytes are zero, the offset word 96, a length word of at most `MAX_PAYLOAD = 4 096` with its high 24 bytes zero, the payload, zero padding to a multiple of 32 bytes, and nothing after. A send is *acceptable* on chain `chain_id` when `destChainId` is neither 0 nor `chain_id`, and `recipient` is not the zero address.

Admission (`kernel_stf_validate_tx`, and selection in `kernel_stf_build_block`) rejects a transaction whose `to` is the outbox address and whose calldata is not an acceptable send with reason 14 (`OUTBOX_MESSAGE`), after the checks every transaction gets and the checks of 13 §2.3, 15 §3.3 and 16 §4.2, and before the checks against the sender's account. Reasons 11 to 13 keep their meanings; the RPC reports reason 14 as `not a valid outbox message`. A message call from a contract is not admitted; it meets the rules of §2.3.

### 2.3 Execution

The reference kernel serves the outbox from its precompile provider (16 §5.2), after Ethereum's precompiles and before native contracts, for every message call whose code address is the outbox address. With `G` the gas the call carries and `n` the payload length:

1. The call *reverts*, with empty return data and no gas used beyond the `CALL`'s own charges, if it is not a `CALL` (a `STATICCALL`, `DELEGATECALL` or `CALLCODE`), if it is a `CALL` made in a static context, or if its calldata is not an acceptable send. revm reverts the call's checkpoint, value transfer included.
2. If `G < send_gas(n)` (§2.4), the call fails: it consumes all of `G`, returns no data and reverts its checkpoint.
3. Otherwise, through revm's journal: `nonce` is one more than slot 0 of the outbox's EVM storage (`NONCE_SLOT`), which starts at zero; slot 0 is set to `nonce`; the slot whose 32-byte big-endian number is `nonce` is set to the message hash (§3); the outbox logs `MessageSent(nonce, sender, destChainId, recipient, value, messageHash, payload)`, where `sender` is the call's caller (`msg.sender`) and `value` its value; the call returns `nonce` as one ABI word and uses `send_gas(n)`.

The value of a send moves to the outbox's balance with the call, and nothing in this version moves it out. A revert of any frame enclosing the send, the transaction included, takes back the nonce, the slot and the log with everything else, exactly as for an `SSTORE` and a `LOG` at the same point; a call query (`eth_call`, gas estimation) runs the send and keeps nothing. Nonces are therefore consecutive from 1 over the messages that stand, in execution order.

The outbox has no code and no nonce. When a transaction's changes are committed, the outbox account is written with its balance, or left out of state (deleted) if its balance is zero, and the slots it changed are written whatever its balance: the EIP-161 rule of the kernel's commit would otherwise delete an empty outbox account together with its writes. No creation can land on the outbox address, which no key or `CREATE2` salt reaches without a Keccak preimage.

### 2.4 Gas

```
send_gas(n) = SEND_GAS + SEND_WORD_GAS × ⌈n / 32⌉        SEND_GAS = 50 000, SEND_WORD_GAS = 300
```

`SEND_GAS` covers the two storage writes (at most 22 100 each, a new slot and the nonce slot) and the log's base and topics; the word charge covers hashing the payload and logging it (8 gas a byte). The `CALL` that reaches the outbox is charged by the EVM as for any account. A transaction that sends `n` payload bytes directly uses its intrinsic gas plus `send_gas(n)`; `crates/orange-bridge/tests/outbox.rs` pins it, with `send_gas(4 096) = 88 400` for the largest payload.

## 3. Messages in state

A message is

```
message = version (1 byte, 1) ‖ source_chain_id (u64) ‖ nonce (u64) ‖ sender (20) ‖ dest_chain_id (u64)
        ‖ recipient (20) ‖ value (32 bytes) ‖ payload
```

integers big-endian, 97 bytes plus the payload: the layout of Solidity's `abi.encodePacked(uint8(1), uint64 sourceChainId, uint64 nonce, address sender, uint64 destChainId, address recipient, uint256 value, bytes payload)`. `source_chain_id` is the OrangeSDK chain's id, `sender` the caller of `send`, `value` its value. The *message hash* is `keccak256(message)`.

Message `nonce` is committed (10 §2) as the EVM storage slot `nonce` of the outbox, under the chain-state key

```
message_key(nonce) = "slot/" (5 bytes) ‖ 0x0000000000000000000000000000000000004f42 ‖ nonce as a 32-byte big-endian word
```

(57 bytes) with the 32-byte message hash as its value. Its leaf in the state trie (10 §4) is `leaf(keccak256(message_key(nonce)), keccak256(message_hash))`. A proof of that key (10 §5) against a block's `state_root` that ends at that leaf shows the message recorded in that block or an earlier one: slots of the outbox are written once and never cleared, so a message stays provable in every later state. `eth_getStorageAt(0x…4f42, nonce)` returns the message hash and slot 0 the last nonce.

## 4. The anchor

A threshold certificate (12 §7) signs a proposal hash, and a proposal (08 §4) carries transactions, not the state they produce: blocks execute after finalization. Nothing that a certificate signed bound a state root, so no contract could verify state against one. This version adds the minimal binding: every proposal carries an *anchor*, `anchor_height` and `anchor_root`, at the fixed bytes 56 to 95 of its encoding (08 §4). An honest leader sets it to the last block it executed and that block's `state_root`; a shareholder adds its partial signature to its finalize vote only for a proposal whose anchor it can vouch for: none (height 0, zero root), or a height below the proposal's that the shareholder executed with exactly that state root (08 §6a). Voting and finalization ignore the anchor, so consensus is unchanged and a false anchor costs the chain only that block's certificate.

So a valid certificate for proposal `P` shows that at least one honest shareholder executed block `P.anchor_height` and obtained `P.anchor_root`, as long as the faulty shareholders hold fewer than the threshold of shares, which is the trust a certificate always needs; shares follow stake, so that holds whenever validators with more than a third of the key set's epoch stake are honest (15 §6.8). The contracts need no list of validators or stakes for it: the bound is in how the kernel dealt the shares, and a certificate verifies under the group key alone. Execution is deterministic, so that root is every honest node's `state_root` of that height. The block hash (`keccak256` of the block's Ethereum header, spec 20 §3.1, which does commit to `state_root`) is not what certificates sign; a contract never needs it.

The anchor of a certified proposal is typically one or two heights below the proposal: a leader proposes on a notarized tip that it has not executed yet. A shareholder that has not executed the anchored height when it votes signs nothing for that proposal; the next blocks are certified again.

## 5. On Ethereum: verifier and light client

### 5.1 `OrangeFinalityVerifierV1`

`contracts/OrangeFinalityVerifierV1.sol` verifies version-1 certificates as 12 §8 specifies, with the chain id and the group key (EIP-2537 encoding, 256 bytes) fixed by its constructor. It and `OrangeLightClient` serve a chain whose key never changes; the reference kernel rotates its key every epoch and produces version-2 certificates only, which §5.3's contracts verify. The constructor refuses a key that is not 256 bytes, is the identity, or does not come back unchanged from `BLS12_G2MSM` (`0x0e`) with scalar 1, which rejects points off the curve, outside the subgroup or not canonically encoded. `verify(uint64 height, bytes32 blockHash, bytes signature)` reverts with `InvalidSignatureLength()` unless the signature is 128 bytes and otherwise returns whether the pairing check holds; a signature that is no valid point makes the pairing precompile fail and `verify` return false. It has no owner, no storage and no way to change: a later certificate version is verified by a new contract (ADR 0013).

### 5.2 `OrangeLightClient`

`contracts/OrangeLightClient.sol` holds the state roots of one OrangeSDK chain. Its constructor takes the verifier and reads its chain id; both are immutable, and it has no owner.

`submit(bytes proposal, bytes signature)` takes an encoded proposal and the certificate's signature in EIP-2537 encoding. With `height` the little-endian `u64` at bytes 8 to 15 of `proposal`, `anchor` the one at bytes 56 to 63 and `root` bytes 64 to 95, it reverts with

| Error | When |
|---|---|
| `ProposalTooShort()` | `proposal` is shorter than 96 bytes |
| `NoAnchor()` | `anchor` is 0 |
| `AnchorNotBelowProposal()` | `anchor ≥ height` |
| `NotMonotonic()` | `anchor` is not above `latestHeight`, the highest height stored so far (0 at first) |
| `InvalidCertificate()` | `verifier.verify(height, keccak256(proposal), signature)` is false |

and otherwise stores `stateRoots[anchor] = root`, sets `latestHeight = anchor` and logs `StateRootStored(uint64 indexed height, bytes32 stateRoot, uint64 proposalHeight, bytes32 proposalHash)`. The checks before the signature are cheap, so a stale or malformed submission costs little. The client reads nothing of the proposal past byte 95; whatever follows is bound by the hash. A certificate of another chain fails because the chain id is part of the signed message; a proposal changed after signing fails because its hash changed.

`stateRoots(height)` returns a stored root or zero. Roots are never overwritten or removed.

### 5.3 `OrangeFinalityVerifierV2` and `OrangeLightClientV2`

`contracts/OrangeFinalityVerifierV2.sol` holds the chain id and no key. `isValidKey(key)` says whether a 256-byte EIP-2537 G2 point is a usable group key (not the identity, unchanged by `BLS12_G2MSM` with scalar 1); `compress(key)` returns its compressed encoding (12 §8, rotations); `verify(key, keyId, height, blockHash, signature)` returns whether the signature verifies under `key` over `message_v2`, and `verifyRotation(key, newKeyId, newKey, signature)` whether it verifies under `key` over the rotation message to `newKeyId` and the compressed `newKey`. A signature or key of the wrong length reverts with `InvalidLength()`. It has no owner and no storage.

`contracts/OrangeLightClientV2.sol` holds the state roots of one OrangeSDK chain and its *current key set*: an id and a group key in EIP-2537 encoding, in storage. Its constructor takes `(verifier, keyId, key, epochBlocks, maxKeyAge)`: the trusted key set to start from (the chain's first key set, or any later one the deployer trusts), the chain's epoch length `L` and its `max_key_age` `K` (15 §2); it reverts with `InvalidParameters()` if `L` or `K` is zero and `InvalidKey()` if the key is not valid. The verifier, the chain id, `L` and `K` never change; it has no owner. `epochOf(h)` is `(h − 1) / L`, 0 for `h = 0`.

`rotate(newKeyId, newKey, signature)` moves the current key set along one handoff (15 §6.6). It reverts with

| Error | When |
|---|---|
| `NotNewer()` | `newKeyId` is not above the current id |
| `KeyExpired()` | `newKeyId` is above the current id plus `K` |
| `InvalidKey()` | `newKey` is not a valid key |
| `InvalidCertificate()` | `signature` (EIP-2537, 128 bytes) is not the current key's group signature over the rotation message to `newKeyId` and `newKey` |

and otherwise makes `(newKeyId, newKey)` the current key set and logs `KeyRotated(uint64 indexed from, uint64 indexed to)`. A rotation needs no other order: a relayer submits the chain's handoffs in turn, each signed by the key it replaces.

`submit(proposal, signature)` is `OrangeLightClient.submit` (§5.2) with the version-2 certificate of the current key set: after the checks of §5.2 up to `NotMonotonic()`, it reverts with `KeyExpired()` if `epochOf(anchor)` is above the current id plus `K`, and with `InvalidCertificate()` unless `signature` verifies under the current key over `message_v2` of the current id, the proposal's height and its hash. A certificate of any other key set, including every certificate that former shareholders of an earlier key set sign, does not verify.

**Why this bounds what old keys can do.** A key set is trusted only for anchors up to `K` epochs past its own id, and only hands off to ids up to `K` past its own. The chain keeps every shareholder of key set `k` bonded or unbonding, and slashable, until after the chain has executed every height that `k` may anchor for this client and an epoch more has passed for evidence (15 §6.7). So a false root that a threshold of shareholders of the current key certify, or a false rotation they sign, is evidence of threshold misbehaviour (15 §5.1) while their stake can still be burned. A client whose current key the chain has handed off from refuses the old key's certificates outright, since they do not verify under the newer key.

`OrangeLightClientV2` implements `IOrangeLightClient`, the interface `OrangeInbox` reads (§6.4).

## 6. On Ethereum: the inbox

### 6.1 Messages and their proofs

`contracts/OrangeInbox.sol` delivers the messages of the light client's chain whose destination is the chain it runs on. A message is passed as the tuple `Message { uint64 nonce; address sender; address recipient; uint256 value; bytes payload; }`; the inbox completes it with `sourceChainId` (the light client's chain id) and `destChainId = block.chainid` and hashes it as §3 says. A message sent for any other destination therefore hashes to something the outbox never stored, and no proof reaches it.

`prove(uint64 height, Message m, bytes32[] siblings)` reverts with `IsPaused()` while paused, `NonceBelowFirst()` if `m.nonce` is below `firstNonce`, `AlreadyProven()` if that nonce was proven before, unless it is pending under a revoked root (§6.3), `RevokedRoot()` if the root of `height` is revoked, `UnknownStateRoot()` if the light client holds no root for `height`, `ProofTooDeep()` for more than 256 siblings, and `InvalidProof()` unless the proof leads to that root. The proof is checked as 10 §5.3 for a present leaf, with the terminal implied: `p = keccak256(message_key(m.nonce))`, `h = leaf(p, keccak256(messageHash))`, then for `i` from the last sibling down to 0, `h = branch(h, siblings[i])` if bit `i` of `p` is 0 and `branch(siblings[i], h)` otherwise; it must end at the root. A proven message is recorded as pending with its hash, `executableAt = block.timestamp + delay` and `height`, replacing the entry a revoked root proved, and `MessageProven(nonce, messageHash, height, executableAt)` is logged.

`execute(Message m)` reverts with `IsPaused()` while paused, `NotPending()` unless the nonce is pending, `RevokedRoot()` if the root it was proven under is revoked, `MessageMismatch()` if `m` does not hash to the proven hash, `TooEarly()` before `executableAt`, and `RateLimited()` if the message does not fit the current window (§6.2). Otherwise it marks the nonce delivered, calls `recipient.onOrangeMessage(sourceChainId, nonce, sender, value, payload)` (`IOrangeMessageRecipient`, `contracts/IOrangeBridge.sol`) with all but one 64th of the gas it has left (EIP-150), and logs `MessageDelivered(nonce, messageHash, recipient)`. If the recipient reverts, `execute` reverts with the recipient's revert data and the message stays pending, so it can be executed again; anyone may call `execute`, and the caller chooses the gas. A recipient without code accepts every message. A nonce is delivered at most once.

`value` is the OrangeSDK value the outbox kept (§2.3), passed to the recipient as a number; the inbox holds and pays no ether. A recipient checks that `msg.sender` is the inbox and decides what `sender`, `sourceChainId` and `value` entitle the message to.

### 6.2 Delay and rate limits

`delay` (seconds, at most `MAX_DELAY = 30 days`) is the time between proving a message and executing it; a change applies to messages proven after it. Deliveries are counted in fixed windows of `window` seconds (non-zero): a window starts at the first delivery at or after the end of the previous one, and a window delivers at most `maxMessagesPerWindow` messages and at most `maxValuePerWindow` value in total. A message that does not fit waits for a later window, and its `execute` reverts with `RateLimited()`; that includes every message, of any value, while a limit lowered during a window sits below what the window has already delivered.

**Recipients with a limit of their own.** Anyone can send messages, and a message to a recipient that accepts anything (one without code, or one that ignores what it does not know) costs its sender little; delivered as each window opens, such messages would fill the shared limit and keep a token gateway's messages waiting `RateLimited()` for as long as the sender pays. So the owner can give a recipient a message limit of its own: `setRecipientLimit(recipient, maxMessages)` logs `RecipientLimitChanged(recipient, maxMessages)`, and while `maxMessages` is non-zero the recipient's messages count against it and not against `maxMessagesPerWindow`, in windows of the same `window` seconds that the recipient's own deliveries open, as the shared ones open with theirs; zero returns the recipient to the shared limit. `recipientLimits(recipient)` returns `(maxMessages, windowStart, messages)`. Every message's value still counts against `maxValuePerWindow`. A recipient with a limit of its own should accept only messages it authenticates, as the gateways do (spec 21 §5.1), since a message it refuses reverts its `execute` and counts for nothing: others then cannot fill its limit, and what a forged root delivers to it is bounded by its limit. The owner gives each token gateway one.

### 6.3 Roles and their limits

| Role | Can | Cannot |
|---|---|---|
| anyone | prove and execute messages, as above | anything else |
| guardian | `pause()`; `veto(nonce)` of a pending message, which then never executes; `revokeRoot(height)` | unpause, change any parameter, deliver anything, prove under a revoked root |
| owner | `pause()`, `unpause()`, `revokeRoot(height)`, `setGuardian`, `setDelay` (≤ `MAX_DELAY`), `setRateLimit` (window non-zero), `setRecipientLimit`, `transferOwnership` (never to zero) | deliver, alter or replay a message, prove without a root, change the light client, the source chain or `firstNonce` |

Pausing stops `prove` and `execute`. The delay exists so that the guardian can pause, and veto a message proven from a certificate that faulty shareholders forged or revoke the forged root, before it executes; the owner (a timelock or multisig) sets how long that window is and how much can move per window, which bounds what a forged certificate can deliver. The value limit counts only the value messages carry: a recipient that holds value itself and moves it on a message's word, as a token gateway does (spec 21 §6.2), is bounded by the message limit and its own caps, not by `maxValuePerWindow`. Neither role is needed for an honest message to arrive: while the inbox is not paused and the message fits a window, anyone can prove and execute it.

**Revoked roots.** Light-client roots are written once (§5.2), so a forged certificate's root stays in the client, and a forger can prove junk under it at any nonce at or above `firstNonce`, far ahead of the outbox's counter included, each of which would then refuse its honest message `AlreadyProven()`. `revokeRoot(height)`, by the guardian or the owner and also while paused, refuses the root of `height` for good (`revoked(height)` is then true; it logs `RootRevoked(height, by)`): `prove` refuses it, `execute` refuses every message proven under it, and a nonce still pending under it is proven again, by anyone, under a root that is not revoked, as if it had never been proven, with a new delay. So a guardian who sees a forged root revokes it before the delay of what it proved runs out, and every honest message whose nonce the forgery took arrives in the end; the inbox needs no successor. A veto stays final: a vetoed nonce is never proven again, because the token gateway refunds the message of a vetoed nonce to its sender (spec 21 §5.1, §5.5c), and delivering it too would pay twice; so the guardian revokes a forged root rather than vetoing what it proved, and vetoes only a message it wants never delivered. A revoked root cannot be restored, and revoking an honest root only makes its pending messages wait for a proof under another root, which every later root gives (§3); neither role can deliver anything by it. What a forged root delivered before it was revoked stays delivered.

`entries(nonce)` returns `(messageHash, executableAt, height, status)` for every proven nonce, `height` being the one whose root proved it, with `status` `Pending` (1), `Delivered` (2) or `Vetoed` (3), and never changes once `Delivered` or `Vetoed`; with `hashMessage(m)` a contract on Ethereum can therefore tell exactly what the inbox delivered with a nonce, or that it will never deliver it. The token gateway reads it to report such nonces back to the OrangeSDK chain (spec 21 §5.1, §5.5c). The record is of the inbox, not of the light client: a nonce a forged certificate proved stays proven, and its honest message, whose hash differs, is refused `AlreadyProven()`, until the guardian revokes the forged root.

### 6.4 Deployment and succession

The constructor takes `(lightClient, firstNonce, owner, guardian, delay, window, maxMessagesPerWindow, maxValuePerWindow)` and refuses a zero owner or guardian (`ZeroAddress()`), a delay above `MAX_DELAY` (`DelayTooLong()`) and a zero window (`InvalidWindow()`). The light client, the source chain and `firstNonce` never change. The inbox reads its light client only through `IOrangeLightClient` (`chainId()`, `stateRoots(height)`), which both `OrangeLightClient` and `OrangeLightClientV2` implement, so the same contract serves either version unchanged. A new certificate version needs a new verifier and light client, and therefore a new inbox instance pointed at it: it is deployed with `firstNonce` above every nonce the old one could have delivered (the old one paused first), so no message is delivered twice across the two, and recipients switch to trusting the new inbox. Moving from version 1 to version 2 is such a succession.

## 7. Relaying

A relayer needs, from an OrangeSDK node: messages (the outbox's `MessageSent` logs, through `eth_getLogs` or receipts); a certificate whose proposal anchors a height at or after the message's block, with that proposal; and the proof of the message's slot against that height's state root. Then on Ethereum it calls `submit` on the light client (unless a root at or after the message is already stored and its node can still prove against it), `prove` on the inbox, and, after the delay, `execute`.

**Keeping a version-2 client current.** The client accepts certificates of its current key set only. A relayer reads the client's `keyId`, submits with a certificate of that key set while the chain still produces them (checking it first, as below), and moves the client along every handoff the chain recorded, in order, by `rotate` with the handoff record (15 §6.6), from the `handoff` query or `orange_getRotation`. It does so promptly: the client's protection rests on it holding a key whose shareholders are still bonded (§10).

**The handoff query.** `handoff` (15 §8) takes a key set id and returns the `Handoff` out of it: the target's id and compressed group key, the group signature and the height that recorded it.

**The query.** `finality_proof` takes a `u64` height and returns, with status 0, `FinalityProof { certificate: bytes, proposal: bytes }`: the threshold certificate the node stored for that height (08 §6a; 97 bytes, version 2, from the reference driver) and the encoded proposal its block hash names, which may be a descendant of the block at that height finalized with it. Status 1 means the node stored no threshold certificate for that height; status 2, bad params. The answer is node-local, like every certificate.

**Historical proofs.** The reference node keeps the state trie of each of the executed blocks in its state history (spec 20 §5.1: the last 1 024 by default, fewer while blocks write heavily, every block on an archive node), so it proves against any of those roots. A relayer submits an anchor no older than that, or keeps the proofs it needs.

**RPC.** Beside the Ethereum methods, `crates/orange-rpc` serves:

| Method | Params | Result |
|---|---|---|
| `orange_getFinalityProof` | height (quantity) | `null` if the node stored no threshold certificate for it; otherwise `{height, blockHash, anchorHeight, anchorRoot, certificate, proposal, signature, calldata}`: the certified proposal's height and hash, its anchor, the certificate and proposal bytes, the signature in EIP-2537 encoding and the light client's `submit` calldata. A server error if the proposal has no anchor. |
| `orange_getOutboxProof` | nonce, height (quantities) | `null` if the node does not hold that height's state, because it is older than its state history or not yet executed; otherwise `{nonce, height, messageHash, stateRoot, siblings}`, the siblings root first. A server error, `the message is not committed at that height`, if the slot does not hold the message there. |
| `orange_getRotation` | from key set id (quantity) | `null` if the chain recorded no handoff out of it; otherwise `{from, to, height, key, keyEip2537, signature, calldata}`: the target, the recording height, the target's group key compressed and in EIP-2537 encoding, the group signature in EIP-2537 encoding and `OrangeLightClientV2.rotate` calldata. |
| `orange_getGroupKey` | none | `null` before the chain adopted its first key set, or on a chain without a threshold key; otherwise `{keyId, groupKey}`: the active key set at the node's head (`dkg/active`) and its 96-byte compressed group key (`dkg/group_key`, 15 §6), the key a joining node trusts a snapshot by (22 §7.2). |

`orange_getFinalityProof` also returns `keyId`, the key set a version-2 certificate names (`null` for version 1).

**The library.** `crates/orange-bridge` does each step against an `orange_node::Node`: `finality_proof`, `submission_covering` (the certified proposal with the highest anchor at or after a height, among the heights the node can still prove against) and `submission_covering_key` (the same among the certificates a client holding one key set takes: before choosing a certificate it checks, off chain, that it names that key set and that its signature verifies under the key set's group key, as the chain adopted it, over `message_v2` of the chain's id; a certificate the node stored is only labelled with its key set, and a label that does not match the signature would cost a reverted `submit`, since the client verifies under its own key and id. It passes over such a certificate and returns it with the reason, another key set or a signature that does not verify, for the relayer to log, and fails for a key set the chain never adopted), `Submission` (decodes a certificate of either version, checks the proposal against it, decompresses the signature into EIP-2537 encoding, builds `submit` calldata), `rotation` and `rotations_from` (the recorded handoff out of a key set, and the chain of them, at most 256 at a time; a record out of a key set that is not from it or not to a newer one, which no chain records, fails the chain, so a faulty node cannot keep a relayer reading for ever) and `Rotation` (decompresses the key and signature, builds `rotate` calldata), `sent_messages` (messages from logs), `slot_proof` and `SlotProof` (checks the proof ends at the message's leaf, recomputes the root as the inbox does, builds `prove` calldata), `execute_calldata`, and the contracts' constructor arguments.

## 8. Gas

Measured on revm 43 at Osaka by `crates/orange-bridge/tests/contracts.rs` and `contracts_v2.rs`, which pin each number; contracts compiled by solc 0.8.28 with the optimizer at 200 runs for the Cancun EVM target. Transaction gas includes the 21 000 base and the calldata.

| Call | Gas |
|---|---|
| `OrangeFinalityVerifierV1.verify`, execution | 126 708 |
| the same, as a transaction | 150 368 |
| `OrangeLightClient.submit` of a 103-byte proposal (one 3-byte transaction in it), transaction | 206 756 |
| `OrangeInbox.prove`, 3 siblings, 4-byte payload, transaction | 86 316 |
| `OrangeInbox.prove`, 14 siblings (a state of 4 099 entries), transaction | 98 476 |
| `OrangeInbox.execute` delivering to the test `MessageRecipient`, transaction | 209 327 |
| `OrangeFinalityVerifierV2.verify`, execution | 127 279 |
| `OrangeFinalityVerifierV2.verifyRotation`, execution | 129 050 |
| `OrangeLightClientV2.submit` of a 103-byte proposal, transaction | 228 155 |
| `OrangeLightClientV2.rotate`, transaction | 236 883 |

Of `verify`, 115 791 is precompiles: 114 275 of BLS (12 §2), 516 of SHA-256 and 2 × 500 of MODEXP at the EIP-7883 price that Osaka charges. Version 2 adds the external call to the verifier and the key passed to it: `OrangeLightClientV2.submit` reads the key's eight storage words and copies them into the call, about 21 000 gas more than version 1. `rotate` checks the new key with `BLS12_G2MSM` (22 500 gas, EIP-2537's single-point price), compresses it, verifies the rotation, and rewrites the key's eight words. `submit` adds the proposal's calldata and hash and two new storage slots; it grows by 16 gas for each non-zero byte of the proposal (more under the EIP-7623 floor for a large one), so a relayer chooses a small certified proposal when it can. Revoked roots (§6.3) added 2 433 gas to `prove` and 2 363 to `execute` on 2026-11-06, from 83 746, 95 906 and 204 362: each reads whether its root is revoked, a cold storage slot (2 100 gas), and `prove` stores the height beside the time it already writes. Recipients with a limit of their own (§6.2), later on 2026-11-06, added 2 602 to `execute`, which reads the recipient's limit, a cold slot, and 137 to each `prove`, whose selector the new function put one step further down the contract's dispatcher. Each sibling adds about 1 100 gas to `prove`: a state of `n` random keys gives proofs of about `log2(n)` siblings (10 §4), some 30 for a chain of a billion entries. `execute` is mostly the recipient's own work; the test recipient writes seven new storage slots.

## 9. Contracts and their fixtures

The Solidity sources are in `contracts/` (test contracts in `contracts/test/`); the version-2 interface is `IOrangeBridgeV2.sol`. The directory also holds spec 18's contracts (`EthereumOutbox`, deployed on Ethereum, and `EthereumInbox`, deployed on the OrangeSDK chain), built and checked the same way. `tools/build-contracts.sh` compiles them with solc 0.8.28 and writes `contracts/build/`: each contract's init code (`.bin`), runtime code (`.bin-runtime`) and ABI (`.abi`), and `SOURCES`, the sha256 of every source. The tests run the committed fixtures and fail when a source's hash differs from `SOURCES` or a source is missing from it, so a contract change without rebuilt fixtures cannot pass. CI does not need solc.

## 10. Limits of this version

- **Former shareholders no longer keep the power to forge, with a version-2 client kept current.** Earlier versions reshared one constant group key, which former shareholders could use for ever with no stake at risk, and recorded that as a departure from codex ADR 0013. Codex ADR 0031 resolves it: every epoch makes a fresh key that the old one hands off to (15 §6.6), a version-2 light client trusts a key for `K` epochs past its own (§5.3), unbonding outlasts that and the handoff latency (15 §6.7), and partials over false anchors, false rotations or after a key's handoff are slashable evidence (15 §5.1). ADR 0013's "unbonding longer than any trusting period" holds; a per-epoch cap on validator-set change is still not implemented and is not needed for this argument.
- **The trusting period is measured in OrangeSDK heights as the client sees them.** The client has no clock of the OrangeSDK chain but the anchors it stores and the key ids it is shown; a forged certificate or rotation carries no time and can be signed after its signers withdrew. So the guarantee needs the client kept current: a relayer moves it past key set `k` before the chain reaches epoch `k + 1 + unbonding_epochs`, when the first shareholders of `k` can withdraw. A client left holding an old key for longer, for instance because nobody relayed for weeks, is exposed to that key's withdrawn shareholders as a version-1 client is: they can sign it a rotation to a key of their own, within `K` ids. Only the delay, the guardian's veto and the rate limits (§6) bound what such a client delivers. A bound in Ethereum time (refusing anything after a long idle period) is left for later.
- **A chain that cannot hand off for `K` epochs strands its clients.** When `K` runs in a row fail, the active key's next handoff goes to an id more than `K` past it, which clients refuse, and they must be redeployed from a key their deployers trust again, as any light client past its trusting period. A rotation certificate to an adopted key set that the chain superseded before recording its handoff (15 §6.6) can strand a client the same way if someone relays it. The chain never records that handoff, so relayers follow the chain's handoff records. A chain whose active key loses, for good, shareholders holding more than `M − t` of its `M` shares can never hand off again, whatever newer keys it adopts (15 §6.6). Its clients strand after `K` epochs, and the chain needs a governance kernel upgrade to move to a new key.
- The guardian should still compare stored roots with the chain: slashing makes a forgery cost its signers a tenth of their stake each, which bounds the value worth forging but does not prevent it.
- The value of a send stays with the outbox. The canonical token bridge (spec 21) does not use it: its gateway on the OrangeSDK chain holds the currency it locks and sends messages without value. Messages from Ethereum to the OrangeSDK chain are the other half of the bridge.
- `submit` takes a whole proposal, transactions included; a block with large transactions or DKG dealings is costly to submit. A transaction or receipt root in the proposal, or certificates over executed headers, would shorten it, and need a new certificate version or a new proposal field.
- A recipient that always reverts keeps its messages pending forever; nothing retires them.
- Proofs are of single messages; proving several messages against one root shares no work.
