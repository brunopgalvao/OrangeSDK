# 18 — Ethereum to Solo: the sync-committee light client and the inbox

## 1. Overview

This document specifies the Ethereum-to-Solo half of the Tier-2 bridge of codex ADR 0013 for the reference kernel:

- an **Ethereum light client** that follows the beacon chain's finalized headers through its sync committees (the Altair light-client sync protocol), and keeps the execution state root of every finalized block it learns (§3);
- an **outbox** contract on Ethereum that stores the hash of every message sent to a Solo chain (§6.1);
- a **message verifier** that proves a message against a finalized execution state root with an account and storage proof, records it delivered, and paces and pauses deliveries (§6.2–§6.4);
- an **inbox** contract on Solo that calls the message's recipient with its payload, once (§6.5).

The light client and the verifier are Solo modules that run as native contracts (spec 16 §5) at two reserved system addresses; the inbox is EVM bytecode at a third. The kernel places all three at genesis (§4). Everything is driven by ordinary Ethereum transactions: anyone may submit light-client updates and relay messages.

The Solo-to-Ethereum direction (threshold certificates verified on Ethereum, spec 12 §8) is separate.

The code is `solo-ethlc` (the protocol, the proofs and both modules' logic over a key-value store, `no_std`), `guest/modules/eth-light-client` and `guest/modules/eth-message-verifier` (the two modules), `guest/kernel/src/bridge.rs` (genesis and admission), `solo_abi::bridge_in` (the addresses and the genesis record) and `contracts/` (the three contracts).

## 2. Trust and limits

- **Sync committees.** The light client accepts what a supermajority of the current (or, across a period boundary, next) sync committee signs. A dishonest supermajority of 512 randomly sampled validators can make it accept any header, as it can every Ethereum light client. Value that enters Solo through this bridge inherits that trust, which is why deliveries are delayed and rate limited (§6.3, §6.4) and can be paused (§6.4).
- **Recovery.** A root accepted from a dishonest committee stays stored, at whatever execution block number the forged header named. Governance recovers in two steps: `pause` the verifier, then `setCheckpoint` with an honest checkpoint, which starts a new checkpoint epoch and so revokes every root stored before it, honest or not (§5.1); then `unpause`. Under the stake track of spec 13 §9 the guardian pauses at once, or a majority of stake does on the fast track, and proposals install the checkpoint and unpause. Messages not yet delivered are proven again against roots of the new epoch, which hold the same outbox storage. Nonces a forged root already marked delivered stay delivered: the delay exists so that governance pauses before any is.
- **Finality only.** Only finalized headers are stored, and an update is applied at once or refused: there is no optimistic header and no pending best update (§3.6).
- **Liveness.** Each sync-committee period (256 epochs, about 27 hours on mainnet) the client must learn the next committee, from an update attested in the period. A client that misses a whole period can no longer verify any signature and stalls; governance then installs a new checkpoint (§5.1, `setCheckpoint`). Relayers keep the client live; anyone can relay.
- **Ethereum forks.** The client is pinned to the Electra container formats, which Fulu keeps (§3.1). A later fork that changes the light-client containers or the generalized indices (Gloas, for instance) needs a new light-client module; until it is installed, by a kernel upgrade (spec 13), updates signed after the fork fail their signature check or do not decode, and the client stalls rather than accepting anything.

## 3. The light client

### 3.1 Version

The protocol is consensus-specs `altair/light-client/sync-protocol.md` with the Capella `LightClientHeader` (an execution payload header proven against the beacon block body) and the Electra generalized indices, at the containers of `electra/light-client/sync-protocol.md` and the Deneb `ExecutionPayloadHeader`. Fulu (mainnet since epoch 411 392) changes none of them. The constants are:

| Name | Value |
|---|---|
| `EXECUTION_PAYLOAD_GINDEX` | 25 (body field 9, depth 4) |
| `FINALIZED_ROOT_GINDEX` | 169 (`finalized_checkpoint.root`, depth 7) |
| `CURRENT_SYNC_COMMITTEE_GINDEX` | 86 (state field 22, depth 6) |
| `NEXT_SYNC_COMMITTEE_GINDEX` | 87 (state field 23, depth 6) |
| `DOMAIN_SYNC_COMMITTEE` | `0x07000000` |
| Signature scheme | BLS12-381, keys in G1, signatures in G2, `FastAggregateVerify` with ciphersuite `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_` |

### 3.2 Containers

SSZ (consensus-specs `ssz/simple-serialize.md`), with `N` the configured committee size (§3.3):

```
BeaconBlockHeader          { slot: u64, proposer_index: u64, parent_root: B32, state_root: B32, body_root: B32 }      112 bytes
ExecutionPayloadHeader     { parent_hash: B32, fee_recipient: B20, state_root: B32, receipts_root: B32,
                             logs_bloom: B256, prev_randao: B32, block_number: u64, gas_limit: u64, gas_used: u64,
                             timestamp: u64, extra_data: ByteList[32], base_fee_per_gas: u256, block_hash: B32,
                             transactions_root: B32, withdrawals_root: B32, blob_gas_used: u64, excess_blob_gas: u64 }
LightClientHeader          { beacon: BeaconBlockHeader, execution: ExecutionPayloadHeader, execution_branch: B32[4] }
SyncCommittee              { pubkeys: B48[N], aggregate_pubkey: B48 }
SyncAggregate              { sync_committee_bits: Bitvector[N], sync_committee_signature: B96 }
LightClientBootstrap       { header, current_sync_committee: SyncCommittee, current_sync_committee_branch: B32[6] }
LightClientUpdate          { attested_header, next_sync_committee: SyncCommittee, next_sync_committee_branch: B32[6],
                             finalized_header, finality_branch: B32[7], sync_aggregate, signature_slot: u64 }
LightClientFinalityUpdate  { attested_header, finalized_header, finality_branch: B32[7], sync_aggregate, signature_slot: u64 }
```

Decoding is strict: the input is exactly one container, every offset of a variable-size field points where the previous part ends (the first just past the fixed part), and `extra_data` is at most 32 bytes. Anything else is `Malformed`. A `LightClientUpdate` whose next-sync-committee branch is all zeros carries no next committee, as in Altair, and its committee field must then be all zeros too (otherwise it is `Malformed`: the committee would be dropped unread, a second encoding of the same update); a finality update never carries one.

### 3.3 Configuration

```
struct Fork              { epoch: u64, version: [4] }
struct LightClientConfig { genesis_validators_root: [32], forks: vec<Fork>, sync_committee_size: u32,
                           slots_per_epoch: u64, epochs_per_period: u64 }
```

`forks` lists the fork versions in ascending epoch order; the first is the earliest fork whose headers the client accepts. A configuration works only if `forks` is non-empty and strictly ascending, `sync_committee_size` is a non-zero multiple of 8 and at most 1 024, and both lengths are non-zero (`BadConfig` otherwise). Ethereum mainnet's is genesis validators root `0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95`, forks `[(364032, 0x05000000), (411392, 0x06000000)]`, 512, 32, 256; the minimal preset uses 32, 8 and 8.

`epoch(s) = s / slots_per_epoch`, `period(s) = epoch(s) / epochs_per_period`, and the fork version at epoch `e` is that of the last fork with `epoch ≤ e`; a slot is *supported* if its epoch has one. The signing root of a header signed in slot `t` is `hash_tree_root(SigningData { object_root: hash_tree_root(header.beacon), domain })` with `domain = DOMAIN_SYNC_COMMITTEE ‖ hash_tree_root(ForkData { version_at(epoch(max(t, 1) − 1)), genesis_validators_root })[0..28]`.

### 3.4 State and bootstrap

The client's state is its *finalized header* (slot `F`), the committee of `period(F)` (*current*), and the committee of `period(F) + 1` (*next*) once known. A header is *valid* when its execution payload header is proven against `beacon.body_root` at `EXECUTION_PAYLOAD_GINDEX`.

A *checkpoint* is a `LightClientBootstrap`. It is accepted if its header's slot is supported (`UnsupportedFork`), the header is valid (`BadExecutionBranch`), and `current_sync_committee` is proven against `header.beacon.state_root` at `CURRENT_SYNC_COMMITTEE_GINDEX` (`BadBootstrap`). Installing it makes its header the finalized header and its committee the current one, and drops every committee held before. A checkpoint is trusted as given: genesis names one, and governance may install another (§5.1). The *checkpoint epoch* counts the checkpoints installed after genesis's (genesis's is epoch 0); installing one moves it on by one, and only roots stored in the current epoch are served (§5.1). There is no trusted-block-root comparison because the checkpoint is the trusted input itself.

### 3.5 Updates

An update `U` (attested header `A`, optional next committee `C`, finalized header `H`, finality branch, aggregate, signature slot `t`) is checked against the state in this order; the first failing check refuses it with the code shown:

1. `H.slot` is supported. — `UnsupportedFork`
2. `3 · participants ≥ 2 · N`. — `LowParticipation`
3. `t > A.slot ≥ H.slot`. — `Slots`
4. With `p = period(F)`: `period(t)` is `p`, or `p + 1` if the next committee is known. — `WrongPeriod`
5. Something changes: `A.slot > F`, or `U` carries a committee the client lacks and `period(A) = p` (Altair's relevance rule); and `H.slot > F`, or `U` carries a committee the client lacks and `period(H) = period(A)` (Altair's apply rule). — `NotNewer`
6. The finality branch is not all zeros. — `NoFinality`
7. `A` and `H` are valid. — `BadExecutionBranch`
8. `hash_tree_root(H.beacon)` is proven against `A.beacon.state_root` at `FINALIZED_ROOT_GINDEX`. — `BadFinalityBranch`
9. If `U` carries `C`: when `period(A) = p` and the next committee is known, `C`'s keys equal it — `CommitteeMismatch`; and `C` is proven against `A.beacon.state_root` at `NEXT_SYNC_COMMITTEE_GINDEX` — `BadCommitteeBranch`.
10. The keys of the committee of `period(t)` (current or next) whose bits are set `FastAggregateVerify` the signature over the signing root of `A` signed in `t` (§3.3). — `BadSignature`

Checks 1 to 6 need no hashing beyond the update's own decoding; admission runs them (§7). An update that passes is applied:

- If the next committee was unknown and `U` carries `C`, `C` becomes the next committee (of `period(A) + 1`).
- If the next committee was known and `period(H) = p + 1`, the client moves to the next period: the next committee becomes current, the old current one is dropped, and `C`, if `U` carries it, becomes the next committee; otherwise the next committee is unknown.
- If `H.slot > F`, `H` becomes the finalized header and its execution state root is stored (§4.2) with `usable_at` = the block's timestamp (seconds) plus the delay, in the current checkpoint epoch.

### 3.6 Departures from Altair

- No `current_slot` check: Solo has no clock it could trust for Ethereum's slot, and the signature authenticates the update whatever the time.
- No `best_valid_update`, optimistic header, or forced update after `UPDATE_TIMEOUT`: an update is applied when it can be and refused otherwise, so state changes only on finalized, supermajority-signed data. A client a whole period behind needs a governance checkpoint (§2).
- Supermajority is Altair's `3 · participants ≥ 2 · N`, required to apply; updates with less participation are refused rather than kept.

### 3.7 Rejection codes

The light client reverts with `UpdateRejected(uint8 code)`:

| Code | Name | Code | Name |
|---|---|---|---|
| 1 | `Malformed` | 8 | `BadFinalityBranch` |
| 2 | `UnsupportedFork` | 9 | `BadCommitteeBranch` |
| 3 | `BadExecutionBranch` | 10 | `CommitteeMismatch` |
| 4 | `Slots` | 11 | `LowParticipation` |
| 5 | `WrongPeriod` | 12 | `BadSignature` |
| 6 | `NotNewer` | 13 | `BadBootstrap` |
| 7 | `NoFinality` | 14 | `BadConfig` |

`Malformed` also covers calldata that is not the canonical ABI encoding of the call (§5) and a state missing its current committee, which genesis and the rules above never produce.

## 4. Placement

| Address | Name | What |
|---|---|---|
| `0x000000000000000000000000000000000000454C` ("EL") | light-client address | native contract running the light-client module (§5.1) |
| `0x000000000000000000000000000000000000454D` ("EM") | verifier address | native contract running the message-verifier module (§5.2) |
| `0x0000000000000000000000000000000000004549` ("EI") | inbox address | the `EthereumInbox` contract (§6.5) |

They lie in the system range of spec 16 §4, where no module is *installed*: the kernel gives the two native contracts their designators directly at genesis, with no module record, no hooks and no `Init`, as spec 16 §4.1 allows for any allocation. They are not upgraded on their own; a kernel upgrade (spec 13) can replace their code and migrate their namespaces.

### 4.1 Genesis

`GenesisParams::bridge_in` carries

```
struct InboxLimits    { delay: u64, window: u64, max_messages: u64 }
struct BridgeInParams { light_client: bytes, verifier: bytes, config: LightClientConfig,
                        bootstrap: bytes, outbox: [20], limits: InboxLimits }
```

An empty `light_client` leaves the bridge off and nothing below happens. Otherwise `kernel_init`, after the modules of spec 16, traps, so the chain cannot start, if an allocation names any of the three addresses, either module is empty or longer than 65 536 bytes (spec 16 §4), the configuration fails §3.3 or the checkpoint fails §3.4. It then:

1. stores each module under `code/` ‖ `keccak256(module)` and gives the light-client and verifier addresses the designators `0xEF02 ‖ code hash` as code, nonce 1;
2. gives the inbox address the `EthereumInbox` runtime code (`contracts/build/EthereumInbox.bin-runtime`, embedded in the kernel), nonce 1;
3. writes the light client's namespace: `config` = `{ config, governance, delay }` and the installed checkpoint, whose state root is usable from time `delay`;
4. writes the verifier's namespace: `config` = `{ outbox, chain id, governance, window, max_messages }`.

`governance` is the governance authority of spec 13 §9.5: the governance key under the key track (zero: nobody governs the bridge), the governance address itself under the stake track, where only the kernel, executing a passed proposal or the guardian's pause, calls the governed functions; the switch of 13 §9.6 renames it in both namespaces. The stored `meta/params` leaves `bridge_in` out: the driver reads the parameters on every step and the namespaces hold the bridge's state. The `solo` command reads the parameters from a `"bridgeIn"` object (see `solo-cli`'s `bridge` module).

### 4.2 Namespaces

Each native contract's state is its namespace (spec 16 §2.3): the stored key is `0x00^12 ‖ address ‖ key`. Records use the canonical encoding (spec 06 §2); integers in keys are big-endian.

| Namespace | Key | Value |
|---|---|---|
| light client | `config` | `{ light: LightClientConfig, governance: [20], delay: u64 }` |
| light client | `finalized` | `{ slot: u64, beacon_root: [32], block_number: u64, block_hash: [32], state_root: [32], epoch: u64 }` |
| light client | `committee/` ‖ period (u64) | the committee's keys, `48 · N` bytes |
| light client | `root/` ‖ execution block number (u64) | `{ state_root: [32], block_hash: [32], slot: u64, usable_at: u64, epoch: u64 }` |
| verifier | `config` | `{ outbox: [20], chain_id: u64, governance: [20], window: u64, max_messages: u64 }` |
| verifier | `delivered/` ‖ nonce (u64) | `[1]` |
| verifier | `paused` | `[1]` while paused |
| verifier | `window` | `{ start: u64, count: u64 }` |

Roots are kept for every finalized block the client stores, so a proof made against a root stays usable after newer updates. `epoch` is the checkpoint epoch (§3.4) of `finalized` and of the update that stored each root.

### 4.3 Why modules

The light client could have been kernel code beside `staking.rs`. It is a module because:

- **The signature check needs a new host function.** Spec 05 §7 admits new functions only behind a feature gate, and a kernel importing a gated function cannot load until the gate is active. As a module, only the light client imports `bls12381_fast_aggregate_verify` (gate 1, spec 13 §8.1): the reference kernel runs on every host, and the light client simply fails to load, so every call to it fails (spec 16 §5.3), until gate 1 is active.
- **Native contracts give EVM semantics for free.** Gas, reverts, static calls and composition from Solidity follow spec 16 §5, with no new transaction type.
- **The verifier is separate** so that each module fits one storage value (65 536 bytes) with room to spare, so that the verifier loads without the gate, and so that the light client stays a general source of Ethereum state roots that other consumers (a token bridge) can read through `executionRoot`.

The inbox is EVM code because only EVM code can call another contract: a module cannot call into the EVM (spec 16 §5.6).

## 5. Interfaces

Calldata to the native contracts is the Solidity ABI of `contracts/IEthereumLightClient.sol` and `contracts/IMessageVerifier.sol`, and only its canonical encoding counts: no bytes after the arguments, zero high bytes in every word, the offset and padding Solidity writes. For a `bytes[]` that means element `i`'s offset is where element `i − 1`'s padded tail ends (the first's, just past the offsets), so no two elements share bytes; a decoder checks each offset before copying the element it points at, and decoding costs time and memory linear in the calldata. A call that is not one of the functions below, or whose words are not canonical, reverts with empty data, except that `submitUpdate`, `submitFinalityUpdate` and `setCheckpoint` revert `UpdateRejected(1)` for a `bytes` argument that is not. Value sent with a call stays with the contract.

### 5.1 The light client (EL)

| Function | Selector | Who | Effect |
|---|---|---|---|
| `submitUpdate(bytes update)` | `0xd1767a4a` | anyone | applies an SSZ `LightClientUpdate` (§3.5) or reverts `UpdateRejected(code)` |
| `submitFinalityUpdate(bytes update)` | `0x7ce7590d` | anyone | the same for a `LightClientFinalityUpdate` |
| `setCheckpoint(bytes bootstrap)` | `0xfa8d858d` | governance | installs the checkpoint (§3.4) in a new checkpoint epoch, revoking every root stored before; its own root is usable after the delay |
| `setDelay(uint64 delay)` | `0xc1073302` | governance | sets the delay of roots stored from then on |
| `finalized()` | `0xb3f05b97` | view | `(uint64 slot, bytes32 beaconRoot, uint64 blockNumber, bytes32 blockHash, bytes32 stateRoot)` |
| `executionRoot(uint64 blockNumber)` | `0xe4779daa` | view | `(bytes32 stateRoot, bytes32 blockHash, uint64 slot, uint64 usableAt)`, zeros if not held or stored in an earlier checkpoint epoch |
| `delay()` | `0x6a42b8f8` | view | the delay in seconds |

A governance function called by any other account, or with no governance account, reverts `NotGovernance()`; under the stake track the governance account is the governance address, which nobody signs for, so the functions are reached only through a passed proposal or the guardian's pause (spec 13 §9.5), which call the module with `ACTION_GAS` VM gas as the governance address. `module_query` (spec 16 §4.3) answers the views.

### 5.2 The message verifier (EM)

| Function | Selector | Who | Effect |
|---|---|---|---|
| `consume(bytes32 stateRoot, uint64 nonce, address sender, address recipient, uint64 gasLimit, bytes payload, bytes[] accountProof, bytes[] storageProof)` | `0x56604c65` | the inbox | §6.4 |
| `pause()` | `0x8456cb59` | governance | stops deliveries |
| `unpause()` | `0x3f4ba83a` | governance | resumes them |
| `setRateLimit(uint64 window, uint64 maxMessages)` | `0xe1e5cca4` | governance | sets the rate limit |
| `delivered(uint64 nonce)` | `0x2f2b0289` | view | whether the message was delivered |
| `paused()` | `0x5c975abb` | view | whether deliveries are stopped |
| `rateLimit()` | `0x61e08e72` | view | `(uint64 window, uint64 maxMessages)` |

## 6. Messages

### 6.1 The outbox

`contracts/EthereumOutbox.sol` is deployed on Ethereum once per Solo chain with that chain's id. `send(address recipient, uint64 gasLimit, bytes payload)` (`0xdd624a88`) gives the message the next nonce (from 0), stores

```
messages[nonce] = keccak256(abi.encode(uint64 soloChainId, uint64 nonce, address sender, address recipient, uint64 gasLimit, bytes payload))
```

with `sender = msg.sender`, and emits `MessageSent(nonce, sender, recipient, gasLimit, payload, messageHash)`. `gasLimit` is the gas the recipient gets to handle the message (§6.5); the sender chooses it, and a message whose `gasLimit` no Solo block can provide is never delivered. `messages` is a `mapping(uint64 => bytes32)` at storage slot 0, so message `n` is at slot `keccak256(uint256(n) ‖ uint256(0))`; `nextNonce` is slot 1. The chain id in the hash keeps a message for one Solo chain from being delivered on another.

### 6.2 Proofs

A delivery proves the message with the `accountProof` and `storageProof` that `eth_getProof(outbox, [slot], block)` returns: lists of RLP-encoded Merkle-Patricia nodes, root first.

Verification of a proof for key `k` against root `r` (Yellow Paper, appendices C and D) walks the nibbles of `keccak256(k)` from `r`. A node referenced by hash must be the next proof element and hash to the reference; a node shorter than 32 bytes is embedded in its parent. A branch node (17 items) consumes a nibble, or yields its value when the path is exhausted; an extension or leaf (2 items, hex-prefix path) must match the path's next nibbles. The walk ends with the value, or with absence: an empty branch slot, a diverging leaf or extension. A node that does not hash to its reference, does not decode as such a node, or a proof that ends early or has elements left over, proves nothing.

The message is proven when the account proof of `keccak256(outbox)` against `stateRoot` yields an account `rlp([nonce, balance, storageRoot, codeHash])`, and the storage proof of `keccak256(slot)` against `storageRoot` yields a value that, as an RLP integer, equals the message hash of §6.1 with the verifier's chain id. Absence proves nothing.

### 6.3 Delay

A state root may prove messages from `usable_at`, the timestamp (seconds) of the block that stored it plus the light client's delay (§3.5). The delay leaves time to pause the inbox (§6.4) after an update that should not have been accepted, before any message proven by it is delivered; a new checkpoint then revokes the root (§2, §5.1).

### 6.4 Consuming a message

`consume` checks, in order:

1. The caller is the inbox address. — `NotInbox()`
2. The calldata is the canonical encoding (§5). — empty revert data
3. Deliveries are not paused. — `Paused()`
4. `delivered/` ‖ nonce is absent. — `AlreadyDelivered(nonce)`
5. The rate limit: with the window record `(start, count)` (zeros if absent), if `timestamp ≥ start + window` a new window opens at `timestamp` with count 0; then `count < maxMessages`. — `RateLimited()`
6. The proofs prove the message (§6.2) against `stateRoot`. — `BadProof()`

It then increments the count, stores the window and marks the nonce delivered. These are native-call writes, so they stand only if every enclosing EVM frame succeeds (spec 16 §5.4).

### 6.5 The inbox

`contracts/EthereumInbox.sol` at the inbox address has no constructor, no immutables and no storage. `deliver(uint64 blockNumber, uint64 nonce, address sender, address recipient, uint64 gasLimit, bytes payload, bytes[] accountProof, bytes[] storageProof)` (`0x9a288f33`):

1. reads `executionRoot(blockNumber)` from the light client; a zero state root reverts `UnknownBlock(blockNumber)`, a block timestamp below `usableAt` reverts `TooEarly(usableAt)`;
2. calls the verifier's `consume` with that state root and its own arguments, bubbling up any revert;
3. calls `recipient.onEthereumMessage(nonce, sender, payload)` (`IEthereumMessageReceiver`, `0x64f7ddb0`) with exactly `gasLimit` gas: if the recipient has no code, `deliver` reverts with empty data; if less than `⌊(gasLimit + 5 000) · 64 / 63⌋` gas is left just before the call, it reverts `InsufficientGas(gasLimit)` (`0xc0a1813d`), so the EVM's 1/64 rule cannot cut the call short; if the recipient reverts, it reverts `DeliveryFailed(reason)`; each undoes step 2;
4. emits `MessageDelivered(nonce, sender, recipient, blockNumber)`.

A message is therefore delivered *exactly once*: never twice, because the verifier refuses a delivered nonce, and never half, because a recipient that fails undoes the whole delivery, which anyone may retry. Because the gas is the sender's choice, proven with the message, a relayer cannot starve the recipient: a recipient that catches a failing inner call still had the gas the sender asked for. A recipient authenticates a message by checking `msg.sender` is the inbox address and trusting `sender` as the Ethereum account that sent it.

## 7. Admission

`kernel_stf_validate_tx` (and selection in `kernel_stf_build_block`) checks transactions to the three addresses at the point spec 13 §2.3 checks the upgrade address, after the checks every transaction gets and before those against the sender's account. Reason 14 is the outbox's (spec 17 §2.2) and 15 to 19 are left free; this document's codes start at 20 so that other system addresses can take codes in parallel without colliding. Transactions to the outbox address are checked before these.

| Code | Name | A transaction to … is refused when |
|---|---|---|
| 20 | `BRIDGE_CALL` | any of the three, on a chain without the bridge (the light client's `config` is absent) or carrying value; to the inbox, its calldata is not the canonical encoding of `deliver` (§5), which admission checks before copying any part of it |
| 21 | `BRIDGE_UPDATE` | the light client, calling `submitUpdate` or `submitFinalityUpdate` with an update that does not decode or fails checks 1 to 6 of §3.5 against the current state |
| 22 | `MESSAGE_DELIVERED` | the inbox, for a nonce the verifier has marked delivered |
| 23 | `INBOX_PAUSED` | the inbox, while the verifier is paused |

Admission is a filter, not a rule of execution: a transaction that is included anyway runs as any EVM transaction does, and the contracts refuse it with the errors of §3.7, §5 and §6, consuming its gas. Calls from contracts reach the three addresses without admission.

## 8. Gas

Calls to the light client and the verifier are native calls, charged as spec 16 §6 says: the EVM's call costs, then `100 + ⌈VM gas / 20⌉` plus the write charges. The light client's VM gas is dominated by `bls12381_fast_aggregate_verify` (`125 000 + 5 500` per participating key, spec 05 §4.3, calibrated by `crates/solo-bls/tests/calibration.rs`), SSZ hashing (`hash_sha256`) and, once a period, the write of the next committee (`5 000 + 600 · ⌈(18 + 48 · N) / 32⌉` EVM gas, 466 400 for `N = 512`). Measured through the reference kernel on 2026-10-21 (`crates/solo-node/tests/bridge_in.rs`; transaction gas used, intrinsic and calldata costs included):

| Transaction | Gas |
|---|---|
| `submitUpdate`, mainnet period 1888 update (512 members, carries the next committee) | 1 314 286 |
| `submitFinalityUpdate`, mainnet, rotating into period 1889 | 332 456 |
| `submitUpdate`, minimal preset (32 members, carries the next committee) | 161 733 |
| `deliver` of a 10-byte message with a three-account state's proofs, to the test recipient `EthereumMessageRecipient` | 157 890 |

A mainnet `deliver` carries proofs of about 9 account-trie nodes and 7 storage-trie nodes (the WETH proof of §10 has 9 and 7), about 10 KiB of calldata.

## 9. Contracts and fixtures

`contracts/` holds this document's contracts beside spec 17's: `EthereumOutbox.sol` (deployed on Ethereum), `EthereumInbox.sol` (the inbox contract on Solo), the interfaces `IEthereumLightClient.sol` and `IMessageVerifier.sol`, and the test recipient on Solo `test/EthereumMessageRecipient.sol`. Contracts deployed on Ethereum keep the names spec 17 gives its own (`SoloFinalityVerifierV1`, `SoloLightClient`, `SoloInbox`) and `EthereumOutbox`; the contract deployed on Solo that delivers Ethereum's messages is `EthereumInbox`. `tools/build-contracts.sh` compiles every source under `contracts/` with solc 0.8.28 (`--optimize --optimize-runs 200 --evm-version cancun --metadata-hash none`) into `contracts/build/` (`<Name>.bin`, `<Name>.bin-runtime`, `<Name>.abi`) and records the SHA-256 of every source in `contracts/build/SOURCES`; a test fails when a source no longer matches its recorded hash, so stale fixtures cannot pass. The kernel embeds `EthereumInbox.bin-runtime`, so the guest is rebuilt (`tools/build-guest.sh`) after the contracts. The guest build does not depend on where the repository is checked out (the script builds a copy at one fixed path), so the gas of §8 is the same from every checkout.

## 10. Test vectors

- **Mainnet light-client data** (`crates/solo-ethlc/tests/vectors/`): a Fulu bootstrap at the first slot of period 1888, that period's `LightClientUpdate`, and a finality update signed by the committee of period 1889, as public beacon APIs serve them in SSZ. They pin the container decoding and re-encoding, every hash tree root and branch, the 512-key `FastAggregateVerify` with the proof-of-possession tag, the domain at the Fulu fork version, and the period rotation; the update and the finality update also run through the kernel (§8).
- **A mainnet `eth_getProof`** of the WETH contract at execution block 26 235 823, the block the finality update finalizes: the account proof and a storage proof verify against the finalized state root, and an absent slot's proof shows absence.
- **A synthetic chain** (`solo_ethlc::testing`): a beacon chain in the minimal preset whose committees sign, with every refusal of §3.5 and §3.7, the fork switch, governance, and an `EthereumOutbox` run on revm whose state and proofs are built as `eth_getProof` returns them.
- consensus-spec-tests' light-client vectors are not used: the smallest release archive holding them is over 400 MB, and the mainnet data covers the same code with real signatures.

## 11. Rationale (non-normative)

- **Finalized updates only.** Applying an update only when a supermajority signed a finalized header keeps the light client's state a function of data Ethereum's finality gadget has committed to, at the cost of waiting for finality (about 13 minutes) before a message can be proven. A bridge that moves value wants exactly that.
- **Roots, not headers, for the inbox.** The verifier needs a state root and nothing else, so the light client exposes roots by execution block number; a relayer proves against whatever finalized block it fetched its proof at, and a newer update never invalidates a proof in flight.
- **Exactly once through revert.** Marking a message delivered inside the same transaction that calls its recipient, and reverting both when the recipient fails, gives at-most-once delivery without a failed-message queue, and leaves retrying to anyone willing to pay for it.
- **Admission codes.** The bridge's reasons start at 20 so that streams adding system addresses at the same time cannot collide; spec 17 took 14 for the outbox, and 15 to 19 stay free.
