# 13 — Kernel upgrades, host feature gates and governance

## 1. Overview

The kernel, consensus included, is replaced by governance; the host is replaced by node releases whose new behaviour stays dormant until the chain activates it (ADR 0011). This document specifies both mechanisms for the reference kernel, and the governance that authorizes the first (ADR 0035):

- **Kernel upgrades.** Governance uploads a new kernel module into chain state in chunks, proposes it with an activation height, and may cancel it before then. Hosts read the pending upgrade after every block, enact it at once (06 §7.2) and switch at exactly the activation height on every node (06 §7.3).
- **Feature gates.** Every validator's host signals, once per epoch, the feature gates its release supports. A gate backed by at least 95% of stake in two consecutive epochs is locked in and becomes active one epoch later; from then on hosts serve the behaviour behind it. An active gate never deactivates.
- **Two governance tracks** (§9). Under the *key* track a genesis account, the governance key, authorizes every privileged action alone and at once: the track of development chains. Under the *stake* track validators decide by stake-weighted vote on proposals, a passed proposal waits out a timelock during which a guardian may veto it, and safety actions pass on a fast track. The key switches a chain from the first track to the second; nothing but a kernel upgrade switches it back.

Upgrade actions, signals and governance calls all travel as transactions to one reserved address, so ordinary Ethereum tooling produces them and explorers show them.

### 1.1 Genesis parameters

`GenesisParams::upgrades` (the reference kernel's genesis record) carries:

```
struct UpgradeParams { governance: [20], min_delay: u64, epoch_blocks: u64 }
```

- `governance`: the *governance key*. Under the key track it is the account that stages, proposes and cancels upgrades and executes every other governance action; under the stake track it is the guardian (§9.1), unless a proposal named another. Zero: no key, so under the key track no upgrades and no governance at all.
- `min_delay` (`N`): the fewest blocks between the block that proposes an upgrade and its activation height. An activation height is always at least one block ahead, whatever `N`.
- `epoch_blocks` (`L`): blocks per feature-gate epoch. Zero disables feature-gate signalling, and no gate can activate.

`GenesisParams::governance` carries the governance track and the proposal rules of §9.1:

```
struct GovernanceParams { mode: u8, voting_blocks: u64, timelock_blocks: u64, quorum_bps: u64, deposit: u128 }
```

The `solo` command reads them from the genesis JSON as `governance` (0x address), `upgradeDelay`, `epochBlocks`, `governanceMode` (`key`, the default, or `stake`), `votingBlocks`, `timelockBlocks`, `quorumBps` and `proposalDeposit` (wei); each number defaults to zero.

## 2. The upgrade address

The *upgrade address*, also the *governance address* of §9, is `0x0000000000000000000000000000000000005010`. A transaction whose `to` is the upgrade address carries an *action* or a *governance call* in its calldata instead of a message call. Its calldata is the Solidity ABI encoding of a call to

```solidity
interface ISoloUpgrades {
    function stage(bytes32 codeHash, uint32 index, bytes calldata chunk) external;   // 0x64639a2e
    function propose(bytes32 codeHash, uint64 activationHeight, uint64 requiredGates) external; // 0x1529d282
    function cancel(bytes32 codeHash) external;                                     // 0xc4d252f5
    function signal(uint64 features) external;                                      // 0xf52ec658
    event UpgradeProposed(bytes32 indexed codeHash, uint64 activationHeight, uint64 requiredGates);
    event UpgradeCancelled(bytes32 indexed codeHash);
}
```

or of the governance interface `ISoloGovernance` of §9.2, so `cast send 0x0000000000000000000000000000000000005010 "propose(bytes32,uint64,uint64)" <hash> <height> 0` works as is.

### 2.1 Decoding

Calldata is an action only if it is the *canonical* encoding of one of the four calls, exactly as a Solidity encoder produces it, within these limits:

- every value word of a `uintN` has its high `32 − N/8` bytes zero;
- `stage`: the offset word of `chunk` is 96, its length is 1 to 61 440 bytes (`CHUNK_SIZE`), the data is padded with zero bytes to a multiple of 32, nothing follows, and `index` is below 128 (`MAX_CHUNKS`, so a kernel is at most 7.5 MiB);
- `propose`, `cancel`, `signal`: exactly 96, 32 and 32 bytes after the selector.

A chunk this size, and the raw transaction carrying it, each fit one storage value (05 §4.2), so the transaction stays retrievable by hash. Calldata that is no action is a governance call if it decodes as one under §9.2's rules.

### 2.2 Authorization

Who may send each action depends on the governance track in force (§9.1):

| Action | Key track | Stake track |
|---|---|---|
| `stage` | the governance key | any validator's account |
| `propose`, `cancel` | the governance key | nobody directly: they are actions a proposal carries (§9.2) |
| `signal` | any validator's account, while `epoch_blocks` is non-zero | the same |

A *validator's account* is the last 20 bytes of a validator id in the current validator set (a validator id is `keccak256` of the consensus public key, spec 08, so this is the Ethereum address of the consensus key). The governance key acts only while it is non-zero.

### 2.3 Admission and execution

A transaction to the upgrade address *can run* if it is signed for this chain (a typed transaction, or a legacy one with an EIP-155 chain id; a pre-EIP-155 legacy transaction carries no chain id and could be replayed from any chain sharing the key), its calldata is an action (§2.1) carrying no value, or a governance call that can run (§9.4), and its sender is authorized for that action (§2.2) or call. Admission (`kernel_stf_validate_tx`, and selection in `kernel_stf_build_block`) rejects one that cannot run with reason 12 (`SYSTEM_ACTION`). That check comes after decoding, the chain-id check, signature recovery and the well-formedness checks every transaction gets, and before the checks against the sender's account (nonce, then funds): a transaction that cannot run gets reason 12 whatever its nonce and the sender's balance. Transactions to the module address of spec 16 §4.2 are checked at the same point under the same rules.

In `kernel_stf_execute_block`, a transaction to the upgrade address that cannot run changes nothing and gets a failed receipt, as any transaction that should not have been included. One that can run executes in two steps:

1. It runs through the EVM as a call to the upgrade address, which has no code: intrinsic gas (including the calldata floor) is charged, fees are paid, the nonce is used, and a deposit's value moves to the address.
2. If that succeeded, the action or call is applied against the state at that point in the block. If the action's state checks (§3) fail, the receipt has status 0, as for a revert: gas and nonce stay spent, the action changes nothing. Otherwise the receipt has status 1 and carries the action's logs (§3). A governance call adds its surcharge (§9.9) to the gas used, and §9.5 says what a failing one leaves behind.

Actions cost no gas beyond the intrinsic cost; only the authorized accounts can send them. `eth_call` and `eth_estimateGas` see the plain call of step 1, not the action.

## 3. Actions

Heights below are those of the block executing the action; under the stake track, `propose` and `cancel` execute when the proposal that carries them does (§9.5), and the height is that block's.

- **`stage(codeHash, index, chunk)`** stores `chunk` as chunk `index` of `codeHash`, replacing any chunk already there. Fails if `codeHash` is the pending upgrade's or that of a kernel the chain has switched to (§5): their code is frozen. Emits nothing.
- **`propose(codeHash, activationHeight, requiredGates)`** at height `B` makes the code the *pending upgrade*. Fails if an upgrade is pending, if `activationHeight < B + max(N, 1)`, if `activationHeight` is `2^64 − 1` (block `H + 1` must have a height), if the chain has already switched to `codeHash` (a kernel never comes back: versions only increase, 06 §7.1), if chunk 0 of `codeHash` is not staged, or if the chunks staged from index 0 up to the first missing index, concatenated, do not hash to `codeHash` under `keccak256`. Records `PendingUpgrade { code_hash, activation_height, required_gates, size, chunks, proposed_at: B }` and emits `UpgradeProposed(codeHash, activationHeight, requiredGates)`.
- **`cancel(codeHash)`** removes the pending upgrade. Fails unless an upgrade is pending and its code hash is `codeHash`. Emits `UpgradeCancelled(codeHash)`. Staged chunks stay; the same code may be proposed again without uploading it again.
- **`signal(features)`** records `Signal { epoch: epoch(B), features }` as the sender's latest signal (§8.2). Emits nothing.

`requiredGates` names, one bit per gate, the feature gates the new kernel needs (it imports their host functions). It is the "required host ABI" of ADR 0011: the host ABI grows only through gates.

## 4. Timeline of a kernel upgrade

1. **Staging**, any number of blocks: `stage` transactions upload the module. A sender's transactions are admitted one nonce at a time, so the upload takes about one block per chunk.
2. **Proposal** at block `B`: the upgrade becomes pending with activation height `H ≥ B + max(N, 1)`. Under the stake track `B` is the block that executes the proposal carrying `propose` (§9.3), so a proposer leaves room for the voting period, the timelock and the execution window when it picks `H`. From the end of block `B`, every host enacts it (06 §7.2) or raises an alert (§7.2).
3. **Cancellation window**: a `cancel` in any block up to and including `H` withdraws it; under the stake track `cancel` is a safety action that passes on the fast track (§9.2). So does lapsing: at the end of block `H`, if any gate in `requiredGates` is not active for block `H + 1` (§8.4), the kernel removes the pending upgrade. A withdrawn upgrade never switches.
4. **Switch** after block `H` (06 §7.3). The new kernel's `kernel_migrate` accepts only the version its kernel supersedes (version − 1 for the reference kernel) and only while the pending upgrade's activation height equals the latest executed height; it removes the pending upgrade and records `EnactedUpgrade { code_hash, height: H, from_version, to_version }`, under `gov/enacted` and under the new kernel's code hash (§5). The writes depend on chain state alone, so every node writes the same.
5. **After `H`**: the old kernel, should a host still run it, traps at the end of any block above the activation height of a pending upgrade, so an outdated host halts instead of forking.

## 5. State

Under the reference kernel's state layout (all covered by the state commitment):

| Key | Value |
|---|---|
| `gov/pending` | `PendingUpgrade`, while one is pending |
| `gov/enacted` | `EnactedUpgrade`, the latest switch |
| `gov/kernel/` ‖ code hash | `EnactedUpgrade`, for every kernel the chain switched to |
| `gov/chunk/` ‖ code hash ‖ index (big-endian `u32`) | chunk bytes |
| `gate/book` | `GateBook` (§8.3) |
| `gate/signal/` ‖ validator id | `Signal`, the validator's latest |

The governance records of §9.7 live beside them. The records, in the canonical encoding (06 §2):

```
struct PendingUpgrade { code_hash: [32], activation_height: u64, required_gates: u64, size: u32, chunks: u32, proposed_at: u64 }
struct EnactedUpgrade { code_hash: [32], height: u64, from_version: u32, to_version: u32 }
struct Signal         { epoch: u64, features: u64 }
struct GateRecord     { gate: u8, streak: u32, activation_height: u64 }
struct GateBook       { next_epoch: u64, gates: vec<GateRecord> }
```

The code of an enacted kernel stays staged and cannot be restaged (§3): the running kernel, and every kernel before it in the lineage other than the genesis kernel, is a program in state (ADR 0004), and `upgrade_code` of its code hash serves exactly that program.

## 6. Queries

| Method | Params | Body on status 0 |
|---|---|---|
| `kernel_version` | — | `u32`, the running kernel's version (06 §7.1) |
| `upgrade_status` | — | `UpgradeStatus` |
| `upgrade_code` | code hash `[32]` | `bytes`: chunks from index 0 up to the first missing one, concatenated; status 1 if chunk 0 is missing, 2 if the params are not 32 bytes |

```
struct ValidatorSignal { id: [32], weight: u64, signal: option<Signal> }
struct UpgradeStatus   { version: u32, params: UpgradeParams, pending: option<PendingUpgrade>,
                         enacted: option<EnactedUpgrade>, gates: GateBook, validators: vec<ValidatorSignal> }
```

`validators` lists every validator in validator-set order with its stake and latest signal. The governance queries are §9.8's.

## 7. The host

### 7.1 After every block

After executing a block at height `h`, the host reads `upgrade_status` (a kernel that does not serve it reads as the default: nothing pending, no gates) and:

1. sets the gates active for block `h + 1` to `gates.active_at(h + 1)` intersected with the gates its release supports (§8.6);
2. enacts a pending upgrade it has not enacted yet (06 §7.2), counting on the gates active for block `H + 1`;
3. notes that block `H` has executed if the pending upgrade's activation height is `h`; the switch follows the `FinalizeBlock` effect for `H` (06 §7.3);
4. if it is a validator whose latest signal does not cover `epoch(h + 1)` with exactly the features it supports, sends a signal (§8.2).

### 7.2 Alerts

A host reports, without stopping:

- a pending upgrade it cannot enact: the code does not hash to its code hash, the module is invalid, it imports a function this host cannot serve for block `H + 1`, its `kernel_version` does not halt with a `u32`, or that version is not above the running kernel's (06 §7.2), so that its `kernel_migrate` would trap at `H`. This is the "host lacks the ABI a pending kernel needs" alert of ADR 0011: governance can cancel (under the stake track on the fast track, §9.2), or operators can install a host release, before `H`.
- gates the chain has locked in that its release does not support: the host cannot serve their behaviour once they activate, and must be replaced by a release that does.

The reference node reports both through its telemetry (11): the gauges `solo_upgrade_blocked` and `solo_upgrade_missing_gates`, the `upgradeAlert` and `missingGates` fields of `/status`, the `SoloUpgradeBlocked` alert rule and a check of `solo doctor`.

## 8. Feature gates

### 8.1 Gates

A *gate* is a bit index from 0 to 63. A host release defines which behaviour each gate guards and supports a set of gates. Gates defined so far:

| Gate | Guards |
|---|---|
| 0 | the host function `secp256k1_verify` (05 §4.3) |
| 1 | the host function `bls12381_fast_aggregate_verify` (05 §4.3), which the Ethereum light client of spec 18 needs |
| 2 | the precompile host functions of 05 §4.8, through which the reference kernel's EVM runs the bn254, modexp, BLAKE2F, point-evaluation and BLS12-381 precompiles on the host (spec 19) |

The host functions of 05 §4 that carry no gate, the BLS12-381 functions included, are part of ABI version 1 and resolve from genesis on every chain. A gated host function resolves (03 §5.1) only while its gate is active: before that, a module importing it fails to load. Once active it behaves exactly as specified, on every node.

### 8.2 Signalling

A validator's host signals by sending a `signal(features)` transaction from the validator's account (§2.2), where `features` has one bit set per gate its release supports: a legacy EIP-155 transaction to the upgrade address with no value, gas price 0 and gas limit 100 000. The base fee of the reference kernel is zero, so signalling costs nothing and needs no balance. A signal counts for the epoch of the block that executes it. After every block `h` it executes, a validator's host sends a signal, with its account's next nonce, unless its latest signal on chain is for epoch `epoch(h + 1)` or later and names exactly its supported features. Resending the same transaction until it is included is idempotent.

### 8.3 Epochs and tallies

With `L = epoch_blocks`, epoch `e` holds the heights `e·L + 1` to `(e + 1)·L`, so `epoch(h) = (h − 1) / L`. At the end of the last block of epoch `e`, before the state commitment, the kernel tallies the epoch: the *support* of a gate is the summed weight (stake) of the validators whose latest signal is for epoch `e` and names the gate. A gate *qualifies* in `e` if `support · 10 000 ≥ total · 9 500`, where `total` is the weight of the whole validator set; with no stake nothing qualifies.

`GateBook::next_epoch` is the epoch expected next. For each gate not yet locked in: if it qualifies, its `streak` becomes one more than before when `e` is the expected epoch, or 1 otherwise; if it does not qualify, its record is removed (streak 0). `next_epoch` becomes `e + 1`. Records are kept in ascending gate order, and only for gates with a streak or a lock-in.

### 8.4 Lock-in and activation

When a gate's streak reaches 2 at the end of epoch `e`, the gate is *locked in* with `activation_height = (e + 2)·L + 1`: epoch `e + 1` is notice, and the gate is active for every block from the first block of epoch `e + 2` on. A gate is active for the block at height `h` if it is locked in and `activation_height ≤ h`.

### 8.5 No way back

A locked-in gate never changes again: later tallies leave its record as it is, whatever the signals. Before lock-in, one epoch under the threshold resets the streak; validators withdraw support simply by signalling without the gate, which is the revoke path. A gate that never reaches the threshold stays dormant; nothing expires, and a release may stop supporting a gate that never locked in.

### 8.6 Hosts and gates

A host serves the behaviour of a gate for block `h` only if the gate is active for `h` and its release supports it. Because activation is a function of chain state at known heights, every supporting host switches the behaviour on at the same block. A host that does not support a locked-in gate keeps running but cannot serve it (§7.2); it fails, deterministically and loudly, the first time a module needs it, for instance at the switch to a kernel that imports a gated function.

## 9. Governance

Every privileged action of the reference kernel is a *governance action*: proposing and cancelling a kernel upgrade (§3), installing a module (16 §4.2), setting the light client's checkpoint and delay and the message verifier's pause and rate limit (18 §5), and governance's own settings (§9.2). Which account, or which vote, authorizes them is the *governance track* (ADR 0035). Feature-gate signalling (§8) is validators' in both tracks and is not a governance action.

### 9.1 Tracks and rules

`GovernanceParams::mode` is 0, the **key track**, or 1, the **stake track**; `kernel_init` traps on any other value, on `quorum_bps > 10 000`, and on the stake track with `voting_blocks = 0`.

- **Key track.** The governance key of §1.1 executes any governance action at once by submitting it (§9.2); nobody else acts, and no proposal, vote, veto or guardian exists. A chain without a key has no governance. This is the track of development chains (`solo dev`), where one operator holds the key, and of a chain's first days before it switches.
- **Stake track.** Anyone *bonded* proposes a governance action: a validator's account (§2.2), or any account that locks `deposit` wei with its proposal (`deposit = 0`: validators only). Validators vote, each with the weight it has in the current validator set. A proposal is tallied at the end of its voting period of `voting_blocks` blocks, waits `timelock_blocks` blocks once passed, and is then executed by anyone within a window as long as the voting period. The **guardian**, the governance key unless a proposal named another account (zero: none), may veto any open proposal and may pause the inbox's message verifier at once, and nothing else.

The rules in force are `GovernanceParams` as genesis set them, until a `setParams` action replaces them (§9.2).

### 9.2 Calls and actions

The governance address serves `ISoloUpgrades` (§2) and

```solidity
interface ISoloGovernance {
    function submit(address target, bytes calldata data) external payable;           // 0x76846edd
    function vote(uint64 id, bool support) external;                                 // 0xc7f21560
    function execute(uint64 id) external;                                            // 0xb590be77
    function veto(uint64 id) external;                                               // 0xc8050630
    function pause(address target) external;                                         // 0x76a67a51
    // Actions governance applies to itself, carried by `submit` with the governance address as target:
    function setGuardian(address guardian) external;                                 // 0x8a0dac4a
    function setMode(uint8 mode) external;                                           // 0x21175b4a
    function setParams(uint64 votingBlocks, uint64 timelockBlocks, uint64 quorumBps, uint256 deposit) external; // 0x94bc43b4
    event ProposalSubmitted(uint64 indexed id, address indexed proposer, address indexed target, bytes data, uint64 votingEnd);
    event Voted(uint64 indexed id, address indexed voter, bool support, uint64 weight);
    event ProposalExecuted(uint64 indexed id);
    event ProposalVetoed(uint64 indexed id);
    event Enacted(address indexed by, address indexed target, bytes data);
    event GuardianSet(address guardian);
    event ModeSet(uint8 mode);
    event ParamsSet(uint64 votingBlocks, uint64 timelockBlocks, uint64 quorumBps, uint256 deposit);
}
```

Calldata is a governance call only in its canonical encoding: zero high bytes in every word, `vote`'s `bool` word 0 or 1, `submit`'s offset word 64 and its `data` at most `MAX_PROPOSAL_DATA = 32 768` bytes (room for a mainnet light-client checkpoint, 18 §3.4, within one storage value), padded with zeros to a whole word, and nothing after the arguments.

An *action* is the pair `(target, data)` that `submit` carries: calldata to a system address. The actions a proposal may carry, and their tracks:

| `target` | `data` | Track |
|---|---|---|
| the governance address | `propose(bytes32,uint64,uint64)` (§3) | normal |
| the governance address | `cancel(bytes32)` (§3) | **fast** |
| the governance address | `setGuardian(address)`, `setParams(uint64,uint64,uint64,uint256)` | normal |
| the governance address | `setMode(uint8)` | key track only (§9.6) |
| the module address (16 §4.2) | `install(address,bytes32,uint64,bytes)` | normal |
| the light-client address (18 §5.1) | `setCheckpoint(bytes)`, `setDelay(uint64)` | normal |
| the verifier address (18 §5.2) | `pause()` | **fast** |
| the verifier address | `unpause()`, `setRateLimit(uint64,uint64)` | normal |

`data` to the governance or the module address must decode as the action (§2.1, 16 §4.2); to a bridge address, only its selector is checked and the module decodes the rest when the action executes. Anything else is no action, and a `submit` carrying it cannot run. `stage` and `signal` are not actions: they are sent directly (§2.2).

**Fast track.** `cancel` and `pause` are *safety actions*, the two that stop something rather than start it. A fast-track proposal has no timelock: it passes as soon as the stake voting yes exceeds half of the whole validator set's stake, and executes in the vote transaction that reaches that, so that one block's votes can stop an upgrade or the inbox. It fails at the end of its voting period otherwise. The guardian's own `pause` needs no proposal at all.

### 9.3 A proposal's life

Under the stake track, `submit(target, data)` at height `B` by a bonded sender (§9.1) opens proposal `id` (ids start at 1 and never repeat) with

```
struct Proposal { id: u64, proposer: [20], deposit: u128, target: [20], data: bytes, submitted_at: u64,
                  voting_end: u64, executable_at: u64, expires_at: u64, fast_track: bool, status: u8,
                  yes: u64, no: u64, total: u64 }
```

`voting_end = B + voting_blocks`; on the normal track `executable_at = voting_end + timelock_blocks + 1` and `expires_at = executable_at + voting_blocks − 1`, on the fast track `executable_at = 0` and `expires_at = voting_end`; `status` 0 is *voting*, 1 *passed*; `deposit` is the value the transaction carried (zero for a validator). It emits `ProposalSubmitted(id, proposer, target, data, votingEnd)`. At most `MAX_OPEN_PROPOSALS = 16` proposals are open at once.

**Voting.** A validator's account votes with `vote(id, support)` in any block up to and including `voting_end` while the proposal is voting; voting again replaces the vote. It emits `Voted(id, voter, support, weight)` with the voter's weight at the time. A vote weighs what its validator weighs in the validator set at the moment of a tally, and nothing once it has left the set.

**Tally.** A *tally* over the current validator set gives `yes` and `no`, the stake voting each way, and `total`, the set's whole stake. The *quorum* holds when `(yes + no) · 10 000 ≥ total · quorum_bps` (never with no stake). A normal-track proposal *passes* when the quorum holds and `yes · 3 > (yes + no) · 2`, more than two thirds of the stake that voted; a fast-track one when `yes · 2 > total`.

- At the end of block `voting_end`, before the state commitment (after the module hooks of 16 §7, before the gate tallies of §8.3 and the epoch transition of 15 §4), a voting proposal is tallied. On the normal track, passed, it becomes *passed* with the tally recorded; otherwise, and always on the fast track, it fails and is pruned (below).
- A fast-track proposal is also tallied after each vote it receives; the vote that makes it pass executes it (§9.5) in the same transaction.
- A passed proposal is executed by anyone with `execute(id)` in any block from `executable_at` to `expires_at`. The guardian vetoes any open proposal with `veto(id)`, voting or passed, which emits `ProposalVetoed(id)`.
- At the end of block `expires_at`, a passed proposal still open has *expired* and is pruned.

**Pruning.** A proposal that is executed, vetoed, failed or expired leaves state: its record, its votes and its place among the open proposals. Its deposit, held by the governance address since the submission, goes back to the proposer, except that a proposal that failed without reaching quorum, which nobody cared to vote on, forfeits it to the zero address, where fees go and nobody spends them.

### 9.4 Who may call, and when

A governance call *can run* in the block at height `h` (for admission, the executed height plus one) when the transaction is signed for this chain, its gas limit is at least its intrinsic gas plus `GOVERNANCE_GAS` (§9.9), and:

| Call | Key track | Stake track |
|---|---|---|
| `submit(target, data)` | the sender is the governance key, no value, and `(target, data)` is an action of §9.2 (`setMode` included) | the sender is a validator's account sending no value, or any account sending exactly `deposit` wei while `deposit` is non-zero; `(target, data)` is an action of §9.2 other than `setMode`; fewer than 16 proposals are open |
| `vote(id, support)` | never | the sender is a validator's account, no value; proposal `id` is open, voting, and `h ≤ voting_end` |
| `execute(id)` | never | no value; proposal `id` is open, passed, and `executable_at ≤ h ≤ expires_at` |
| `veto(id)` | never | the sender is the guardian, no value; proposal `id` is open |
| `pause(target)` | never | the sender is the guardian, no value; `target` is the verifier address and the bridge is on (its address holds a module designator) |
| `setGuardian`, `setMode`, `setParams` sent directly | never | never |

A transaction to the module address (16 §4.2) can run only under the key track, from the governance key, with no value and an `install` as calldata. One that cannot run, to either address, is refused at admission with reason 12 (§2.3).

### 9.5 Execution

A governance call that can run executes as §2.3 says: the plain call, then the call itself, which adds `GOVERNANCE_GAS` to the gas used and charges it at the transaction's gas price to the zero address, like every fee.

- **`submit` under the key track** executes the action at once, as a proposal that passes under the key. The receipt carries `Enacted(key, target, data)` followed by the action's own logs; if the action's checks fail, the transaction reverts (status 0, nothing changed).
- **`submit` under the stake track** opens the proposal (§9.3).
- **`vote`** records the vote; on the fast track, when the vote makes the proposal pass, the receipt carries `ProposalExecuted(id)` and the action's logs after `Voted`, and the proposal is pruned.
- **`execute`** prunes the proposal (its deposit returned) and applies the action: the receipt carries `ProposalExecuted(id)` and the action's logs. If the action's checks fail, the receipt has status 0 and the proposal is pruned all the same: a passed proposal is executed exactly once, whatever comes of it, so that nobody can make every node redo an expensive action by executing it again.
- **`veto`** prunes the proposal (its deposit returned) and emits `ProposalVetoed(id)`.
- **`pause(target)`** by the guardian executes the action `(target, pause())` at once; the receipt carries `Enacted(guardian, target, pause())`.

An action executes against the state at that point in the block, at that block's height and timestamp, as if sent directly by the authority of the track:

- `propose` and `cancel` as §3 says;
- `install` as 16 §4.2 says, the `ModuleInstalled` log included;
- a bridge action as a call to the native contract at `target` (16 §5) made by the *governance authority*: the governance key under the key track, the governance address itself under the stake track, which is the account the two modules' configuration names as their governance (18 §4.1, §9.6). The module runs sandboxed with `ACTION_GAS = 2^26` VM gas of the kernel's own, with no value, and its writes are applied if it returns; a module that reverts, fails or is not there (the bridge is off, or the light client's gate is not yet active) fails the action. Nothing is charged to anyone beyond the surcharge: the actions are bounded by the voting and by the proposal bound.
- `setGuardian(guardian)` records the guardian (zero: none) and emits `GuardianSet`; `setParams(voting, timelock, quorum, deposit)` fails unless `voting ≥ 1` and `quorum ≤ 10 000`, else records the rules and emits `ParamsSet`; `setMode` is §9.6's.

### 9.6 The switch

Under the key track, the key submits `setMode(1)`; the action fails unless the rules in force have `voting_blocks ≥ 1` and `quorum_bps ≤ 10 000`. It records the stake track, makes the key the guardian unless a `setGuardian` already named one, renames the governance in both bridge modules' configuration (18 §4.2) to the governance address, so that from then on only the kernel, executing a proposal or the guardian's pause, reaches their governed functions, and emits `ModeSet(1)`. `setMode(0)`, or any `setMode` under the stake track, is no action that can run: the switch is irreversible, and only a kernel upgrade, which can rewrite `gov/mode`, takes a chain back. A chain may also start under the stake track at genesis, with the key as its guardian and the modules configured accordingly from the first block.

### 9.7 State

| Key | Value |
|---|---|
| `gov/mode` | `u8`, once the mode left its genesis value |
| `gov/guardian` | `[20]`, once a guardian was named |
| `gov/params` | `GovernanceParams`, once `setParams` ran |
| `gov/next` | `u64`, the id of the next proposal |
| `gov/open` | `vec<OpenProposal { id: u64, due: u64 }>`, the open proposals in id order, `due` the next height the end of a block must look at each (its voting end, then its expiry) |
| `gov/proposal/` ‖ id (big-endian u64) | `Proposal` |
| `gov/vote/` ‖ id ‖ validator id | `bool`, the validator's vote |
| `gov/voters/` ‖ id | `vec<[32]>`, the validators that voted, so pruning finds every vote |

All of it is committed (10 §2). Deposits are the governance address's balance.

### 9.8 Queries

| Method | Params | Body on status 0 |
|---|---|---|
| `governance` | — | `GovernanceStatus` |
| `governance_proposal` | `u64` id | `ProposalView`; status 1 if the proposal is not open, 2 if the params are not 8 bytes |

```
struct Ballot           { validator: [32], support: bool, weight: u64 }
struct ProposalView     { proposal: Proposal, yes: u64, no: u64, total: u64, votes: vec<Ballot> }
struct GovernanceStatus { mode: u8, key: [20], guardian: [20], params: GovernanceParams, next_id: u64, proposals: vec<ProposalView> }
```

A view's `yes`, `no` and `total` are the live tally over the current validator set and `votes` every vote of a validator still in it, in set order; `proposal.yes`, `no` and `total` are the tally recorded when a proposal passed. The reference node serves them as `solo_getGovernance`, `solo_getProposals` and `solo_getProposal(id)` (`null` once a proposal is pruned), and the `solo gov` command prints the calldata of every call above.

### 9.9 Gas and bounds

| Name | Value |
|---|---|
| `GOVERNANCE_GAS`, the surcharge of every governance call | 50 000 |
| `ACTION_GAS`, the VM gas of a governed bridge call | 2^26 |
| `MAX_OPEN_PROPOSALS` | 16 |
| `MAX_PROPOSAL_DATA` | 32 768 bytes |

A `vote(id, true)` transaction with no other calldata uses 71 860 gas: its intrinsic gas at the EIP-7623 floor, 21 860, plus the surcharge (`crates/solo-node/tests/governance.rs`, 2026-10-21). A `submit` pays for its calldata like any transaction, so the largest action costs about 525 000 gas of calldata before the surcharge. With the base fee of the reference kernel at zero the surcharge counts against the block gas limit, which bounds governance calls to 600 a block, and the deposit is what a proposal costs a sender that is not a validator.

### 9.10 Limits of this version

- Votes weigh the validator set at the tally, not at the vote: a validator that leaves the set loses its vote, one that joins can vote. Delegated or token-holder voting (15 §9) does not exist; only validators vote.
- A proposal carries one action. Several actions take several proposals, which may run at the same time within the bound.
- The guardian's powers, veto and pause, cover proposals and the inbox; they do not cancel a pending upgrade (that is the validators' fast track) or pause the token gateways of spec 21, which have guardians of their own.
- The deposit is returned or burned, never paid to voters or to anyone who executes; nothing pays for governance beyond the proposer's interest.
- The only way back from the stake track is a kernel upgrade, which the stake track itself must pass.
