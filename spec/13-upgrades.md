# 13 — Kernel upgrades and host feature gates

## 1. Overview

The kernel, consensus included, is replaced by governance; the host is replaced by node releases whose new behaviour stays dormant until the chain activates it (ADR 0011). This document specifies both mechanisms for the reference kernel:

- **Kernel upgrades.** A genesis-configured governance account uploads a new kernel module into chain state in chunks, proposes it with an activation height, and may cancel it before then. Hosts read the pending upgrade after every block, enact it at once (06 §7.2) and switch at exactly the activation height on every node (06 §7.3).
- **Feature gates.** Every validator's host signals, once per epoch, the feature gates its release supports. A gate backed by at least 95% of stake in two consecutive epochs is locked in and becomes active one epoch later; from then on hosts serve the behaviour behind it. An active gate never deactivates.

Both travel as transactions to one reserved address, so ordinary Ethereum tooling produces them and explorers show them.

### 1.1 Genesis parameters

`GenesisParams::upgrades` (the reference kernel's genesis record) carries:

```
struct UpgradeParams { governance: [20], min_delay: u64, epoch_blocks: u64 }
```

- `governance`: the account that may stage, propose and cancel upgrades. Zero disables kernel upgrades.
- `min_delay` (`N`): the fewest blocks between the block that proposes an upgrade and its activation height. An activation height is always at least one block ahead, whatever `N`.
- `epoch_blocks` (`L`): blocks per feature-gate epoch. Zero disables feature-gate signalling, and no gate can activate.

The `solo` command reads them from the genesis JSON as `governance` (0x address), `upgradeDelay` and `epochBlocks`; each defaults to zero.

## 2. The upgrade address

The *upgrade address* is `0x0000000000000000000000000000000000005010`. A transaction whose `to` is the upgrade address carries an *action* in its calldata instead of a message call. Its calldata is the Solidity ABI encoding of a call to

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

so `cast send 0x0000000000000000000000000000000000005010 "propose(bytes32,uint64,uint64)" <hash> <height> 0` works as is.

### 2.1 Decoding

Calldata is an action only if it is the *canonical* encoding of one of the four calls, exactly as a Solidity encoder produces it, within these limits:

- every value word of a `uintN` has its high `32 − N/8` bytes zero;
- `stage`: the offset word of `chunk` is 96, its length is 1 to 61 440 bytes (`CHUNK_SIZE`), the data is padded with zero bytes to a multiple of 32, nothing follows, and `index` is below 128 (`MAX_CHUNKS`, so a kernel is at most 7.5 MiB);
- `propose`, `cancel`, `signal`: exactly 96, 32 and 32 bytes after the selector.

A chunk this size, and the raw transaction carrying it, each fit one storage value (05 §4.2), so the transaction stays retrievable by hash.

### 2.2 Authorization

`stage`, `propose` and `cancel` are *governance actions*: the sender must be the `governance` account, and it must be non-zero. `signal` is a *validator action*: `epoch_blocks` must be non-zero and the sender must be a validator's account, the last 20 bytes of a validator id (a validator id is `keccak256` of the consensus public key, spec 08, so this is the Ethereum address of the consensus key).

### 2.3 Admission and execution

A transaction to the upgrade address *can run* if it is signed for this chain (a typed transaction, or a legacy one with an EIP-155 chain id; a pre-EIP-155 legacy transaction carries no chain id and could be replayed from any chain sharing the key), carries no value, its calldata is an action (§2.1), and its sender is authorized for that action (§2.2). Admission (`kernel_stf_validate_tx`, and selection in `kernel_stf_build_block`) rejects one that cannot run with reason 12 (`SYSTEM_ACTION`). That check comes after decoding, the chain-id check, signature recovery and the well-formedness checks every transaction gets, and before the checks against the sender's account (nonce, then funds): a transaction that cannot run gets reason 12 whatever its nonce and the sender's balance.

In `kernel_stf_execute_block`, a transaction to the upgrade address that cannot run changes nothing and gets a failed receipt, as any transaction that should not have been included. One that can run executes in two steps:

1. It runs through the EVM as a call to the upgrade address, which has no code: intrinsic gas (including the calldata floor) is charged, fees are paid, the nonce is used.
2. If that succeeded, the action is applied against the state at that point in the block. If the action's state checks (§3) fail, the receipt has status 0, as for a revert: gas and nonce stay spent, the action changes nothing. Otherwise the receipt has status 1 and carries the action's logs (§3).

Actions cost no gas beyond the intrinsic cost; only the authorized accounts can send them. `eth_call` and `eth_estimateGas` see the plain call of step 1, not the action.

## 3. Actions

Heights below are those of the block executing the action.

- **`stage(codeHash, index, chunk)`** stores `chunk` as chunk `index` of `codeHash`, replacing any chunk already there. Fails if `codeHash` is the pending upgrade's or that of a kernel the chain has switched to (§5): their code is frozen. Emits nothing.
- **`propose(codeHash, activationHeight, requiredGates)`** at height `B` makes the code the *pending upgrade*. Fails if an upgrade is pending, if `activationHeight < B + max(N, 1)`, if `activationHeight` is `2^64 − 1` (block `H + 1` must have a height), if the chain has already switched to `codeHash` (a kernel never comes back: versions only increase, 06 §7.1), if chunk 0 of `codeHash` is not staged, or if the chunks staged from index 0 up to the first missing index, concatenated, do not hash to `codeHash` under `keccak256`. Records `PendingUpgrade { code_hash, activation_height, required_gates, size, chunks, proposed_at: B }` and emits `UpgradeProposed(codeHash, activationHeight, requiredGates)`.
- **`cancel(codeHash)`** removes the pending upgrade. Fails unless an upgrade is pending and its code hash is `codeHash`. Emits `UpgradeCancelled(codeHash)`. Staged chunks stay; the same code may be proposed again without uploading it again.
- **`signal(features)`** records `Signal { epoch: epoch(B), features }` as the sender's latest signal (§8.2). Emits nothing.

`requiredGates` names, one bit per gate, the feature gates the new kernel needs (it imports their host functions). It is the "required host ABI" of ADR 0011: the host ABI grows only through gates.

## 4. Timeline of a kernel upgrade

1. **Staging**, any number of blocks: `stage` transactions upload the module. A sender's transactions are admitted one nonce at a time, so the upload takes about one block per chunk.
2. **Proposal** at block `B`: the upgrade becomes pending with activation height `H ≥ B + max(N, 1)`. From the end of block `B`, every host enacts it (06 §7.2) or raises an alert (§7.2).
3. **Cancellation window**: a `cancel` in any block up to and including `H` withdraws it. So does lapsing: at the end of block `H`, if any gate in `requiredGates` is not active for block `H + 1` (§8.4), the kernel removes the pending upgrade. A withdrawn upgrade never switches.
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

The records, in the canonical encoding (06 §2):

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

`validators` lists every validator in validator-set order with its stake and latest signal.

## 7. The host

### 7.1 After every block

After executing a block at height `h`, the host reads `upgrade_status` (a kernel that does not serve it reads as the default: nothing pending, no gates) and:

1. sets the gates active for block `h + 1` to `gates.active_at(h + 1)` intersected with the gates its release supports (§8.6);
2. enacts a pending upgrade it has not enacted yet (06 §7.2), counting on the gates active for block `H + 1`;
3. notes that block `H` has executed if the pending upgrade's activation height is `h`; the switch follows the `FinalizeBlock` effect for `H` (06 §7.3);
4. if it is a validator whose latest signal does not cover `epoch(h + 1)` with exactly the features it supports, sends a signal (§8.2).

### 7.2 Alerts

A host reports, without stopping:

- a pending upgrade it cannot enact: the code does not hash to its code hash, the module is invalid, it imports a function this host cannot serve for block `H + 1`, its `kernel_version` does not halt with a `u32`, or that version is not above the running kernel's (06 §7.2), so that its `kernel_migrate` would trap at `H`. This is the "host lacks the ABI a pending kernel needs" alert of ADR 0011: governance can cancel, or operators can install a host release, before `H`.
- gates the chain has locked in that its release does not support: the host cannot serve their behaviour once they activate, and must be replaced by a release that does.

The reference node reports both through its telemetry (11): the gauges `solo_upgrade_blocked` and `solo_upgrade_missing_gates`, the `upgradeAlert` and `missingGates` fields of `/status`, the `SoloUpgradeBlocked` alert rule and a check of `solo doctor`. It also reports where an upgrade and the gates stand, so that an operator can follow a switch and an activation across every node: the gauges `solo_kernel_version`, `solo_upgrade_activation_height` and `solo_gate_active`, the `kernelVersion`, `kernelHash`, `activeGates` and `pendingUpgrade` fields of `/status`, and `upgrade_status` (§6) as the JSON-RPC method `solo_upgradeStatus`, with the host's own view (code hash, active and supported gates, the upgrade it has prepared, its alert) under `host`.

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
