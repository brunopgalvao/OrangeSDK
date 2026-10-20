# 06 — Driver interface and kernel entrypoints

## 1. Overview

The kernel is one module (03) with the `Privileged` capability set that exports a fixed set of entrypoints. Two groups exist. The *driver* group implements consensus as a pure state machine: the host delivers one input at a time and receives a list of effects. The *state transition* group implements validation, block building, execution, finalisation, and queries. Both are deterministic functions of their inputs; the host owns all IO, the clock, the keys, and the network.

This document fixes the entrypoint names, the encoding of inputs and effects, the determinism contract, and the switchover protocol between kernels. The *semantics* of any particular consensus protocol are the kernel's business and are specified with that kernel, not here.

## 2. Encoding

All structured data crossing the boundary uses the *Solo canonical encoding*:

- Fixed-width integers little-endian: `u8`, `u16`, `u32`, `u64`, `i64`.
- `bytes`: `u:n` length (canonical ULEB128) followed by the bytes.
- `vec<T>`: `u:n` count followed by the elements.
- `enum`: `u8` tag followed by the variant's fields in order.
- `option<T>`: `u8` 0, or `u8` 1 followed by `T`.
- No padding, no alignment, no field names. Two encodings of the same value are byte-identical.

Hashes and identifiers are 32-byte arrays written without a length prefix.

## 3. Entrypoints

Each entrypoint is an export (03 §5.2). The host places the encoded argument in the input blob (05 §4.1) and reads the encoded result from the output blob at `Halt`. Any termination other than `Halt` is a kernel fault (§6). Registers carry nothing except that `a0` on `Halt` is 0.

| Export | Group | Input | Output |
|---|---|---|---|
| `kernel_init` | both | `Genesis` | `()` |
| `kernel_driver_step` | driver | `Input` | `vec<Effect>` |
| `kernel_driver_state` | driver | `()` | `bytes` (opaque driver state for migration) |
| `kernel_migrate` | both | `MigrateArgs { from_version: u32, driver_state: bytes }` | `()` |
| `kernel_version` | both | `()` | `u32` (§7.1) |
| `kernel_stf_validate_tx` | stf | `ValidateArgs { tx: bytes, context: ExecContext }` | `ValidateResult` |
| `kernel_stf_build_block` | stf | `BuildArgs { context: ExecContext, limits: Limits, candidates: vec<bytes> }` | `Block` |
| `kernel_stf_execute_block` | stf | `ExecuteArgs { block: Block, context: ExecContext }` | `ExecuteResult` |
| `kernel_stf_finalize_block` | stf | `FinalizeArgs { height: u64, certificate: bytes }` | `()` |
| `kernel_query` | stf | `QueryArgs { method: bytes, params: bytes, at: option<u64> }` | `QueryResult { status: u32, body: bytes }` |

Driver entrypoints may import the time and network functions of 05; state-transition entrypoints may not (05 §4.6). A kernel exports all of the above; a module that exports only `main` is a contract or kernel module, not a kernel.

## 4. Driver inputs and effects

### 4.1 Inputs

```
enum Input {
  0  NetworkMessage { peer: [32], topic: u16, payload: bytes }
  1  BlobReceived   { blob_id: [32], payload: bytes }
  2  Request        { peer: [32], request_id: u64, payload: bytes }
  3  Response       { request_id: u64, payload: bytes }
  4  TimerFired     { timer_id: u64, now_ms: u64 }
  5  TxArrived      { tx_hash: [32], size: u32 }
  6  MempoolContents{ txs: vec<bytes> }                       // reply to Effect::MempoolTake
  7  BlockExecuted  { height: u64, block_hash: [32], state_root: [32], result: ExecuteSummary }
  8  Started        { now_ms: u64, resumed_state: option<bytes> }
  9  PeerConnected  { peer: [32] }
  10 PeerDisconnected { peer: [32] }
}
```

### 4.2 Effects

```
enum Effect {
  0  Send          { peer: [32], topic: u16, payload: bytes }
  1  Broadcast     { topic: u16, payload: bytes }
  2  Disseminate   { blob_id: [32], payload: bytes }
  3  Request       { peer: [32], request_id: u64, payload: bytes }
  4  Respond       { request_id: u64, payload: bytes }
  5  SetTimer      { timer_id: u64, deadline_ms: u64 }
  6  CancelTimer   { timer_id: u64 }
  7  ExecuteBlock  { block: Block }
  8  FinalizeBlock { height: u64, certificate: bytes }
  9  PersistState  { state: bytes }
  10 PeerScore     { peer: [32], delta: i64 }
  11 MempoolTake   { max_bytes: u32, max_gas: u64 }
  12 MempoolAdmit  { tx_hash: [32] }
  13 MempoolReject { tx_hash: [32], reason: u32 }
  14 Metric        { name: bytes, value: i64 }
}
```

The driver MAY also call the network, timer, and persistence host functions directly (05 §4.5–4.6) with identical meaning; the effect list exists so that a driver can be written as a pure function with no host imports at all, which is the form the simulator and the conformance suite use. A kernel SHOULD use one style, not both.

Effects are applied by the host in list order after the entrypoint halts. `ExecuteBlock` causes the host to run `kernel_stf_execute_block` (asynchronously, in a separate instance) and to deliver `BlockExecuted` as a later input. `FinalizeBlock` causes `kernel_stf_finalize_block` and advances the finalized head. `PersistState` writes to node-local storage and is the state returned at `Started.resumed_state` after a restart.

### 4.3 Driver determinism

Given the same `Genesis`, the same sequence of `Input` values, and the same results from any host functions it calls, the driver produces the same sequence of effect lists and the same `kernel_driver_state`. The host appends every input to its write-ahead log before delivery, so a crashed node replays from `Started.resumed_state` plus the log. Signing is the one node-specific operation; its results are not consensus state and may differ between nodes.

## 5. State transition types

```
struct ExecContext { height: u64, slot: u64, timestamp_ms: u64, proposer: [32], parent_hash: [32], prev_randao: [32], fee_params: bytes, fork_schedule_id: u32, exec_lag_k: u32 }
struct Limits      { max_gas: u64, max_bytes: u32, max_txs: u32 }
struct Block       { header: bytes, txs: vec<bytes>, participation: bytes }
struct ExecuteSummary { gas_used: u64, tx_count: u32, receipts_root: [32], logs_bloom: bytes }
struct ExecuteResult  { state_root: [32], summary: ExecuteSummary, receipts: vec<bytes> }
enum   ValidateResult { 0 Valid { priority: u64, reserved_fee: u64 }, 1 Invalid { reason: u32 } }
struct Genesis     { chain_id: u64, fee_schedule: bytes, modules: vec<ModuleInstall>, params: bytes, validators: bytes }
struct ModuleInstall { address: [20], code_hash: [32], capabilities: u64, init: bytes }
```

`header`, `txs`, `receipts`, `participation`, `fee_params`, and `validators` are opaque to this document; the kernel defines them (for a Type 2 kernel, `txs` are RLP-encoded Ethereum transactions and `receipts` Ethereum receipts). `kernel_stf_validate_tx` implements the reserve-balance admission rule against the state as of `height − exec_lag_k`; `kernel_stf_execute_block` executes against the state produced by the previous executed block and returns the root the driver places in the header of block `height + exec_lag_k`; for the reference kernel that is the state commitment of 10, as `storage_commit` reports it during the block. The reference kernel asks for it after recording the evidence the block carries (08 §9) and writing the block's receipts, and before storing the header, its hash index, the height and the last hash, so the root covers the block's evidence records and transactions but not that bookkeeping, which the next block's root covers; a block with neither transactions nor newly kept evidence commits to the state the block before left. A proof against a header therefore comes from the state as it was when the kernel asked for the root, not the state after the block.

## 6. Faults and resource limits

- Driver entrypoints run with a gas budget set by the host from the latency preset. Exhausting it, or any termination other than `Halt`, is a *driver fault*: the host records it, restarts the driver instance from the last `PersistState`, and replays the log. Repeated faults on the same input halt the node with an alert; they are never papered over, because a deterministic fault will recur on every node and is a kernel bug or a kernel upgrade waiting to happen.
- State-transition entrypoints run with the gas limit of the block or query. A fault in `kernel_stf_execute_block` makes the block invalid.
- The query gas limit is host policy and is separate from the block limits: a query's work is chosen by whoever asks (an `eth_call` runs arbitrary code), and a host that serves queries on the thread that drives consensus relies on this limit to bound how long one query holds it. A query that exhausts it ends with `OutOfGas` and changes nothing; the host reports the query as aborted.
- An entrypoint that calls a host function outside its group terminates with `HostError(Unavailable)`.

## 7. Kernel switchover

A kernel is replaced at an *activation height* `H`: the old kernel executes and finalizes every block up to and including `H`, the new kernel every block after it. How a chain decides on a new kernel and `H` is the kernel's business; spec 13 specifies it for the reference kernel. This section fixes what every host and every kernel do around `H`.

### 7.1 Versions

Every kernel exports `kernel_version`. It takes an empty input and returns the kernel's version as a `u32`. The version is a constant of the module: every call, on every node, returns the same value, and the export reads no state. Along one chain's lineage of kernels the version increases with each switch. The reference kernel is version 1.

The version is an export, not a module section or a query: it needs no change to the module format (03), and query methods are a namespace each kernel defines for itself.

### 7.2 Enactment

A kernel announces a pending upgrade to the host: the code hash of the new module (03 §1) and the activation height `H`. The host reads it through the `upgrade_status` query and the module bytes through the `upgrade_code` query, both specified in spec 13 §6; a kernel that does not serve `upgrade_status` has no pending upgrade and no active feature gates. After every block it executes, the host reads the pending upgrade. When it first sees one, it *enacts* it:

1. It reads the module bytes and checks that their `keccak256` is the code hash.
2. It validates the module (03 §7) for the `Privileged` set, resolving imports against the host functions available for block `H + 1`. These include the gated functions whose feature gates the chain has activated, or scheduled to activate, by height `H + 1` (spec 13 §8).
3. It compiles the module and keeps it ready under its code hash.
4. It calls the new module's `kernel_version` and checks that it halts with a `u32` above the running kernel's version (§7.1). A module that is not a later version cannot migrate from the running kernel (§7.4).

A host that cannot enact a pending upgrade keeps running the old kernel and raises an alert (spec 13 §7.2). It tries again only when the pending upgrade or the set of gates it may count on changes. Unless the upgrade is cancelled or lapses before `H`, that host halts at `H` (§7.5).

### 7.3 Switch

1. The old kernel executes block `H`, and its `FinalizeBlock` effect for `H` is applied. The host executes no block above `H` with the old kernel: an `ExecuteBlock` effect for a height above `H` that arrives first is *held*, in order.
2. Once the `FinalizeBlock` effect for `H` and the rest of that step's effects are applied, the host calls the old kernel's `kernel_version`, which becomes `from_version`, and its `kernel_driver_state`, and holds the bytes.
3. The host calls the new kernel's `kernel_migrate { from_version, driver_state }`. From then on it calls the new kernel for every entrypoint. Chain state stays in the same storage; nothing is copied.
4. The host executes the held blocks with the new kernel, in order.
5. The host delivers `Started { resumed_state: none }` to the new driver, then the `BlockExecuted` inputs of the held blocks, then every input that was queued since step 2, and resumes the input loop. Inputs are queued, never dropped.
6. If the new driver's protocol differs, its first act is to emit the *genesis certificate* for height `H + 1`: a message signed under the new scheme by at least the activation threshold of stake, which the new driver requires before it will finalize anything.

A kernel that hands over to a different protocol MUST NOT finalize above its activation height, and its successor MUST use topics, or an envelope version, that the old driver ignores, so that nodes that have not switched ignore the new traffic. The versions of the reference kernel share one protocol and one driver-state format, so blocks the old driver finalized above `H` stay finalized and are executed by the new kernel (step 4).

### 7.4 Migration

A kernel's `kernel_migrate` MUST accept the driver state of the kernel version it supersedes and MUST fail (terminate with `Trap`) for any other version, so that a misconfigured host halts loudly rather than running with partial state. It returns `()`. It MAY write chain state, but only as a function of chain state and `from_version`: `driver_state` differs between nodes, and nothing derived from it may reach the state commitment. The reference kernel records the switch in chain state there (spec 13 §5).

### 7.5 Halting

The host halts if, at the switch, the pending upgrade was not enacted, if `kernel_version` of either kernel does not halt with a `u32`, or if `kernel_migrate` terminates with anything but `Halt`. A halted host delivers no further input and reports the same failure on every later attempt. Queries reach the kernel that was running when the failure occurred: the old kernel if the switch failed before `kernel_migrate` halted, the new kernel after that (a failure executing the held blocks, for instance), with the chain-state writes of `kernel_migrate` kept. A failure that is deterministic, such as a `kernel_migrate` that traps, halts every node at the same height, which is why §7.2 alerts long before `H`: the chain cannot pass `H` without operators.

### 7.6 Restarts

A restarted node whose chain state is gone (the reference host keeps chain state in memory) replays the chain from genesis under the genesis kernel. The blocks it replays recreate the pending upgrades, so it enacts and switches at every activation height it passes. It resumes the driver with the latest driver state it persisted, whichever kernel wrote it. Until hosts keep chain state across restarts, the kernels of one lineage therefore keep their persisted driver state readable by their predecessors, as the reference kernel's versions do.
