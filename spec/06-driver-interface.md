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

At the activation height `H` of a new kernel:

1. The old kernel finalizes block `H` (`FinalizeBlock` effect applied).
2. The host calls the old kernel's `kernel_driver_state` and holds the bytes.
3. The host instantiates the new kernel, already validated and compiled at enactment, and calls `kernel_migrate { from_version, driver_state }`.
4. The host delivers `Started { resumed_state: none }` to the new driver and resumes the input loop. Inputs that arrived during steps 2–3 are queued, not dropped.
5. If the new driver's protocol differs, its first act is to emit the *genesis certificate* for height `H + 1`: a message signed under the new scheme by at least the activation threshold of stake, which the new driver requires before it will finalize anything. Nodes that have not switched ignore the new traffic because every message envelope carries the kernel version.

A kernel's `kernel_migrate` MUST accept the driver state of the kernel version it supersedes and MUST fail (terminate with `Trap`) for any other version, so that a misconfigured host halts loudly rather than running with partial state.
