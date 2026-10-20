# 05 — Host ABI

## 1. Overview

The host ABI is the complete set of functions a module may call through `ecall`, and the complete set of entrypoints a host may call on a module. It is the boundary between what governance can change (everything inside the VM) and what only a node release can change (everything outside). Because of that it is designed to stay small, to grow only by addition, and to never change the meaning of an existing function. Version 1 has 27 functions. A function, once published in a released minor, is never removed and never changes behaviour; a replacement gets a new name.

## 2. Capability sets

An instance is created with one capability set (01 §8). The import resolution at load (03 §5.1) fails for any function outside the set, so a sandboxed module cannot even reference a privileged function.

| Set | May import |
|---|---|
| `Sandboxed` | Everything in §4.1 (memory and context), §4.2 (storage, own namespace only), §4.3 (crypto), §4.4 (invoke), `log_emit`, `metric_emit` |
| `Privileged` | Everything |

Capabilities granted to kernel modules by the kernel's capability manager are a kernel concern layered above this ABI: a module with the "validator set write" capability still calls ordinary storage functions; the kernel decides which keys it may write. The host enforces only the two sets above.

## 3. Calling convention

- The module places arguments in `a0`–`a5` and executes `ecall i`. Results are returned in `a0` (and `a1` where stated). Every other register is preserved.
- Pointers are 32-bit effective addresses into instance memory, passed in the low 32 bits of a register; lengths are 32-bit. The host validates that every (pointer, length) range it reads is readable and every range it writes is writable in the instance's memory map *before* performing any effect; a violation terminates the instance with `HostError(MemoryFault)`. A range of length zero is valid at any address.
- Functions that return variable-length data take an output pointer and an output capacity, write at most `capacity` bytes, and return the full length in `a0` even when truncated. A caller that needs the rest calls again with a larger buffer. Truncation is never an error.
- `a0` holds a status in the low 32 bits for functions marked *status-returning*: `0` success, otherwise a code from §6. Data results for such functions are in `a1` or in an output buffer.
- Gas: the VM charges the base cost (04 §3.3). Per-unit costs stated per function are charged by the host from the instance's counter before any irreversible effect.

### 3.1 Entrypoints the host calls

The host starts an instance at an exported block (03 §5.2) with `a0`–`a5` set as the entrypoint's contract states and `sp` at `stack_top`. Return values are read from `a0`, `a1` at `Halt`. Which exports a kernel, a kernel module, or a contract must provide is defined by the kernel ABI (06 for the driver and state transition entrypoints; the kernel module interface in the design doc, to be specified in a later document). The host itself requires only:

| Export | Who | Called when |
|---|---|---|
| `_start` | every module | Never by the host in consensus; reserved for tooling. |
| `main` | contracts, modules | By the kernel through `invoke`. |
| `kernel_*` | the kernel | See 06. |

## 4. Functions

Each row gives the name as it appears in the import table, arguments by register, results, the capability set, base cost in VM gas, and per-unit cost.

### 4.1 Memory and context

| Name | Arguments | Result | Set | Cost |
|---|---|---|---|---|
| `abi_version` | — | `a0` = host ABI version (`1`) | Sandboxed | 10 |
| `input_len` | — | `a0` = length of the instance's input blob | Sandboxed | 10 |
| `input_read` | `a0` dst, `a1` offset, `a2` len | `a0` = bytes copied | Sandboxed | 10 + 1 per 32 bytes |
| `output_write` | `a0` src, `a1` len | `a0` = 0 | Sandboxed | 10 + 1 per 32 bytes |
| `gas_remaining` | — | `a0` = remaining VM gas of this instance | Sandboxed | 10 |

The *input blob* and *output blob* are how the host passes a call's data in and results out without the entrypoint having to fit in registers. `output_write` replaces any previous output. The kernel maps these to EVM calldata and return data.

### 4.2 Storage

Keys are byte strings of 1–64 bytes. Values are byte strings of 0–65536 bytes. A sandboxed instance's keys are implicitly prefixed by the host with the instance's *namespace* (the contract or module address the kernel supplied at invoke), so two contracts can never see each other's keys; a privileged instance passes full keys.

| Name | Arguments | Result | Set | Cost |
|---|---|---|---|---|
| `storage_get` | `a0` key, `a1` key_len, `a2` dst, `a3` cap | `a0` = value length or `2^32−1` if absent | Sandboxed | 200 + 1 per 32 bytes returned |
| `storage_set` | `a0` key, `a1` key_len, `a2` val, `a3` val_len | `a0` = status | Sandboxed | 500 + 4 per 32 bytes written |
| `storage_delete` | `a0` key, `a1` key_len | `a0` = status | Sandboxed | 300 |
| `storage_iter_open` | `a0` prefix, `a1` prefix_len | `a0` = iterator handle | Sandboxed | 300 |
| `storage_iter_next` | `a0` handle, `a1` key_dst, `a2` key_cap, `a3` val_dst, `a4` val_cap | `a0` = key length or `2^32−1` at end; `a1` = value length | Sandboxed | 200 + 1 per 32 bytes returned |
| `storage_commit` | `a0` dst(32 bytes) | `a0` = status; writes the state commitment root | Privileged | 10 000 |
| `storage_proof` | `a0` key, `a1` key_len, `a2` dst, `a3` cap | `a0` = proof length | Privileged | 2 000 + 1 per 32 bytes |

Writes are buffered in a per-instance overlay and become visible to the instance immediately; the host applies or discards the overlay according to the invoke semantics (§4.4). Iteration order is bytewise ascending over keys. Iterator handles are invalidated when the instance terminates. State-growth pricing (the kernel's state-gas dimension) is a kernel fee-schedule charge in EVM gas layered on top of these costs; it is not a host matter.

### 4.3 Cryptography

| Name | Arguments | Result | Set | Cost |
|---|---|---|---|---|
| `hash_keccak256` | `a0` src, `a1` len, `a2` dst(32) | `a0` = 0 | Sandboxed | 30 + 6 per 32 bytes |
| `hash_sha256` | `a0` src, `a1` len, `a2` dst(32) | `a0` = 0 | Sandboxed | 30 + 6 per 32 bytes |
| `hash_blake2b256` | `a0` src, `a1` len, `a2` dst(32) | `a0` = 0 | Sandboxed | 30 + 4 per 32 bytes |
| `secp256k1_recover` | `a0` msg(32), `a1` sig(65), `a2` dst(64) | `a0` = status | Sandboxed | 3 000 |
| `p256_verify` | `a0` msg(32), `a1` sig(64), `a2` pubkey(64) | `a0` = status (0 valid, 1 invalid) | Sandboxed | 6 900 |
| `bls12381_verify` | `a0` msg, `a1` msg_len, `a2` sig(96), `a3` pubkey(48) | `a0` = status (0 valid, 1 invalid) | Sandboxed | 100 000 |
| `bls12381_pairing_check` | `a0` pairs, `a1` count | `a0` = status (0 holds, 1 fails) | Sandboxed | 70 000 + 50 000 per pair |
| `sign` | `a0` key_role, `a1` msg, `a2` msg_len, `a3` dst, `a4` cap | `a0` = signature length or status | Privileged | 10 000 |

`secp256k1_recover` reads `sig` as `r ‖ s ‖ v` with `v` one of 0, 1, 27 or 28, and writes the recovered public key as 64 bytes (the uncompressed point without its `0x04` prefix). It returns `InvalidArgument` if `v` is anything else, if `r` or `s` is zero or not below the group order `n`, if `s > n/2`, or if no key recovers. Accepting only the low-s form, which EIP-2 requires of transactions, keeps every host agreeing on which signatures are valid. A caller that must also accept high-s signatures, such as the EVM `ecrecover` precompile, replaces `s` by `n − s` and flips the parity before calling.

`storage_commit` covers every key except those under the prefix `local/`, which a kernel uses for node-local bookkeeping that must not affect the root (the reference kernel keeps its finalized height there). `sign` is the only function that touches node keys. It writes the signature to `dst` when `cap` allows and returns its length (65 for the recoverable secp256k1 signature of key role 0 over a 32-byte message); it returns 0 when the node has no key for the role, the message is not 32 bytes, or `cap` is too small. `key_role` is a small integer naming a key in the host keystore (consensus, preconfirmation, identity); the host signs with the node's own key and never exports it. Precompile-grade operations beyond this list (modexp, bn254, point evaluation) are kernel-level precompiles implemented in modules with native acceleration, not host functions.

### 4.4 Invoke

| Name | Arguments | Result | Set | Cost |
|---|---|---|---|---|
| `invoke` | `a0` code_hash(32), `a1` namespace(32), `a2` input, `a3` input_len, `a4` gas_limit, `a5` flags | `a0` = status, `a1` = callee gas used | Sandboxed | 2 000 |
| `invoke_output_len` | — | `a0` = length of the last callee's output | Sandboxed | 10 |
| `invoke_output_read` | `a0` dst, `a1` offset, `a2` len | `a0` = bytes copied | Sandboxed | 10 + 1 per 32 bytes |

`invoke` instantiates the module with code hash `code_hash` under storage namespace `namespace` with the given input blob, capability set `Sandboxed` unless the caller is privileged and `flags` bit 0 is set, and gas limit `gas_limit`, which is debited from the caller before the call and credited back minus `callee gas used` after. `flags` bit 1 (`static`) forbids the callee any storage write, `storage_delete`, or nested non-static invoke; a violation terminates the callee with `HostError(StaticViolation)` and returns that status to the caller. The callee's storage overlay is applied to the caller's overlay on `Halt` and discarded on any other termination; the caller receives the termination status in `a0`. Nesting depth is limited by the host to 1024; exceeding it returns `HostError(DepthExceeded)` without instantiating. The host manages the whole frame stack; the kernel never re-enters for a contract-to-contract call.

### 4.5 Network (privileged)

| Name | Arguments | Result | Cost |
|---|---|---|---|
| `net_send` | `a0` peer(32), `a1` msg, `a2` len | `a0` = status | 100 + 1 per 32 bytes |
| `net_broadcast` | `a0` topic, `a1` msg, `a2` len | `a0` = status | 100 + 1 per 32 bytes |
| `net_disseminate` | `a0` blob_id(32), `a1` data, `a2` len | `a0` = status | 1 000 + 1 per 32 bytes |
| `net_request` | `a0` peer(32), `a1` req, `a2` len | `a0` = request id | 100 + 1 per 32 bytes |
| `net_respond` | `a0` request_id, `a1` data, `a2` len | `a0` = status | 100 + 1 per 32 bytes |
| `net_peer_score` | `a0` peer(32), `a1` delta (signed, low 32) | `a0` = status | 10 |

Network functions are *effects* in the driver model (06): they enqueue; nothing is observable to the instance. Delivery, retries, and dissemination coding are host policy. `net_disseminate` is erasure-coded broadcast of large blobs; receivers get the reassembled blob as a driver input.

### 4.6 Time and persistence (privileged)

| Name | Arguments | Result | Cost |
|---|---|---|---|
| `time_now` | — | `a0` = host monotonic time, milliseconds | 10 |
| `timer_set` | `a0` timer_id, `a1` deadline_ms | `a0` = status | 10 |
| `timer_cancel` | `a0` timer_id | `a0` = status | 10 |
| `persist_set` | `a0` key, `a1` key_len, `a2` val, `a3` val_len | `a0` = status | 100 + 1 per 32 bytes |
| `persist_get` | `a0` key, `a1` key_len, `a2` dst, `a3` cap | `a0` = length or `2^32−1` | 100 + 1 per 32 bytes |

`time_now` is only callable from driver entrypoints (06), never from state-transition entrypoints, and the loader enforces this by import set: a module exporting any `kernel_stf_*` entrypoint may not import `time_now`. `persist_*` is node-local, non-consensus storage for driver state that must survive restarts; it is written to the input log's checkpoint, never to chain state.

### 4.7 Telemetry

| Name | Arguments | Result | Set | Cost |
|---|---|---|---|---|
| `log_emit` | `a0` level, `a1` msg, `a2` len | `a0` = 0 | Sandboxed | 10 + 1 per 32 bytes |
| `metric_emit` | `a0` name, `a1` name_len, `a2` value (i64), `a3` kind | `a0` = 0 | Sandboxed | 10 |

Both are ignored by consensus. A host MAY drop them under load. They are charged so that a contract cannot use them as free work.

## 5. Determinism requirements on the host

Every function in §4.1–§4.4 MUST return identical results on every node given identical chain state and arguments. Functions in §4.5–§4.7 have no result the program can branch on except a status that MUST be `0` whenever the arguments are well-formed; a host that cannot send a message still returns `0` and drops it. This is what allows the driver to be a pure state machine over host effects.

## 6. Status and error codes

| Code | Name | Terminates instance? |
|---|---|---|
| 0 | `Ok` | no |
| 1 | `InvalidArgument` | no |
| 2 | `NotFound` | no |
| 3 | `StaticViolation` | yes, callee |
| 4 | `DepthExceeded` | no |
| 5 | `OutOfGas` | yes, as `OutOfGas` |
| 6 | `MemoryFault` | yes |
| 7 | `CalleeTrapped` | no; returned by `invoke` when the callee terminated with any status but `Halt` |
| 8 | `Unavailable` | no; a privileged function used outside its allowed entrypoint |

## 7. Versioning and growth

- `abi_version` returns 1. A host supporting version `n` supports every function of every version `≤ n`.
- New functions arrive in a new version behind a feature gate. A module importing a function from a version the host lacks fails to load, which is the intended failure: it is visible at install, never at run time.
- Per-unit and base costs in this document are part of the host-call cost table, version 1, and are recalibrated and versioned exactly like the instruction cost table (04 §2). A kernel declares the cost-table versions it was built against; the host charges by the versions the active fee schedule names.
