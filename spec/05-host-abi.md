# 05 — Host ABI

## 1. Overview

The host ABI is the complete set of functions a module may call through `ecall`, and the complete set of entrypoints a host may call on a module. It is the boundary between what governance can change (everything inside the VM) and what only a node release can change (everything outside). Because of that it is designed to stay small, to grow only by addition, and to never change the meaning of an existing function. Version 1 has 36 functions, all available from genesis (§4); gate 0 (13 §8.1) adds a 37th, `secp256k1_verify`, and gate 1 a 38th, `bls12381_fast_aggregate_verify`. A function, once published in a released minor, is never removed and never changes behaviour; a replacement gets a new name.

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

The host starts an instance at an exported block (03 §5.2) with `a0`–`a5` set as the entrypoint's contract states and `sp` at `stack_top`. Return values are read from `a0`, `a1` at `Halt`. Which exports a kernel, a kernel module, or a contract must provide is defined by the kernel ABI (06 for the driver and state transition entrypoints; 16 for the reference kernel's modules and native contracts). The host itself requires only:

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
| `storage_commit` | `a0` dst(32 bytes) | `a0` = status; writes the state commitment root (10 §4) | Privileged | 10 000 |
| `storage_proof` | `a0` key, `a1` key_len, `a2` dst, `a3` cap | `a0` = proof length, or 0 for a key length outside 1–96; writes the proof (10 §5.1) | Privileged | 2 000 + 1 per 32 bytes written |

`storage_commit` writes the root of the binary Merkle trie of spec 10 over the committed entries: every key visible to the calling instance, its own pending overlay writes included, except those under the prefix `local/` (10 §2). `storage_proof` writes the encoded proof (10 §5) for the key against the root `storage_commit` would write at the same point: of the key's value hash if it is committed, of its absence otherwise, which is always the case for a key under `local/`. The key is a stored key, so a sandboxed instance's key is named with its 32-byte namespace in front, up to 96 bytes in all (10 §2). Proofs are at most 8 259 bytes; a buffer that size never truncates. The flat costs of the two rest on the host keeping the trie as it goes (10 §6): the hashing a written key needs is paid for by `storage_set` and `storage_delete`, and each call costs O(depth) hashes for every key written since the previous call, however much state there is and however many writes are pending.

Writes are buffered in a per-instance overlay and become visible to the instance immediately; the host applies or discards the overlay according to the invoke semantics (§4.4). Iteration order is bytewise ascending over keys. Iterator handles are invalidated when the instance terminates. State-growth pricing (the kernel's state-gas dimension) is a kernel fee-schedule charge in EVM gas layered on top of these costs; it is not a host matter.

### 4.3 Cryptography

| Name | Arguments | Result | Set | Cost |
|---|---|---|---|---|
| `hash_keccak256` | `a0` src, `a1` len, `a2` dst(32) | `a0` = 0 | Sandboxed | 30 + 6 per 32 bytes |
| `hash_sha256` | `a0` src, `a1` len, `a2` dst(32) | `a0` = 0 | Sandboxed | 30 + 6 per 32 bytes |
| `hash_blake2b256` | `a0` src, `a1` len, `a2` dst(32) | `a0` = 0 | Sandboxed | 30 + 4 per 32 bytes |
| `secp256k1_recover` | `a0` msg(32), `a1` sig(65), `a2` dst(64) | `a0` = status | Sandboxed | 3 000 |
| `p256_verify` | `a0` msg(32), `a1` sig(64), `a2` pubkey(64) | `a0` = status (0 valid, 1 invalid) | Sandboxed | 6 900 |
| `secp256k1_verify` | `a0` msg(32), `a1` sig(64), `a2` pubkey(64) | `a0` = status (0 valid, 1 invalid) | Sandboxed, behind gate 0 | 3 000 |
| `bls12381_verify` | `a0` msg, `a1` msg_len, `a2` sig(48), `a3` pubkey(96), `a4` dst, `a5` dst_len | `a0` = status (0 valid, 1 invalid) | Sandboxed | 100 000 + 6 per 32 bytes of msg |
| `bls12381_pairing_check` | `a0` pairs, `a1` count | `a0` = status (0 holds, 1 fails) | Sandboxed | 70 000 + 50 000 per pair |
| `bls12381_fast_aggregate_verify` | `a0` keys, `a1` count, `a2` msg, `a3` msg_len, `a4` sig(96) | `a0` = status (0 valid, 1 invalid) | Sandboxed, behind gate 1 | 125 000 + 5 500 per key + 6 per 32 bytes of msg |
| `sign` | `a0` key_role, `a1` msg, `a2` msg_len, `a3` dst, `a4` cap | `a0` = signature length or status | Privileged | 10 000 |

The prefix `local/` is for node-local bookkeeping that must not affect the state commitment (the reference kernel keeps its finalized height there); `storage_commit` and `storage_proof` leave it out (§4.2, 10 §2). `sign` is the only function that touches node keys. `key_role` is a small integer naming a key in the host keystore; the host uses the node's own keys and never exports them. Roles defined so far:

| Role | Key | `msg` | Result |
|---|---|---|---|
| 0 | consensus (secp256k1) | a 32-byte digest | the 65-byte recoverable signature `r ‖ s ‖ recovery id` |
| 2 | threshold keystore (15 §6.4) | an encoded `KeystoreRequest` | the request's answer |

For role 0, `sign` writes the signature to `dst` when `cap` is at least 65 and returns 65; it returns 0 when the node has no consensus key, the message is not 32 bytes, or `cap` is smaller. For role 2, the answer varies in length: like every variable-length result (§3) it is written truncated to `cap` and `sign` returns its full length; it returns 0 when the keystore cannot answer (a request that does not decode, a key or share the node lacks, a DKG run that fails). Every other role returns 0. The threshold keystore derives the node's DKG decryption key and dealer randomness from the consensus key, keeps the threshold shares the DKG gives it, and answers with encryption keys, DKG messages, partial signatures and combined signatures, so the kernel can drive the DKG and produce threshold certificates (08 §6a) without holding a secret. Its answers depend on the node's keys and are node-local: they feed the driver, never a state transition.

`secp256k1_recover` reads `sig` as `r ‖ s ‖ v` with `v` one of 0, 1, 27 or 28, and writes the recovered public key as 64 bytes (the uncompressed point without its `0x04` prefix). It returns `InvalidArgument` if `v` is anything else, if `r` or `s` is zero or not below the group order `n`, if `s > n/2`, or if no key recovers. Accepting only the low-s form, which EIP-2 requires of transactions, keeps every host agreeing on which signatures are valid. A caller that must also accept high-s signatures, such as the EVM `ecrecover` precompile, replaces `s` by `n − s` and flips the parity before calling.

`secp256k1_verify` checks an ECDSA signature `r || s` over a 32-byte digest against an uncompressed public key `x || y`, without recovery. A signature with `s` above half the group order is invalid, as Ethereum requires of transactions; so are an `r` or `s` of zero or not below the order, and a key that is not on the curve. It resolves only once feature gate 0 is active (spec 13 §8).

`bls12381_verify` checks a BLS signature in the scheme of spec 12 §3, signature in G1 and public key in G2, both compressed (12 §2): it hashes `msg` to G1 with the RFC 9380 suite `BLS12381G1_XMD:SHA-256_SSWU_RO_` under the tag `dst` and returns 0 exactly when `e(sig, −g2) · e(H(msg), pubkey) = 1`. It returns 1 for a tag shorter than 1 or longer than 255 bytes, checking `dst_len` before reading `dst`, so such a tag is never read and its range never faults; it also returns 1 for a point that does not decode or lies outside the prime-order subgroup, and an identity public key. A kernel verifies a finality certificate (12 §7) by passing the certificate message, the tag `DST_SIG` and the group key. `bls12381_pairing_check` reads `count` pairs of 144 bytes, each a compressed G1 point followed by a compressed G2 point, and returns 0 exactly when `count ≥ 1` and the product of their pairings is the identity of the target group; identity points are allowed, and a point that does not decode or lies outside its subgroup returns 1. Gas is charged before any range is read, so a `count` whose input would exceed the address space ends the instance with `OutOfGas` or `MemoryFault`. Signatures of the Ethereum consensus layer (keys in G1, signatures in G2) are outside `bls12381_verify`; `bls12381_fast_aggregate_verify` checks them.

`bls12381_fast_aggregate_verify` is `FastAggregateVerify` of draft-irtf-cfrg-bls-signature-05 with the proof-of-possession ciphersuite `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`, the scheme of Ethereum's sync committees (spec 18 §3.1): it reads `count` compressed G1 public keys of 48 bytes each at `keys`, `msg_len` bytes at `msg` and a compressed G2 signature of 96 bytes at `sig`, hashes `msg` to G2 with suite `BLS12381G2_XMD:SHA-256_SSWU_RO_` under that tag, and returns 0 exactly when `e(Σ keys, H(msg)) = e(g1, sig)`. It returns 1 when `count` is 0, when a key does not decode, lies outside the prime-order subgroup or is the identity (`KeyValidate`), when the keys sum to the identity, and when the signature does not decode or lies outside its subgroup. Keys must have had their proofs of possession checked when they were registered, as the beacon chain checks them at deposit. Gas is charged before any range is read, so a `count` whose keys would exceed the address space ends the instance with `OutOfGas` or `MemoryFault`. The per-key cost covers decoding a key with its subgroup check and adding it, measured on 2026-10-21 at the same rate per microsecond as `bls12381_verify`; a 512-key check costs 2 941 000 plus the message words. It resolves only once feature gate 1 is active (spec 13 §8).

Precompile-grade operations beyond this list (modexp, bn254, point evaluation) are kernel-level precompiles implemented in modules with native acceleration, not host functions.

### 4.4 Invoke

| Name | Arguments | Result | Set | Cost |
|---|---|---|---|---|
| `invoke` | `a0` code_hash(32), `a1` namespace(32), `a2` input, `a3` input_len, `a4` gas_limit, `a5` flags | `a0` = status, `a1` = callee gas used | Sandboxed | 2 000 |
| `invoke_output_len` | — | `a0` = length of the last callee's output | Sandboxed | 10 |
| `invoke_output_read` | `a0` dst, `a1` offset, `a2` len | `a0` = bytes copied | Sandboxed | 10 + 1 per 32 bytes |

`invoke` instantiates the module with code hash `code_hash` under storage namespace `namespace` with the given input blob, capability set `Sandboxed` unless the caller is privileged and `flags` bit 0 is set, and gas limit `gas_limit`, which is debited from the caller before the call and credited back minus `callee gas used` after. `flags` bit 1 (`static`) forbids the callee any storage write, `storage_delete`, or nested non-static invoke; a violation terminates the callee with `HostError(StaticViolation)` and returns that status to the caller. The callee's storage overlay is applied to the caller's overlay on `Halt` and discarded on any other termination; the caller receives the termination status in `a0`. Nesting depth is limited by the host to 1024; exceeding it returns `HostError(DepthExceeded)` without instantiating. The host manages the whole frame stack; the kernel never re-enters for a contract-to-contract call.

#### 4.4.1 Modules in chain state

A host runs a module it was handed directly (the kernel, and whatever else it loads itself) by its code hash alone. For any other code hash `h`, the module is the value of the key `code/` ‖ `h` (`63 6f 64 65 2f` followed by the 32 bytes) in the state visible to the caller, its own pending overlay writes included, so a kernel can store a module and invoke it within one entrypoint:

The steps run in this order, and each outcome is the same whether or not the host has the module cached:

1. A gas limit the VM rejects (04 §4) fails the call before instantiating with `InvalidArgument`, no gas used.
2. The callee pays for loading: `⌈len / 32⌉` VM gas, `len` being the length of the value, is taken from its gas limit before any work on the value, on every call. A limit below that ends the callee with `OutOfGas` having used its whole limit, and `invoke` returns `CalleeTrapped`.
3. The value must hash to `h` under `keccak256` and validate (03 §7) for the capability set of the call; otherwise the call fails before instantiating having used the load cost, and `invoke` returns `NotFound` with that gas used in `a1`. A missing export fails the same way.
4. A host MAY cache what it loaded, but runs it only while the key still holds the same bytes, since another node may have no cache, and checks a cached module's imports against the capability set of each call, since it may have been validated for a wider one.

This lookup is part of ABI version 1 as spec 16 publishes it: before it no chain kept modules under `code/`, so no earlier call observes a difference, and invoking a hash whose value there is not a module (EVM bytecode, which the reference kernel keeps under the same prefix) still returns `NotFound`.

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

Both are ignored by consensus. A host MAY drop them under load. They are charged so that a contract cannot use them as free work. The meaning of `kind` and of `level`, and how a node exports what it records, are in 11 §4–§5.

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
- The functions of §4 without a gate in their capability cell, `bls12381_verify` and `bls12381_pairing_check` among them, are version 1 and resolve from genesis on every chain; a chain needs no gate to use them.
- New functions added after that arrive behind a feature gate (spec 13 §8), and in a new version once one is published: a gated function resolves only once the chain has activated its gate. `secp256k1_verify` is the first, behind gate 0; `bls12381_fast_aggregate_verify` the second, behind gate 1. A module importing a function from a version the host lacks, or one whose gate is not active, fails to load, which is the intended failure: it is visible at install, never at run time.
- Per-unit and base costs in this document are part of the host-call cost table, version 1, and are recalibrated and versioned exactly like the instruction cost table (04 §2). A kernel declares the cost-table versions it was built against; the host charges by the versions the active fee schedule names.
