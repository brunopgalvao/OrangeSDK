# 19 — Precompiles and kernel gas

## 1. Overview

The reference kernel runs the EVM (revm, Osaka) inside the Solo VM, metered in VM gas (04), and charges transactions Ethereum's gas. That is sound only while the kernel gas an operation takes stays roughly proportional to the EVM gas it is charged. Ethereum prices its precompiles for native code; computed in the interpreted guest, the bn254, KZG and BLS12-381 precompiles cost the kernel up to 1 700 VM gas per EVM gas, against 40 to 130 for ordinary opcodes, so a cheap transaction could take a block's whole kernel-gas allowance: a denial of service on block production, or a block a node with a smaller allowance cannot execute (§2).

This document specifies how the reference kernel keeps kernel gas per EVM gas bounded without changing Ethereum's gas (codex ADR 0032):

- the arithmetic of those precompiles runs on the host, through thirteen host functions behind feature gate 2 (05 §4.8), reached from the kernel's EVM through a small module, so that the kernel loads on every host whatever the gate (§3);
- two ordinary operations the measurement also found above the bound are served differently: `KECCAK256` hashes on the host, and `BLOCKHASH` reads a stored hash (§4);
- until gate 2 is active, the precompiles still above the bound in the guest draw on a per-block budget and halt out of gas once it is spent, so every block stays within a known kernel gas (§5).

Results are the same on both paths, byte for byte (§3.4). The Ethereum gas of every operation is unchanged; the only departure from Ethereum is the budget of §5, which binds only before gate 2 and only in a block that spends it.

Why a spec of its own rather than additions to 04 and 05: 04 and 05 define the VM's metering and the host ABI for any kernel, and 05 §4.8 does hold the new functions; how the reference kernel's EVM uses them, the bound it keeps and the budget before the gate are reference-kernel policy, like spec 16's native gas rate, and need their measurements beside them.

## 2. Measurement and the bound

*Kernel gas per EVM gas* of an operation is the VM gas the kernel spends on it divided by the EVM gas the transaction is charged for it. `crates/solo-conformance/tests/precompiles.rs` measures it through the conformance guest (07 §4.2), which runs the kernel's own EVM code: for a precompile, a contract that copies its calldata to memory and `STATICCALL`s the precompile with all its gas, once and twice, and the difference of the two runs in VM gas and in EVM gas (the call's 100 gas and memory included); for an ordinary opcode, a loop of it run 100 and 200 times. The figures are identical on the interpreter and the native backend, as gas is a property of the spec (04 §1); `measure_precompiles` and `measure_ordinary` print the tables.

The **bound** is 256 VM gas per EVM gas: about twice the costliest ordinary opcode found, `EXP` with a full exponent. With gate 2 active, no precompile on its worst-case inputs and no ordinary operation measured exceeds it; `kernel_gas_per_evm_gas_stays_within_the_bound` checks every row of both tables and that exactly the rows marked *above* exceed it in the guest.

### Table 2.1 — Precompiles, worst-case inputs (measured 2026-10-21)

| Precompile, input | EVM gas | VM gas, guest | per EVM gas | VM gas, gate 2 | per EVM gas |
|---|---|---|---|---|---|
| ECRECOVER (host from genesis) | 3 116 | 14 864 | 4.7 | 14 864 | 4.7 |
| SHA-256, 1 KiB (host from genesis) | 560 | 9 569 | 17.0 | 9 569 | 17.0 |
| RIPEMD-160, 64 B | 956 | 15 696 | 16.4 | 15 696 | 16.4 |
| RIPEMD-160, 1 KiB | 4 556 | 61 061 | 13.4 | 61 061 | 13.4 |
| MODEXP, 32 B, exponent 2^256 − 1, odd modulus | 4 196 | 595 741 | 141.9 | 28 343 | 6.7 |
| MODEXP, 32 B, exponent 2^256 − 1, even modulus | 4 196 | 623 238 | 148.5 | 28 343 | 6.7 |
| MODEXP, 64 B, exponent 2^256 − 1 | 32 756 | 1 673 145 | 51.0 | 86 617 | 2.6 |
| MODEXP, 1 KiB, exponent 255 | 229 492 | 17 451 968 | 76.0 | 495 407 | 2.1 |
| bn254 add | 266 | 27 388 | 102.9 | 17 375 | 65.3 |
| bn254 mul, scalar 2^256 − 1 — *above* | 6 116 | 2 725 527 | 445.6 | 28 967 | 4.7 |
| bn254 pairing, 1 pair — *above* | 79 116 | 30 705 551 | 388.1 | 177 807 | 2.2 |
| bn254 pairing, 2 pairs — *above* | 113 116 | 44 154 530 | 390.3 | 251 973 | 2.2 |
| bn254 pairing, 8 pairs — *above* | 317 116 | 123 607 487 | 389.7 | 694 739 | 2.1 |
| BLAKE2F, 12 rounds | 128 | 13 342 | 104.2 | 13 342 | 104.2 |
| BLAKE2F, 63 rounds | 179 | 24 315 | 135.8 | 24 315 | 135.8 |
| BLAKE2F, 64 rounds | 180 | 24 532 | 136.2 | 22 925 | 127.3 |
| BLAKE2F, 10 000 rounds | 10 116 | 2 162 758 | 213.7 | 42 797 | 4.2 |
| point evaluation (valid proof) — *above* | 50 116 | 84 687 123 | 1 689.8 | 115 873 | 2.3 |
| BLS12-381 G1 add | 491 | 45 980 | 93.6 | 19 935 | 40.6 |
| BLS12-381 G1 MSM, 1 pair — *above* | 12 116 | 7 327 286 | 604.7 | 44 962 | 3.7 |
| BLS12-381 G1 MSM, 16 pairs — *above* | 130 100 | 52 049 864 | 400.0 | 332 203 | 2.5 |
| BLS12-381 G2 add — *above* | 716 | 392 017 | 547.5 | 24 409 | 34.0 |
| BLS12-381 G2 MSM, 1 pair — *above* | 22 616 | 21 010 638 | 929.0 | 70 065 | 3.0 |
| BLS12-381 G2 MSM, 16 pairs — *above* | 258 236 | 122 388 687 | 473.9 | 626 739 | 2.4 |
| BLS12-381 pairing, 1 pair — *above* | 70 416 | 47 025 807 | 667.8 | 159 746 | 2.2 |
| BLS12-381 pairing, 2 pairs — *above* | 103 016 | 64 335 647 | 624.5 | 229 268 | 2.2 |
| BLS12-381 pairing, 8 pairs — *above* | 298 616 | 170 390 475 | 570.6 | 646 714 | 2.1 |
| BLS12-381 map to G1 — *above* | 5 616 | 3 468 566 | 617.6 | 27 948 | 4.9 |
| BLS12-381 map to G2 — *above* | 23 916 | 10 714 862 | 448.0 | 67 282 | 2.8 |
| P256VERIFY (host from genesis) | 7 016 | 15 765 | 2.2 | 15 765 | 2.2 |

MODEXP's worst case is a modulus of at most 32 bytes, which EIP-7883 prices at a flat 16 per iteration whatever the size, with an exponent of all ones; BLAKE2F's is a large round count, Ethereum charging 1 gas per round. Each call costs the kernel about 12 000 VM gas before the precompile's own work, revm's call frame in the guest, which is why the cheapest precompiles stay above 60 per EVM gas on either path. The host path adds the module call of §3.2, about 5 000 VM gas more; BLAKE2F below 64 rounds is cheaper in the guest and stays there (§3.3).

### Table 2.2 — Ordinary operations (measured 2026-10-21)

| Loop body | EVM gas (100 iterations) | VM gas | per EVM gas |
|---|---|---|---|
| loop control only (`PUSH1 SWAP1 SUB DUP1 PUSH1 JUMPI JUMPDEST`) | 2 600 | 123 800 | 47.6 |
| 16 × `JUMPDEST` | 4 200 | 192 600 | 45.8 |
| 8 × `PUSH0 POP` | 5 800 | 227 800 | 39.2 |
| `ADD` | 3 700 | 166 500 | 45.0 |
| `MULMOD` | 4 500 | 231 700 | 51.4 |
| `EXP`, 3^(2^256 − 1) | 164 400 | 20 409 600 | 124.1 |
| `KECCAK256`, 32 B | 6 900 | 200 200 | 29.0 |
| `KECCAK256`, 1 KiB | 25 500 | 219 300 | 8.6 |
| `MSTORE`, `MLOAD` | 4 100 | 241 800 | 58.9 |
| `MCOPY`, 1 KiB | 13 300 | 311 900 | 23.4 |
| `SLOAD`, warm | 13 000 | 345 200 | 26.5 |
| `SSTORE`, warm | 13 000 | 490 749 | 37.7 |
| `TSTORE`, `TLOAD` | 23 400 | 543 284 | 23.2 |
| `BALANCE`, cold | 263 000 | 1 153 502 | 4.3 |
| `EXTCODEHASH`, cold | 263 000 | 1 234 702 | 4.6 |
| `BLOCKHASH`, block with 1 000 transactions | 5 000 | 673 700 | 134.7 |
| `SELFBALANCE` | 3 300 | 278 600 | 84.4 |
| `STATICCALL` of an empty account | 14 100 | 1 001 000 | 70.9 |
| `STATICCALL` of the identity precompile | 15 600 | 982 000 | 62.9 |
| `STATICCALL` of itself | 423 700 | 36 181 300 | 85.3 |
| `LOG0`, empty | 40 500 | 277 954 | 6.8 |
| `CREATE`, empty | 3 203 400 | 2 779 241 | 0.8 |

Before this change `KECCAK256` cost 945 (32 B) and 1 974 (1 KiB) VM gas per EVM gas, the guest hashing in software, and `BLOCKHASH` 274 for an empty block and 17 469 for one of 1 000 transactions, the kernel decoding, re-encoding and hashing the stored header on every call (§4).

## 3. Acceleration

### 3.1 Host functions

The host functions are those of 05 §4.8: modexp, bn254 add, multiplication and pairing, BLAKE2F, KZG point evaluation, and the seven EIP-2537 operations. Each costs `200 + 2 · g` VM gas, `g` being Ethereum's Osaka gas for the same operation. `crates/solo-host/tests/precompile_calibration.rs` times each operation with the arithmetic the functions run, in the same run as `bls12381_verify`, and converts at that function's rate (100 000 VM gas for one verification); the rate needed per Ethereum gas, on 2026-10-21:

### Table 3.1 — Calibration (release build; `bls12381_verify` 1 440 µs, 69.5 VM gas per µs)

| Operation | Ethereum gas | µs | VM gas at that rate | per Ethereum gas |
|---|---|---|---|---|
| modexp, 32 B, exponent 2^256 − 1 | 4 080 | 17.4 | 1 207 | 0.30 |
| modexp, 64 B, exponent 2^256 − 1 | 32 640 | 40.3 | 2 801 | 0.09 |
| modexp, 1 KiB, exponent 255 | 229 376 | 441.0 | 30 630 | 0.13 |
| modexp, 1 KiB, 33-byte exponent | 8 880 128 | 6 478.3 | 449 963 | 0.05 |
| bn254 add | 150 | 0.2 | 12 | 0.08 |
| bn254 mul | 6 000 | 38.7 | 2 689 | 0.45 |
| bn254 pairing, 8 pairs | 317 000 | 1 329.2 | 92 325 | 0.29 |
| BLAKE2F, 100 000 rounds | 100 000 | 615.9 | 42 777 | 0.43 |
| point evaluation | 50 000 | 1 090.4 | 75 734 | 1.51 |
| BLS12-381 G1 MSM, 1 pair | 12 000 | 92.9 | 6 451 | 0.54 |
| BLS12-381 G1 MSM, 128 pairs | 797 184 | 4 421.4 | 307 094 | 0.39 |
| BLS12-381 G2 add | 600 | 4.7 | 324 | 0.54 |
| BLS12-381 G2 MSM, 1 pair | 22 500 | 220.0 | 15 283 | 0.68 |
| BLS12-381 G2 MSM, 128 pairs | 1 509 120 | 7 885.4 | 547 695 | 0.36 |
| BLS12-381 pairing, 1 pair | 70 300 | 569.9 | 39 582 | 0.56 |
| BLS12-381 map to G1 | 5 500 | 47.7 | 3 311 | 0.60 |
| BLS12-381 map to G2 | 23 800 | 135.3 | 9 397 | 0.39 |

The rate 2 covers the costliest, point evaluation, with a third to spare; the base 200 covers the fixed cost of a call, which dominates only the cheapest operations (a single BLAKE2F round takes about 3 VM gas at this rate).

### 3.2 The precompile module

A kernel that imported a gated function would not load until the gate is active (05 §7, 13 §8.1), so the reference kernel does not import them. The *precompile module*, `guest/modules/precompiles`, does: it is the only code that imports the functions of 05 §4.8. `tools/build-guest.sh` builds it first and recompiles it with the host's `solo-recompile` into `guest/kernel/precompiles.solo`, which the kernel embeds; its code hash is the `keccak256` of those bytes.

- **Installation.** At the start of every `kernel_stf_execute_block` for which gate 2 is active (13 §8.4), the kernel writes the module's bytes under `code/` ‖ code hash (05 §4.4.1) unless they are there already. The key is covered by the state commitment; the first block with the gate active is the first whose state holds it. A call query (§3.3) writes it the same way when its gate is active; the host discards everything a query writes (06 §6), so the write lasts only for that query and the first block with the gate active still installs the module on every node alike.
- **Input.** `op ‖ operands`, `op` one byte indexing 05 §4.8's table from 0 (`evm_modexp`) to 12 (`evm_bls12381_map_fp2_to_g2`). The operands are the function's input bytes; for `evm_modexp` they are `base_len ‖ exp_len ‖ mod_len` as little-endian `u32` followed by `base ‖ exp ‖ mod`, and for the functions that take a `count`, the pairs, whose number follows from their length. An unknown `op`, or operands of the wrong length for it, traps.
- **Output.** One status byte, the function's `a0`, followed by what the function wrote to `dst` (nothing for the checks).
- **Call.** The kernel invokes it static under namespace zero with all its remaining VM gas but 100 000. It is charged like any invoke (05 §4.4): 2 000, plus loading `⌈len / 32⌉` (133 for the 4 249-byte module), plus its own instructions and host call. If the invoke does not halt, which happens only when the host cannot serve gate 2 (13 §8.6) or the kernel is out of gas, the kernel traps: a host that cannot serve an active gate fails loudly instead of computing something else.

### 3.3 Routing in the kernel's EVM

revm hands every precompile's arithmetic to the installed `Crypto`; the kernel's (`guest/kernel/src/evm.rs`, `HostCrypto`) routes it:

| `Crypto` method | Before gate 2 | Gate 2 active |
|---|---|---|
| `sha256`, `secp256k1_ecrecover`, `secp256r1_verify_signature` | host (`hash_sha256`, `secp256k1_recover`, `p256_verify`), from genesis | same |
| `ripemd160` | guest | guest |
| `modexp`, `bn254_g1_add`, `bls12_381_g1_add` | guest | host, through the module |
| `blake2_compress` | guest | host for 64 rounds or more, guest below |
| `bn254_g1_mul`, `bn254_pairing_check`, `verify_kzg_proof`, `bls12_381_g1_msm`, `bls12_381_g2_add`, `bls12_381_g2_msm`, `bls12_381_pairing_check`, `bls12_381_fp_to_g1`, `bls12_381_fp2_to_g2` | guest, within the budget of §5 | host, through the module |

Whether gate 2 is active is read from the gate book at the start of each `kernel_stf_execute_block`, for the block's height, and for a call query (`eth_call`, gas estimation) for the height after the head, the gates the host serves at that point (13 §7.1). revm's parsing, input checks and gas stay in the guest on both paths: the host computes only what `Crypto` is asked.

### 3.4 Equivalence

Both paths run revm 43's own backends (arkworks for bn254, BLS12-381 and KZG, `aurora-engine-modexp`, revm's BLAKE2F): in the guest compiled for the Solo VM, on the host natively. They return the same output for every input, and halt for the same inputs; which `PrecompileHalt` a halt names may differ, which nothing observes, every halt failing the call and consuming its gas. `host_and_guest_paths_agree_on_every_precompile` runs every row of table 2.1 and 27 refused or degenerate inputs (invalid and off-curve points, non-canonical field elements, bad lengths and padding, a wrong proof or versioned hash, empty inputs, zero scalars, pairings that do not hold) through both paths, the host path on both backends, and requires identical outcomes and post-states; the host functions' own tests compare each result with revm's precompile on the same operands.

## 4. Ordinary operations

- **`KECCAK256`.** revm hashes through `alloy-primitives`' `keccak256`, which the kernel builds with its `native-keccak` feature; the kernel's `native_keccak256` calls the host's `hash_keccak256` (05 §4.3, 30 + 6 VM gas per 32 bytes), an ungated function of ABI version 1, so this holds from genesis on every host. The same path serves `CREATE2` addresses and code hashes.
- **`BLOCKHASH`.** With every block it stores, the kernel stores the block's hash under `bnum/` ‖ height (big-endian `u64`), and `BLOCKHASH` reads those 32 bytes; a height without the key answers zero, as before for heights without a block. A kernel version that switches from one that stored no such keys writes them for the last 256 blocks in its `kernel_migrate`; the reference kernel has stored them from genesis on.

## 5. Before gate 2: the budget

Until gate 2 is active, the operations of table 5.1 run in the guest only while the kernel gas spent so far in the block, plus their bound, stays within `PRECOMPILE_BUDGET` = 2^34 VM gas:

- "So far" counts from the start of `kernel_stf_execute_block` (for a call query, from the start of the query), everything included.
- An operation's *bound* is its Ethereum gas times its ratio in table 5.1, the measured worst case of table 2.1 with a margin.
- An operation that would exceed the budget halts out of gas (`PrecompileHalt::OutOfGas`): the precompile call fails and consumes the gas it was given, exactly as if it had been given too little. Later transactions of the block run normally, and their precompile calls of table 5.1 fail the same way; the next block starts a new budget.

### Table 5.1 — In-guest operations checked against the budget

| Operation | Ratio (VM gas per Ethereum gas) |
|---|---|
| bn254 mul | 600 |
| bn254 pairing | 500 |
| point evaluation | 2 200 |
| BLS12-381 G1 MSM | 800 |
| BLS12-381 G2 add | 800 |
| BLS12-381 G2 MSM | 1 200 |
| BLS12-381 pairing | 900 |
| BLS12-381 map to G1 | 800 |
| BLS12-381 map to G2 | 600 |

Every other operation is within the bound in the guest (table 2.1) and is never checked. This is the one departure from Ethereum's semantics: before gate 2, only a block that spends 2^34 VM gas reaches it, and only for the operations of table 5.1. The budget is large enough that every transaction of the full pinned conformance set passes alone in a block (§6.1), the largest a 454-pair BLS12-381 pairing bounded at 1.3 · 10^10, and small enough to keep a block within the bound of §5.1. `in_guest_precompiles_halt_past_the_budget` runs 250 point evaluations in one transaction: in the guest fewer pass and the kernel spends less than 2^34 · 9/8, with gate 2 all pass; 40 large modular exponentiations all pass in the guest, unchecked.

### 5.1 The kernel gas of a block

With the bound of §2 and the budget, a block of the reference kernel takes at most the budget (2^34, 1.72 · 10^10), plus 256 VM gas per EVM gas of the block gas limit (30 000 000, so 7.68 · 10^9), plus what every block and transaction costs outside the EVM (decoding, signature recovery, receipts, hooks, the state commitment; about 4 · 10^5 per transaction): `solo_node::BLOCK_KERNEL_GAS` = 2^35 VM gas covers it with room to spare. The pairings of staking admission checks that fail during execution, which no EVM gas pays for, are bounded separately by the pairing budget of 15 §3.3 and fit in that room: their transactions' gas limits sum to at most the block gas limit, and each of at least the 21 000 intrinsic gas costs the kernel one `bls12381_pairing_check` of one pair or one `bls12381_verify` (05 §4.3, at most 120 000 VM gas plus 6 per 32 bytes of message), so fewer than 1 430 of them add under 1.8 · 10^8. Both budgets apply whatever gate 2's state: the kernel's own BLS checks call the version 1 functions of 05 §4.3 directly, never the precompile module. A node whose kernel gas per call (`NodeConfig::kernel_gas`, `solo dev --kernel-gas`) is below it can fail to execute a valid block and stall; the default, `KERNEL_GAS` = 2^40, is far above.

`crates/solo-node/tests/precompiles.rs` runs a single validator with exactly 2^35, on the native backend, and fills blocks with two transactions of 14 900 000 gas, each making 240 point evaluations of 60 000 gas. Before gate 2 the block executes in 17 113 649 850 VM gas, the evaluations stopping at the budget; once the gate is active, all 480 of a block succeed in 56 740 232 VM gas; every block finalizes and the chain goes on. (Both rose by 82 314 and 82 352 on 2026-10-22 with the fee market of spec 23: the base fee read from the parent's header and the parameters at the start of every block, the base fee checks of every transaction, the treasury and the vault at the end of the block; before that, by 9 932 and 9 896 between 2026-10-21 and 2026-10-22 for the governance bookkeeping of spec 13 §9.3 at the end of every block and the admission of every transaction through it, the staker, veto, quorum and surcharge rules of spec 13 §3 and §9, less the driver's replay of a restarted node's own finalized blocks (08 §7).)

## 6. Conformance

The committed subset (07 §4.2) passes with gate 2 active as without it, 534 passed, 22 expected failures, 0 failures, on both backends (`committed_subset_passes_with_gate_2_on_both_backends`), each case also run without the gate and required to agree. The `solo-conformance` command takes `--gated` for the same run over any fixtures. The full pinned set does not regress either way (§6.1).

### 6.1 Full pinned set

fusaka-devnet-5 v2.1.0, 5 571 cases, native backend, run locally on 2026-10-21 (`solo-conformance --native [--gated]`); the same as before this change (07 §4.2):

| Run | Passed | Expected | Failed |
|---|---|---|---|
| gate 2 inactive | 4 223 | 1 348 | 0 |
| gate 2 active | 4 223 | 1 348 | 0 |

With set-code transactions accepted (spec 20 §6), rerun on 2026-10-21 on both backends (`solo-conformance --both [--gated]`): 4 767 passed, 804 expected, 0 failed, with the gate inactive and active alike.

A budget of 2^31, tried first, failed two cases with the gate inactive, single transactions of 129 and 454 BLS12-381 pairs whose bounds exceed it; hence 2^34.

## 7. Rationale (non-normative)

- **Acceleration, not repricing.** Charging the guest's cost as EVM gas would make Solo's gas schedule differ from Ethereum's for every contract using these precompiles, breaking the Type 2 equivalence that lets Ethereum tooling estimate gas. Moving the work to the host keeps Ethereum's gas exact; the budget before the gate is the least deviation that still bounds a block.
- **Through `Crypto`, not a precompile of the kernel's own.** revm 43's `Crypto` trait exposes exactly the arithmetic, after revm's input parsing and gas; routing it keeps every Ethereum rule (lengths, padding, gas formulas, the versioned-hash check) in revm, where conformance tests it, and leaves the host only mathematics, priced by a rule that follows Ethereum's own calibration.
- **A module, not a kernel upgrade.** A kernel importing the gated functions would need a kernel upgrade with `requiredGates` set (13 §3) once the gate is active, and two kernels to maintain. The module lets one kernel run before and after the gate, switching at the activation height on every node with no governance action, at a cost of about 5 000 VM gas per call, as the light client of spec 18 waits for gate 1.
- **Per-block budget, not per transaction.** A transaction's EVM gas cannot bound the guest's work for these operations, which is the problem; the budget bounds the block, which is what a node must execute in time. A per-transaction cap would let many transactions add up to the same unbounded block.
- **The bound.** 256 is about twice the costliest ordinary opcode measured, so with the gate active no precompile is a worse use of kernel gas than ordinary code; the native-call rate of spec 16 §6 (20 VM gas per EVM gas) is a price, not this bound.
