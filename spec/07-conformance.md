# 07 — Conformance

## 1. What conformance means

An implementation of the VM conforms if it passes every vector in the conformance suite and agrees with the reference interpreter on every program the differential harnesses generate. A recompiler conforms if it produces byte-identical modules to the reference recompiler on the corpus. A host conforms if the host-ABI vectors pass against it. Coverage is part of conformance: the reference crates ship with 100% line coverage enforced in CI, so every rule in 01–06 is exercised by at least one test that would fail if the rule were broken.

## 2. Vector format

Vectors are JSON files, one suite per directory under `conformance/`. A VM vector:

```json
{
  "name": "div_by_zero_signed",
  "spec": "02 §6.1",
  "module": "534f4c4f0001...",          // hex, whole module bytes
  "entry": "main",
  "regs": { "a0": "0x8000000000000000", "a1": "0" },
  "gas": 1000,
  "input": "",                           // hex input blob
  "host": [                              // scripted host-call results, in call order
    { "name": "storage_get", "args": ["..."], "result": { "a0": 4, "writes": [{"ptr": 4096, "data": "deadbeef"}] }, "gas_charged": 204 }
  ],
  "expect": {
    "status": "Halt",                     // or OutOfGas | Trap | MemoryFault | InvalidJump | HostError:n
    "regs": { "a0": "0xffffffffffffffff" },
    "gas_remaining": 993,
    "output": "",
    "memory": [ { "ptr": 4096, "data": "00000000" } ]
  }
}
```

Unspecified registers and memory are unconstrained. A validation vector has `module` and `expect: { "invalid": "7.5.12" }` naming the rule in 03 §7 that must reject it; a valid-module vector has `expect: { "valid": true, "block_costs": [7, 3, ...] }`.

## 3. Suites

| Suite | Pins |
|---|---|
| `decode/` | Every opcode encodes and decodes to itself; every non-canonical LEB128, bad register byte, out-of-range shift, and reserved opcode is rejected with the right rule |
| `module/` | Each rule of 03 §7, one failing vector per rule and the minimal passing module |
| `isa/` | Every instruction's semantics on boundary values: zero, one, all-ones, sign boundaries, shift amounts 0/31/32/63/64, division edge cases, misaligned and cross-page memory accesses, register 0 as source and destination |
| `control/` | Fallthrough, self-loops, indirect jumps to every kind of bad slot address, call continuation rules, final-block rules |
| `gas/` | Every row of the cost table, block re-entry charging, the exact `OutOfGas` point for static and dynamic charges, `sbrk` and bulk memory pricing |
| `host/` | Every function in 05 with a scripted host: argument validation, truncation, status codes, capability-set rejection at load, static-call violation, depth limit, overlay apply and discard |
| `driver/` | Encoding round-trips for every `Input`, `Effect`, and struct in 06; the switchover sequence against a pair of toy kernels |
| `recompiler/` | A corpus of ELF inputs with their expected module bytes |

## 4. Oracles and differential testing

- **RISC-V semantics.** riscv-tests `rv64ui` and `rv64um` are compiled with the stock toolchain, recompiled to modules, and run on the interpreter; the pass/fail word of each test must match. The same ELF binaries run under `qemu-system-riscv64` as a second oracle for the semantic subset.
- **Interpreter against a semantic model.** A property-based harness generates random straight-line and looping programs over the arithmetic subset, executes them on the interpreter, and checks every register against a direct Rust model of 02 §5–§6. This runs in CI on every change.
- **Backend against interpreter.** Every JIT backend is fuzzed against the interpreter on generated modules, comparing termination status, all registers, gas remaining, and a digest of memory. A mismatch is a release blocker for the backend. §4.1 states the procedure.
- **Recompiler determinism.** Two runs over the corpus on different hosts must produce identical bytes.
- **EVM path.** The EVM compiled to the VM runs Ethereum's execution-spec state tests for the target fork; §4.2 states the procedure.

### 4.1 Differential testing of native backends

A native backend (a JIT or ahead-of-time compiler) conforms only if, for every valid module, entry, argument registers, gas limit and host, it produces the same observable result as the reference interpreter. *Observable result* means all of:

1. the termination status (01 §6), including the code of `HostError`;
2. all thirty-two registers;
3. the gas counter, including its exact negative value after `OutOfGas`;
4. the program position at termination: the block and the index of the instruction that ended execution, or index 0 for an `OutOfGas` at block entry;
5. the contents of every region (01 §3.2) and the heap size;
6. the sequence of host calls made, each with its handle and argument registers `a0`–`a5`.

The harness runs every comparison under each register-allocation setting the backend offers, at least: no guest register in a host register, a few, and as many as the target allows, so that both the in-register and the in-memory operand paths of every lowering are exercised. It consists of:

- **Generated modules.** A property test generates valid modules of one to six blocks with: every register–register and register–immediate operation on boundary immediates; constants of every width; loads and stores of every width whose addresses are drawn from the first and last bytes of every region, the guard pages, and addresses with the high 32 bits set, so that every fault boundary of 01 §3.2 is crossed; `sbrk` within and beyond `heap_max`; `memcopy` and `memfill` over valid, overlapping and faulting ranges; host calls to a deterministic recording host whose functions charge gas, write memory, grow the heap, clobber registers (including `zero`), fail with `HostError`, run out of gas, and drive the counter to near the minimum and return success (which must saturate at the next charge, 01 §5); fall-through, branches, loops, `call`, `jump_indirect` and `call_indirect` to valid, empty, out-of-range and misaligned slot addresses; and gas limits from 0 upward, so that `OutOfGas` occurs at every kind of charge point. At least 400 cases run on every change.
- **Deterministic tables.** Every instruction with every operand shape (distinct registers, destination aliasing a source, both sources equal, `zero` in each position, rarely used registers) on the boundary values of 02 §5–§6 and §6.1; every access width at and around every region boundary; every branch condition taken and not taken, forward and backward, including a backward branch over more than a mebibyte of native code; every host behaviour above; a block whose static cost exceeds any immediate operand. These tables, not the random cases, carry the 100% line coverage requirement of §6, so coverage does not depend on a seed.
- **Real guests.** The recompiled `hello` guest, and the reference kernel running `kernel_init`, `kernel_query`, `kernel_driver_state` and `kernel_stf_validate_tx` through the host executor with the node's privileged functions, must produce, after every call, identical call results, positions, logs, metrics and state commitments on both backends, and the harness must confirm that the native backend compiled the program rather than falling back to the interpreter.

A backend MAY return `Unsupported` for a target it does not implement; callers then use the interpreter. Step limits (01 §6, `StepLimit`) are a debugging facility of the interpreter and are not required of native backends.

### 4.2 Ethereum execution-spec conformance

The reference kernel claims Ethereum equivalence at the Osaka fork. What it runs is not revm as revm's own test suite runs it: revm is compiled for `riscv64imac`, recompiled into a module (03 §8), executed by the interpreter or a native backend, with `ecrecover`, `SHA-256` and `P256VERIFY` answered by host functions (05 §4.3), and with every account, code and storage read and write going through the kernel's storage layout and its commit of revm's changes. Each of those layers can break Ethereum semantics without revm being wrong, so the whole pipeline is held to Ethereum's own test vectors.

**Vectors.** The `state_test` fixtures of `ethereum/execution-spec-tests`, release `fusaka-devnet-5@v2.1.0` (`fixtures_fusaka-devnet-5.tar.gz`, SHA-256 `96a39d8eb8de742e450a7e7c63ffb4c2b82187f4fed9c1406f39ff3ef9f53a91`, filled 2025-09-08 from commit `7159decdb9107d6f052dd6a21a3d61b271a8e340` for Osaka). Only the `Osaka` expectations are read. `tools/fetch-conformance.sh` downloads that archive, checks the hash and extracts the state tests (5 571 cases in 266 files). The repository carries a subset, `crates/solo-conformance/tests/fixtures/state_tests`: 521 cases across the opcode families, the precompiles (identity, modexp with EIP-7823 and EIP-7883, BLAKE2, the KZG point evaluation, BLS12-381, `P256VERIFY`), CREATE and CREATE2, SELFDESTRUCT under EIP-6780, EIP-2930 and EIP-1559 transactions, the EIP-7623, EIP-7825 and EIP-3860 limits, transient storage, `MCOPY`, `CLZ`, `PUSH0` and the warm coinbase. `tools/curate-conformance.py` reproduces the subset from the full set: per category a quota of cases, taken round-robin across the category's test functions, trimmed to the fields the runner reads. Blockchain tests are not used: they check Ethereum's block structure (headers, withdrawals, system contracts, blob gas accounting), which the kernel replaces with its own (06, 08); the transaction-level semantics they share with state tests are covered by the state tests.

**Procedure.** For each case the runner (`crates/solo-conformance`):

1. encodes the environment (`currentCoinbase`, `currentNumber`, `currentTimestamp`, `currentGasLimit`, `currentBaseFee`, `currentRandom`, `currentDifficulty`, `currentExcessBlobGas`, the chain id), the pre-state as genesis allocations and the signed transaction (`txbytes`) as a `conformance::Case` (`solo_abi::conformance`);
2. calls the export `conformance_run` of the conformance guest (`guest/evm-conformance`) on empty storage, privileged and with bare keys, exactly as the node loads the kernel, recompiled with the recompiler's defaults. The guest compiles the kernel's own `evm`, `state` and `tx` source files, so the code under test is the kernel's: genesis allocation (`state::init`), sender recovery (`tx::decode_signed`), and `evm::run_in`, the function behind the kernel's `evm::run`, with the case's environment in place of the kernel's fixed one. The kernel's block-level admission checks (`stf::well_formed`: its own block gas limit and fee floor) are not applied; revm's transaction validation is;
3. reads the post-state back from storage in the kernel's layout (`acct/`, `code/`, `slot/` keys), computes Ethereum's state root over it (the hexary Merkle-Patricia trie of the Yellow Paper, appendix D) and `keccak256` of the RLP of the logs the guest returned;
4. passes the case if and only if the transaction is refused (the guest reports `INVALID`) exactly when the fixture has `expectException`, the state root equals the fixture's `hash` and the logs hash equals its `logs`. When the root differs, the report names the first account and field that differ from the fixture's post-state.

Every case runs on the interpreter and on the native backend. The interpreter's result is the one compared with the fixture; the native backend's result (status, gas, logs and the whole post-state) must equal it, or the case fails whatever the fixture says (§4.1), and the run confirms that the native backend compiled the guest rather than falling back. The guest gets 2^50 VM gas, so a case ends by its own EVM gas limit, never by the VM's.

**Expected failures.** A case that fails must match an entry of `crates/solo-conformance/tests/fixtures/expected-failures.txt`, which gives the reason the kernel deliberately differs from Ethereum. An entry is a test id, a prefix of ids ending in `*`, or `type:N`, every case whose transaction has EIP-2718 type `N`. An entry naming one test must fail: when it passes, the entry is removed. A prefix or type entry must excuse at least one failure of the committed subset. Nothing is skipped: a case whose pre-state the kernel cannot hold (a balance of 2^128 or more, the kernel's limit) fails with that reason and needs an entry like any other. The entries in force:

| Entry | Reason |
|---|---|
| `type:3` | The kernel does not accept EIP-4844 blob transactions (`solo-eth` decodes them as unsupported); a solochain has no blob data-availability layer. |
| `type:4` | The kernel does not accept EIP-7702 set-code transactions yet; accounts holding a delegation designator from genesis do run delegated code. |

**Results** (2026-10-20). Committed subset: 490 pass, 31 fail as expected (blob and set-code transactions), none fail otherwise; the test pins these numbers. Full pinned set: 4 223 pass, 1 348 fail as expected, none fail otherwise. A failure outside the list is a bug in the pipeline and gets a regression test where it is fixed; the first run found one: a single 2^24-gas transaction exhausting the guest heap (03 §8 rule 10).

The CI gate runs the committed subset (`cargo test -p solo-conformance`). The full run is opt-in:

```sh
tools/fetch-conformance.sh
cargo run --release -p solo-conformance -- --both --expected crates/solo-conformance/tests/fixtures/expected-failures.txt .conformance/fixtures/state_tests
```

## 5. Calibration

Cost tables are versioned (04 §2, 05 §7). A new version is produced by the calibration procedure:

1. Reference machine: a published cloud instance type and a published bare-metal equivalent, with pinned OS and compiler versions.
2. For each instruction, a microbenchmark executes it in a tight loop under the x86-64 JIT; the median nanoseconds per instruction, divided by the cheapest instruction's figure, rounded up, is its cost.
3. For each host function, the same with representative argument sizes; per-unit costs are fitted by least squares over sizes.
4. The result is a new table version, a conformance vector set pinning it, and an ADR in the codex recording the measurements.

Until the first calibration, table version 1 is in force and marked provisional.

## 6. Coverage rules

- CI fails if line coverage of any `solo-*` crate is below 100%. Lines that genuinely cannot execute are removed, not excluded.
- Every `enum` of errors, statuses, and terminations has a vector per variant.
- Every table row in 02, 04, and 05 has a vector that would fail if the number changed.
- A change to `spec/` without a corresponding vector change fails review.
