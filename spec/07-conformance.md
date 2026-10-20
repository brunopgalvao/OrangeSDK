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
- **Backend against interpreter.** Every JIT backend is fuzzed against the interpreter on generated modules, comparing termination status, all registers, gas remaining, and a digest of memory. A mismatch is a release blocker for the backend.
- **Recompiler determinism.** Two runs over the corpus on different hosts must produce identical bytes.
- **EVM path.** The EVM interpreter compiled to the VM runs Ethereum's execution spec tests for the target fork through a `t8n`-style adapter; the fixture set and fork are pinned in CI.

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
