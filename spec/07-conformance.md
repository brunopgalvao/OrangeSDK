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
- **EVM path.** The EVM interpreter compiled to the VM runs Ethereum's execution spec tests for the target fork through a `t8n`-style adapter; the fixture set and fork are pinned in CI.

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
