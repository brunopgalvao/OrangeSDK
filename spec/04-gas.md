# 04 — Gas

## 1. Overview

Gas bounds the work an instance may do and is the unit the kernel converts into user-facing EVM gas. It is charged in two ways: a *static* cost per basic block, computed at load time from the instruction cost table and charged on every entry to the block, and *dynamic* costs charged at the point of execution by instructions whose work depends on run-time values and by host calls. Gas is a property of the specification: the interpreter and every JIT charge identical amounts, and a conformance vector (07) pins every number in this document.

The unit is the *VM gas unit*. One unit is the static cost of the cheapest instruction. The conversion between VM gas and EVM gas is a kernel fee-schedule parameter, not a VM concern.

## 2. Static cost

The static cost of a block is the sum of the costs of its instructions from Table 2.1, with a minimum of 1. It is charged on block entry as 01 §5 specifies, including re-entry by a loop and entry by fallthrough.

### Table 2.1 — Instruction cost table, version 1

| Instructions | Cost |
|---|---|
| `li`, `addi`, `andi`, `ori`, `xori`, `slti`, `sltiu`, `slli`, `srli`, `srai`, `addiw`, `slliw`, `srliw`, `sraiw` | 1 |
| `add`, `sub`, `and`, `or`, `xor`, `sll`, `srl`, `sra`, `slt`, `sltu`, `addw`, `subw`, `sllw`, `srlw`, `sraw` | 1 |
| `mul`, `mulw` | 3 |
| `mulh`, `mulhsu`, `mulhu` | 4 |
| `div`, `divu`, `rem`, `remu`, `divw`, `divuw`, `remw`, `remuw` | 20 |
| `lb`, `lbu`, `lh`, `lhu`, `lw`, `lwu`, `ld` | 3 |
| `sb`, `sh`, `sw`, `sd` | 3 |
| `jump`, `call`, `beq`, `bne`, `blt`, `bge`, `bltu`, `bgeu` | 2 |
| `jump_indirect`, `call_indirect` | 4 |
| `halt`, `trap` | 1 |
| `ecall` | 10 (plus dynamic, §3.3) |
| `sbrk` | 10 (plus dynamic, §3.1) |
| `memcopy`, `memfill` | 10 (plus dynamic, §3.2) |

The values in version 1 are provisional: they are ratios estimated from the JIT's expected native cost per instruction and will be recalibrated on the published reference machine before mainnet (07 §5). A recalibration produces cost table version 2 and a new fee-schedule version; it never changes the charging rules in this document. Modules are not redeployed when the table changes, because block costs are computed at load.

## 3. Dynamic cost

Dynamic costs are charged immediately before the instruction performs its effect. If the counter would go negative the instance traps `OutOfGas` with no effect from the instruction.

### 3.1 Heap growth
`sbrk` charges `pages × 256`, where `pages` is the number of 4096-byte pages added. A failed `sbrk` (01 §3.2 limits) charges nothing beyond its static cost.

### 3.2 Bulk memory
`memcopy` and `memfill` charge `⌈len / 32⌉ × 1`, where `len` is the byte count. A fault charges the dynamic cost anyway, since the fault is detected after the charge; the instance terminates regardless.

### 3.3 Host calls
Every host function has a *base cost* and may have a *per-unit cost* defined in 05 for that function (per byte read or written, per signature verified, per storage key touched). The VM charges the base cost before transferring to the host. The host charges per-unit costs through the gas counter it is given and MUST do so before performing any effect that cannot be undone. A host function that cannot complete within the remaining gas returns the terminating error `OutOfGas`, and the instance terminates with that status, not `HostError`.

## 4. The gas counter at the boundary

- The host sets the counter at instantiation and reads it at termination. It is a signed 64-bit integer; a limit above 2^62 is rejected by the host.
- The counter is not readable by the program. (A `gasleft`-style query for contracts is a host function in 05 that returns the EVM-gas view, charged like any call; the kernel implements EVM semantics on top.)
- Across nested instances (a contract calling a contract through the host's invoke function), the caller's counter is debited the callee's limit on invoke and credited the callee's unused gas on return, exactly as the host's invoke semantics state in 05. The VM has no notion of nesting.

## 5. Worked example

Block: `addi; ld; add; bne` → static cost `1 + 3 + 1 + 2 = 7`. Each loop iteration re-entering this block charges 7. A `memcopy` of 1000 bytes inside another block charges that block's static cost on entry, then `10` static plus `⌈1000/32⌉ = 32` dynamic at the instruction.

## 6. Rationale, non-normative

Per-block static charging makes gas independent of the backend and removes a decrement from every instruction in the JIT. Loads and stores cost more than arithmetic because the address check and the memory access are the expensive part of a sandboxed JIT. Division is priced near its worst case because a JIT cannot cheaply distinguish fast and slow divisions. Indirect jumps carry the slot lookup and a mispredicted branch. These are starting ratios; the conformance suite exists so that changing them is a measured, versioned act.
