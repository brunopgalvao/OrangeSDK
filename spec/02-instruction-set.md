# 02 — Instruction set

## 1. Scope

This document defines every instruction a Solo module may contain: its encoding, its operands, and its semantics. Semantics are those of RISC-V RV64E plus M wherever an instruction has a RISC-V counterpart; the encoding is Solo's own. Anything not listed here is not an instruction, and a module containing it is invalid at load time (03 §7). Nothing is decided at run time that can be decided at load time.

## 2. Encoding primitives

Instructions are byte sequences. Each begins with a one-byte opcode followed by operands in the order the instruction's row lists them.

| Primitive | Encoding |
|---|---|
| `rA` | One byte. Register index in bits 0–4; bits 5–7 MUST be 0. |
| `s:imm` | Canonical signed LEB128 (SLEB128), at most 10 bytes, value range `[-2^63, 2^63)`. |
| `u:n` | Canonical unsigned LEB128 (ULEB128), at most 5 bytes, value range `[0, 2^32)`. |

*Canonical* means the shortest encoding that represents the value: no continuation byte may be a redundant sign or zero extension. A non-canonical LEB128, a register byte with any of bits 5–7 set, or an opcode not in §11 makes the module invalid (03 §7). Consequently every instruction has exactly one byte representation, and the code hash of a module identifies its program uniquely.

Register indices are 0–31 as defined in 01 §2. Writing register 0 is permitted and has no effect; reading it yields 0.

## 3. Notation

- `R[x]` is the 64-bit value of register `x`. `R[0]` always reads 0.
- `sx32(v)` sign-extends the low 32 bits of `v` to 64 bits. `zx32(v)` zero-extends them.
- `addr(v)` is the effective address: the low 32 bits of `v`, zero-extended (01 §3.1).
- `M[a, n]` is the `n`-byte little-endian value at effective address `a`.
- All arithmetic is two's-complement modulo 2^64 unless stated.
- "Ends the block" means the instruction MUST be the last instruction of its basic block (03 §4). "Falls through" means that if control is not transferred, execution continues at block index + 1.

## 4. Control and system instructions

| Opcode | Mnemonic | Operands | Semantics |
|---|---|---|---|
| `0x00` | `trap` | — | Terminates with status `Trap`. Ends the block. No fallthrough. |
| `0x01` | `halt` | — | Terminates with status `Halt`; `R[a0]`, `R[a1]` are the return values. Ends the block. No fallthrough. |
| `0x02` | `ecall` | `u:import` | Calls host function number `import` of the module's import table (03 §5, 05). Arguments are `R[a0]`–`R[a5]`; results are written to `R[a0]` and `R[a1]`; all other registers are preserved. Charges dynamic gas per 05 before the call. If the host returns a terminating error the instance terminates with `HostError(code)`. Does not end the block. |
| `0x03` | `sbrk` | `rd`, `rs1` | Grows the heap. Let `n = addr(R[rs1])`, rounded up to a multiple of 4096. If `heap_size + n ≤ heap_max`: charges dynamic gas for `n / 4096` pages (04 §3), extends the heap by `n` zero bytes, and sets `R[rd]` to the previous heap end (`heap_base + old heap_size`). Otherwise sets `R[rd] = 0` and changes nothing. `sbrk` with `n = 0` returns the current heap end and charges nothing. |
| `0x04` | `memcopy` | `rdst`, `rsrc`, `rlen` | Copies `addr(R[rlen])` bytes from `addr(R[rsrc])` to `addr(R[rdst])`, as if through a temporary buffer (overlap is safe). Charges dynamic gas per byte (04 §3) before copying. Every source byte must be readable and every destination byte writable or the instruction traps `MemoryFault` with no bytes written. |
| `0x05` | `memfill` | `rdst`, `rval`, `rlen` | Writes the low 8 bits of `R[rval]` to `addr(R[rlen])` bytes starting at `addr(R[rdst])`. Gas and fault rules as `memcopy`. |

## 5. Constants and register–immediate arithmetic

Operands: `rd`, `rs1`, `s:imm` (for `li`: `rd`, `s:imm`).

| Opcode | Mnemonic | Semantics |
|---|---|---|
| `0x10` | `li` | `R[rd] = imm`. Replaces every `lui`/`auipc`/`addi` constant sequence; the recompiler folds them (03 §8). |
| `0x11` | `addi` | `R[rd] = R[rs1] + imm` |
| `0x12` | `andi` | `R[rd] = R[rs1] & imm` |
| `0x13` | `ori` | `R[rd] = R[rs1] \| imm` |
| `0x14` | `xori` | `R[rd] = R[rs1] ^ imm` |
| `0x15` | `slti` | `R[rd] = (signed R[rs1] < imm) ? 1 : 0` |
| `0x16` | `sltiu` | `R[rd] = (unsigned R[rs1] < unsigned imm) ? 1 : 0` (imm is sign-extended then compared unsigned, as in RISC-V) |
| `0x17` | `slli` | `R[rd] = R[rs1] << (imm & 63)` |
| `0x18` | `srli` | `R[rd] = R[rs1] >>ᵤ (imm & 63)` |
| `0x19` | `srai` | `R[rd] = R[rs1] >>ₛ (imm & 63)` |
| `0x1A` | `addiw` | `R[rd] = sx32(R[rs1] + imm)` |
| `0x1B` | `slliw` | `R[rd] = sx32(R[rs1] << (imm & 31))` |
| `0x1C` | `srliw` | `R[rd] = sx32(low32(R[rs1]) >>ᵤ (imm & 31))` |
| `0x1D` | `sraiw` | `R[rd] = sx32(low32(R[rs1]) >>ₛ (imm & 31))` |

For the shift-immediate forms the module is invalid if `imm` is outside `[0, 63]` (`[0, 31]` for W forms); the masks above are stated for completeness and never take effect in a valid module.

## 6. Register–register arithmetic

Operands: `rd`, `rs1`, `rs2`.

| Opcode | Mnemonic | Semantics |
|---|---|---|
| `0x20` | `add` | `R[rd] = R[rs1] + R[rs2]` |
| `0x21` | `sub` | `R[rd] = R[rs1] - R[rs2]` |
| `0x22` | `and` | `R[rd] = R[rs1] & R[rs2]` |
| `0x23` | `or` | `R[rd] = R[rs1] \| R[rs2]` |
| `0x24` | `xor` | `R[rd] = R[rs1] ^ R[rs2]` |
| `0x25` | `sll` | `R[rd] = R[rs1] << (R[rs2] & 63)` |
| `0x26` | `srl` | `R[rd] = R[rs1] >>ᵤ (R[rs2] & 63)` |
| `0x27` | `sra` | `R[rd] = R[rs1] >>ₛ (R[rs2] & 63)` |
| `0x28` | `slt` | `R[rd] = (signed R[rs1] < signed R[rs2]) ? 1 : 0` |
| `0x29` | `sltu` | `R[rd] = (unsigned R[rs1] < unsigned R[rs2]) ? 1 : 0` |
| `0x2A` | `mul` | `R[rd] = low64(R[rs1] × R[rs2])` |
| `0x2B` | `mulh` | `R[rd] = high64(signed R[rs1] × signed R[rs2])` |
| `0x2C` | `mulhsu` | `R[rd] = high64(signed R[rs1] × unsigned R[rs2])` |
| `0x2D` | `mulhu` | `R[rd] = high64(unsigned R[rs1] × unsigned R[rs2])` |
| `0x2E` | `div` | Signed quotient, see §6.1 |
| `0x2F` | `divu` | Unsigned quotient, see §6.1 |
| `0x30` | `rem` | Signed remainder, see §6.1 |
| `0x31` | `remu` | Unsigned remainder, see §6.1 |
| `0x32` | `addw` | `R[rd] = sx32(R[rs1] + R[rs2])` |
| `0x33` | `subw` | `R[rd] = sx32(R[rs1] - R[rs2])` |
| `0x34` | `sllw` | `R[rd] = sx32(R[rs1] << (R[rs2] & 31))` |
| `0x35` | `srlw` | `R[rd] = sx32(low32(R[rs1]) >>ᵤ (R[rs2] & 31))` |
| `0x36` | `sraw` | `R[rd] = sx32(low32(R[rs1]) >>ₛ (R[rs2] & 31))` |
| `0x37` | `mulw` | `R[rd] = sx32(R[rs1] × R[rs2])` |
| `0x38` | `divw` | 32-bit signed quotient of `low32` operands, result sign-extended; §6.1 rules at 32 bits |
| `0x39` | `divuw` | 32-bit unsigned quotient, sign-extended; §6.1 |
| `0x3A` | `remw` | 32-bit signed remainder, sign-extended; §6.1 |
| `0x3B` | `remuw` | 32-bit unsigned remainder, sign-extended; §6.1 |

### 6.1 Division rules

Division never traps. Exactly as RISC-V:

| Case | Quotient | Remainder |
|---|---|---|
| Divisor 0, signed | all ones (−1) | dividend |
| Divisor 0, unsigned | all ones (2^N − 1) | dividend |
| Signed overflow (most negative ÷ −1) | most negative | 0 |

`N` is 64, or 32 for the W forms, in which case the results are sign-extended to 64 bits.

## 7. Loads

Operands: `rd`, `rs1`, `s:off`. Effective address `a = addr(R[rs1] + off)`. Any alignment is permitted. A fault (01 §3.2) leaves `R[rd]` unchanged.

| Opcode | Mnemonic | Semantics |
|---|---|---|
| `0x40` | `lb` | `R[rd] = sx8(M[a, 1])` |
| `0x41` | `lbu` | `R[rd] = zx8(M[a, 1])` |
| `0x42` | `lh` | `R[rd] = sx16(M[a, 2])` |
| `0x43` | `lhu` | `R[rd] = zx16(M[a, 2])` |
| `0x44` | `lw` | `R[rd] = sx32(M[a, 4])` |
| `0x45` | `lwu` | `R[rd] = zx32(M[a, 4])` |
| `0x46` | `ld` | `R[rd] = M[a, 8]` |

## 8. Stores

Operands: `rs1`, `rs2`, `s:off`, where `rs1` is the base and `rs2` the value. Effective address `a = addr(R[rs1] + off)`.

| Opcode | Mnemonic | Semantics |
|---|---|---|
| `0x48` | `sb` | `M[a, 1] = low8(R[rs2])` |
| `0x49` | `sh` | `M[a, 2] = low16(R[rs2])` |
| `0x4A` | `sw` | `M[a, 4] = low32(R[rs2])` |
| `0x4B` | `sd` | `M[a, 8] = R[rs2]` |

## 9. Control transfer

Blocks are numbered from 0 in code-section order (03 §4). The *jump table* (03 §6) is a list of block indices; slot 0 is reserved and always empty. The *slot address* of slot `k` is `8k`. Function pointers and return addresses in a Solo program are slot addresses, never byte addresses; the recompiler assigns a slot to every block whose address is taken and to every call continuation (03 §8).

| Opcode | Mnemonic | Operands | Semantics |
|---|---|---|---|
| `0x50` | `jump` | `u:block` | Transfers control to `block`. Ends the block. No fallthrough. |
| `0x51` | `call` | `rd`, `u:block`, `u:slot` | `R[rd] = 8 × slot`, then transfers control to `block`. `slot` MUST name the block that immediately follows this one in layout (03 §7). Ends the block. No fallthrough. |
| `0x52` | `jump_indirect` | `rs1`, `s:off` | Let `v = addr(R[rs1] + off)`. If `v = 0`, or `v mod 8 ≠ 0`, or `v / 8 ≥ jump-table length`, or slot `v / 8` is empty, terminates with `InvalidJump`. Otherwise transfers control to the block in that slot. Ends the block. No fallthrough. `ret` is `jump_indirect ra, 0`. |
| `0x53` | `call_indirect` | `rd`, `rs1`, `s:off`, `u:slot` | `R[rd] = 8 × slot`, then as `jump_indirect rs1, off` using the value of `R[rs1]` read *before* `rd` is written (they may be the same register). Same continuation rule as `call`. Ends the block. No fallthrough. |
| `0x58` | `beq` | `rs1`, `rs2`, `u:block` | If `R[rs1] = R[rs2]` transfer to `block`, else fall through. Ends the block. |
| `0x59` | `bne` | `rs1`, `rs2`, `u:block` | If `R[rs1] ≠ R[rs2]` … |
| `0x5A` | `blt` | `rs1`, `rs2`, `u:block` | If signed `R[rs1] < R[rs2]` … |
| `0x5B` | `bge` | `rs1`, `rs2`, `u:block` | If signed `R[rs1] ≥ R[rs2]` … |
| `0x5C` | `bltu` | `rs1`, `rs2`, `u:block` | If unsigned `R[rs1] < R[rs2]` … |
| `0x5D` | `bgeu` | `rs1`, `rs2`, `u:block` | If unsigned `R[rs1] ≥ R[rs2]` … |

A branch to its own block, or any jump whose target is the current block, is legal and re-charges the block's static cost on re-entry (01 §5). Every `block` operand MUST be less than the block count, and every `slot` operand MUST be a non-empty jump-table slot; both are checked at load (03 §7).

## 10. Block termination and fallthrough

A block ends after any instruction marked "ends the block", or at the last instruction of the code section, or immediately before an instruction that is the start of the next block in the block table. A block whose last instruction is not a control transfer *falls through*: execution continues at block index + 1, charging that block's static cost on entry. The last block in a module MUST end with a no-fallthrough instruction (03 §7).

## 11. Opcode map

| Range | Use |
|---|---|
| `0x00`–`0x05` | Control and system (§4) |
| `0x10`–`0x1D` | Constants and register–immediate (§5) |
| `0x20`–`0x3B` | Register–register (§6) |
| `0x40`–`0x46` | Loads (§7) |
| `0x48`–`0x4B` | Stores (§8) |
| `0x50`–`0x53`, `0x58`–`0x5D` | Control transfer (§9) |
| `0xC0`–`0xFF` | Reserved for extensions. Spec 0.1 defines none. A module using one is invalid. |
| Everything else | Reserved. A module using one is invalid. |

Extensions planned for a later minor, each behind a feature gate and each additive: 256-bit limb add/sub/mul with carry, a keccak-f[1600] round, and modular multiplication. They will occupy `0xC0` upward and be specified by the same rules as every row above.

## 12. What was deliberately left out, and why

- **`lui`, `auipc`, `jal`, `jalr`**: folded into `li`, `call`, `jump`, and the indirect forms by the recompiler. Code is not addressable, so pc-relative anything has no meaning in a module.
- **Floating point (F, D)**: nondeterminism and spec surface. Toolchains target soft-float.
- **Atomics (A)**: an instance is single-threaded. The recompiler lowers each `amo*` and `lr/sc` to the equivalent plain load, operation, and store, using `tp` as its scratch register; `lr/sc` always succeeds.
- **`fence`, `fence.i`, CSRs, `wfi`, `mret`, and every privileged instruction**: nothing to order, no CSRs exist. The recompiler deletes fences and rejects the rest.
- **Compressed (C)**: an encoding concern of the input ELF; the recompiler expands it. Solo's own encoding is already compact.
- **Immediate-form branches, conditional moves, bit-manipulation (B)**: candidates for a later minor if profiling justifies them. Not in 0.1.
