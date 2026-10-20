# 03 — Module format

## 1. Overview

A *module* is the unit of deployable code: a kernel, a kernel module, a native contract, or the EVM interpreter itself. It is a byte string with a fixed header and a sequence of sections. The loader validates it completely (§7) before anything executes; a module that fails any rule is rejected as a whole and never runs. A valid module's behaviour is fully determined by this specification.

The *code hash* of a module is `keccak256` of its entire byte string, including any debug section. Builders strip debug sections before deployment.

## 2. Header

| Offset | Size | Field | Value |
|---|---|---|---|
| 0 | 4 | magic | ASCII `SOLO` (`0x53 0x4F 0x4C 0x4F`) |
| 4 | 1 | spec major | `0` |
| 5 | 1 | spec minor | `1` |
| 6 | 2 | flags | Reserved, MUST be 0 |

A loader MUST reject a module whose major differs from its own or whose minor is greater than its own. A later minor loader MUST accept every valid earlier-minor module unchanged.

## 3. Sections

The header is followed by sections, each encoded as:

```
u8   id
u:n  length        canonical ULEB128, byte length of payload
[]   payload
```

Sections MUST appear in strictly increasing `id` order, at most once each. The required sections are 1, 6, and 7; others are optional. An `id` not listed below makes the module invalid, except `0x7F`.

| id | Name | Required | Contents |
|---|---|---|---|
| 1 | Memory layout | yes | §3.1 |
| 2 | Read-only data | no | Raw bytes copied to `[ro_base, ro_base + ro_size)` |
| 3 | Data | no | Raw bytes copied to `[rw_base, rw_base + data_size)` |
| 4 | Imports | no | §5 |
| 5 | Exports | no | §5 |
| 6 | Jump table | yes | §6 |
| 7 | Code | yes | §4 |
| 0x7F | Debug | no | Opaque to the VM. Ignored by consensus except through the code hash. |

### 3.1 Memory layout section

Nine little-endian `u32` values, in this order: `ro_base`, `ro_size`, `rw_base`, `data_size`, `bss_size`, `heap_base`, `heap_max`, `stack_base`, `stack_top`. Rules are in §7.2. `rw_size` in 01 §3.2 is `data_size + bss_size`.

## 4. Code section and basic blocks

The code section is a sequence of blocks:

```
u:n  block_count
repeat block_count times:
  u:n  byte_length          canonical ULEB128, > 0
  []   instructions         exactly byte_length bytes
```

Blocks are numbered from 0 in order. Within a block, instructions are decoded consecutively per 02 §2 and MUST exactly fill `byte_length`; a block whose last instruction overruns or underruns its length is invalid. Only the last instruction of a block may be one that "ends the block" (02); an ends-the-block instruction anywhere else is invalid. A block may end with a non-terminating instruction, in which case it falls through (02 §10). The final block MUST end with a no-fallthrough instruction.

Block boundaries carry no cost information. The loader computes each block's static gas from the instruction cost table of the active fee schedule (04 §2) at load time, so a module never has to be redeployed when a cost table changes.

## 5. Imports and exports

### 5.1 Imports

```
u:n  import_count
repeat import_count times:
  u:n   name_length
  []    name                 ASCII, [A-Za-z0-9_], 1..64 bytes
```

Import `i` is the host function with that `name` in the host ABI (05). `ecall u:import` refers to this index. At load the host resolves every name; an unknown name, or a name outside the instance's capability set (01 §8), is a load failure, so a module never discovers a missing host function at run time. Names MUST be unique within the table.

### 5.2 Exports

```
u:n  export_count
repeat export_count times:
  u:n   name_length
  []    name                 ASCII, [A-Za-z0-9_], 1..64 bytes
  u:n   block                entry block index
```

An export names a block at which the host may start execution. Names MUST be unique. The entrypoints a kernel, module, or contract must export are defined by the host ABI (05 §3) and the driver interface (06), not by this document.

## 6. Jump table

```
u:n  slot_count              ≥ 1
repeat slot_count times:
  u:n  block_plus_one        0 = empty slot; otherwise block index + 1
```

Slot 0 MUST be empty. Slot `k` has slot address `8k` (02 §9). The table exists so that every indirect control transfer in a module is to a block the loader has already validated; it is the only mechanism by which a computed value becomes a control-flow target.

## 7. Validation

A loader MUST check every rule below and reject the module on the first failure. The checks are listed so that each depends only on earlier ones; an implementation may order them differently if it rejects the same set of modules.

### 7.1 Structure
1. Header magic and version (§2); flags are 0.
2. Sections in increasing id order, no duplicates, no unknown ids except `0x7F`, each `length` canonical and exactly consumed; no trailing bytes after the last section.
3. Required sections present.
4. Total module length ≤ 16 MiB + sections 2 and 3 sizes, and code section payload ≤ 16 MiB (01 §9).

### 7.2 Memory layout
5. All nine values are multiples of 4096 except `ro_size`, `data_size`, `bss_size`, which are arbitrary (the loader rounds the end of each region up to a page).
6. `ro_base ≥ 0x10000`. Regions appear in the order ro, rw, heap, stack with at least one unmapped 4096-byte page between the rounded end of each and the base of the next. `stack_top ≤ 0xFFFF_0000`. `stack_base < stack_top`. `heap_base + heap_max ≤ stack_base − 4096`.
7. Section 2 length equals `ro_size`; section 3 length equals `data_size`. A missing section 2 or 3 requires the corresponding size to be 0.
8. `ro_size + data_size + bss_size ≤ 1 GiB`; `heap_max + (stack_top − stack_base) ≤ 2 GiB`.

### 7.3 Imports and exports
9. Import and export names well-formed and unique; every import resolves in the host's table for the instance's capability set.

### 7.4 Jump table
10. `slot_count ≥ 1`, `slot_count ≤ 2^20`, slot 0 empty, every non-empty slot names a block `< block_count`.

### 7.5 Code
11. `1 ≤ block_count ≤ 2^24`; every `byte_length > 0`.
12. Every instruction decodes per 02 §2 with a listed opcode, canonical LEB128 operands, register bytes with bits 5–7 clear, shift immediates in range, and the block's bytes are exactly consumed.
13. Only the last instruction of a block ends the block; the last block ends with a no-fallthrough instruction.
14. Every `u:block` operand `< block_count`. Every `u:slot` operand names a non-empty slot. Every `call` and `call_indirect` slot names block index (current block + 1).
15. Every `u:import` operand `< import_count`.
16. Every export block `< block_count`.

### 7.6 Cost
17. Each block's static cost computed from the active instruction cost table (04 §2) fits in a signed 64-bit integer; the sum over all blocks fits as well.

A module passing all checks is *valid for this spec minor and this cost-table version*. Validity never depends on the host machine.

## 8. The recompiler

The recompiler turns a standard RV64 ELF, produced by a stock toolchain for the `riscv64imac` target with soft-float and linked with `--emit-relocs` so that every code-address constant is identifiable, into a valid module. Its behaviour is normative where it affects semantics:

1. **Block discovery.** Every instruction that is the target of any direct branch or jump, the instruction after every `jal`/`jalr`, every function entry, and every address-taken location starts a block. Blocks are emitted in address order.
2. **Constants.** `lui`, `auipc`, and `addi` chains forming a constant or an address of a data symbol fold into `li` with the absolute address. Addresses of code symbols fold into `li` of the symbol's slot address.
3. **Direct control.** `jal rd, L` becomes `call rd, block(L), slot(next)` when `rd ≠ zero`, else `jump block(L)`. Conditional branches map one-to-one; a branch with an immediate-zero comparison uses register `zero`.
4. **Indirect control.** `jalr rd, rs1, off` becomes `call_indirect rd, rs1, off, slot(next)` when `rd ≠ zero`, else `jump_indirect rs1, off`. Every block whose address escapes (function pointers, return continuations, jump-table targets from `switch` lowering) is assigned a jump-table slot; the recompiler rewrites every code-address constant to the slot address.
5. **Host calls.** A call to a symbol named `__solo_import_<name>` is replaced by `ecall i` where `i` is the index of `<name>` in the import table the recompiler builds; the arguments are already in `a0`–`a5` by the C calling convention.
6. **Memory intrinsics.** Calls to `memcpy`, `memmove`, and `memset` with the standard signature MAY be replaced by `memcopy` and `memfill`.
7. **Removed.** `fence`, `fence.i`, and `nop`-equivalents are deleted. `ebreak`, `unimp`, and any illegal instruction become `trap`. Compressed instructions are expanded first.
8. **Atomics.** `amo<op>.{w,d}` becomes load, op, store on the same address; `lr` becomes a load and `sc` becomes a store that writes 0 (success) to its destination.
9. **Rejected.** Floating-point instructions, CSR access, privileged instructions, and any ELF relocation the recompiler cannot resolve statically make the input unconvertible.
10. **Layout.** `rodata`, `data`, and `bss` are placed per §3.1 with `ro_base = 0x10000` unless the linker script says otherwise; the recompiler rejects a layout violating §7.2.

Two conforming recompilers given the same ELF MUST produce byte-identical modules. The recompiler is therefore part of the conformance suite (07).
