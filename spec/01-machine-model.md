# 01 — Machine model

## 1. Overview

A Solo *instance* executes one *module* (03) in isolation. It has sixteen 64-bit general registers, a 32-bit byte-addressed little-endian memory, a gas counter, and a program position. It communicates with the outside world only through *host calls* (05). Execution is deterministic: given the same module, the same initial register arguments, the same memory image, the same gas limit, and the same sequence of host-call results, every conforming implementation produces the same registers, memory, gas remaining, and termination status.

## 2. Registers

| Name | Index | Role under the standard ABI |
|---|---|---|
| `zero` | 0 | Always reads 0. Writes are discarded. |
| `ra` | 1 | Return address |
| `sp` | 2 | Stack pointer |
| `gp` | 3 | Global pointer |
| `tp` | 4 | Thread pointer (unused; preserved) |
| `t0`–`t2` | 5–7 | Temporaries |
| `s0`/`fp`, `s1` | 8–9 | Saved registers |
| `a0`–`a5` | 10–15 | Arguments and return values |

- Every register is 64 bits wide. There are no floating-point registers, no vector registers, and no control or status registers.
- The ABI roles are those of the RISC-V RV64E ILP32E-style calling convention as emitted by stock toolchains for `riscv64imac` with the E register subset; the VM does not enforce them except where host calls (05) specify argument registers.
- At instance start every register is 0 except those the host sets as entrypoint arguments (05 §3) and `sp`, which the host sets to the top of the stack region (§3.2).

## 3. Memory

### 3.1 Address space

- Addresses are 32-bit unsigned integers. The address space is `[0, 2^32)`.
- Registers hold 64-bit values. The *effective address* of every load, store, and instruction-fetch target is the low 32 bits of the computed 64-bit value, zero-extended. The high 32 bits are ignored, never trapped on. A conforming program never relies on this truncation; a correct program links entirely below 4 GiB and the truncation is unobservable to it.
- Memory is little-endian.
- Loads and stores of any width at any alignment are permitted. There is no alignment trap. (Alignment affects gas only through the single access cost in 04; misaligned accesses are not cheaper or dearer.)

### 3.2 Regions

An instance's memory consists of the following regions, each a multiple of the 4096-byte page. Sizes come from the module header (03) and from the host at instantiation.

| Region | Address range | Access | Contents |
|---|---|---|---|
| Null guard | `[0, 0x10000)` | none | Any access traps `MemoryFault`. |
| Read-only data | `[ro_base, ro_base + ro_size)` | read | Copied from the module's `rodata` section. |
| Read-write data | `[rw_base, rw_base + rw_size)` | read, write | Copied from the module's `data` section, followed by `bss_size` zero bytes. |
| Heap | `[heap_base, heap_base + heap_size)` | read, write | Zero-initialised. `heap_size` starts at 0 and grows via the `sbrk` instruction (02) up to `heap_max`. |
| Stack | `[stack_base, stack_top)` | read, write | Zero-initialised. `sp` starts at `stack_top`. |
| Top guard | `[0xFFFF_0000, 2^32)` | none | Any access traps `MemoryFault`. |

- Regions are laid out in the order above with at least one unmapped guard page between consecutive regions. The module header fixes `ro_base`, `rw_base`, `heap_base`, `heap_max`, `stack_base`, and `stack_top`; the loader validates that the layout satisfies this section (03 §6).
- Access to any address not inside a mapped region, or a write to a read-only region, traps `MemoryFault` at the instruction that performed it. The instruction has no other effect. Partial accesses do not occur: a multi-byte access that would cross into an unmapped page traps before writing any byte.
- Code is not in the address space. Instructions are fetched from the module's code section by basic-block index (§4), never by memory address. A program cannot read, write, or jump into its own code bytes through memory. `pc`-relative data addressing emitted by toolchains is resolved by the recompiler (03 §8).

### 3.3 Initial contents

At instance start, `rodata` and `data` are populated from the module, every other mapped byte is 0, and heap size is 0.

## 4. Program position and basic blocks

- A module's code is a sequence of *basic blocks* (03 §4). A block is a sequence of instructions in which only the last instruction may transfer control. Every control transfer target is the first instruction of a block.
- The program position is the pair (block index, instruction offset within the block). It is not addressable by the program. Indirect jumps name a block index through the module's jump table (02 §9), never an arbitrary address.
- Execution begins at the block designated by the invoked export (03 §5).

## 5. Gas

- An instance has a gas counter, a signed 64-bit integer set by the host at instantiation.
- On entry to a basic block the counter is decremented by the block's static cost (04 §2). If the result is negative, the instance traps `OutOfGas` *before executing any instruction of that block*, and the counter is left at the negative value for the host to read.
- Some instructions and all host calls additionally charge dynamic gas (04 §3) at the point of execution; the same rule applies.
- The charge points above are normative. An implementation MAY batch the subtraction (for example, charge several blocks at once in straight-line code) only if the observable outcome, including which block the instance is in when `OutOfGas` is raised and the final counter value, is identical to charging at every block entry.

## 6. Termination

An instance terminates in exactly one of these ways:

| Status | Meaning |
|---|---|
| `Halt` | The program executed the `halt` instruction (02 §10). Return values are in `a0`, `a1`. |
| `OutOfGas` | §5. |
| `Trap` | The program executed the `trap` instruction or an unconditional illegal condition (02). |
| `MemoryFault` | §3.2. |
| `InvalidJump` | An indirect jump named a jump-table slot that is empty (02 §9). |
| `HostError(code)` | A host call returned a terminating error (05 §6). |
| `StepLimit` | Only in debugging and simulation hosts that impose an instruction budget; never in consensus. |

After termination the host may read all registers, the gas counter, and memory. The instance cannot be resumed.

## 7. Determinism and what does not exist

- There is no floating point, no timer, no cycle counter, no random source, no thread, no interrupt, no self-modifying code, and no way to observe the host machine's word size, endianness, or timing.
- Every input to a computation is the module, the initial registers, the initial memory, the gas limit, and host-call results. Every output is registers, memory, gas, and termination status.
- Host calls are synchronous and their results are inputs to determinism: a host that returns different results on different nodes breaks consensus, which is the host's responsibility, not the VM's.

## 8. Capability sets

An instance is instantiated with a *capability set* chosen by the host: `Privileged` (the kernel) or `Sandboxed` (contracts and modules unless a capability grants more). The set determines which host functions are callable (05 §2). The VM itself is identical under both; only the host-call table differs.

## 9. Limits

| Limit | Value |
|---|---|
| Registers | 16 |
| Address space | 2^32 bytes |
| Maximum module code size | 16 MiB |
| Maximum basic blocks per module | 2^24 |
| Maximum jump-table entries | 2^20 |
| Maximum `rodata + data + bss` | 1 GiB |
| Maximum `heap_max + stack` | 2 GiB |
| Call depth | Not a VM concept; the host enforces frame limits across instances |

These limits are part of the spec version and may only be raised in a later minor.
