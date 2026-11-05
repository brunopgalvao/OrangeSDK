# 16 — Kernel modules and native contracts

## 1. Overview

A *kernel module* is an OrangeSDK module (03) that the kernel installs at an address, records with a capability set, initializes, and calls at block boundaries (codex ADR 0009). A *native contract* is an account whose code designates an OrangeSDK module: an EVM message call to it runs the module instead of the EVM interpreter (codex ADR 0004, ADR 0026). Every installed kernel module is also a native contract at its address; a native contract need not be an installed module.

The kernel reaches a module only through the host's `invoke` (05 §4.4), and always *static*: a module never writes storage through the host. It returns its writes in its output, and the kernel applies them. That is what lets a native contract's writes follow the EVM's revert rules exactly without any host function beyond those of 05.

This document specifies the module interface (§2), capabilities (§3), installation and the registry (§4), native contracts (§5), gas (§6) and block hooks (§7) for the reference kernel. The records and constants are in `orange_abi::modules`; the module-side runtime is `guest/orange-module`, and `guest/modules/counter` is the example module.

## 2. Module interface

A module exports `main` (05 §3.1). The kernel invokes it with flags `static` (bit 1) and, for a privileged install's kernel-invoked entries, `privileged` (bit 0) (§3). The input blob is a `ModuleCall`; the output blob, written with `output_write`, is a `ModuleOutput`. Both use the canonical encoding (06 §2).

### 2.1 Input

```
enum ModuleCall {
  0 Init       { arg: bytes }
  1 BeginBlock { height: u64, timestamp_ms: u64 }
  2 EndBlock   { height: u64, timestamp_ms: u64 }
  3 Call       { context: CallContext, data: bytes, pending: vec<Write> }
  4 Query      { data: bytes }
}
struct CallContext { address: [20], caller: [20], value: u128, height: u64, timestamp: u64, is_static: bool }
struct Write       { key: bytes, value: option<bytes> }
```

- `Init` runs once, when the module is installed (§4), with the install's `init` argument.
- `BeginBlock` and `EndBlock` run in every block for a module with the `HOOKS` capability (§7).
- `Call` is a message call from the EVM (§5). `context.address` is the native contract's address, `caller` the EVM caller (`msg.sender`), `value` the wei the call carries (`msg.value`), `height` and `timestamp` (seconds) those of the block, `is_static` whether the call is static. `data` is the calldata. `pending` lists the writes earlier native calls of the same transaction made to this namespace and that still stand (§5.4), oldest first; a later entry for a key overrides an earlier one.
- `Query` serves the `module_query` query method (§4.3); `data` is passed through.

Tags 5 (`Epoch`) and 6 (`Migrate`) are reserved for the remaining entries of ADR 0009. This kernel version never sends them; a module receiving an unknown tag SHOULD trap.

### 2.2 Output

```
struct ModuleOutput { status: u8, data: bytes, writes: vec<Write> }
```

`status` 0 (`RETURN`) is success: `data` is the return data and `writes` the module's storage writes. `status` 1 (`REVERT`) is a revert: `data` is the revert data and `writes` is ignored. The output *counts* only if the module halted (`invoke` status 0), the output decodes exactly as a `ModuleOutput`, `status` is 0 or 1, and every write is *valid*: a key of 1 to 32 bytes for a sandboxed module, whose stored key is the 32-byte namespace followed by it (§2.2), or of 1 to 64 bytes for a privileged one, so that every stored key fits the host's 64-byte limit for full keys, and, unless the value is `None`, a value of at most 65 536 bytes (05 §4.2). Anything else is a *failure*: a trap, running out of gas, a module that does not load, or an output that does not count.

### 2.3 Storage

A module reads its storage with `storage_get` and `storage_iter_*` (05 §4.2). A sandboxed module's keys are behind its namespace, the 32-byte word that holds its address left-padded with zeros (`namespace(a) = 0x00^12 ‖ a`); a privileged module's keys are full keys. A module reads its own writes and the pending writes of §2.1 before host storage; `orange-module`'s `Store` does that.

The kernel applies a write set in order: `Some(v)` sets the stored key to `v`, `None` deletes it. The stored key is `namespace(address) ‖ key` for a sandboxed module and `key` for a privileged one. Two modules at different addresses therefore never share a key, even when they run the same code.

## 3. Capabilities

An install carries a `u64` of capability bits:

| Bit | Name | Grants |
|---|---|---|
| 0 | `HOOKS` | The kernel calls `BeginBlock` and `EndBlock` (§7). |
| 1 | `PRIVILEGED` | `Init`, `BeginBlock` and `EndBlock` run with the host's `Privileged` set, and the write set names full keys. |

Any other bit makes the install fail. `PRIVILEGED` is granted only at genesis (§4.1); a governance install may carry `HOOKS` only (§4.2).

The host enforces the set: a module importing a function outside the set it is invoked under does not load (05 §2, 03 §5.1), and the invoke fails. `Call` and `Query` always run `Sandboxed`, whatever the install's bits, so a module that imports a privileged function cannot be called from the EVM or queried at all.

## 4. Installation and the registry

Installing the module with code hash `h` at address `a` with bits `c` and argument `init`, at height `n`:

1. The module's bytes are at `code/` ‖ `h` (05 §4.4.1).
2. The kernel invokes `Init { arg: init }` as the install's entries run (§3) with 2^24 VM gas (§6.4). If the output does not count or its status is `REVERT`, the install fails and nothing below happens.
3. It applies the write set (§2.3).
4. It stores the designator `0xEF02 ‖ h` (§5.1) under `code/` ‖ `keccak256(designator)` and sets the account's code hash to that hash, keeping its balance and nonce.
5. It records `ModuleRecord { code_hash: h, capabilities: c, installed_at: n }` under `module/` ‖ `a` and inserts `a` into the ascending list of installed addresses under `meta/modules` (a `vec<[20]>`).

Addresses whose first 18 bytes are zero (`0x0000…0000` to `0x0000…FFFF`) are the *system range*: the precompiles and system addresses live there, and no module may be installed there. The kernel itself may make a system address a native contract at genesis without installing a module there, as the bridge of spec 18 does (18 §4).

### 4.1 At genesis

`Genesis::modules` (06 §5) lists `ModuleInstall { address, code_hash, capabilities, init }`. A module's bytes travel as the `code` of the genesis allocation at its address (in `GenesisParams::allocations`), which genesis stores under `code/` ‖ `keccak256(code)` like any predeploy. After the allocations, the kernel installs the modules in list order at height 0. `kernel_init` traps, so the chain cannot start, if for any entry:

- `capabilities` has a bit outside §3;
- `address` is in the system range;
- the account at `address` does not have code hash `code_hash`, or the code is empty or longer than 65 536 bytes (one storage value; a longer allocation never reaches state);
- the install fails (§4, step 2); a sandboxed install of a module that imports a privileged function fails here.

A second entry for an address already installed fails the code-hash check: the account holds the designator by then.

An allocation may also give an account the designator of a module directly; that account is a native contract (§5) with no record, no hooks and no `Init`. Its module must be in state, for instance installed at another address.

`kernel_init` also traps if an allocation that is a native contract, one whose code is a designator or one at the address of a `Genesis::modules` entry, has any non-zero storage slot: slot 0 of a native contract's EVM storage tracks its writes within a transaction (§5.4) and starts every transaction at zero.

The `orange` command reads genesis modules from a `"modules"` array of `{"address", "code", "capabilities", "init"}`, `code` being the module's bytes in hex, and adds the code to the address's allocation (which must not have code of its own).

### 4.2 By governance

The *module address* is `0x0000000000000000000000000000000000005011`. A transaction to it carries an install in its calldata, the Solidity ABI encoding of

```solidity
interface IOrangeModules {
    function install(address target, bytes32 codeHash, uint64 capabilities, bytes calldata init) external; // 0xd38ebbe9
    event ModuleInstalled(address indexed target, bytes32 indexed codeHash, uint64 capabilities);
}
```

Calldata is an install only if it is the canonical encoding a Solidity encoder produces: the address word's high 12 bytes and the `uint64` word's high 24 bytes are zero, the offset word of `init` is 128, `init` is at most 4 096 bytes, padded with zero bytes to a multiple of 32, and nothing follows.

An install is a governance action (spec 13 §9). Under the key track, a transaction to the module address *can run* if it is signed for this chain (a typed transaction, or a legacy one with an EIP-155 chain id), carries no value, its calldata is an install, and its sender is the governance key of spec 13 §1.1, which must be non-zero. Under the stake track no transaction to the module address can run: an install is proposed with `submit(moduleAddress, install(…))` to the governance address, which opens only if the module is in state under `codeHash` or its staged chunks hash to it, freezes that code while the proposal is open (13 §9.3), and is applied, as below, when the passed proposal executes (13 §9.5). Admission rejects a transaction that cannot run with reason 12 (`SYSTEM_ACTION`), at the point spec 13 §2.3 checks the upgrade address. In `kernel_stf_execute_block` one that cannot run changes nothing and gets a failed receipt. One that can run first runs through the EVM as a plain call to the module address (intrinsic gas, fees, nonce); if that succeeded, the install is applied, and the receipt has status 0 with nothing else changed if any check below fails:

- `capabilities` has a bit other than `HOOKS`;
- `target` is in the system range, has code or a non-zero nonce, or has a module record;
- the module's bytes are not in state and the code staged under `codeHash` with the upgrade address's `stage` action (spec 13 §3: chunks from 0 up to the first missing one, concatenated) is empty, longer than 65 536 bytes, or does not hash to `codeHash`; otherwise the kernel stores it under `code/` ‖ `codeHash`;
- the install fails (§4, step 2); code the step before stored is removed again.

On success the receipt (of the transaction, or of the `execute` that ran the proposal) carries the log `ModuleInstalled(target, codeHash, capabilities)` from the module address, and `installed_at` is the block's height. `eth_call` sees only the plain call.

### 4.3 Queries

| Method | Params | Result |
|---|---|---|
| `module` | `[20]` address | status 0 and the `ModuleRecord`; 1 if no module is installed there; 2 for bad params |
| `module_query` | `ModuleQuery { address: [20], data: bytes }` | the module the account's code designates runs `Query { data }` sandboxed with half the VM gas the kernel instance has left: status 0 and the return data; 4 and the revert data on `REVERT`; 5 on failure; 1 if the account's code is no designator; 2 for bad params |

## 5. Native contracts

### 5.1 Designator

A *designator* is the 34 bytes `0xEF 0x02 ‖ code_hash`. An account whose code is exactly a designator is a native contract running the module with that code hash. Code that merely starts with `0xEF02`, or is any other length, is EVM code as before (and `0xEF` is an invalid opcode).

### 5.2 Dispatch

The reference kernel runs revm (Osaka) with its own precompile provider, which revm consults for every message call after the depth check, the call's journal checkpoint and the value transfer, and before running any bytecode. The provider serves the Ethereum precompiles first, by address, then the outbox of spec 17 §2.3, by code address. Otherwise, when the code being called (for a call to an EIP-7702 delegated account, the delegate's code) is a designator, the call is a *native call* and the provider produces its result; revm commits the checkpoint when the result is a success and reverts it otherwise, the value transfer included. In every other case the EVM runs the code.

A native call runs the module only as the account that holds the designator: if the call is a `DELEGATECALL` or `CALLCODE`, or the target account's own code hash is not the designator's (a call to an EIP-7702 account delegating to a native contract), the call fails (§5.3) without running the module.

### 5.3 Call semantics

With `G` the gas the call carries:

1. If `G < 100` (`CALL_GAS`), the call fails.
2. The kernel invokes the module sandboxed and static under `namespace(target)` with `Call { context, data, pending }` (§2.1) and a VM gas limit of `(G − 100) × 20` (§6). For a query (`eth_call`, gas estimation) the limit is at most half the VM gas the kernel instance has left.
3. If the output does not count (§2.2), the call fails.
4. `REVERT`: the call reverts with the output's data and uses `100 + ⌈u / 20⌉` gas, `u` being the module's VM gas used.
5. `RETURN`: if the call is static and the write set is not empty, the call fails. Otherwise its gas is `100 + ⌈u / 20⌉ + write_gas(writes)` (§6.2); if that exceeds `G`, the call fails. Otherwise the writes are recorded (§5.4) and the call returns the output's data.

A call that *fails* is an exceptional halt, as an EVM frame's: it consumes all of `G`, returns no data, and reverts its checkpoint. The caller sees `0` from `CALL` with empty return data, a transaction to the native contract gets receipt status 0.

### 5.4 Storage and reverts

A native contract has no EVM storage of its own: its storage is its namespace (§2.3), and EVM storage reads of it (`eth_getStorageAt`) return zero. The kernel keeps the writes of a transaction's native calls as numbered *batches* (from 1), each naming the batch before it, and uses slot 0 of the native contract's EVM storage inside revm's journal to hold the number of its latest standing batch:

- A native call that returns a non-empty write set appends a batch, naming the contract, whose predecessor is the slot's current value, then sets the slot to the new batch's number through the journal.
- A revert of any frame enclosing the call, the transaction itself included, rolls the slot back with everything else, so the batches *standing* for a contract are the chain that starts at the slot's value at the end of the transaction. The chain ends at a batch of another contract as at 0; genesis keeps the slot at zero (§4.1), so this happens only by mistake, and then never mixes contracts' writes.
- `pending` (§2.1) lists the writes of the standing chain at the time of the call, oldest batch first.
- When the transaction's state is committed, the kernel applies each native contract's standing writes, oldest first, under its namespace, and writes no EVM storage for any native contract; the slot never reaches state. A query commits nothing.

Every write a native call makes is thus kept exactly when the EVM would have kept an `SSTORE` made at the same point.

### 5.5 What the EVM sees

`EXTCODESIZE` of a native contract is 34, `EXTCODEHASH` is `keccak256(designator)` and `EXTCODECOPY` copies the designator; `eth_getCode` returns it. A native contract can hold and receive value like any account. It cannot send transactions (EIP-3607: it has code).

### 5.6 Nesting

EVM code calls native contracts at any depth, and a native call may be made from any frame, including one inside a static call (then with an empty write set). A module cannot call back into the EVM: the host functions it may use reach only OrangeSDK modules, and `invoke` from a static module is static (05 §4.4), so a native contract may invoke other modules for computation but never causes an EVM frame or a write outside its write set. A nested EVM → native → EVM call is therefore not expressible in this kernel version.

### 5.7 Deployment

EIP-3541 rejects new code starting with `0xEF` from `CREATE`, `CREATE2` and creation transactions, and an EIP-7702 authorization only writes `0xEF0100 ‖ address`. A designator therefore enters state only through genesis (§4.1, an install or an allocation's code) or a governance install (§4.2). This kernel version has no way to replace a module at an address; per-module upgrades are the reserved `Migrate` entry's business.

## 6. Gas

Native code is metered in VM gas (04) and charged to the transaction in EVM gas at one fixed rate, so a transaction's gas limit bounds a native call exactly as it bounds EVM execution (ADR 0010).

### 6.1 Constants

| Name | Value | Unit |
|---|---|---|
| `VM_GAS_PER_EVM_GAS` | 20 | VM gas per EVM gas |
| `CALL_GAS` | 100 | EVM gas per native call, before the module runs |
| `WRITE_GAS` | 5 000 | EVM gas per write-set entry |
| `WRITE_WORD_GAS` | 600 | EVM gas per started 32 bytes of an entry's key and value |
| `HOOK_GAS` | 2^24 | VM gas for each `Init` and each hook |

The rate reflects the reference interpreter running the EVM inside the kernel at roughly 20 VM gas per EVM gas of ordinary opcodes (the measurement behind the node's default query budget, 2026-10-20): a native contract pays for the machine work it does at the price the EVM pays for the same work. The values are provisional like the cost tables of 04 and 05 and change only with a new fee-schedule version; a test pins them.

### 6.2 Charges

A native call costs `CALL_GAS + ⌈u / 20⌉ + write_gas` EVM gas, where `u` includes the VM gas `invoke` itself charges the callee (05 §4.4.1) and

```
write_gas(writes) = Σ ( WRITE_GAS + WRITE_WORD_GAS × ⌈(len(key) + len(value)) / 32⌉ )
```

with `len(value) = 0` for a deletion. The `CALL` that reaches the native contract is charged by the EVM as for any account (warm or cold access, value transfer, memory), before the native call's own gas.

### 6.3 Queries

A query's VM budget is host policy (06 §6). A native call made by a query is capped at half the VM gas the kernel instance has left (§5.3), so an `eth_call` with the default gas limit fits the budget; within the cap its result and gas are those of the same call in a block.

### 6.4 Kernel-invoked entries

`Init`, `BeginBlock` and `EndBlock` each run with `HOOK_GAS` VM gas out of the kernel's own budget. They are charged to no one and do not count against the block gas limit; the cap, the static invoke and the per-block order of §7 bound them.

## 7. Block hooks

In `kernel_stf_execute_block`, after recording the block's participation (its evidence and DKG envelopes, 08 §9, 15 §6.2) and before the first transaction, the kernel runs `BeginBlock { height, timestamp_ms }` for every installed module with `HOOKS`, in ascending address order. After the last transaction and before the upgrade bookkeeping of spec 13 and the epoch transition of spec 15 §4, it runs `EndBlock` the same way. A hook that fails, or returns `REVERT`, changes nothing, and the block goes on; a hook that returns applies its write set at once, so later hooks and the block's transactions see it. Hook writes are chain state like any other and are covered by the block's state commitment.

## 8. Rationale (non-normative)

- **Write sets instead of host overlays.** A module invoked non-static would write into the host overlay, which `invoke` commits when the module halts. An enclosing EVM frame that reverts later lives in revm's journal, not in the host, so those writes would survive it. Returning writes and keeping them in batches tied to a journaled slot gives exact EVM revert semantics with the frozen ABI of 05, no new host function, and no gate.
- **The precompile provider.** revm 43 exposes the code being called to its precompile provider, after the checkpoint and value transfer, so dispatching on the code prefix needs no fork of revm and no reserved address range.
- **Code by hash.** Modules live under `code/` ‖ hash, where the kernel already keeps EVM code by `keccak256`, and the module's code hash is its `keccak256` (03 §1), so one store serves both and a module installed twice is stored once.
