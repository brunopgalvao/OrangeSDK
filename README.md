# Solo (working name)

A framework for EVM-compatible solochains.

- One RISC-V derived VM, specified in `spec/` and implemented first as a reference interpreter.
- One host binary for every chain; a chain is a kernel blob plus a genesis file.
- The kernel, including consensus, is upgraded by governance. The host is upgraded by releases behind feature gates.
- Type 2 Ethereum compatibility: standard EVM bytecode, exact gas, full RPC.

Status: spec v0 written; the reference kernel runs Simplex BFT consensus (spec 08) across validators connected over TCP (spec 09), with catch-up sync for nodes that fall behind, view synchronization for validators that drift into different views, and equivocation evidence recorded in chain state. Each block header commits to the state through a binary Merkle trie whose entries can be proven (spec 10). Ethereum transactions (legacy, EIP-2930 and EIP-1559) run on revm at the Osaka fork inside the kernel: contract creation, calls, storage, logs, reverts and precompiles are tested end to end through the node (`crates/solo-node/tests/evm.rs`). The JSON-RPC serves what wallets, `cast`, ethers, viem and explorers use: receipts with logs, `eth_call` and gas estimation, code and storage, log filters, fee history. See `spec/README.md`.

## Try it

Run a development chain with Ethereum JSON-RPC on port 8545 and point any wallet, `cast` or an explorer at it:

```sh
cargo run -p solo-cli -- dev --kernel crates/solo-node/tests/fixtures/kernel.elf --genesis examples/genesis.json
cast chain-id --rpc-url http://127.0.0.1:8545
cast balance 0x1a642f0e3c3af545e7acbd38b07251b3990914f1 --rpc-url http://127.0.0.1:8545
```

The genesis address above is the account of the private key `0x01…01` (32 bytes of `0x01`), funded with one million ether. The kernel is a Rust guest compiled to RISC-V and recompiled to a Solo module on start; it executes the EVM (revm) inside the Solo VM, so contracts deploy and run as on Ethereum:

```sh
KEY=0x0101010101010101010101010101010101010101010101010101010101010101
RPC=http://127.0.0.1:8545
# Deploy the test contract (crates/solo-node/tests/fixtures/Counter.sol) with a starting count of 5.
cast send --private-key $KEY --rpc-url $RPC --create "$(cat crates/solo-node/tests/fixtures/Counter.bin)$(cast abi-encode 'f(uint256)' 5 | cut -c3-)"
COUNTER=$(cast compute-address 0x1a642f0e3c3af545e7acbd38b07251b3990914f1 --nonce 0 | awk '{print $NF}')
cast send --private-key $KEY --rpc-url $RPC $COUNTER 'increment(uint256)' 2
cast call $COUNTER 'count()(uint256)' --rpc-url $RPC
cast logs --address $COUNTER --from-block 0 --rpc-url $RPC
```

The node keeps the state of the head block only: state methods (`eth_getBalance`, `eth_call`, ...) answer for the head and refuse an older block rather than answer from the wrong state. Requests run on the thread that drives consensus, so each kernel query runs within a budget (`--query-gas`, 2^26 VM gas by default) and long requests (batches, gas estimation, log scans) let the node poll its peers and tick between their steps.

An `alloc` entry is either a balance in wei (a decimal string, `0x` hex, or a JSON number) or a geth-style account, which is how a chain predeploys contracts at genesis:

```json
"alloc": {
  "0x1a642f0e3c3af545e7acbd38b07251b3990914f1": "1000000000000000000000000",
  "0x4200000000000000000000000000000000000001": {
    "balance": "0x0",
    "nonce": "0x1",
    "code": "0x<runtime bytecode>",
    "storage": {"0x00": "0x2a"}
  }
}
```

Every field of an account is optional. Storage keys and values are hex of at most 32 bytes, left-padded with zeros. The kernel stores the code under its `keccak256` hash and the non-zero slots under the account, exactly as if a transaction had deployed it. An account with storage needs code or a non-zero nonce: a contract creation could land on any other account, and the kernel does not apply EIP-7610, so it refuses such a genesis rather than let old slots show through a new contract. Code is run the way geth runs it: `0xef0100` followed by an address is an EIP-7702 delegation, and an account with that code, or none, can send transactions; any other code is legacy bytecode, even when it starts with `0xef`.

The reference kernel's base fee is zero and its block beneficiary is the zero address, so every fee, `gas used × price paid`, is credited to `0x0000…0000`, where no one can spend it. The genesis block has no header and its hash is zero: block 1's parent hash, `BLOCKHASH(0)` and the RPC's block 0 all say so.

Run a chain of several validators, each with its own key. `solo key` prints the validator id to list in the genesis file:

```sh
solo key 5151515151515151515151515151515151515151515151515151515151515151
# genesis.json: {"chainId": 1337, "slotMs": 400, "alloc": {...}, "validators": ["0x<id 1>", "0x<id 2>", ...]}
solo node --kernel kernel.elf --genesis genesis.json --key <seed 1> --listen 127.0.0.1:30301 --rpc 127.0.0.1:8545
solo node --kernel kernel.elf --genesis genesis.json --key <seed 2> --listen 127.0.0.1:30302 --rpc 127.0.0.1:8546 --peer 127.0.0.1:30301
```

A node without `--key` follows the chain as an observer. A node that falls behind syncs the finalized blocks it missed from its peers.

Build everything and run the gates:

```sh
tools/build-guest.sh                      # builds guest/hello and guest/kernel for riscv64imac-unknown-none-elf
cargo run -p solo-recompile -- guest/target/riscv64imac-unknown-none-elf/release/hello hello.solo
cargo test --workspace                    # includes running the recompiled guests on the interpreter
cargo llvm-cov --workspace --fail-under-lines 100
```

## Layout

- `spec/` — normative specification (machine model, instruction set, module format, gas, host ABI, driver interface, conformance, consensus, transport, state commitment).
- `crates/solo-vm` — reference interpreter, `no_std`-capable, the oracle for every other backend.
- `crates/solo-recompile` — turns a linked RV64 ELF into a Solo module.
- `crates/solo-host` — module cache, storage overlays, the host ABI and the executor that runs modules.
- `crates/solo-abi` — the canonical codec and the types shared by host and kernel (spec 06 and the reference chain records).
- `crates/solo-rlp` — Ethereum RLP.
- `crates/solo-trie` — the binary Merkle trie of the state commitment (spec 10), with inclusion and exclusion proofs, `no_std`.
- `crates/solo-bls` — threshold BLS over BLS12-381: the DKG and resharing, finality certificates and their Ethereum verification inputs (spec 12), `no_std`.
- `crates/solo-node` — the node host: privileged functions (including `sign`), the driver loop, mempool, queries, the TCP transport, and `Sim`, an in-process network of nodes with a virtual clock.
- `crates/solo-rpc` — Ethereum JSON-RPC over a node, with a minimal HTTP server.
- `crates/solo-cli` — the `solo` command (`solo dev`, `solo node`, `solo key`).
- `guest/` — separate workspace for programs that run on the VM: the `solo-guest` runtime, `hello`, and the reference `kernel`.
- `examples/` — a genesis file for `solo dev`.
- `tools/` — build scripts.
