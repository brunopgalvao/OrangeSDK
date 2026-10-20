# Solo (working name)

A framework for EVM-compatible solochains.

- One RISC-V derived VM, specified in `spec/` and implemented first as a reference interpreter.
- One host binary for every chain; a chain is a kernel blob plus a genesis file.
- The kernel, including consensus, is upgraded by governance. The host is upgraded by releases behind feature gates.
- Type 2 Ethereum compatibility: standard EVM bytecode, exact gas, full RPC.

Status: spec v0 written; a single-node development chain runs Ethereum legacy transfers end to end, from `eth_sendRawTransaction` to receipts, on the reference kernel. See `spec/README.md`.

## Try it

Run a development chain with Ethereum JSON-RPC on port 8545 and point any wallet, `cast` or an explorer at it:

```sh
cargo run -p solo-cli -- dev --kernel crates/solo-node/tests/fixtures/kernel.elf --genesis examples/genesis.json
cast chain-id --rpc-url http://127.0.0.1:8545
cast balance 0x1a642f0e3c3af545e7acbd38b07251b3990914f1 --rpc-url http://127.0.0.1:8545
```

The genesis address above is the account of the private key `0x01…01` (32 bytes of `0x01`), funded with one million ether. The kernel is a Rust guest compiled to RISC-V and recompiled to a Solo module on start; value transfers work, contracts arrive with the EVM interpreter.

Build everything and run the gates:

```sh
tools/build-guest.sh                      # builds guest/hello and guest/kernel for riscv64imac-unknown-none-elf
cargo run -p solo-recompile -- guest/target/riscv64imac-unknown-none-elf/release/hello hello.solo
cargo test --workspace                    # includes running the recompiled guests on the interpreter
cargo llvm-cov --workspace --fail-under-lines 100
```

## Layout

- `spec/` — normative specification (machine model, instruction set, module format, gas, host ABI, driver interface, conformance).
- `crates/solo-vm` — reference interpreter, `no_std`-capable, the oracle for every other backend.
- `crates/solo-recompile` — turns a linked RV64 ELF into a Solo module.
- `crates/solo-host` — module cache, storage overlays, the host ABI and the executor that runs modules.
- `crates/solo-abi` — the canonical codec and the types shared by host and kernel (spec 06 and the reference chain records).
- `crates/solo-rlp` — Ethereum RLP.
- `crates/solo-node` — the node host: privileged functions, the driver loop, mempool, queries.
- `crates/solo-rpc` — Ethereum JSON-RPC over a node, with a minimal HTTP server.
- `crates/solo-cli` — the `solo` command (`solo dev`).
- `guest/` — separate workspace for programs that run on the VM: the `solo-guest` runtime, `hello`, and the reference `kernel`.
- `examples/` — a genesis file for `solo dev`.
- `tools/` — build scripts.
