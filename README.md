# Solo (working name)

A framework for EVM-compatible solochains.

- One RISC-V derived VM, specified in `spec/` and implemented first as a reference interpreter.
- One host binary for every chain; a chain is a kernel blob plus a genesis file.
- The kernel, including consensus, is upgraded by governance. The host is upgraded by releases behind feature gates.
- Type 2 Ethereum compatibility: standard EVM bytecode, exact gas, full RPC.

Status: spec v0 written; the reference kernel runs Simplex BFT consensus (spec 08) across validators connected over TCP (spec 09), with catch-up sync for nodes that fall behind. Ethereum legacy transfers work end to end, from `eth_sendRawTransaction` to receipts. See `spec/README.md`.

## Try it

Run a development chain with Ethereum JSON-RPC on port 8545 and point any wallet, `cast` or an explorer at it:

```sh
cargo run -p solo-cli -- dev --kernel crates/solo-node/tests/fixtures/kernel.elf --genesis examples/genesis.json
cast chain-id --rpc-url http://127.0.0.1:8545
cast balance 0x1a642f0e3c3af545e7acbd38b07251b3990914f1 --rpc-url http://127.0.0.1:8545
```

The genesis address above is the account of the private key `0x01…01` (32 bytes of `0x01`), funded with one million ether. The kernel is a Rust guest compiled to RISC-V and recompiled to a Solo module on start; value transfers work, contracts arrive with the EVM interpreter.

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

- `spec/` — normative specification (machine model, instruction set, module format, gas, host ABI, driver interface, conformance).
- `crates/solo-vm` — reference interpreter, `no_std`-capable, the oracle for every other backend.
- `crates/solo-recompile` — turns a linked RV64 ELF into a Solo module.
- `crates/solo-host` — module cache, storage overlays, the host ABI and the executor that runs modules.
- `crates/solo-abi` — the canonical codec and the types shared by host and kernel (spec 06 and the reference chain records).
- `crates/solo-rlp` — Ethereum RLP.
- `crates/solo-node` — the node host: privileged functions (including `sign`), the driver loop, mempool, queries, the TCP transport, and `Sim`, an in-process network of nodes with a virtual clock.
- `crates/solo-rpc` — Ethereum JSON-RPC over a node, with a minimal HTTP server.
- `crates/solo-cli` — the `solo` command (`solo dev`, `solo node`, `solo key`).
- `guest/` — separate workspace for programs that run on the VM: the `solo-guest` runtime, `hello`, and the reference `kernel`.
- `examples/` — a genesis file for `solo dev`.
- `tools/` — build scripts.
