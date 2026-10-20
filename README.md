# Solo (working name)

A framework for EVM-compatible solochains.

- One RISC-V derived VM, specified in `spec/` and implemented first as a reference interpreter.
- One host binary for every chain; a chain is a kernel blob plus a genesis file.
- The kernel, including consensus, is upgraded by governance. The host is upgraded by releases behind feature gates.
- Type 2 Ethereum compatibility: standard EVM bytecode, exact gas, full RPC.

Status: spec v0 written; reference interpreter, guest toolchain and recompiler working. See `spec/README.md`.

## Try it

```sh
tools/build-guest.sh                      # builds guest/hello for riscv64imac-unknown-none-elf
cargo run -p solo-recompile -- guest/target/riscv64imac-unknown-none-elf/release/hello hello.solo
cargo test --workspace                    # includes running the recompiled hello guest on the interpreter
cargo llvm-cov --workspace --fail-under-lines 100
```

## Layout

- `spec/` — normative specification (machine model, instruction set, module format, gas, host ABI, driver interface, conformance).
- `crates/solo-vm` — reference interpreter, `no_std`-capable, the oracle for every other backend.
- `crates/solo-recompile` — turns a linked RV64 ELF into a Solo module.
- `guest/` — separate workspace for programs that run on the VM: the `solo-guest` runtime and `hello`.
- `tools/` — build scripts.
