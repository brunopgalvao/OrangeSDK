# Solo — Claude instructions

Solo is a framework for EVM-compatible solochains: a from-scratch RISC-V derived VM, a host binary shared by every chain, and a governance-upgradeable kernel that includes consensus. Working name; rename pending.

## Rules

- `spec/` is normative. Code that disagrees with the spec is a bug in the code, unless an ADR in the codex changes the spec first.
- Full test coverage is a gate, not a goal: CI fails under 100% line coverage. Every backend is differentially tested against the reference interpreter. Every change to a cost table has a test that pins the number.
- No `unsafe` outside crates whose name ends in `-jit` or `-sandbox`, and there only behind a documented invariant.
- Commit straight to `main`. Commit messages say why. Never mention AI assistance in commits, PRs, or code.
- Dates absolute, never relative.

## Codex reference

The long arc (vision, strategy, decisions, research) lives in the codex at `/Users/bruno/src/projects/solochain/solochain-codex/`. Before shaping the product, read in order: `company/vision.md`, `product/solo/vision.md`, `product/solo/features/README.md`, `product/solo/ideas/README.md`, `decisions/README.md`. Durable insights go back to the codex, not here. Architecture design doc: https://claude.ai/code/artifact/ca8b7b11-96e2-475b-b15f-4c83e7cd7afb

## Layout

- `spec/` — the VM, module format, gas, host ABI, driver interface, reference consensus (08), transport (09), state commitment (10), telemetry (11), threshold certificates (12), kernel upgrades and feature gates (13) and mempool (14) specifications.
- `crates/solo-vm` — reference interpreter, `no_std`-capable, the oracle for every other backend. `crates/solo-jit` — the native backend (AArch64, x86-64), differentially tested against it (spec 07 §4.1).
- `crates/solo-recompile` — RV64 ELF to Solo module. `crates/solo-host` — executor and host ABI. `crates/solo-abi` — codec and shared types. `crates/solo-rlp` — RLP. `crates/solo-trie` — the binary Merkle trie of the state commitment (spec 10). `crates/solo-bls` — threshold BLS, DKG and resharing, finality certificates (spec 12). `crates/solo-upgrade` — kernel upgrade actions, their records and the feature-gate state machine (spec 13).
- `crates/solo-node` — node host (driver loop, mempool (spec 14), queries, kernel switchover and gated host functions) and `Sim`, the in-process multi-node network for consensus tests. `crates/solo-rpc` — Ethereum JSON-RPC. `crates/solo-cli` — the `solo` command.
- `crates/solo-conformance` — Ethereum execution-spec state tests through the recompiler and both backends (spec 07 §4.2); the committed subset and its expected failures live in its `tests/fixtures`.
- `guest/` — separate RISC-V workspace: `solo-guest` runtime, `hello`, the reference `kernel`, and `evm-conformance`, which includes the kernel's `evm.rs`, `state.rs` and `tx.rs` by path. Rebuild fixtures with `tools/build-guest.sh` after touching it; it builds `hello.elf`, `kernel.elf`, `evm-conformance.elf` and, with the `upgrade-test` feature, `kernel_v2.elf`.
- `tools/` — build scripts; `fetch-conformance.sh` and `curate-conformance.py` for the execution-spec fixtures; differential fuzz harnesses as they land.
- `crates/solo-metrics` and `ops/` — telemetry (spec 11) and the alert rules and dashboard over it; a test keeps `ops/` and the spec's metric table in step with what the node exports.
