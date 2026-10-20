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

- `spec/` — the VM, module format, gas, host ABI and driver interface specifications.
- `crates/solo-vm` — reference interpreter, `no_std`-capable, the oracle for every other backend.
- `tools/` — recompiler, conformance runners, differential fuzz harnesses (as they land).
