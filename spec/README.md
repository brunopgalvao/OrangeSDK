# Solo specification, version 0.1 (draft)

This directory is normative. An implementation that disagrees with it is wrong; a spec change requires an ADR in the codex first.

## Documents

| # | Document | Status |
|---|---|---|
| 01 | [Machine model](01-machine-model.md) — registers, memory, execution state, determinism, traps | draft |
| 02 | [Instruction set](02-instruction-set.md) — semantics and encoding of every instruction | draft |
| 03 | [Module format](03-module-format.md) — container, sections, basic-block table, validation | draft |
| 04 | [Gas](04-gas.md) — the instruction cost table, dynamic charges, the out-of-gas point | draft |
| 05 | [Host ABI](05-host-abi.md) — the frozen interface between host and kernel, and the sandboxed subset for contracts | draft |
| 06 | [Driver interface](06-driver-interface.md) — inputs and effects of the consensus state machine, kernel versions and the switchover between kernels | draft |
| 07 | [Conformance](07-conformance.md) — test vectors, differential oracles, coverage requirements | draft |
| 08 | [Simplex driver](08-simplex-driver.md) — the reference kernel's consensus: views, stake-weighted votes, epochs, view synchronization, vote and threshold certificates, equivocation evidence, persistence | draft |
| 09 | [Peer-to-peer transport](09-p2p.md) — TCP framing, handshake, mapping between frames and driver inputs and effects | draft |
| 10 | [State commitment](10-state-commitment.md) — the binary Merkle trie behind `storage_commit`, its proofs and their verification | draft |
| 11 | [Telemetry](11-telemetry.md) — metrics endpoint and names, emitted metrics, status document, alert and health semantics | draft |
| 12 | [Threshold certificates](12-threshold-certificates.md) — threshold BLS over BLS12-381, the DKG and resharing, the finality certificate (versions 1 and 2), the rotation message, and their verification on Ethereum | draft |
| 13 | [Kernel upgrades and feature gates](13-upgrades.md) — the upgrade address and its actions, the upgrade timeline, feature-gate signalling, lock-in and activation | draft |
| 14 | [Mempool](14-mempool.md) — host policy: per-sender nonce queues, pending and queued, replacement, limits and eviction, the block-ordered take, gossip | draft |
| 15 | [Staking, epochs, slashing and the threshold key](15-staking.md) — the staking address, epochs and validator sets, slashing for equivocation and threshold misbehaviour, the DKG runs for a fresh key each epoch, their messages in blocks, key-set adoption, handoffs from one key to the next, key age and unbonding, the host's threshold keystore | draft |
| 16 | [Kernel modules and native contracts](16-modules.md) — the module interface, capabilities, genesis and governance installs, block hooks, native contracts called from the EVM (`0xEF02` designators), the native gas rate | draft |
| 17 | [Bridge to Ethereum](17-bridge-out.md) — the outbox system address and its messages in state, the proposal anchor that certificates vouch for, the Ethereum light clients (a fixed key, and a rotating key with a trusting period) and inbox with delay, rate limits, guardian and owner, relaying, the `finality_proof` and `handoff` queries and the `solo_getFinalityProof`, `solo_getOutboxProof` and `solo_getRotation` RPC methods | draft |
| 18 | [Ethereum to Solo](18-bridge-in.md) — the sync-committee light client of Ethereum, the outbox on Ethereum, message proofs, the message verifier and the inbox, delay, rate limit and pause, admission | draft |
| 19 | [Precompiles and kernel gas](19-precompiles.md) — kernel gas per EVM gas of every precompile and ordinary operation, the bound, the precompile host functions behind gate 2 and the module that reaches them, `KECCAK256` and `BLOCKHASH`, the per-block budget before the gate, the kernel gas of a block | draft |
| 20 | [Ethereum surface](20-ethereum-surface.md) — the transaction types accepted (EIP-7702 set-code transactions, not blob ones), Ethereum block headers whose hash is the block hash, Merkle-Patricia transactions and receipts roots, `eth_getProof` with spec 10 proofs, historical state within a retention window | draft |
| 21 | [Canonical token bridge](21-token-bridge.md) — the token gateways on Ethereum and on Solo over the message channels of 17 and 18, native and wrapped tokens, the wrapped token's `CREATE2` address, deposits, mints, burns and releases, owed releases, caps, pause, refused tokens, the value invariant | draft |

## Conventions

- **MUST / MUST NOT / SHOULD / MAY** are used as in RFC 2119.
- Numbers are decimal unless prefixed `0x`. Bit 0 is the least significant bit.
- A *trap* ends execution of the current instance with a status code; traps are never recoverable from inside the instance.
- "Implementation-defined" never appears in this spec. Every observable behaviour is specified; anything not specified is a defect in the spec, to be fixed by an ADR, not by an implementation choosing.

## Versioning

The spec version is `major.minor`. A module declares the spec version it targets in its header. Within a major version, later minors only add instructions, host functions, or sections; they never change the meaning of anything a valid earlier module could contain. Deployed modules therefore run unchanged forever within a major version. There is no plan for a second major version.

## Relationship to RISC-V

Instruction *semantics* are those of RISC-V RV64I base plus the M extension, restricted and clarified as this spec states (no floating point, no CSRs, no fences, atomics lowered to plain memory operations). Instruction *encoding* and the *program container* are Solo's own. A post-link recompiler translates standard RV64 ELF produced by stock toolchains into the Solo module format. Because semantics are preserved, riscv-tests, the Sail model, and QEMU remain conformance oracles through the recompiler.
