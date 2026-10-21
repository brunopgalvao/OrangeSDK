# Solo (working name)

A framework for EVM-compatible solochains.

- One RISC-V derived VM, specified in `spec/` and implemented first as a reference interpreter.
- One host binary for every chain; a chain is a kernel blob plus a genesis file.
- The kernel, including consensus, is upgraded by governance. The host is upgraded by releases behind feature gates.
- Type 2 Ethereum compatibility: standard EVM bytecode, exact gas, full RPC.

Status: spec v0 written; the reference kernel runs Simplex BFT consensus (spec 08) across validators connected over TCP (spec 09), with catch-up sync for nodes that fall behind, view synchronization for validators that drift into different views, and equivocation evidence recorded in chain state. Votes are weighed by stake; with staking enabled, validators bond and unbond through a system address, the set of each epoch is decided at the end of the one before, recorded equivocation slashes the offender once and removes it from the next set, and the validators of each epoch generate a fresh threshold BLS key whose 97-byte certificates replace vote lists in `FinalizeBlock`; the old key hands off to the new one with a signed rotation, a key is trusted by light clients for a bounded number of epochs that unbonding outlasts, and a shareholder that signs a false anchor, a false rotation or with a key already handed off is slashed once (spec 15). Each block header commits to the state through a binary Merkle trie whose entries can be proven (spec 10). Ethereum transactions (legacy, EIP-2930, EIP-1559 and EIP-7702 set-code) run on revm at the Osaka fork inside the kernel: contract creation, calls, storage, logs, reverts and precompiles are tested end to end through the node (`crates/solo-node/tests/evm.rs`). The same EVM code, recompiled and run on the VM, passes Ethereum's execution-spec state tests for Osaka except those with blob transactions, which the kernel does not accept (spec 07 §4.2). Every block has an Ethereum header whose hash is the block hash, with Merkle-Patricia transactions and receipts roots and a logs bloom, so tools that verify headers and receipts work; the state root stays Solo's binary trie, and `eth_getProof` answers with its proofs (spec 20). The JSON-RPC serves what wallets, `cast`, ethers, viem and explorers use: receipts with logs, `eth_call` and gas estimation, code and storage, log filters, fee history. A running chain upgrades its kernel by governance at an activation height, every node switching at the same block, and host behaviour activates behind stake-signalled feature gates (spec 13). Kernel modules, Solo modules installed at genesis or by governance with a capability set, run block hooks, and every module is also a native contract: an account whose code is `0xEF02 ‖ code hash` runs that module when Solidity calls it, with EVM revert semantics and gas (spec 16). Any account or contract sends a message to Ethereum through the outbox at `0x…4f42`; each proposal anchors an executed state root that the threshold certificate vouches for, so a light client on Ethereum that follows the chain's key handoffs stores Solo state roots and an inbox there proves and delivers each message once, after a delay and within rate limits (spec 17). Messages cross from Ethereum through a sync-committee light client of the beacon chain, which anyone keeps current with ordinary transactions once feature gate 1 activates its signature check: a contract calls `EthereumOutbox.send` on Ethereum, and once the light client holds a finalized state root that stores the message, anyone delivers it to its recipient on Solo with the `eth_getProof` output, exactly once, after a delay, within a rate limit and unless paused (spec 18). The bn254, KZG, modexp, BLAKE2F and BLS12-381 precompiles run on the host once feature gate 2 is active, so no precompile costs the kernel more than 256 VM gas per EVM gas, at Ethereum's gas; before the gate, those still costlier in the guest draw on a per-block budget that bounds every block's kernel gas (spec 19). A canonical token bridge rides on both channels: a gateway on each side locks its chain's tokens (ETH, Solo's own currency, ERC-20s) and the paired gateway mints them as wrapped tokens at addresses anyone computes, burning them releases the locked tokens, with per-token caps, a pause, refusal of unlisted and fee-taking tokens, and releases that fail kept owed until claimed (spec 21). See `spec/README.md`.

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

The mempool works as geth's does (spec 14): an account can have many transactions waiting, so `cast send` twice in a row, `forge script` and batch senders work without waiting for blocks. A transaction whose nonce is ahead of the account waits, queued, until the nonces before it arrive; a block takes each account's transactions in nonce order; a transaction replaces the waiting one with the same nonce only if it raises both fee fields by 10% and the account can still pay for the ones behind it. A transaction over 128 KiB is refused, as geth refuses it. `eth_getTransactionCount` at `pending` counts the waiting transactions, and `txpool_status` and `txpool_content` show the pool.

The node keeps the state of its last 1 024 blocks (`--state-history <blocks>`, or every block with `--archive`): state methods (`eth_getBalance`, `eth_call`, `eth_getProof`, ...) answer at any of those heights and refuse an older one with geth's `missing trie node` (spec 20 §5). An account delegates to a contract with an EIP-7702 transaction and keeps sending; the pool holds one transaction of a delegated account at a time, as geth does. Requests run on the thread that drives consensus, so each kernel query runs within a budget (`--query-gas`, 2^26 VM gas by default) and long requests (batches, gas estimation, log scans) let the node poll its peers and tick between their steps.

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

Every field of an account is optional. Storage keys and values are hex of at most 32 bytes, left-padded with zeros. The kernel stores the code under its `keccak256` hash and the non-zero slots under the account, exactly as if a transaction had deployed it. An account with storage needs code or a non-zero nonce: a contract creation could land on any other account, and the kernel does not apply EIP-7610, so it refuses such a genesis rather than let old slots show through a new contract. Code is run the way geth runs it: `0xef0100` followed by an address is an EIP-7702 delegation, and an account with that code, or none, can send transactions; any other code is legacy bytecode, even when it starts with `0xef`, except the 34-byte native-contract designator `0xef02 ‖ code hash` (spec 16).

A `modules` array installs kernel modules at genesis (spec 16 §4.1): `{"address": "0x…", "code": "0x<Solo module>", "capabilities": 1, "init": "0x…"}`, `code` being the output of `solo-recompile`; the account at `address` becomes a native contract that Solidity calls like any other.

The reference kernel's base fee is zero and its block beneficiary is the zero address, so every fee, `gas used × price paid`, is credited to `0x0000…0000`, where no one can spend it. The genesis block has no header and its hash is zero: block 1's parent hash, `BLOCKHASH(0)` and the RPC's block 0 all say so.

Run a chain of several validators, each with its own key. `solo key` prints the validator id to list in the genesis file:

```sh
solo key 5151515151515151515151515151515151515151515151515151515151515151
# genesis.json: {"chainId": 1337, "slotMs": 400, "alloc": {...}, "validators": ["0x<id 1>", "0x<id 2>", ...]}
solo node --kernel kernel.elf --genesis genesis.json --key <seed 1> --data-dir node-1 --listen 127.0.0.1:30301 --rpc 127.0.0.1:8545
solo node --kernel kernel.elf --genesis genesis.json --key <seed 2> --data-dir node-2 --listen 127.0.0.1:30302 --rpc 127.0.0.1:8546 --peer 127.0.0.1:30301
```

A node without `--key` follows the chain as an observer. A validator keeps its driver state in `--data-dir` (`driver.state`, the latest persisted state, and `persist.log`, a journal of the driver's node-local writes), written before anything it signs leaves the node, so a restarted validator resumes the view it left and never votes twice in one view (spec 08 §7). Chain state is not kept: a node that restarts or falls behind syncs the finalized blocks it misses from its peers.

Watch it: every node serves Prometheus metrics at `GET /metrics` and a JSON status at `GET /status` on its JSON-RPC address (spec 11), and `solo doctor` turns both into a verdict, exiting non-zero when the node is unhealthy. `ops/` has the alert rules, a Prometheus configuration and a Grafana dashboard:

```sh
curl -s http://127.0.0.1:8545/status
solo doctor --rpc 127.0.0.1:8545
prometheus --config.file=ops/prometheus.yml   # then import ops/grafana-solo.json into Grafana
```

## Run a devnet

`solo devnet` runs a network of validator processes on one machine, with staking, epochs and the rotating threshold key of spec 15 on, governed kernel upgrades and feature gates of spec 13 on, and the bridges off. `init` draws the keys (reproducibly with `--seed`), recompiles the kernel once and writes the genesis, one directory per node (its key, and once it runs its log and driver state) and the manifest `devnet.json`; `up` starts every node over the TCP transport of spec 09 and waits for them; `status` and `wait` watch them without reading logs:

```sh
solo devnet init --dir devnet --kernel crates/solo-node/tests/fixtures/kernel.elf --validators 4
solo devnet up --dir devnet &                 # JSON-RPC on 127.0.0.1:8545 to 8548, logs in devnet/node-*/log
solo devnet wait --dir devnet --peers 3 --head 10
solo devnet status --dir devnet
solo devnet stop --dir devnet --node 3        # the others keep finalizing
solo devnet start --dir devnet --node 3       # back in the view it left, it syncs and signs again
solo devnet down --dir devnet
```

The genesis funds the README's account above (`solo key` prints a validator's id, address and the DKG encryption key a `staking.keys` entry needs). `solo upgrade` proposes a kernel upgrade with the governance key `init` wrote: it stages the module in chunks, waits for the receipts and proposes an activation height; every node then switches at that block (spec 06 §7):

```sh
solo upgrade --rpc 127.0.0.1:8545 --key-file devnet/governance.key --kernel crates/solo-node/tests/fixtures/kernel_v2.elf
solo devnet wait --dir devnet --kernel-version 2
```

`tools/rehearse-upgrade.sh devnet` rehearses, against the running devnet, what a chain goes through: the upgrade (the governance step is one shell function, for when governance grows beyond a single key), every validator signalling the feature gates and the gates locking in and activating everywhere, a validator stopping while the others keep finalizing, that validator coming back with its driver state, catching up and signing threshold certificates again, and no validator having voted twice across its restart; it prints a PASS or FAIL line per phase. `cargo test -p solo-cli --test devnet` runs it end to end on four processes. `ops/docker-compose.yml` runs the same topology as containers with Prometheus and Grafana wired to `ops/alerts.yml` and `ops/grafana-solo.json`; see `ops/README.md`.

Build everything and run the gates:

```sh
tools/build-guest.sh                      # builds hello, modules/precompiles (recompiled into guest/kernel/precompiles.solo, which the kernel embeds), kernel, kernel_v2 (upgrade-test), modules/counter, modules/eth-light-client, modules/eth-message-verifier and evm-conformance for riscv64imac-unknown-none-elf at one fixed staging path (fixtures do not depend on the checkout) and refreshes their fixtures
tools/build-contracts.sh                  # compiles contracts/ with solc 0.8.28 (not needed in CI) and refreshes contracts/build
cargo run -p solo-recompile -- guest/target/riscv64imac-unknown-none-elf/release/hello hello.solo
cargo test --workspace                    # includes running the recompiled guests on the interpreter
cargo llvm-cov --workspace --fail-under-lines 100
```

## Native backend

`solo-jit` translates a validated program to native code once and runs it in-process. It is bit-exact with the reference interpreter, which stays the oracle: same registers, memory, gas (including the exact out-of-gas point), termination status and program position. Host calls, `sbrk`, `memcopy` and `memfill` return to Rust and are performed exactly as the interpreter performs them, so a host implements the same `Host` trait for both. The executor picks a backend with `Executor::set_backend(Backend::Native)`. It compiles each code hash at most once and caches the outcome, failures included, and it keeps at most `NATIVE_CODE_BUDGET` bytes of native code (adjustable with `set_native_code_budget`). A program that has no native backend on this target, does not compile, or would not fit in the budget runs on the interpreter.

Every change runs the differential suite of spec 07 §4.1: generated modules, per-instruction edge tables, the `hello` guest and the kernel's entrypoints, each on both backends. Timings, in release mode:

```sh
cargo test --release -p solo-jit --test bench --test guests -- --ignored --nocapture
```

## Layout

- `spec/` — normative specification (machine model, instruction set, module format, gas, host ABI, driver interface, conformance, consensus, transport, state commitment, telemetry, threshold certificates, kernel upgrades and feature gates, mempool, staking, kernel modules and native contracts, the bridge to Ethereum, the bridge from Ethereum, precompiles and kernel gas, the Ethereum surface, the token bridge).
- `crates/solo-vm` — reference interpreter, `no_std`-capable, the oracle for every other backend.
- `crates/solo-jit` — the native backend: compiles a program ahead of time to AArch64 (Apple silicon) or x86-64 (Unix) machine code and runs it with the interpreter's interface and results.
- `crates/solo-recompile` — turns a linked RV64 ELF into a Solo module.
- `crates/solo-host` — module cache, storage overlays, the host ABI and the executor that runs modules.
- `crates/solo-abi` — the canonical codec and the types shared by host and kernel (spec 06 and the reference chain records).
- `crates/solo-rlp` — Ethereum RLP.
- `crates/solo-eth` — Ethereum transactions (every type the kernel accepts, EIP-7702 included), intrinsic gas, the Ethereum block header and receipt encodings, logs blooms and Merkle-Patricia roots (spec 20), `no_std`.
- `crates/solo-trie` — the binary Merkle trie of the state commitment (spec 10), with inclusion and exclusion proofs, `no_std`.
- `crates/solo-bls` — threshold BLS over BLS12-381: the DKG and resharing, finality certificates and their Ethereum verification inputs (spec 12), `no_std`.
- `crates/solo-upgrade` — kernel upgrades and feature gates (spec 13): the upgrade-address actions, their records, the gate state machine.
- `crates/solo-node` — the node host: privileged functions (including `sign`), the driver loop, the mempool of spec 14 (per-sender nonce queues, replacement, limits), queries, the kernel switchover and gated host functions of spec 13, telemetry, the threshold keystore behind `sign` key role 2 (spec 15 §6.4), the TCP transport, and `Sim`, an in-process network of nodes with a virtual clock.
- `crates/solo-rpc` — Ethereum JSON-RPC over a node, including `txpool_status` and `txpool_content` and the bridge relayer's `solo_getFinalityProof` and `solo_getOutboxProof`, with a minimal HTTP server.
- `crates/solo-bridge` — the relayer library of the bridge to Ethereum (spec 17): light-client submissions from threshold certificates, outbox proofs, and the calldata of every call to the contracts; and the token bridge's messages, wrapped-token addresses, calls and constructor arguments (spec 21, `solo_bridge::tokens`).
- `crates/solo-cli` — the `solo` command (`solo dev`, `solo node`, `solo key`, `solo doctor`, `solo upgrade`, `solo devnet`).
- `crates/solo-metrics` — telemetry: a metrics registry with Prometheus text exposition, the node's metric schema, and the health rules `solo doctor` applies.
- `crates/solo-ethlc` — the Ethereum-to-Solo bridge (spec 18): SSZ, the Altair light-client sync protocol at the Electra format, Merkle-Patricia proofs, the light-client and message-verifier logic and the admission checks, `no_std`; with `testing`, a synthetic beacon chain, an Ethereum state with `eth_getProof` proofs and an EVM.
- `crates/solo-conformance` — Ethereum execution-spec state tests through the whole pipeline: the kernel's EVM code recompiled to a module, on the interpreter and the native backend, compared by Ethereum state root and logs hash (spec 07 §4.2), with feature gate 2 inactive and active (`--gated`, spec 19).
- `guest/` — separate workspace for programs that run on the VM: the `solo-guest` runtime, `hello`, the reference `kernel`, `solo-module` (the runtime for kernel modules and native contracts), the example module `modules/counter`, the bridge's `modules/eth-light-client` and `modules/eth-message-verifier`, `modules/precompiles` (the only importer of the gate-2 precompile functions, spec 19), and `evm-conformance`, which runs one state test through the kernel's EVM code.
- `contracts/` — the bridges' Solidity contracts with compiled fixtures in `contracts/build`: deployed on Ethereum, `SoloFinalityVerifierV2`, `SoloLightClientV2` (rotating keys), `SoloFinalityVerifierV1`, `SoloLightClient` (a fixed key) and `SoloInbox` of the bridge to Ethereum (spec 17) and `EthereumOutbox` of the bridge from Ethereum (spec 18); deployed on Solo, `EthereumInbox` (spec 18); the token bridge's `TokenGatewayOnEthereum`, `TokenGatewayOnSolo` and `BridgedToken` in `contracts/tokens` (spec 21); their interfaces and test contracts.
- `examples/` — a genesis file for `solo dev`.
- `tools/` — build scripts; `fetch-conformance.sh` downloads the pinned execution-spec fixture set for a full conformance run; `build-contracts.sh` compiles `contracts/` with solc 0.8.28 and refreshes its fixtures; `rehearse-upgrade.sh` rehearses a kernel upgrade, a gate activation and a validator restart on a devnet, and `compose-rehearsal.sh` does so on the compose stack.
- `ops/` — operator assets: Prometheus alert rules and configuration, a Grafana dashboard, and the Dockerfile and compose file of a four-validator devnet with Prometheus and Grafana (`ops/README.md`).
