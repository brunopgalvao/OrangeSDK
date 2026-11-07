# OrangeSDK

OrangeSDK is a framework for EVM-compatible solochains. The first chain built with it is **tangerine**.

- **One VM.** A RISC-V derived virtual machine, specified in [`spec/`](spec/README.md), with a reference interpreter and a bit-exact native backend (AArch64, x86-64).
- **One host binary for every chain.** A chain is a kernel plus a genesis file.
- **Consensus lives in the kernel.** The kernel runs Simplex BFT, staking and the EVM. Governance upgrades it on a running chain, every node switching at the same block.
- **Type 2 Ethereum compatibility.** Standard EVM bytecode at the Osaka fork, exact gas, Ethereum block headers and the JSON-RPC that wallets, Foundry, ethers, viem and explorers use.
- **Bridges to Ethereum, both ways.** A threshold-BLS light client on Ethereum, a sync-committee light client of Ethereum on the chain, and a canonical token bridge over both.

The specification is normative: code that disagrees with it is a bug. Every change keeps 100% line coverage, and the native backend is differentially tested against the interpreter.

## What a chain gets

| Area | What it does | Spec |
|---|---|---|
| Consensus | Simplex BFT with stake-weighted votes, epochs, view synchronization and recorded equivocation evidence | [08](spec/08-simplex-driver.md) |
| Finality certificates | A fresh threshold BLS key per epoch; 97-byte certificates; each key hands off to the next with a signed rotation | [12](spec/12-threshold-certificates.md), [15](spec/15-staking.md) |
| Staking | Bonding, delegation, slashing for equivocation and threshold misbehaviour, rewards paid out per epoch | [15](spec/15-staking.md) |
| Networking | TCP with authenticated, encrypted frames, peer exchange with anti-eclipse limits, catch-up, DNS names for configured peers | [09](spec/09-p2p.md) |
| State | A binary Merkle trie whose entries can be proven; a crash-safe store on disk; snapshots that a certificate vouches for | [10](spec/10-state-commitment.md), [22](spec/22-storage-and-snapshots.md) |
| Upgrades and governance | Kernel upgrades at an activation height, stake-signalled feature gates, stake-weighted proposals with a timelock, a guardian and a fast track | [13](spec/13-upgrades.md) |
| Ethereum surface | Legacy, EIP-2930, EIP-1559 and EIP-7702 transactions; Ethereum headers whose hash is the block hash; `eth_getProof`; filters; WebSocket subscriptions; `debug_trace*` | [20](spec/20-ethereum-surface.md) |
| Fees | An EIP-1559 base fee scaled to slot time, burned or paid to a treasury; priority fees to validators and delegators | [23](spec/23-fee-market.md) |
| Kernel modules | Modules installed at genesis or by governance, with capabilities and block hooks, callable from Solidity as native contracts | [16](spec/16-modules.md) |
| Bridges | Messages to and from Ethereum with delays, rate limits, a guardian and recovery paths; a token bridge for ETH, the chain's currency and ERC-20s | [17](spec/17-bridge-out.md), [18](spec/18-bridge-in.md), [21](spec/21-token-bridge.md) |
| Operations | Prometheus metrics, a JSON status, health checks, alert rules and a Grafana dashboard | [11](spec/11-telemetry.md) |

## Quick start

Requires a recent stable Rust toolchain. Start a development chain with JSON-RPC on port 8545:

```sh
cargo run -p orange-cli -- dev --kernel crates/orange-node/tests/fixtures/kernel.elf --genesis examples/genesis.json
```

The example genesis funds `0x1a642f0e3c3af545e7acbd38b07251b3990914f1`, the account of the private key `0x01…01` (32 bytes of `0x01`), with one million ether. Deploy and call a contract with Foundry:

```sh
KEY=0x0101010101010101010101010101010101010101010101010101010101010101
RPC=http://127.0.0.1:8545
cast chain-id --rpc-url $RPC
# Deploy the test contract (crates/orange-node/tests/fixtures/Counter.sol) with a starting count of 5.
cast send --private-key $KEY --rpc-url $RPC --create "$(cat crates/orange-node/tests/fixtures/Counter.bin)$(cast abi-encode 'f(uint256)' 5 | cut -c3-)"
COUNTER=$(cast compute-address 0x1a642f0e3c3af545e7acbd38b07251b3990914f1 --nonce 0 | awk '{print $NF}')
cast send --private-key $KEY --rpc-url $RPC $COUNTER 'increment(uint256)' 2
cast call $COUNTER 'count()(uint256)' --rpc-url $RPC
cast logs --address $COUNTER --from-block 0 --rpc-url $RPC
```

- **WebSocket:** `ws://127.0.0.1:8545` serves `eth_subscribe` for `newHeads`, `logs` and `newPendingTransactions`.
- **Tracing:** `orange dev` serves `debug_traceTransaction`, `debug_traceCall` and `debug_traceBlockBy*` with `callTracer` and `prestateTracer`. `orange node` serves them only with `--rpc-debug`.
- **Browsers:** a page sends an `Origin` header, and the node answers only the origins `--rpc-cors <origin>` names (`*` for any).
- **History:** state methods answer at any of the last 1 024 blocks (`--state-history <blocks>`, or `--archive` for all).

## Configure a chain

The genesis file sets the chain id, slot time, accounts, validators and optional features. See [`examples/genesis.json`](examples/genesis.json).

- **Accounts.** An `alloc` entry is a balance in wei, or a geth-style account with `balance`, `nonce`, `code` and `storage`, which predeploys a contract.
- **Kernel modules.** A `modules` array installs modules at genesis (spec 16 §4.1). Each module's address becomes a native contract that Solidity calls like any other.
- **Fees.** Without a `fees` object, the base fee stays zero. With one, for example `{"denominator": 125, "elasticity": 2, "minBaseFee": "1000000000"}`, the chain runs the fee market of spec 23. The base fee is burned, or paid to a `treasury` address.
- **Governance.** A `governance` address acts alone under the key track, the right setting for development. `"governanceMode": "stake"`, or `orange gov set-mode stake` later, hands decisions to the validators for good. `orange gov` prints the calldata of every governance call.

## Run several validators

`orange key` prints the validator id to list in the genesis file:

```sh
orange key 5151515151515151515151515151515151515151515151515151515151515151
# genesis.json: {"chainId": 1337, "slotMs": 400, "alloc": {...}, "validators": ["0x<id 1>", "0x<id 2>", ...]}
orange node --kernel kernel.elf --genesis genesis.json --key <seed 1> --data-dir node-1 --listen 127.0.0.1:30301 --rpc 127.0.0.1:8545
orange node --kernel kernel.elf --genesis genesis.json --key <seed 2> --data-dir node-2 --listen 127.0.0.1:30302 --rpc 127.0.0.1:8546 --peer 127.0.0.1:30301
```

- **Observers.** A node without `--key` follows the chain as an observer.
- **Peer addresses.** `--peer` and `--bootstrap` take an IP or a DNS name with its port.
- **Restarts.** A node keeps its driver state and chain state in `--data-dir`. A restarted validator resumes the view it left, never votes twice in one view, and executes nothing again.

### Start from a snapshot

The kernel records a snapshot of the state at the end of every epoch, and a certificate for any later block vouches for it:

```sh
orange snapshot export --data-dir node-1 --out epoch.snap
orange snapshot verify --snapshot epoch.snap --genesis genesis.json --trust-key 0x<the chain's group key>
orange node --kernel kernel.elf --genesis genesis.json --key <seed 3> --data-dir node-3 --snapshot epoch.snap --trust-key 0x<group key> --peer 127.0.0.1:30301
```

### A devnet on one machine

`orange devnet` runs validator processes with staking, the rotating threshold key, governed upgrades, feature gates and the fee market on:

```sh
orange devnet init --dir devnet --kernel crates/orange-node/tests/fixtures/kernel.elf --validators 4
orange devnet up --dir devnet &          # JSON-RPC on 127.0.0.1:8545 to 8548
orange devnet wait --dir devnet --peers 3 --head 10
orange devnet status --dir devnet
orange devnet down --dir devnet
```

`orange upgrade` proposes a kernel upgrade with the devnet's governance key, and every node switches at the activation height:

```sh
orange upgrade --rpc 127.0.0.1:8545 --key-file devnet/governance.key --kernel crates/orange-node/tests/fixtures/kernel_v2.elf
orange devnet wait --dir devnet --kernel-version 2
```

`tools/rehearse-upgrade.sh devnet` rehearses an upgrade, gate activation and a validator restart against a running devnet. `ops/docker-compose.yml` runs the same network as containers with Prometheus and Grafana ([`ops/README.md`](ops/README.md)).

### A network across hosts

A network run by several operators starts with a genesis ceremony: `orange key generate`, `orange genesis operator`, `orange genesis assemble` and `orange genesis verify`. [`ops/testnet/`](ops/testnet/README.md) has the systemd unit, a container alternative, the host and inventory scripts, and the operator's runbook. `tools/rehearse-testnet.sh` rehearses the whole flow on one machine.

## Monitor a node

Every node serves Prometheus metrics at `GET /metrics` and a JSON status at `GET /status` on its RPC address. `orange doctor` turns both into a verdict and exits non-zero when the node is unhealthy:

```sh
curl -s http://127.0.0.1:8545/status
orange doctor --rpc 127.0.0.1:8545
```

`ops/` has the alert rules, a Prometheus configuration and a Grafana dashboard.

## Build and test

```sh
tools/build-guest.sh        # builds the kernel and the other RISC-V guests and refreshes their fixtures
tools/build-contracts.sh    # compiles contracts/ with solc 0.8.28 (CI uses the committed build)
cargo test --workspace
cargo llvm-cov --workspace --fail-under-lines 100
```

CI also runs the Docker Compose devnet and an ecosystem suite of ethers, viem and Foundry against `orange dev` ([`tools/ecosystem/README.md`](tools/ecosystem/README.md)).

## Repository layout

| Path | Contents |
|---|---|
| [`spec/`](spec/README.md) | The normative specification, 23 documents |
| `crates/orange-vm`, `orange-jit` | Reference interpreter and native backend |
| `crates/orange-recompile` | RV64 ELF to OrangeSDK module |
| `crates/orange-host` | Executor, storage overlays and the host ABI |
| `crates/orange-node` | The node: driver loop, mempool, transport, keystore, chain state, and `Sim` for in-process networks |
| `crates/orange-rpc` | Ethereum JSON-RPC, WebSocket and tracing |
| `crates/orange-cli` | The `orange` command |
| `crates/orange-store` | The chain store on disk and snapshot files |
| `crates/orange-trie`, `orange-eth`, `orange-rlp` | The binary state trie, Ethereum encodings and roots, RLP |
| `crates/orange-bls` | Threshold BLS, DKG and finality certificates |
| `crates/orange-upgrade` | Kernel upgrades and feature gates |
| `crates/orange-bridge`, `orange-ethlc` | The relayer to Ethereum and the token bridge; the light client of Ethereum |
| `crates/orange-metrics` | Metrics registry and health rules |
| `crates/orange-conformance`, `orange-fuzz` | Ethereum execution-spec tests through both backends; the fuzzing harness |
| `guest/` | Programs that run on the VM: the reference kernel, kernel modules and the precompile module |
| `contracts/` | Solidity contracts of the bridges and the token gateways, with compiled fixtures |
| `ops/`, `tools/` | Operator assets, build and rehearsal scripts |

## License

Apache-2.0. See [LICENSE](LICENSE).
