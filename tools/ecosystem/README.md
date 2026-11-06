# Ecosystem suite

Standard Ethereum clients against a real OrangeSDK node, to show the Type 2 surface works with the tools people use rather than only with our own tests (spec 20 §8.4). CI runs it on every change to the node, the RPC or the suite (`.github/workflows/ecosystem.yml`).

- `test/ethers.test.mjs` — ethers 6.17.0: blocks by number, hash and tag; balances and nonces; EIP-1559, legacy EIP-155 and EIP-2930 transfers and their receipts; a nonce refused in geth's words; fee data and `eth_feeHistory`; an ERC-20 deployed with `ContractFactory`, its calls, gas estimates, `queryFilter` (`eth_getLogs`), `contract.once` (the polled filters of spec 20 §8.1) and block events; a custom error and a revert string decoded from `eth_call` and `eth_estimateGas`; a reverted transaction reported as failed.
- `test/viem.test.mjs` — viem 2.57.7: the same ground through public and wallet clients, plus `watchBlockNumber`, transactions by block position, `getBlobBaseFee`, an EIP-7702 authorization and the delegation it writes, `getProof`, `simulateContract`, log, block and pending-transaction filters polled by hand, and `watchContractEvent`.
- `test/websocket.test.mjs` — the WebSocket on the same port (spec 20 §8.7), through ethers' `WebSocketProvider` and viem's `webSocket` transport: ordinary calls over the socket, block events and `watchBlocks` (`newHeads`), `contract.once` and `watchContractEvent` on the token (`logs`), and pending-transaction events (`newPendingTransactions`). `ORANGE_WS` overrides the socket's URL, by default `ORANGE_RPC` with `ws` for `http`.
- `foundry.sh` — Foundry (`v1.7.1` in CI): `cast` for chain id, blocks, fees, balances, nonces, EIP-1559 and legacy sends, storage, `eth_getProof`, calls, estimates, logs and revert reasons; `forge create`; `forge script` (`script/Deploy.s.sol`), which broadcasts four transactions of one sender before any is mined; and `cast run`, which replays a transaction in Foundry's own EVM over the node's historical state and must charge the gas the kernel charged.
- `contracts/Token.sol` — the ERC-20 both halves deploy, with one custom error and one revert string; the node half compiles it with solc-js 0.8.28, forge with solc 0.8.28.
- `genesis.json` — chain id 1337, the README's key `0x01…01` funded, the fee market on with a 1 gwei floor, so that clients price transactions as on Ethereum.

## Running it

```sh
cargo build --release -p orange-cli
(cd tools/ecosystem && npm ci)
tools/ecosystem/run.sh            # starts orange dev on 127.0.0.1:18545, runs both halves, stops it
```

`run.sh` takes `ORANGE` (the binary), `ORANGE_RPC_PORT` and `SKIP_FOUNDRY=1` (where Foundry is not installed). Against a node started some other way, with this genesis:

```sh
cd tools/ecosystem
ORANGE_RPC=http://127.0.0.1:8545 npm test
ORANGE_RPC=http://127.0.0.1:8545 ./foundry.sh
```

Each run uses fresh accounts and contracts, so it can run again against the same node. It takes about a minute.

## What it found

Every difference from geth it turned up is fixed in the node or written down in spec 20 §8.3:

- `eth_newFilter` and the other polled filters were missing, so ethers' `contract.on` failed and viem fell back to `eth_getLogs`: now served (spec 20 §8.1).
- The block-position methods (`eth_getTransactionByBlockNumberAndIndex` and kin), the uncle counts, `web3_sha3`, `net_listening`, `net_peerCount` and `eth_blobBaseFee` were missing: now served (spec 20 §8.2).
- `eth_subscribe` answered "method not found": over HTTP it now answers as geth does there, `notifications not supported` (spec 20 §8.3), and since 2026-11-06 a WebSocket on the same port serves `newHeads`, `logs` and `newPendingTransactions` (spec 20 §8.7).
- ethers caches identical requests for 250 ms, shorter than a slot would need: a send right after a receipt can reuse the cached pending nonce and be refused as `nonce too low`, as against anvil. The suite sets `cacheTimeout: -1`, which an OrangeSDK chain's ethers clients should too (spec 20 §8.3).
- `debug_*`, `trace_*`, `eth_createAccessList` and `eth_simulateV1` are not served, so `cast access-list` does not work; `cast run` does (spec 20 §8.3).
