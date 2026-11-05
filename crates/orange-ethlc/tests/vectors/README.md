# Ethereum mainnet vectors

Public Ethereum mainnet data, fetched on 2026-10-21, used unchanged by
`tests/mainnet.rs`. Chain data carries no licence restrictions.

| File | What | Source |
|---|---|---|
| `bootstrap-1888.ssz` | `LightClientBootstrap` (Fulu) for block root `0x5ded74ce1ea2e8e7d5c47e043e207a403c41c70222629989de5b6ba6a1df20b5`, slot 15466496, the first slot of sync-committee period 1888 | `GET /eth/v1/beacon/light_client/bootstrap/{root}`, SSZ, from the public beacon API at `lodestar-mainnet.chainsafe.io` |
| `update-1888.ssz` | `LightClientUpdate` (Fulu) of period 1888: attested slot 15466561, finalized slot 15466496, signature slot 15466562, carrying the committee of period 1889 | `GET /eth/v1/beacon/light_client/updates?start_period=1888&count=1`, SSZ, with the response chunk's 8-byte length and 4-byte fork digest removed |
| `finality-15475041.ssz` | `LightClientFinalityUpdate` (Fulu): attested slot 15475041, finalized slot 15474976 (execution block 26235823), signed in slot 15475042 by the committee of period 1889 | `GET /eth/v1/beacon/light_client/finality_update`, SSZ |
| `weth-proof-26235823.json` | `eth_getProof` of WETH (`0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2`) for slot 0 (present) and slot `0xdeadbeef` (absent) at execution block 26235823, whose state root the finality update finalizes, with that block's hash and state root | `eth_getProof` and `eth_getBlockByNumber` from the public JSON-RPC endpoint `eth.drpc.org` |

Mainnet's configuration: genesis validators root
`0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95`, Electra
(fork version `0x05000000`) from epoch 364032, Fulu (`0x06000000`) from epoch
411392, 512-member committees, 32 slots an epoch, 256 epochs a period.
