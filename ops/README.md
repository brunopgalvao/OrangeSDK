# Operator assets

What a node exports is specified in [spec 11](../spec/11-telemetry.md); a test (`crates/solo-metrics/tests/ops.rs`) keeps these files in step with it.

- `alerts.yml` — Prometheus alert rules: the conditions of spec 11 §7, with the thresholds `solo doctor` judges by.
- `prometheus.yml` — a scrape configuration for one node on this machine (`127.0.0.1:8545`).
- `grafana-solo.json` — the Solo dashboard: chain progress, kernel calls, peers, mempool, emitted metrics, kernel upgrades and feature gates.
- `Dockerfile`, `docker-compose.yml`, `prometheus-devnet.yml`, `grafana/` — the compose stack below.

## The compose stack

`docker-compose.yml` runs the topology of `solo devnet init --validators 4` as containers: one image built once from `Dockerfile` (the host in release mode plus the committed kernel fixtures `kernel.elf` and `kernel_v2.elf`), an `init` service that writes genesis, keys and the recompiled kernel to a volume, four validators that dial each other at fixed addresses, Prometheus scraping all four with `alerts.yml` loaded, and Grafana with the dashboard provisioned.

```sh
docker compose -f ops/docker-compose.yml up --build -d
solo devnet status --rpc 127.0.0.1:8545,127.0.0.1:8546,127.0.0.1:8547,127.0.0.1:8548
open http://127.0.0.1:3000   # Grafana, anonymous admin; Prometheus is on :9090
docker compose -f ops/docker-compose.yml down -v
```

The nodes' JSON-RPC is published on `127.0.0.1:8545` to `8548`. The genesis has epochs of 20 blocks, DKG phases of 5 and a known governance key (`SOLO_GOVERNANCE_KEY`, default `0x60…60`; `SOLO_EPOCH_BLOCKS` and `SOLO_DKG_PHASE_BLOCKS` change the epochs). The `devnet` volume keeps the chain's identities across `up` and `down`; `down -v` starts over.

To rehearse a kernel upgrade on the stack, as `tools/rehearse-upgrade.sh` does on a local devnet:

```sh
SOLO_DOCKER=1 tools/compose-rehearsal.sh              # up --build, rehearse, down -v
# or by hand, against a running stack:
DEVNET_DRIVER=compose RPCS=127.0.0.1:8545,127.0.0.1:8546,127.0.0.1:8547,127.0.0.1:8548 \
  GOVERNANCE_KEY=6060606060606060606060606060606060606060606060606060606060606060 \
  tools/rehearse-upgrade.sh compose crates/solo-node/tests/fixtures/kernel_v2.elf
```

The compose driver stops and starts validators with `docker compose stop` and `start`; a restarted container has no chain state and syncs from its peers, as a restarted process does. `cargo test -p solo-cli --test devnet` runs the compose rehearsal only when `SOLO_DOCKER` is set.

## Prometheus and Grafana by hand

For nodes on this machine, point Prometheus at them and import the dashboard:

```sh
prometheus --config.file=ops/prometheus.yml    # edit the targets for more nodes
# Grafana: add the Prometheus data source, import ops/grafana-solo.json
```

The dashboard's `Node` variable lists every scraped instance; the "Kernel upgrades" row shows each node's kernel version, the activation height of a pending upgrade, the active feature gates and the upgrade alerts of spec 13 §7.2.
