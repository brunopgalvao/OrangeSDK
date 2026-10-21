# 11 — Telemetry (version 0)

## 1. Overview

A node reports what it is doing as metrics, a status document and a health verdict, so that an operator can graph it, alert on it and ask it whether it is well without reading logs. This document fixes the endpoints, the exposition format, every metric a node exports with its type and labels, how metrics emitted by the kernel and its modules (05 §4.7, 06 §4.2) are exported, the status document, and the alert and health semantics that ship with the framework (codex decision 0014).

Telemetry is *consensus-ignored*. Nothing a kernel can observe depends on it: `metric_emit` and `log_emit` return `0` whether or not the host records anything (05 §5), and the `Metric` effect produces no input. Two nodes that record differently, or a node that records nothing, execute and vote identically. Metric values are node-local observations (wall-clock durations, peer counts, traffic) and are never chain data.

## 2. Endpoints

Telemetry is served by the node's JSON-RPC HTTP server, on the same address (`--rpc`, `127.0.0.1:8545` by default), next to JSON-RPC on `POST`:

| Request | Response |
|---|---|
| `GET /metrics` | `200`, `Content-Type: text/plain; version=0.0.4; charset=utf-8`, every metric family of §4 in the format of §3 |
| `GET /status` | `200`, `Content-Type: application/json`, the document of §6; `503` with a plain-text reason when the kernel cannot answer the chain id query |
| `GET /health` | `200`, `ok`: the server is accepting connections |

One address keeps the deployment to one port to open and one process to scrape. An operator who must not expose JSON-RPC to the monitoring network fronts the address with a proxy that forwards only these paths. Answering a request reads node state on the node's own thread; it never blocks consensus for longer than rendering takes. The one kernel call telemetry makes is the chain id query (`kernel_query`): the node asks it on a `/metrics` or `/status` request until the kernel first answers, then keeps the id for its life and asks no more. Each such call is a kernel call like any other and is counted in the `solo_kernel_*` families of §4, faults included.

## 3. Exposition format

`/metrics` is the Prometheus text exposition format, version 0.0.4:

- Families appear in bytewise order of name. Each starts with `# HELP <name> <text>` and `# TYPE <name> <counter|gauge|histogram>`, followed by its samples, one per line: the sample name, the label set in braces if not empty, a space, the value, a line feed. No timestamps are written.
- A family is listed, with its `HELP` and `TYPE` lines, from the moment the node opens, even before it has samples. A labelled series appears once it is first recorded and stays until the node exits, except that the series of `solo_kernel_faults_total` for every `entrypoint` of 06 §3 and every `status` of §4, and of `solo_emitted_dropped_total` for every `reason` of §5, exist at `0` from the moment the node opens.
- Label values are written between double quotes with `\` as `\\`, `"` as `\"` and line feed as `\n`; `HELP` text escapes `\` and line feed the same way. Label names are written in the order §4 lists them.
- Values are written as the shortest decimal that reads back as the same IEEE 754 double, or `NaN`, `+Inf`, `-Inf`.
- A counter's family name ends in `_total`. A histogram family `h` writes, per series, one `h_bucket` sample per bucket bound with the label `le` (the bound, last label) counting the observations less than or equal to it, a final `h_bucket{le="+Inf"}` equal to the count, then `h_sum` and `h_count`.

## 4. Metrics

Names follow EIP-2159 where it defines a metric (`ethereum_*`); every other name starts with `solo_` and is not an EIP-2159 name. Heights are block numbers, durations seconds, sizes bytes.

| Name | Type | Labels | Meaning |
|---|---|---|---|
| `ethereum_blockchain_height` | gauge | — | The current height of the canonical chain: the last block this node executed (EIP-2159). |
| `ethereum_best_known_block_number` | gauge | — | The estimated highest block available (EIP-2159). The node does not know a sync target, so this equals the head, as EIP-2159 prescribes for a node that is not syncing. |
| `ethereum_peer_count` | gauge | — | Peers that completed the handshake (09 §3) (EIP-2159). Absent on a node without a peer-to-peer transport. |
| `solo_chain_finalized_height` | gauge | — | The last height this node finalized. |
| `solo_chain_head_age_seconds` | gauge | — | Seconds since the head last advanced, or since the node opened if it has executed no block. Computed at scrape time. |
| `solo_chain_id` | gauge | — | The chain id the kernel reports (§2). Absent until the kernel has answered once, then kept. |
| `solo_blocks_executed_total` | counter | — | Blocks this node executed (`ExecuteBlock` applied). |
| `solo_blocks_finalized_total` | counter | — | Blocks this node finalized (`FinalizeBlock` applied). |
| `solo_block_transactions_total` | counter | — | Transactions in executed blocks, from each `ExecuteSummary.tx_count`. |
| `solo_block_gas_used_total` | counter | — | Gas used by executed blocks, from each `ExecuteSummary.gas_used`. |
| `solo_mempool_transactions` | gauge | — | Transactions waiting in the mempool. Computed at scrape time. |
| `solo_mempool_bytes` | gauge | — | Raw bytes of those transactions. Computed at scrape time. |
| `solo_driver_timers` | gauge | — | Timers the driver has armed and not yet seen fire. Computed at scrape time. |
| `solo_kernel_call_duration_seconds` | histogram | `entrypoint` | Wall-clock duration of each top-level kernel entrypoint call (06 §3), from entry to termination; `_count` is the number of calls. |
| `solo_kernel_gas_used_total` | counter | `entrypoint` | VM gas those calls consumed. |
| `solo_kernel_faults_total` | counter | `entrypoint`, `status` | Calls that ended in anything but `Halt` (06 §6). A fault of a `kernel_driver_*` entrypoint is a driver fault. |
| `solo_kernel_logs_total` | counter | `level` | Lines written with `log_emit` by the kernel and the instances it invoked. |
| `solo_emitted_counter_total` | counter | `origin`, `name` | Counters emitted by the driver, the kernel and sandboxed instances (§5). |
| `solo_emitted_gauge` | gauge | `origin`, `name` | Gauges emitted by the kernel and sandboxed instances (§5). |
| `solo_emitted_dropped_total` | counter | `reason` | Emitted metrics the node discarded (§5). |
| `solo_p2p_bytes_total` | counter | `direction` | Bytes the transport read from and wrote to its connections. |
| `solo_p2p_frames_total` | counter | `direction`, `kind` | Frames (09 §2) the transport received, and queued for sending, including each connection's `Hello`. |
| `solo_upgrade_blocked` | gauge | — | `1` while a pending kernel upgrade cannot be enacted by this host (13 §7.2), else `0`. |
| `solo_upgrade_missing_gates` | gauge | — | Feature gates the chain has locked in that this host release does not support (13 §7.2). |
| `solo_upgrade_activation_height` | gauge | — | The activation height of the pending kernel upgrade (13 §4), or `0` while none is pending. |
| `solo_kernel_version` | gauge | — | The running kernel's version (06 §7.1), as its `upgrade_status` reports it; `0` for a kernel that does not serve the query. |
| `solo_gate_active` | gauge | `gate` | `1` while the feature gate is active for the next block and served by this host (13 §8.6), else `0`. One series per gate the host release supports, from the moment the node opens. |
| `solo_build_info` | gauge | `version` | Always `1`; `version` is the node release. |
| `solo_node_start_time_seconds` | gauge | — | Unix time at which the node opened. |

Label values:

- `entrypoint`: the export name called, one of the names of 06 §3.
- `status`: `out_of_gas`, `trap`, `memory_fault`, `invalid_jump`, `host_error` or `step_limit` (01 §6).
- `level`: `error`, `warn`, `info`, `debug`, `trace` for `log_emit` levels 0 to 4; `other` for any other level.
- `direction`: `in` or `out`.
- `kind`: `hello`, `message`, `tx`, `request`, `response`, the frame variants of 09 §2.
- `gate`: a feature gate's index (13 §8.1), in decimal.
- `origin`, `name`, `reason`: §5.

`solo_kernel_call_duration_seconds` has the bucket bounds 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5 and 10 seconds. Calls made by `invoke` inside a kernel call are part of that call and are not counted separately. The calls a kernel switch makes (06 §7) are counted like any other: `kernel_version` of the running kernel and of a pending upgrade's module, when the host prepares it and at the switch, and the new kernel's `kernel_migrate`, so a `kernel_migrate` that halts the node is a fault in `solo_kernel_faults_total`.

## 5. Emitted metrics

The driver emits metrics with the `Metric { name, value }` effect (06 §4.2); any instance emits them with `metric_emit` (05 §4.7), whose `kind` argument this document defines:

| `kind` | Meaning | Exported as |
|---|---|---|
| 0 | counter step: `value` (≥ 0) is added to the counter `name` | `solo_emitted_counter_total` |
| 1 | gauge: the gauge `name` is set to `value` | `solo_emitted_gauge` |

The `Metric` effect is a counter step (kind 0). The `origin` label says who emitted: `driver` for the effect, `kernel` for `metric_emit` from a `Privileged` instance, `sandboxed` for `metric_emit` from a `Sandboxed` instance (a kernel module or contract run through `invoke`). The same `name` from two origins is two series, so a contract cannot move a kernel metric, and the series limit below is kept per origin, so a contract cannot keep a kernel or driver metric from being recorded.

A name is 1 to 64 bytes of ASCII letters, digits, `_`, `.`, `:` and `-`, exported verbatim as the `name` label. The node drops an emitted metric, and counts it in `solo_emitted_dropped_total` with `reason`:

- `name`: the name breaks the rule above;
- `kind`: `kind` is neither 0 nor 1;
- `negative`: a counter step is negative;
- `cardinality`: the name is new and the family already holds 256 series of the same origin.

Dropping is the "MAY drop" of 05 §4.7; it never changes what the instance observes. Emitted metrics are recorded after the call that emitted them ends, whatever its status, since they are not state.

## 6. Status document

`GET /status` returns one JSON object:

| Field | Type | Meaning |
|---|---|---|
| `version` | string | Node release, as in `solo_build_info`. |
| `chainId` | number | Chain id from the kernel. |
| `head` | number | `ethereum_blockchain_height`. |
| `headAgeSeconds` | number | `solo_chain_head_age_seconds`. |
| `finalized` | number | `solo_chain_finalized_height`. |
| `p2p` | boolean | Whether the node runs a peer-to-peer transport. |
| `peers` | number | `ethereum_peer_count`, or `0` without a transport. |
| `mempool` | number | `solo_mempool_transactions`. |
| `uptimeSeconds` | number | Seconds since the node opened. |
| `validator` | string or null | The node's validator id (08 §2) as `0x` hex, or `null` for a node without a consensus key. |
| `upgradeAlert` | string or null | Why the pending kernel upgrade cannot be enacted by this host (13 §7.2), or `null` when there is none or it can. |
| `missingGates` | array of numbers | The gates (13 §8.1) the chain has locked in that this host release does not support, ascending; empty when there are none. |
| `kernelVersion` | number | `solo_kernel_version`. |
| `kernelHash` | string | The code hash (03 §1) of the running kernel, as `0x` hex. |
| `activeGates` | array of numbers | The gates active for the next block that this host serves (13 §8.6), ascending; empty when there are none. |
| `pendingUpgrade` | object or null | The pending kernel upgrade (13 §4) as `{"codeHash": string, "activationHeight": number}`, or `null` while none is pending. |

Fields are only ever added; a client ignores fields it does not know, and reads the fields an earlier release does not send as absent: `upgradeAlert` and `pendingUpgrade` as `null`, `missingGates` and `activeGates` as empty, `kernelVersion` as `0` and `kernelHash` as zero.

## 7. Alerts and the health verdict

The framework ships alert rules for Prometheus (`ops/alerts.yml`), a scrape configuration (`ops/prometheus.yml`) and a Grafana dashboard (`ops/grafana-solo.json`) over the metrics of §4. A test keeps them honest: every metric name in an alert expression or a dashboard query must be one a node exports; every threshold in the rule file, in the table below and in the list of health checks must equal the default the health verdict uses; and every series an alert reads with `increase` must exist at `0` when the node opens (§3), since `increase` sees no step in a series whose first sample is already `1`, and the first fault would otherwise go unalerted.

| Alert | Condition | For | Severity |
|---|---|---|---|
| `SoloNodeDown` | the scrape fails (`up == 0`) | 1 m | critical |
| `SoloHeadNotAdvancing` | `solo_chain_head_age_seconds > 60` | 1 m | critical |
| `SoloFinalityLag` | `ethereum_blockchain_height − solo_chain_finalized_height > 16` | 2 m | warning |
| `SoloNoPeers` | `ethereum_peer_count < 1` (only nodes with a transport have the series) | 2 m | critical |
| `SoloMempoolBacklog` | `solo_mempool_transactions > 1000` | 5 m | warning |
| `SoloDriverFault` | `solo_kernel_faults_total` of a `kernel_driver_*` entrypoint increased in the last 5 m | — | critical |
| `SoloKernelFault` | `solo_kernel_faults_total` of any other entrypoint increased in the last 5 m | — | warning |
| `SoloKernelCallSlow` | p99 of `solo_kernel_call_duration_seconds` over 5 m `> 1` s, per entrypoint | 10 m | warning |
| `SoloUpgradeBlocked` | `solo_upgrade_blocked + solo_upgrade_missing_gates > 0` | — | critical |
| `SoloEmittedMetricsDropped` | `solo_emitted_dropped_total` increased in the last 15 m | — | info |

`solo doctor [--rpc <addr>]` reads `/status` and `/metrics` once and judges the node by the same conditions on that snapshot. The node is unhealthy, with one reason per failed check, when:

1. `headAgeSeconds` exceeds the head-age limit (default 60 s, `--max-head-age`);
2. `head − finalized` exceeds the finality-lag limit (default 16, `--max-finality-lag`);
3. `p2p` is true and `peers` is below the peer minimum (default 1, `--min-peers`);
4. `mempool` exceeds the mempool limit (default 1000, `--max-mempool`);
5. any `solo_kernel_faults_total` series is above zero: a fault since the node opened;
6. for any entrypoint but `kernel_init`, `kernel_migrate` and `kernel_version`, which run only at open or around a kernel switch, `solo_kernel_call_duration_seconds` `_sum / _count` exceeds the call-time limit (default 1 s, `--max-call-ms`): a mean since the node opened, where the alert uses a recent p99;
7. `upgradeAlert` is not `null`, or `missingGates` is not empty: the node cannot run what the chain is upgrading to (13 §7.2).

The doctor prints a summary line and `healthy` and exits with status 0, or prints the summary, `unhealthy:` and the reasons to standard error and exits with status 2. A node it cannot reach, or whose answers do not parse, is reported the same way with the reason.

## 8. Cost

Recording is a constant number of map updates per kernel call, block and transport poll; rendering happens only when `/metrics` is requested, and a request runs no kernel call once the chain id is known (§2). The budget of decision 0014, under 2% of node CPU, holds with a scrape interval of one second or more.
