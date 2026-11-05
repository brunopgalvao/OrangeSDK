#!/usr/bin/env bash
# Smoke test of the compose stack of ops/docker-compose.yml: builds the
# image, brings the four validators, Prometheus and Grafana up, checks that
# the chain makes and finalizes blocks that every node agrees on, that the
# JSON-RPC answers, that each node's /metrics, /health and /status serve,
# that `solo doctor` passes, that Prometheus scrapes all four with the alert
# rules loaded and that Grafana has its data source and dashboard; restarts
# one validator and checks it catches up; then takes the stack down.
#
# usage: tools/compose-smoke.sh
#
# Needs docker with the compose plugin, curl and jq. On failure it prints
# what it was waiting for, the containers and their recent logs, and exits
# non-zero; the stack goes down either way.
#
# Environment:
#   SMOKE_EXTERNAL=1  check a stack that is already up (or any nodes, with
#                     RPCS) instead of building and starting one; skips the
#                     restart and leaves everything running. PROMETHEUS_URL
#                     or GRAFANA_URL set to "" skips those checks.
#   RPCS              the nodes' JSON-RPC host:port list
#                     (default 127.0.0.1:8545,...,127.0.0.1:8548)
#   PROMETHEUS_URL    default http://127.0.0.1:9090
#   GRAFANA_URL       default http://127.0.0.1:3000
#   SMOKE_TIMEOUT     seconds each wait may take (default 180)
#   CHAIN_ID          the chain id expected (default 1337, the devnet's)
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd -P)
COMPOSE=(docker compose -f "$ROOT/ops/docker-compose.yml")
IFS=, read -r -a NODES <<<"${RPCS:-127.0.0.1:8545,127.0.0.1:8546,127.0.0.1:8547,127.0.0.1:8548}"
PROMETHEUS_URL=${PROMETHEUS_URL-http://127.0.0.1:9090}
GRAFANA_URL=${GRAFANA_URL-http://127.0.0.1:3000}
TIMEOUT=${SMOKE_TIMEOUT:-180}
CHAIN_ID=${CHAIN_ID:-1337}
EXTERNAL=${SMOKE_EXTERNAL:-}
N=${#NODES[@]}

log() { printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*"; }
fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

for tool in curl jq; do
    command -v "$tool" >/dev/null || fail "$tool is required"
done
if [ -z "$EXTERNAL" ]; then
    docker compose version >/dev/null 2>&1 || fail "docker with the compose plugin is required"
fi

# One JSON-RPC call to node $1; prints the result, fails on an error.
rpc() {
    local node=$1 method=$2 params=${3:-[]} body
    body=$(curl -sf -m 10 -H 'content-type: application/json' \
        -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$method\",\"params\":$params}" \
        "http://$node") || return 1
    jq -e 'has("result")' <<<"$body" >/dev/null || return 1
    jq -r '.result' <<<"$body"
}

# A quantity as decimal.
dec() { printf '%d' "$1"; }

head_of() { dec "$(rpc "$1" eth_blockNumber)"; }
finalized_of() { dec "$(rpc "$1" eth_getBlockByNumber '["finalized",false]' | jq -r .number)"; }

# Retries the command "$@" until it succeeds or TIMEOUT passes; $WHAT says
# what is being waited for.
wait_for() {
    local deadline=$((SECONDS + TIMEOUT))
    until "$@" >/dev/null 2>&1; do
        [ "$SECONDS" -lt "$deadline" ] || fail "timed out after ${TIMEOUT}s waiting for: $WHAT"
        sleep 2
    done
}

cleanup() {
    local status=$?
    if [ -z "$EXTERNAL" ]; then
        if [ "$status" -ne 0 ]; then
            "${COMPOSE[@]}" ps -a || true
            "${COMPOSE[@]}" logs --no-color --tail 80 || true
        fi
        "${COMPOSE[@]}" down -v --remove-orphans || true
    fi
    exit "$status"
}
trap cleanup EXIT

if [ -z "$EXTERNAL" ]; then
    # Start from nothing: a volume left by an earlier run holds another
    # chain's identities.
    "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
    log "building the image"
    # The nodes share the image the init service builds: build it first, so
    # that `up` finds it and never tries to pull solo:devnet.
    "${COMPOSE[@]}" build
    log "starting the stack"
    "${COMPOSE[@]}" up -d
fi

# --- JSON-RPC and block production -------------------------------------

chain_id_is() { [ "$(dec "$(rpc "$1" eth_chainId)")" = "$CHAIN_ID" ]; }
for node in "${NODES[@]}"; do
    WHAT="eth_chainId $CHAIN_ID on $node"
    wait_for chain_id_is "$node"
done
log "all $N nodes answer eth_chainId $CHAIN_ID"
[ "$(rpc "${NODES[0]}" net_version)" = "$CHAIN_ID" ] || fail "net_version"

declare -a START
for i in "${!NODES[@]}"; do
    START[i]=$(head_of "${NODES[i]}")
done
advanced() { [ "$(head_of "$1")" -ge $(($2 + 5)) ]; }
finalized_past() { [ "$(finalized_of "$1")" -ge "$2" ]; }
for i in "${!NODES[@]}"; do
    WHAT="5 new blocks on ${NODES[i]} (from ${START[i]})"
    wait_for advanced "${NODES[i]}" "${START[i]}"
    WHAT="finalized height 3 on ${NODES[i]}"
    wait_for finalized_past "${NODES[i]}" 3
done
log "every node made at least 5 blocks and finalized past 3"

# The nodes agree on the chain: the block at the lowest finalized height
# has one hash everywhere.
lowest=
for node in "${NODES[@]}"; do
    f=$(finalized_of "$node")
    if [ -z "$lowest" ] || [ "$f" -lt "$lowest" ]; then lowest=$f; fi
done
hex=$(printf '0x%x' "$lowest")
want=$(rpc "${NODES[0]}" eth_getBlockByNumber "[\"$hex\",false]" | jq -r .hash)
for node in "${NODES[@]}"; do
    got=$(rpc "$node" eth_getBlockByNumber "[\"$hex\",false]" | jq -r .hash)
    [ "$got" = "$want" ] || fail "$node has block $lowest as $got, ${NODES[0]} as $want"
done
log "all nodes agree on block $lowest ($want)"

# --- each node's operator endpoints ------------------------------------

metric() { # the value of the unlabelled sample $2 in node $1's /metrics
    # Read whole before awk stops at the sample: under pipefail, curl
    # writing into a closed pipe fails the script (curl exit 23).
    local page
    page=$(curl -sf -m 10 "http://$1/metrics") || return 1
    awk -v name="$2" '$1 == name { print $2; exit }' <<<"$page"
}
peered() { [ "$(curl -sf -m 10 "http://$1/status" | jq -r .peers)" -ge $((N - 1)) ]; }
for node in "${NODES[@]}"; do
    [ "$(curl -sf -m 10 "http://$node/health")" = ok ] || fail "$node /health"
    WHAT="$N-1 peers on $node"
    wait_for peered "$node"
    status=$(curl -sf -m 10 "http://$node/status")
    jq -e --argjson id "$CHAIN_ID" '.chainId == $id and .head > 0 and .p2p == true and .validator != null' \
        <<<"$status" >/dev/null || fail "$node /status: $status"
    height=$(metric "$node" ethereum_blockchain_height)
    [ -n "$height" ] && [ "${height%.*}" -gt 0 ] || fail "$node ethereum_blockchain_height: '$height'"
    peers=$(metric "$node" ethereum_peer_count)
    [ -n "$peers" ] && [ "${peers%.*}" -ge $((N - 1)) ] || fail "$node ethereum_peer_count: '$peers'"
    finalized=$(metric "$node" solo_chain_finalized_height)
    [ -n "$finalized" ] || fail "$node exports no solo_chain_finalized_height"
    [ -n "$(metric "$node" solo_store_size_bytes)" ] || fail "$node exports no solo_store_size_bytes (no chain store?)"
done
log "every node serves /health, /status and /metrics with $((N - 1)) peers"

if [ -z "$EXTERNAL" ]; then
    out=$("${COMPOSE[@]}" exec -T solo-0 solo doctor --rpc 127.0.0.1:8545 --min-peers $((N - 1)) 2>&1) \
        || fail "solo doctor on solo-0: $out"
    log "solo doctor passes on solo-0"
fi

# --- Prometheus --------------------------------------------------------

if [ -n "$PROMETHEUS_URL" ]; then
    prom() { curl -sf -m 10 "$PROMETHEUS_URL$1"; }
    WHAT="Prometheus ready at $PROMETHEUS_URL"
    wait_for prom /-/ready
    all_up() {
        prom /api/v1/targets | jq -e --argjson n "$N" \
            '[.data.activeTargets[] | select(.labels.job == "solo" and .health == "up")] | length == $n'
    }
    WHAT="Prometheus scraping all $N nodes"
    wait_for all_up
    # Every node's height, as Prometheus scraped it.
    scraped() {
        prom '/api/v1/query?query=ethereum_blockchain_height' | jq -e --argjson n "$N" \
            '.status == "success" and (.data.result | length == $n) and all(.data.result[]; (.value[1] | tonumber) > 0)'
    }
    WHAT="ethereum_blockchain_height of all $N nodes in Prometheus"
    wait_for scraped
    rules=$(prom /api/v1/rules)
    jq -e '[.data.groups[].rules[] | select(.type == "alerting")] | length > 0' <<<"$rules" >/dev/null \
        || fail "Prometheus loaded no alert rules: $rules"
    jq -e 'all(.data.groups[].rules[]; .health != "err")' <<<"$rules" >/dev/null \
        || fail "an alert rule does not evaluate: $(jq -c '[.data.groups[].rules[] | select(.health == "err") | {name, lastError}]' <<<"$rules")"
    firing=$(prom /api/v1/alerts | jq -c '[.data.alerts[] | select(.state == "firing") | .labels.alertname]')
    log "Prometheus scrapes $N nodes, $(jq '[.data.groups[].rules[]] | length' <<<"$rules") rules loaded, firing: $firing"
fi

# --- Grafana -----------------------------------------------------------

if [ -n "$GRAFANA_URL" ]; then
    graf() { curl -sf -m 10 "$GRAFANA_URL$1"; }
    WHAT="Grafana healthy at $GRAFANA_URL"
    healthy() { graf /api/health | jq -e '.database == "ok"'; }
    wait_for healthy
    graf /api/datasources/uid/prometheus | jq -e '.type == "prometheus"' >/dev/null \
        || fail "Grafana has no Prometheus data source"
    dashboard() { graf '/api/search?type=dash-db' | jq -e 'any(.[]; .title == "Solo node")'; }
    WHAT="the Solo dashboard provisioned in Grafana"
    wait_for dashboard
    through() {
        graf '/api/datasources/proxy/uid/prometheus/api/v1/query?query=up%7Bjob%3D%22solo%22%7D' \
            | jq -e --argjson n "$N" '.data.result | length == $n'
    }
    WHAT="Grafana querying Prometheus"
    wait_for through
    log "Grafana has its data source and the Solo dashboard, and queries Prometheus"
fi

# --- a validator restart -----------------------------------------------

if [ -z "$EXTERNAL" ]; then
    last=${NODES[N - 1]}
    service=solo-$((N - 1))
    "${COMPOSE[@]}" stop "$service"
    before=$(head_of "${NODES[0]}")
    WHAT="the other nodes going on without $service"
    wait_for advanced "${NODES[0]}" "$before"
    "${COMPOSE[@]}" start "$service"
    target=$(head_of "${NODES[0]}")
    caught_up() { [ "$(head_of "$last")" -ge "$target" ]; }
    WHAT="$service catching up to block $target after a restart"
    wait_for caught_up
    hex=$(printf '0x%x' "$target")
    [ "$(rpc "$last" eth_getBlockByNumber "[\"$hex\",false]" | jq -r .hash)" = \
        "$(rpc "${NODES[0]}" eth_getBlockByNumber "[\"$hex\",false]" | jq -r .hash)" ] \
        || fail "$service disagrees on block $target after the restart"
    log "$service restarted and caught up to block $target"
fi

log "compose smoke test passed"
