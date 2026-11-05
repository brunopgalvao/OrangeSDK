#!/usr/bin/env bash
# Starts `orange dev` with the suite's genesis, runs the ethers and viem suite
# (npm test) and the Foundry checks (foundry.sh) against it, and stops it.
#
# usage: tools/ecosystem/run.sh
#
# Environment: ORANGE, the orange binary (default target/release/orange, built
# with `cargo build --release -p orange-cli` if missing); ORANGE_RPC_PORT, the
# port it serves JSON-RPC on (default 18545); SKIP_FOUNDRY=1 to run the
# node half only where Foundry is not installed. To run against a node
# started some other way, run `npm test` and foundry.sh with ORANGE_RPC set.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd -P)
ROOT=$(cd "$HERE/../.." && pwd -P)
ORANGE=${ORANGE:-$ROOT/target/release/orange}
PORT=${ORANGE_RPC_PORT:-18545}
export ORANGE_RPC=http://127.0.0.1:$PORT
LOG=$(mktemp "${TMPDIR:-/tmp}/orange-ecosystem.XXXXXX")

if [ ! -x "$ORANGE" ]; then
    (cd "$ROOT" && cargo build --release -p orange-cli)
fi

rpc() {
    curl -sf -m 5 -H 'content-type: application/json' \
        -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$1\",\"params\":[]}" "$ORANGE_RPC"
}

if rpc eth_chainId >/dev/null 2>&1; then
    echo "something already answers on $ORANGE_RPC; set ORANGE_RPC_PORT" >&2
    exit 1
fi

"$ORANGE" dev --kernel "$ROOT/crates/orange-node/tests/fixtures/kernel.elf" \
    --genesis "$HERE/genesis.json" --rpc "127.0.0.1:$PORT" >"$LOG" 2>&1 &
PID=$!
stop() {
    rpc orange_stop >/dev/null 2>&1 || true
    for _ in $(seq 50); do
        kill -0 "$PID" 2>/dev/null || break
        sleep 0.1
    done
    kill "$PID" 2>/dev/null || true
    rm -f "$LOG"
}
trap stop EXIT

for _ in $(seq 300); do
    rpc eth_chainId >/dev/null 2>&1 && break
    kill -0 "$PID" 2>/dev/null || { cat "$LOG" >&2; echo "orange dev exited" >&2; exit 1; }
    sleep 0.2
done
rpc eth_chainId >/dev/null || { cat "$LOG" >&2; echo "orange dev did not answer on $ORANGE_RPC" >&2; exit 1; }
echo "orange dev on $ORANGE_RPC"

cd "$HERE"
[ -d node_modules ] || npm ci --no-audit --no-fund
npm test
if [ -n "${SKIP_FOUNDRY:-}" ]; then
    echo "foundry checks skipped (SKIP_FOUNDRY)"
else
    "$HERE/foundry.sh"
fi
