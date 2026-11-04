#!/usr/bin/env bash
# Starts `solo dev` with the suite's genesis, runs the ethers and viem suite
# (npm test) and the Foundry checks (foundry.sh) against it, and stops it.
#
# usage: tools/ecosystem/run.sh
#
# Environment: SOLO, the solo binary (default target/release/solo, built
# with `cargo build --release -p solo-cli` if missing); SOLO_RPC_PORT, the
# port it serves JSON-RPC on (default 18545); SKIP_FOUNDRY=1 to run the
# node half only where Foundry is not installed. To run against a node
# started some other way, run `npm test` and foundry.sh with SOLO_RPC set.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd -P)
ROOT=$(cd "$HERE/../.." && pwd -P)
SOLO=${SOLO:-$ROOT/target/release/solo}
PORT=${SOLO_RPC_PORT:-18545}
export SOLO_RPC=http://127.0.0.1:$PORT
LOG=$(mktemp "${TMPDIR:-/tmp}/solo-ecosystem.XXXXXX")

if [ ! -x "$SOLO" ]; then
    (cd "$ROOT" && cargo build --release -p solo-cli)
fi

rpc() {
    curl -sf -m 5 -H 'content-type: application/json' \
        -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$1\",\"params\":[]}" "$SOLO_RPC"
}

if rpc eth_chainId >/dev/null 2>&1; then
    echo "something already answers on $SOLO_RPC; set SOLO_RPC_PORT" >&2
    exit 1
fi

"$SOLO" dev --kernel "$ROOT/crates/solo-node/tests/fixtures/kernel.elf" \
    --genesis "$HERE/genesis.json" --rpc "127.0.0.1:$PORT" >"$LOG" 2>&1 &
PID=$!
stop() {
    rpc solo_stop >/dev/null 2>&1 || true
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
    kill -0 "$PID" 2>/dev/null || { cat "$LOG" >&2; echo "solo dev exited" >&2; exit 1; }
    sleep 0.2
done
rpc eth_chainId >/dev/null || { cat "$LOG" >&2; echo "solo dev did not answer on $SOLO_RPC" >&2; exit 1; }
echo "solo dev on $SOLO_RPC"

cd "$HERE"
[ -d node_modules ] || npm ci --no-audit --no-fund
npm test
if [ -n "${SKIP_FOUNDRY:-}" ]; then
    echo "foundry checks skipped (SKIP_FOUNDRY)"
else
    "$HERE/foundry.sh"
fi
