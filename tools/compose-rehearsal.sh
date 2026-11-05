#!/usr/bin/env bash
# Brings up the compose stack of ops/docker-compose.yml, runs the upgrade
# rehearsal against it and takes the stack down again. Needs docker; does
# nothing, and says so, unless ORANGE_DOCKER is set, so that the test that
# runs it passes on a machine without docker.
#
# usage: ORANGE_DOCKER=1 tools/compose-rehearsal.sh
#
# Environment: ORANGE, the orange binary the rehearsal's tooling runs with
# (default: orange on PATH); REHEARSE_TIMEOUT as in rehearse-upgrade.sh. The
# kernel the chain upgrades to is the committed kernel_v2 fixture, the same
# file the image carries.
set -euo pipefail
if [ -z "${ORANGE_DOCKER:-}" ]; then
    echo "compose rehearsal skipped: set ORANGE_DOCKER=1 to run it"
    exit 0
fi
ROOT=$(cd "$(dirname "$0")/.." && pwd -P)
COMPOSE=(docker compose -f "$ROOT/ops/docker-compose.yml")
export DEVNET_DRIVER=compose
export RPCS=127.0.0.1:8545,127.0.0.1:8546,127.0.0.1:8547,127.0.0.1:8548
export GOVERNANCE_KEY=${ORANGE_GOVERNANCE_KEY:-6060606060606060606060606060606060606060606060606060606060606060}
cleanup() { "${COMPOSE[@]}" down -v; }
trap cleanup EXIT
"${COMPOSE[@]}" up --build -d
"$ROOT/tools/rehearse-upgrade.sh" compose "$ROOT/crates/orange-node/tests/fixtures/kernel_v2.elf"
