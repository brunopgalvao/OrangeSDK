#!/usr/bin/env bash
# Rehearses, against a running devnet, what a chain goes through in its life:
# a kernel upgrade through governance that every node switches to at the
# activation height (spec 06 §7, spec 13), a feature gate that every validator
# signals and that locks in and activates on every node (spec 13 §8), a
# validator that stops while the others keep finalizing, and that comes back
# with its driver state, catches up and signs with its threshold share again
# (spec 08 §7, spec 15 §6), and no validator having voted twice in a view
# across its restart (spec 08 §9). Prints a PASS or FAIL line per phase and
# exits non-zero on the first failure.
#
# usage: tools/rehearse-upgrade.sh <devnet dir> [kernel_v2.elf|kernel_v2.orange]
#
# The devnet is one `orange devnet init` made and `orange devnet up` runs, or the
# compose stack of ops/docker-compose.yml (then the first argument is unused
# and RPCS names the nodes). Environment:
#   ORANGE              the orange binary (default: orange on PATH)
#   DEVNET_DRIVER     process (default): the nodes are the processes of <devnet dir>;
#                     compose: the services of ops/docker-compose.yml, reached at RPCS
#   RPCS              comma-separated JSON-RPC addresses of the nodes (compose driver)
#   GOVERNANCE_KEY    hex key of the governance account (compose driver; the process
#                     driver reads <devnet dir>/governance.key)
#   GATES             the feature gates the hosts support (default 0,1,2)
#   REHEARSE_TIMEOUT  seconds each wait may take (default 600)
#   STOP_NODE         the validator stopped and restarted (default: the last one)
#   SIGNER_NODE       the validator stopped afterwards, so that every threshold
#                     certificate needs the restarted one's share (default: the one before)
set -euo pipefail

DIR=${1:?usage: tools/rehearse-upgrade.sh <devnet dir> [kernel_v2]}
ROOT=$(cd "$(dirname "$0")/.." && pwd -P)
KERNEL_V2=${2:-$ROOT/crates/orange-node/tests/fixtures/kernel_v2.elf}
ORANGE=${ORANGE:-orange}
DRIVER=${DEVNET_DRIVER:-process}
GATES=${GATES:-0,1,2}
TIMEOUT=${REHEARSE_TIMEOUT:-600}
COMPOSE=(docker compose -f "$ROOT/ops/docker-compose.yml")

# --- the devnet driver: how nodes are addressed, stopped and started ---------

case $DRIVER in
process)
    TARGET=(--dir "$DIR")
    RPCS=$(sed -n 's/^ *"rpc": "\([^"]*\)".*/\1/p' "$DIR/devnet.json" | paste -sd, -)
    GOVERNANCE_KEY=$(cat "$DIR/governance.key")
    ;;
compose)
    if [ -z "${RPCS:-}" ] || [ -z "${GOVERNANCE_KEY:-}" ]; then
        echo "the compose driver needs RPCS (the JSON-RPC addresses) and GOVERNANCE_KEY" >&2
        exit 2
    fi
    TARGET=(--rpc "$RPCS")
    ;;
*)
    echo "DEVNET_DRIVER must be process or compose" >&2
    exit 2
    ;;
esac
stop_node() {
    if [ "$DRIVER" = process ]; then
        "$ORANGE" devnet stop --dir "$DIR" --node "$1"
    else
        "${COMPOSE[@]}" stop "orange-$1"
    fi
}
start_node() {
    if [ "$DRIVER" = process ]; then
        "$ORANGE" devnet start --dir "$DIR" --node "$1"
    else
        "${COMPOSE[@]}" start "orange-$1"
    fi
}

IFS=, read -r -a RPC_LIST <<<"$RPCS"
N=${#RPC_LIST[@]}
RPC0=${RPC_LIST[0]}
STOP_NODE=${STOP_NODE:-$((N - 1))}
SIGNER_NODE=${SIGNER_NODE:-$((N - 2))}

# --- governance: how an upgrade is submitted ---------------------------------
# Main offers a single governance key (spec 13 §1.1); `orange upgrade` stages the
# module and proposes it with that key. A governance with proposals and votes
# replaces this one function.
submit_upgrade() {
    "$ORANGE" upgrade --rpc "$RPC0" --key "$GOVERNANCE_KEY" --kernel "$KERNEL_V2" --timeout "$TIMEOUT"
}

# --- helpers -----------------------------------------------------------------

PASSED=0
FAILED=0
phase() { printf '\n[%s] %s\n' "$1" "$2"; }
pass() {
    PASSED=$((PASSED + 1))
    echo "PASS $1"
}
fail() {
    FAILED=$((FAILED + 1))
    echo "FAIL $1" >&2
    summary
    exit 1
}
summary() {
    printf '\nrehearsal: %d passed, %d failed\n' "$PASSED" "$FAILED"
}
# Waits until the selected nodes meet the conditions, or fails the phase.
wait_nodes() {
    local what=$1
    shift
    "$ORANGE" devnet wait "${TARGET[@]}" --timeout "$TIMEOUT" "$@" || fail "$what"
}
# A number from node $1's status: the value of field $2.
field() {
    "$ORANGE" devnet status "${TARGET[@]}" --nodes "$1" --json | sed -n "s/^ *\"$2\": \([0-9]*\).*/\1/p" | head -1
}
# Every node but the ones given, as a --nodes list.
others() {
    local out=()
    for ((i = 0; i < N; i++)); do
        local skip=0
        for x in "$@"; do [ "$i" = "$x" ] && skip=1; done
        [ $skip = 0 ] && out+=("$i")
    done
    local IFS=,
    echo "${out[*]}"
}

echo "rehearsal on $N nodes ($RPCS), driver $DRIVER, kernel $KERNEL_V2"

# --- 1. the network is up ----------------------------------------------------
phase 1/7 "every node is up, connected and producing blocks"
wait_nodes "network up" --peers 1 --head 2
pass "network up: $N nodes, every node connected, head past 2"

# --- 2. the kernel upgrade ---------------------------------------------------
phase 2/7 "governance proposes kernel_v2; every node switches at the activation height"
REPORT=$(submit_upgrade) || fail "upgrade submission"
echo "$REPORT"
CODE_HASH=$(echo "$REPORT" | sed -n 's/^code hash *//p')
ACTIVATION=$(echo "$REPORT" | sed -n 's/^activation *//p')
[ -n "$CODE_HASH" ] && [ -n "$ACTIVATION" ] || fail "upgrade submission: no code hash or activation height in the report"
wait_nodes "kernel switch" --kernel-version 2 --kernel-hash "$CODE_HASH" --finalized $((ACTIVATION + 2))
pass "kernel switch: every node runs version 2 ($CODE_HASH) and finalized past block $ACTIVATION"

# --- 3. the feature gates ----------------------------------------------------
phase 3/7 "every validator signals the gates $GATES; they lock in and activate everywhere"
wait_nodes "gate signalling" --signalled "$GATES"
pass "gate signalling: every validator's latest signal names gates $GATES"
wait_nodes "gate lock-in" --locked-in "$GATES"
pass "gate lock-in: gates $GATES locked in"
wait_nodes "gate activation" --active-gates "$GATES"
pass "gate activation: gates $GATES active on every node"

# --- 4. a validator stops ----------------------------------------------------
phase 4/7 "validator $STOP_NODE stops; the others keep finalizing"
stop_node "$STOP_NODE" || fail "stopping node $STOP_NODE"
FINALIZED=$(field 0 finalized)
wait_nodes "liveness without node $STOP_NODE" --nodes "$(others "$STOP_NODE")" --finalized $((FINALIZED + 3))
pass "liveness: the other nodes finalized 3 blocks past $FINALIZED without node $STOP_NODE"

# --- 5. it comes back --------------------------------------------------------
phase 5/7 "validator $STOP_NODE restarts with its driver state and catches up"
start_node "$STOP_NODE" || fail "starting node $STOP_NODE"
wait_nodes "catch-up of node $STOP_NODE" --nodes "$STOP_NODE" --peers 1 --kernel-version 2 --active-gates "$GATES" --caught-up
pass "catch-up: node $STOP_NODE runs version 2 with the gates active and is within 2 blocks of the head"

# --- 6. its threshold share still signs --------------------------------------
phase 6/7 "validator $SIGNER_NODE stops: every threshold certificate now needs node $STOP_NODE's share"
stop_node "$SIGNER_NODE" || fail "stopping node $SIGNER_NODE"
# Node $SIGNER_NODE may have signed finalize votes for a couple of blocks past
# the finalized height before it left; the ones four blocks on were proposed
# after, so their certificates hold only the shares of the nodes left.
ABOVE=$(($(field 0 finalized) + 4))
wait_nodes "threshold certificates with node $STOP_NODE's share" --nodes 0 --certified 3 --above "$ABOVE"
pass "threshold share: 3 blocks above $ABOVE carry threshold certificates signed without node $SIGNER_NODE"
FINALIZED=$(field 0 finalized)
start_node "$SIGNER_NODE" || fail "starting node $SIGNER_NODE"
wait_nodes "catch-up of node $SIGNER_NODE" --nodes "$SIGNER_NODE" --caught-up --finalized "$FINALIZED"
pass "catch-up: node $SIGNER_NODE is back within 2 blocks of the head, past $FINALIZED"

# --- 7. nobody voted twice ---------------------------------------------------
phase 7/7 "no validator voted twice in a view across its restart"
# A validator that came back without the votes it had cast could vote again
# in the view it left; every node records such an equivocation (spec 08 §9).
wait_nodes "equivocation check" --no-equivocations
pass "no equivocation: no node recorded an equivocation across the restarts"

summary
