#!/usr/bin/env bash
# Rehearses the launch and operation of a multi-operator testnet on this
# machine, with the tooling of ops/testnet and every "host" a directory and
# a set of loopback ports:
#
#   1. the ceremony: N operators each generate a key in their own directory
#      and export a signed card; a coordinator assembles the genesis from
#      the template, the cards and a governance key; every operator
#      verifies it against the published hash, and a tampered copy fails;
#   2. deploy: an inventory of N validators, an RPC node and a late joiner,
#      all `local` hosts; orange-ops installs the binary, pushes the
#      configuration and keys, checks it on every host, and `--dry-run`
#      prints what it would run over ssh for the same hosts;
#   3. start the validators and the RPC node, wait until every host is
#      healthy and they agree on a finalized block;
#   4. the late joiner starts on an empty data directory and joins from the
#      peers' snapshots (spec 22 §7.4), trusting the group key two
#      validators report, and catches up;
#   5. a kernel upgrade by the governance key, every node switching;
#   6. a rolling restart of every host, each healthy and caught up before
#      the next, then health, agreement and no equivocation anywhere;
#   7. a steady-state window (SOAK seconds, 120 by default) under a light
#      load of value transfers when `cast` is installed (LOAD=0 turns it
#      off): each node's RSS, CPU, p2p bytes and data growth per second and
#      per block; then teardown.
#
# usage: tools/rehearse-testnet.sh [work dir]
#
# Environment: ORANGE_BIN (default target/release/orange, built if missing),
# VALIDATORS (4), SLOT_MS (400), EPOCH_BLOCKS (40), DKG_PHASE_BLOCKS (5),
# P2P_PORT (31301), RPC_PORT (18545), SOAK (120), LOAD (1), KEEP=1 to keep
# the work directory.
# Prints a PASS or FAIL line per phase; exits non-zero on the first failure,
# stopping every node it started.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd -P)
OPS=$ROOT/ops/testnet/orange-ops
ORANGE=${ORANGE_BIN:-$ROOT/target/release/orange}
KERNEL=$ROOT/crates/orange-node/tests/fixtures/kernel.elf
KERNEL_V2=$ROOT/crates/orange-node/tests/fixtures/kernel_v2.elf
N=${VALIDATORS:-4}
SLOT_MS=${SLOT_MS:-400}
EPOCH=${EPOCH_BLOCKS:-40}
DKG=${DKG_PHASE_BLOCKS:-5}
P2P=${P2P_PORT:-31301}
RPC=${RPC_PORT:-18545}
CHAIN_ID=${CHAIN_ID:-424242}
WORK=${1:-$(mktemp -d "${TMPDIR:-/tmp}/orange-testnet.XXXXXX")}
mkdir -p "$WORK"
WORK=$(cd "$WORK" && pwd -P)
INV=$WORK/inventory
export ORANGE_OPS_LOCAL=$WORK/hosts
# A loaded machine: the doctor's defaults are a real host's.
export ORANGE_DOCTOR_ARGS=${ORANGE_DOCTOR_ARGS:---max-head-age 60 --max-call-ms 60000}
export ORANGE_OPS_TIMEOUT=${ORANGE_OPS_TIMEOUT:-300}

STARTED=$(date +%s)
log() { printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*"; }
pass() { printf 'PASS %s\n' "$*"; }
fail() {
    printf 'FAIL %s\n' "$*" >&2
    exit 1
}
ops() { "$OPS" --inventory "$INV" "$@"; }

cleanup() {
    local status=$?
    [ -z "${LOAD_PID:-}" ] || kill "$LOAD_PID" 2>/dev/null || true
    if [ -f "$INV" ]; then
        ops stop >/dev/null 2>&1 || true
    fi
    # Nothing of this rehearsal's may outlive it.
    pkill -f "$WORK/hosts/" 2>/dev/null || true
    if [ "$status" -ne 0 ]; then
        echo "--- last log lines of every host" >&2
        for f in "$WORK"/hosts/*/var/log/orange/node.log; do
            [ -f "$f" ] || continue
            echo "== $f" >&2
            tail -n 15 "$f" >&2
        done
        echo "work directory kept: $WORK" >&2
    elif [ "${KEEP:-0}" != 1 ]; then
        rm -rf "$WORK"
    else
        echo "work directory kept: $WORK"
    fi
    exit "$status"
}
trap cleanup EXIT

for tool in jq curl; do command -v "$tool" >/dev/null || fail "$tool is required"; done
if [ ! -x "$ORANGE" ]; then
    log "building $ORANGE"
    (cd "$ROOT" && cargo build --release -p orange-cli)
fi

rpc_of() { echo "127.0.0.1:$((RPC + $1))"; }
p2p_of() { echo "127.0.0.1:$((P2P + $1))"; }
ALL_RPCS=
for i in $(seq 0 $((N + 1))); do ALL_RPCS+="${ALL_RPCS:+,}$(rpc_of "$i")"; done
VALIDATOR_RPCS=
for i in $(seq 0 $((N - 1))); do VALIDATOR_RPCS+="${VALIDATOR_RPCS:+,}$(rpc_of "$i")"; done

# --- 1. the ceremony --------------------------------------------------------

log "ceremony: $N operators, chain id $CHAIN_ID"
CARDS=()
for i in $(seq 0 $((N - 1))); do
    dir=$WORK/operators/op-$i
    mkdir -p "$dir"
    "$ORANGE" key generate --out "$dir/validator.key" >/dev/null
    "$ORANGE" genesis operator --key-file "$dir/validator.key" --name "op-$i" \
        --chain-id "$CHAIN_ID" --p2p "$(p2p_of "$i")" --out "$dir/card.json" >/dev/null
    # Only the card leaves the operator's directory.
    cp "$dir/card.json" "$WORK/operators/card-$i.json"
    CARDS+=(--operator "$WORK/operators/card-$i.json")
done
coord=$WORK/coordinator
mkdir -p "$coord" "$WORK/network"
"$ORANGE" key generate --out "$coord/governance.key" >/dev/null
governance=$("$ORANGE" key --key-file "$coord/governance.key" | awk '$1 == "address" { print $2 }')
jq --argjson id "$CHAIN_ID" --argjson t "$(date +%s)" --arg gov "$governance" \
    --argjson slot "$SLOT_MS" --argjson epoch "$EPOCH" --argjson dkg "$DKG" '
    .chainId = $id | .timestamp = $t | .slotMs = $slot | .governance = $gov
    | .alloc[$gov] = "1000000000000000000000" | .upgradeDelay = 4 | .epochBlocks = $epoch
    | .staking.epochBlocks = $epoch | .staking.dkgPhaseBlocks = $dkg
    | .staking.unbondingEpochs = 4 | .staking.maxKeyAge = 2' \
    "$ROOT/ops/testnet/genesis-template.json" >"$coord/template.json"
said=$("$ORANGE" genesis assemble --template "$coord/template.json" --kernel "$KERNEL" \
    "${CARDS[@]}" --out "$WORK/network/genesis.json")
HASH=${said##* }
echo "$HASH" >"$WORK/network/genesis.hash"
cp "$KERNEL" "$WORK/network/kernel.elf"
[ "$(jq -r .name "$WORK/network/genesis.json")" = tangerine ] || fail "ceremony: the genesis is not named tangerine"
for i in $(seq 0 $((N - 1))); do
    "$ORANGE" genesis verify --genesis "$WORK/network/genesis.json" --kernel "$WORK/network/kernel.elf" \
        --hash "$HASH" --key-file "$WORK/operators/op-$i/validator.key" "${CARDS[@]}" >/dev/null ||
        fail "ceremony: operator $i does not verify the genesis"
done
jq '.slotMs = 401' "$WORK/network/genesis.json" >"$WORK/tampered.json"
if "$ORANGE" genesis verify --genesis "$WORK/tampered.json" --kernel "$KERNEL" --hash "$HASH" >/dev/null 2>&1; then
    fail "ceremony: a tampered genesis verifies"
fi
pass "ceremony: $N keys and cards, genesis tangerine $HASH assembled and verified by every operator; a tampered copy refused"

# --- 2. deploy ----------------------------------------------------------------

"$ORANGE" key generate --out "$coord/rpc-1.key" >/dev/null
"$ORANGE" key generate --out "$coord/late-1.key" >/dev/null
{
    echo "# The rehearsal's hosts: directories under $WORK/hosts."
    for i in $(seq 0 $((N - 1))); do
        echo "val-$i validator local $(p2p_of "$i") $(rpc_of "$i") key=$WORK/operators/op-$i/validator.key"
    done
    echo "rpc-1 rpc local $(p2p_of "$N") $(rpc_of "$N") key=$coord/rpc-1.key public-rpc=1"
    echo "late-1 rpc local $(p2p_of $((N + 1))) $(rpc_of $((N + 1))) key=$coord/late-1.key join=sync trust=$(rpc_of 0),$(rpc_of 1)"
} >"$INV"
ops install --binary "$ORANGE" >/dev/null
ops configure --network "$WORK/network" | grep -c "configuration ok" | grep -qx $((N + 2)) ||
    fail "deploy: check-config did not pass on every host"
# The same hosts over ssh, printed and not run.
sed 's/ local / orange@198.51.100.1 /' "$INV" >"$WORK/inventory.ssh"
dry=$("$OPS" --dry-run --inventory "$WORK/inventory.ssh" configure --network "$WORK/network" 2>/dev/null)
grep -q "scp -q -o BatchMode=yes" <<<"$dry" && grep -q "sudo.*/opt/orange/bin/orange-host.*check-config" <<<"$dry" ||
    fail "deploy: --dry-run over ssh does not print the scp and ssh steps"
"$OPS" --inventory "$INV" render "$WORK/rendered" >/dev/null
grep -q "127.0.0.1:$RPC" "$WORK/rendered/prometheus.yml" || fail "deploy: prometheus.yml lacks the nodes"
pass "deploy: binary, genesis, kernel, keys and node.env on $((N + 2)) hosts, check-config ok; ssh dry run and prometheus.yml rendered"

# --- 3. the network starts ------------------------------------------------------

FIRST="val-0"
for i in $(seq 1 $((N - 1))); do FIRST+=",val-$i"; done
FIRST+=",rpc-1"
ops --hosts "$FIRST" start >/dev/null
"$OPS" --inventory "$INV" --hosts "$FIRST" wait-healthy 300 >"$WORK/health-1.txt" ||
    fail "start: not every host became healthy: $(cat "$WORK/health-1.txt")"
pass "start: $N validators and rpc-1 healthy, $(tail -n 1 "$WORK/health-1.txt")"

# --- 4. the late joiner ---------------------------------------------------------

log "waiting for a second epoch's snapshot and an adopted threshold key"
"$ORANGE" devnet wait --rpc "$VALIDATOR_RPCS" --finalized $((2 * EPOCH + 8)) --timeout 600 >/dev/null ||
    fail "join: the validators did not finalize two epochs"
until "$ORANGE" snapshot trust-key --rpc "$(rpc_of 0),$(rpc_of 1)" >/dev/null 2>&1; do sleep 1; done
JOINED_AT=$(date +%s)
ops --hosts late-1 start >/dev/null
joined=0
for _ in $(seq 1 3); do
    if "$ORANGE" devnet wait --rpc "$ALL_RPCS" --caught-up --timeout 240 >/dev/null 2>&1; then
        joined=1
        break
    fi
    # The key may have rotated between asking and fetching: the node stops,
    # and a start asks again, as systemd's restart would.
    ops --hosts late-1 start >/dev/null || true
done
[ "$joined" = 1 ] || fail "join: late-1 did not catch up"
grep -q "fetched from peers and imported" "$WORK/hosts/late-1/var/log/orange/node.log" ||
    fail "join: late-1 caught up without a snapshot"
pass "join: late-1 fetched a snapshot from its peers and caught up in $(($(date +%s) - JOINED_AT))s ($(grep -m1 'fetched from peers' "$WORK/hosts/late-1/var/log/orange/node.log" | sed 's/ fetched.*//'))"

# --- 5. a kernel upgrade ---------------------------------------------------------

"$ORANGE" upgrade --rpc "$(rpc_of 0)" --key-file "$coord/governance.key" --kernel "$KERNEL_V2" >"$WORK/upgrade.txt" ||
    fail "upgrade: $(cat "$WORK/upgrade.txt")"
"$ORANGE" devnet wait --rpc "$ALL_RPCS" --kernel-version 2 --timeout 300 >/dev/null ||
    fail "upgrade: not every node switched to kernel version 2"
pass "upgrade: every node runs kernel version 2 ($(tail -n 1 "$WORK/upgrade.txt"))"

# --- 6. a rolling restart -----------------------------------------------------------

ops rolling-restart >"$WORK/rolling.txt" 2>&1 || fail "rolling restart: $(tail -n 5 "$WORK/rolling.txt")"
ops wait-healthy 300 >"$WORK/health-2.txt" || fail "rolling restart: $(cat "$WORK/health-2.txt")"
"$ORANGE" devnet wait --rpc "$ALL_RPCS" --no-equivocations --caught-up --kernel-version 2 --timeout 120 >/dev/null ||
    fail "rolling restart: an equivocation, or a node behind"
pass "rolling restart: $((N + 2)) hosts one at a time, $(tail -n 1 "$WORK/health-2.txt"), no equivocation"

# --- 7. resources and teardown -----------------------------------------------------

# A steady-state window of SOAK seconds after the restart, under a light
# load of value transfers from the governance account when `cast` is here:
# each node's CPU time, p2p bytes and data growth over the window, per
# second and per block, and its RSS at the end.
SOAK=${SOAK:-120}
seconds_of() { # ps time ([[dd-]hh:]mm:ss[.xx]) in seconds
    awk -F'[:-]' '{ s = 0; for (i = 1; i <= NF; i++) s = s * 60 + $i; print s }' <<<"$1"
}
value_of() { sed -n "s/.* $1=\([^ ]*\).*/\1/p" <<<" $2"; }
sample() { ops resources >"$1"; }
head_now() { "$ORANGE" devnet status --rpc "$(rpc_of 0)" --json | jq '.[0].head'; }
sample "$WORK/res-0.txt"
H0=$(head_now)
LOAD_PID=
SENT=$WORK/sent.txt
: >"$SENT"
if command -v cast >/dev/null && [ "${LOAD:-1}" != 0 ]; then
    gov_key=0x$(tr -d '[:space:]' <"$coord/governance.key")
    (
        while :; do
            cast send --async --private-key "$gov_key" --rpc-url "http://$(rpc_of 0)" \
                0x000000000000000000000000000000000000dEaD --value 1 >/dev/null 2>&1 && echo >>"$SENT"
            sleep 0.2
        done
    ) &
    LOAD_PID=$!
fi
log "soak: ${SOAK}s${LOAD_PID:+ under a load of value transfers}"
sleep "$SOAK"
[ -z "$LOAD_PID" ] || kill "$LOAD_PID" 2>/dev/null || true
sample "$WORK/res-1.txt"
H1=$(head_now)
BLOCKS=$((H1 - H0))
TXS=$(wc -l <"$SENT" | tr -d ' ')
[ "$BLOCKS" -gt 0 ] || fail "soak: no block in ${SOAK}s"
{
    printf 'steady state over %ss: %s blocks (slot %s ms), %s transactions sent\n' "$SOAK" "$BLOCKS" "$SLOT_MS" "$TXS"
    printf '%-8s %8s %10s %12s %12s %12s %12s %10s\n' node rss_mib cpu_pct in_B/s out_B/s in_B/block out_B/block data_KiB/h
    while read -r before; do
        name=$(value_of name "$before")
        after=$(grep "name=$name " "$WORK/res-1.txt")
        cpu_ms=$(awk -v a="$(seconds_of "$(value_of cpu "$after")")" -v b="$(seconds_of "$(value_of cpu "$before")")" 'BEGIN { printf "%d", (a - b) * 1000 }')
        in=$(($(value_of p2p_in_bytes "$after" | cut -d. -f1) - $(value_of p2p_in_bytes "$before" | cut -d. -f1)))
        out=$(($(value_of p2p_out_bytes "$after" | cut -d. -f1) - $(value_of p2p_out_bytes "$before" | cut -d. -f1)))
        data=$(($(value_of data_kib "$after") - $(value_of data_kib "$before")))
        printf '%-8s %8d %10s %12d %12d %12d %12d %10d\n' "$name" $(($(value_of rss_kib "$after") / 1024)) \
            "$(awk -v ms="$cpu_ms" -v s="$SOAK" 'BEGIN { printf "%.1f", ms / 10 / s }')" \
            $((in / SOAK)) $((out / SOAK)) $((in / BLOCKS)) $((out / BLOCKS)) $((data * 3600 / SOAK))
    done <"$WORK/res-0.txt"
} | tee "$WORK/measurements.txt"
pass "soak: ${SOAK}s steady state measured, $BLOCKS blocks"

ops stop >/dev/null
sleep 1
if pgrep -f "$WORK/hosts/" >/dev/null; then fail "teardown: a node is still running"; fi
pass "teardown: every node stopped after $(($(date +%s) - STARTED))s"
