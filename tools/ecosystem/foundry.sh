#!/usr/bin/env bash
# The Foundry half of the ecosystem suite: cast and forge against a running
# OrangeSDK node, as a developer drives them by hand or from a deploy pipeline.
#
# usage: ORANGE_RPC=http://127.0.0.1:8545 tools/ecosystem/foundry.sh
#
# The node must run the suite's genesis (genesis.json: chain id 1337, the
# key 0x01…01 funded, a 1 gwei base-fee floor). Needs cast, forge and jq;
# forge fetches solc 0.8.28 on first use. Exits non-zero on the first check
# that fails, saying which.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd -P)
export ETH_RPC_URL=${ORANGE_RPC:-http://127.0.0.1:8545}
CHAIN_ID=${ORANGE_CHAIN_ID:-1337}
KEY=0x0101010101010101010101010101010101010101010101010101010101010101
FUNDED=0x1a642f0E3c3aF545E7AcBD38b07251B3990914F1
# A fresh account for each run, so a rerun against the same node starts clean.
USER_KEY=0x$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')
USER=$(cast wallet address "$USER_KEY")
DEAD=0x000000000000000000000000000000000000dEaD
# Fail fast rather than retry: a refused request is a finding.
export FOUNDRY_DISABLE_NIGHTLY_WARNING=1

step() { printf '\n== %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
expect_eq() { [ "$1" = "$2" ] || fail "$3: expected '$2', got '$1'"; }
# The number a cast output starts with (cast appends "[1e18]" to big values).
num() { awk '{print $1}' <<<"$1"; }

cd "$HERE"

step "chain id and blocks"
expect_eq "$(cast chain-id)" "$CHAIN_ID" "cast chain-id"
first=$(cast block-number)
for _ in $(seq 50); do
    [ "$(cast block-number)" -gt "$first" ] && break
    sleep 0.2
done
[ "$(cast block-number)" -gt "$first" ] || fail "the head did not move from $first"
latest=$(cast block latest --json)
hash=$(jq -r .hash <<<"$latest")
number=$(cast to-dec "$(jq -r .number <<<"$latest")")
expect_eq "$(cast block "$hash" --json | jq -r .number | xargs cast to-dec)" "$number" "block by hash"
parent=$(cast block $((number - 1)) --json | jq -r .hash)
expect_eq "$(jq -r .parentHash <<<"$latest")" "$parent" "parent hash"
cast block finalized --json | jq -e '.number' >/dev/null || fail "no finalized block"
[ "$(cast base-fee)" -ge 1000000000 ] || fail "base fee below the genesis floor"
[ "$(cast gas-price)" -gt 0 ] || fail "zero gas price"
cast rpc eth_maxPriorityFeePerGas >/dev/null
cast rpc eth_feeHistory 4 latest '[25,75]' | jq -e '.baseFeePerGas | length == 5' >/dev/null \
    || fail "eth_feeHistory"

step "balance and nonce"
[ "$(cast balance "$FUNDED" --ether | cut -d. -f1)" -gt 1000 ] || fail "funded balance"
nonce=$(cast nonce "$FUNDED")
expect_eq "$(cast nonce "$FUNDED" --block pending)" "$nonce" "pending nonce"

step "EIP-1559 transfer"
receipt=$(cast send --private-key "$KEY" "$USER" --value 2ether --json)
expect_eq "$(jq -r .status <<<"$receipt")" 0x1 "transfer status"
expect_eq "$(jq -r .type <<<"$receipt")" 0x2 "transfer type"
expect_eq "$(cast balance "$USER")" 2000000000000000000 "recipient balance"
expect_eq "$(cast tx "$(jq -r .transactionHash <<<"$receipt")" --json | jq -r .type)" 0x2 "tx type"

step "legacy EIP-155 transaction"
receipt=$(cast send --private-key "$USER_KEY" --legacy "$DEAD" --value 1 --json)
expect_eq "$(jq -r .status <<<"$receipt")" 0x1 "legacy status"
expect_eq "$(jq -r .type <<<"$receipt")" 0x0 "legacy type"
tx=$(cast tx "$(jq -r .transactionHash <<<"$receipt")" --json)
expect_eq "$(cast to-dec "$(jq -r .chainId <<<"$tx")")" "$CHAIN_ID" "legacy chain id"

step "forge create"
created=$(forge create --broadcast --json --private-key "$KEY" contracts/Token.sol:Token \
    --constructor-args 1000000000000000000000000)
TOKEN=$(jq -r .deployedTo <<<"$created")
[ "$(cast code "$TOKEN" | wc -c)" -gt 100 ] || fail "no code at $TOKEN"
expect_eq "$(cast call "$TOKEN" 'symbol()(string)')" '"STT"' "symbol"
expect_eq "$(num "$(cast call "$TOKEN" 'totalSupply()(uint256)')")" 1000000000000000000000000 "supply"
expect_eq "$(cast storage "$TOKEN" 0 | cast to-dec)" 1000000000000000000000000 "storage slot 0"
cast proof "$TOKEN" 0 | jq -e '.storageProof | length == 1' >/dev/null || fail "eth_getProof"

step "gas estimation, a transfer and its event"
gas=$(cast estimate --from "$FUNDED" "$TOKEN" 'transfer(address,uint256)' "$USER" 1000)
{ [ "$gas" -gt 21000 ] && [ "$gas" -lt 100000 ]; } || fail "estimate $gas"
receipt=$(cast send --private-key "$KEY" "$TOKEN" 'transfer(address,uint256)' "$USER" 1000 --json)
expect_eq "$(jq -r .status <<<"$receipt")" 0x1 "token transfer status"
[ "$(cast to-dec "$(jq -r .gasUsed <<<"$receipt")")" -le "$gas" ] || fail "used more than estimated"
expect_eq "$(num "$(cast call "$TOKEN" 'balanceOf(address)(uint256)' "$USER")")" 1000 "token balance"
from_block=$(cast to-dec "$(jq -r .blockNumber <<<"$receipt")")
logs=$(cast logs --json --address "$TOKEN" --from-block 0 'Transfer(address indexed,address indexed,uint256)')
expect_eq "$(jq length <<<"$logs")" 2 "Transfer logs"
logs=$(cast logs --json --address "$TOKEN" --from-block "$from_block" \
    'Transfer(address indexed,address indexed,uint256)' "" "$USER")
expect_eq "$(jq length <<<"$logs")" 1 "Transfer logs to the user"

step "cast run: Foundry's EVM replays the block and agrees on gas"
# cast run forks the chain at the block's parent (historical state, spec 20
# §5), replays the transactions before it and traces this one: the gas its
# own EVM charges must be what the kernel charged.
used=$(cast to-dec "$(jq -r .gasUsed <<<"$receipt")")
out=$(cast run "$(jq -r .transactionHash <<<"$receipt")" 2>&1) || fail "cast run: $out"
expect_eq "$(sed -n 's/^Gas used: //p' <<<"$out")" "$used" "gas of the replay"

step "revert reasons"
selector=$(cast sig 'InsufficientBalance(address,uint256,uint256)')
out=$(cast call --from "$USER" "$TOKEN" 'transfer(address,uint256)' "$DEAD" 2000 2>&1) \
    && fail "a transfer above the balance succeeded"
grep -q "execution reverted" <<<"$out" || fail "custom error: $out"
grep -qi "${selector#0x}" <<<"$out" || fail "custom error data missing: $out"
out=$(cast estimate --from "$USER" "$TOKEN" 'transferFrom(address,address,uint256)' "$FUNDED" "$USER" 1 2>&1) \
    && fail "a transferFrom without allowance estimated"
grep -q "allowance exceeded" <<<"$out" || fail "revert string: $out"
# Sent with a gas limit, so that no estimate refuses it first: it is mined
# and fails.
receipt=$(cast send --private-key "$USER_KEY" --gas-limit 100000 "$TOKEN" \
    'transfer(address,uint256)' "$DEAD" 2000 --json)
expect_eq "$(jq -r .status <<<"$receipt")" 0x0 "a reverted transaction's status"

step "forge script: several transactions of one sender at once"
out=$(PRIVATE_KEY=$KEY RECIPIENT=$USER forge script script/Deploy.s.sol:Deploy \
    --broadcast --rpc-url "$ETH_RPC_URL" --json 2>&1) || fail "forge script: $out"
run=broadcast/Deploy.s.sol/$CHAIN_ID/run-latest.json
expect_eq "$(jq '.receipts | length' "$run")" 4 "forge script receipts"
expect_eq "$(jq -r '[.receipts[].status] | unique | join(",")' "$run")" 0x1 "forge script statuses"
SCRIPTED=$(jq -r '.transactions[0].contractAddress' "$run")
expect_eq "$(num "$(cast call "$SCRIPTED" 'balanceOf(address)(uint256)' "$USER")")" 3000000000000000000 "scripted transfers"
expect_eq "$(num "$(cast call "$SCRIPTED" 'allowance(address,address)(uint256)' "$FUNDED" "$USER")")" 3000000000000000000 "scripted approval"

printf '\nfoundry: all checks passed\n'
