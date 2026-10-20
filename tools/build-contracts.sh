#!/usr/bin/env bash
# Compiles the bridge contracts in contracts/ with solc 0.8.28 and refreshes
# their committed fixtures in contracts/fixtures: for each contract,
# <Name>.bin (creation code), <Name>.runtime (deployed code), both hex
# without 0x, and <Name>.abi.json; and sources.sha256, the SHA-256 of every
# source file. A test (crates/solo-ethlc/tests/contracts.rs) fails when a
# source no longer matches its recorded hash, so stale fixtures cannot pass.
# Usage: tools/build-contracts.sh [path to solc 0.8.28]
set -euo pipefail
cd "$(dirname "$0")/../contracts"
SOLC=${1:-$(ls "$HOME"/Library/Caches/hardhat-nodejs/compilers-v2/*/solc-*-v0.8.28+* 2>/dev/null | head -n 1)}
[ -n "$SOLC" ] || { echo "usage: build-contracts.sh <path to solc 0.8.28>" >&2; exit 1; }
"$SOLC" --version | grep -q "0\.8\.28" || { echo "need solc 0.8.28" >&2; exit 1; }
SOURCES=(IEthereumLightClient.sol IMessageVerifier.sol EthereumOutbox.sol SoloInbox.sol test/MessageRecipient.sol)
CONTRACTS=(EthereumOutbox.sol:EthereumOutbox SoloInbox.sol:SoloInbox test/MessageRecipient.sol:MessageRecipient)
OUT=$(mktemp -d)
trap 'rm -rf "$OUT"' EXIT
for c in "${CONTRACTS[@]}"; do
    file=${c%%:*}
    name=${c##*:}
    "$SOLC" --optimize --optimize-runs 200 --metadata-hash none --bin --bin-runtime --abi -o "$OUT/$name" --overwrite "$file" >/dev/null
    tr -d '\n' < "$OUT/$name/$name.bin" > "fixtures/$name.bin"
    tr -d '\n' < "$OUT/$name/$name.bin-runtime" > "fixtures/$name.runtime"
    cp "$OUT/$name/$name.abi" "fixtures/$name.abi.json"
done
: > fixtures/sources.sha256
for s in "${SOURCES[@]}"; do
    shasum -a 256 "$s" >> fixtures/sources.sha256
done
echo "fixtures refreshed"
