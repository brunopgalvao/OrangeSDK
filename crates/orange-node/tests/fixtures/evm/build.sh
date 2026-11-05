#!/usr/bin/env bash
# Regenerates the bytecode fixtures from Contracts.sol: <Name>.bin is the
# creation code and <Name>.runtime the deployed code, both hex without 0x.
# Usage: build.sh <path to solc 0.8.28>
set -euo pipefail
cd "$(dirname "$0")"
SOLC=${1:?usage: build.sh <path to solc 0.8.28>}
"$SOLC" --version | grep -q "0\.8\.28" || { echo "need solc 0.8.28" >&2; exit 1; }
OUT=$(mktemp -d)
trap 'rm -rf "$OUT"' EXIT
"$SOLC" --bin --bin-runtime --metadata-hash none -o "$OUT" --overwrite Contracts.sol
for name in Store Probe Factory Doomed; do
  tr -d '\n' < "$OUT/$name.bin" > "$name.bin"
  tr -d '\n' < "$OUT/$name.bin-runtime" > "$name.runtime"
done
echo "fixtures refreshed"
