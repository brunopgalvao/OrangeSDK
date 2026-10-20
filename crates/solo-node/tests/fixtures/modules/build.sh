#!/usr/bin/env bash
# Regenerates Caller.bin (creation code) and Caller.runtime (deployed code),
# both hex without 0x, from Caller.sol. The module itself, counter.elf, comes
# from tools/build-guest.sh.
# Usage: build.sh <path to solc 0.8.28>
set -euo pipefail
cd "$(dirname "$0")"
SOLC=${1:?usage: build.sh <path to solc 0.8.28>}
"$SOLC" --version | grep -q "0\.8\.28" || { echo "need solc 0.8.28" >&2; exit 1; }
OUT=$(mktemp -d)
"$SOLC" --bin --bin-runtime --metadata-hash none -o "$OUT" --overwrite Caller.sol
tr -d '\n' < "$OUT/Caller.bin" > Caller.bin
tr -d '\n' < "$OUT/Caller.bin-runtime" > Caller.runtime
rm -r "$OUT"
echo "fixtures refreshed"
