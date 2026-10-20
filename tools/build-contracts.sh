#!/usr/bin/env bash
# Compiles the Solidity contracts in contracts/ with solc 0.8.28 and refreshes
# the committed fixtures in contracts/build: for each contract its init code
# (`.bin`), runtime code (`.bin-runtime`) and ABI (`.abi`), and SOURCES, the
# sha256 of every source. The Rust tests run the fixtures on revm and fail when
# a source no longer matches SOURCES, so a stale fixture never passes.
#
# CI has no solc; run this wherever solc 0.8.28 is installed after changing a
# contract. SOLC names the binary, or it is looked up on PATH and in the
# Hardhat compiler cache.
set -euo pipefail
cd "$(dirname "$0")/../contracts"
VERSION=0.8.28
if [ -z "${SOLC:-}" ]; then
  for candidate in "$(command -v solc || true)" "$HOME"/Library/Caches/hardhat-nodejs/compilers-v2/*/solc-*-v$VERSION+commit.* "$HOME"/.cache/hardhat-nodejs/compilers-v2/*/solc-*-v$VERSION+commit.*; do
    if [ -x "$candidate" ] && "$candidate" --version | grep -q "Version: $VERSION+"; then
      SOLC=$candidate
      break
    fi
  done
fi
if [ -z "${SOLC:-}" ] || ! "$SOLC" --version | grep -q "Version: $VERSION+"; then
  echo "solc $VERSION not found; set SOLC" >&2
  exit 1
fi
SOURCES=$(find . -name '*.sol' | sed 's|^\./||' | LC_ALL=C sort)
rm -rf build
mkdir build
# shellcheck disable=SC2086
"$SOLC" --optimize --optimize-runs 200 --evm-version cancun --metadata-hash none \
  --base-path . --bin --bin-runtime --abi -o build $SOURCES
# Interfaces have no code.
find build -name '*.bin*' -empty -delete
# shellcheck disable=SC2086
shasum -a 256 $SOURCES > build/SOURCES
ls -1 build
