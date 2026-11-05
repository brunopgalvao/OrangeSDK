#!/usr/bin/env bash
# Downloads the pinned execution-spec-tests fixture set for a full EVM
# conformance run (spec 07 §4.2) into .conformance/ (gitignored) and checks
# its SHA-256. The committed subset in crates/orange-conformance needs nothing
# from here; this is the opt-in run over every state test of the set.
#
#   tools/fetch-conformance.sh
#   cargo run --release -p orange-conformance -- --both \
#     --expected crates/orange-conformance/tests/fixtures/expected-failures.txt \
#     .conformance/fixtures/state_tests
#
# ORANGE_CONFORMANCE_URL and ORANGE_CONFORMANCE_SHA256 select another release
# (both must be given); the runner reads each fixture's Osaka expectations.
set -euo pipefail
cd "$(dirname "$0")/.."
URL=${ORANGE_CONFORMANCE_URL:-https://github.com/ethereum/execution-spec-tests/releases/download/fusaka-devnet-5%40v2.1.0/fixtures_fusaka-devnet-5.tar.gz}
SHA256=${ORANGE_CONFORMANCE_SHA256:-96a39d8eb8de742e450a7e7c63ffb4c2b82187f4fed9c1406f39ff3ef9f53a91}
DIR=.conformance
TAR="$DIR/fixtures.tar.gz"

sha256() {
  if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1
}

mkdir -p "$DIR"
if [ ! -f "$TAR" ] || [ "$(sha256 "$TAR")" != "$SHA256" ]; then
  curl -fL --retry 3 -o "$TAR.part" "$URL"
  GOT=$(sha256 "$TAR.part")
  if [ "$GOT" != "$SHA256" ]; then
    rm -f "$TAR.part"
    echo "SHA-256 mismatch: expected $SHA256, got $GOT" >&2
    exit 1
  fi
  mv "$TAR.part" "$TAR"
fi
rm -rf "$DIR/fixtures"
tar -xzf "$TAR" -C "$DIR" fixtures/state_tests
echo "$(find "$DIR/fixtures/state_tests" -name '*.json' | wc -l | tr -d ' ') fixture files in $DIR/fixtures/state_tests"
