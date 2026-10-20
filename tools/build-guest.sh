#!/usr/bin/env bash
# Builds every guest program for the Solo target (hello, the kernel, the
# example module, the two bridge modules and the conformance guest),
# refreshes the test fixtures and prints the ELF paths. The kernel is built
# twice: as is, and with the
# `upgrade-test` feature, the next kernel version the upgrade tests switch to.
# The example module `counter` (spec 16) becomes the module tests' fixture,
# and the bridge's two modules (spec 18) the bridge tests'. The kernel embeds
# contracts/build/EthereumInbox.bin-runtime: run tools/build-contracts.sh first
# when the contracts change.
#
# Reproducible: the fixtures do not depend on where the repository is
# checked out. Cargo hashes the absolute path of a path dependency outside
# the guest workspace (the host crates under crates/) into its crate
# metadata, which steers code generation, so a build in another checkout
# gave other binaries and other gas. The script therefore copies the
# sources to one fixed directory, $BUILD below, and builds there, with
# home-directory paths remapped; a rebuild from any checkout with the same
# toolchain leaves `git status` clean. Builds from several checkouts take
# turns on a lock. The staging directory, target included, is removed at
# the end unless SOLO_GUEST_KEEP=1 keeps it for faster rebuilds.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd -P)
BUILD=/tmp/solo-guest-build
LOCK=$BUILD.lock
until mkdir "$LOCK" 2>/dev/null; do
    echo "waiting for another guest build ($LOCK)" >&2
    sleep 5
done
cleanup() {
    [ "${SOLO_GUEST_KEEP:-0}" = 1 ] || rm -rf "$BUILD"
    rmdir "$LOCK"
}
trap cleanup EXIT
mkdir -p "$BUILD"
rsync -a --delete --exclude /.git --exclude /target --exclude /guest/target \
    --exclude /.downloads --exclude /.conformance --exclude /coverage --exclude /.claude \
    "$ROOT/" "$BUILD/"
cd "$BUILD/guest"
OBJCOPY=$(dirname "$(rustup which rustc)")/../lib/rustlib/$(rustc -vV | sed -n "s/host: //p")/bin/rust-objcopy
REMAP="target.riscv64imac-unknown-none-elf.rustflags=[\"--remap-path-prefix=$HOME=/home\"]"
OUT=target/riscv64imac-unknown-none-elf/release
FIX=$ROOT/crates
cargo build --config "$REMAP" --release -p kernel --features upgrade-test "$@"
"$OBJCOPY" --strip-debug "$OUT/kernel" "$FIX/solo-node/tests/fixtures/kernel_v2.elf"
cargo build --config "$REMAP" --release "$@"
ls -1 "$OUT/hello" "$OUT/kernel" "$OUT/counter" "$OUT/eth-light-client" "$OUT/eth-message-verifier" "$OUT/evm-conformance"
cp "$OUT/hello" "$FIX/solo-recompile/tests/fixtures/hello.elf"
"$OBJCOPY" --strip-debug "$OUT/kernel" "$FIX/solo-node/tests/fixtures/kernel.elf"
"$OBJCOPY" --strip-debug "$OUT/counter" "$FIX/solo-node/tests/fixtures/counter.elf"
"$OBJCOPY" --strip-debug "$OUT/eth-light-client" "$FIX/solo-node/tests/fixtures/eth-light-client.elf"
"$OBJCOPY" --strip-debug "$OUT/eth-message-verifier" "$FIX/solo-node/tests/fixtures/eth-message-verifier.elf"
mkdir -p "$FIX/solo-conformance/tests/fixtures"
"$OBJCOPY" --strip-debug "$OUT/evm-conformance" "$FIX/solo-conformance/tests/fixtures/evm-conformance.elf"
echo "fixtures refreshed"
