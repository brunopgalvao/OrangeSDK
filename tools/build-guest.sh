#!/usr/bin/env bash
# Builds every guest program for the Solo target (hello, the kernel and the
# conformance guest), refreshes the test fixtures and prints the ELF paths.
# The kernel is built twice: as is, and with the `upgrade-test` feature, the
# next kernel version the upgrade tests switch to.
set -euo pipefail
cd "$(dirname "$0")/../guest"
OBJCOPY=$(dirname "$(rustup which rustc)")/../lib/rustlib/$(rustc -vV | sed -n "s/host: //p")/bin/rust-objcopy
OUT=target/riscv64imac-unknown-none-elf/release
cargo build --release -p kernel --features upgrade-test "$@"
"$OBJCOPY" --strip-debug "$OUT/kernel" ../crates/solo-node/tests/fixtures/kernel_v2.elf
cargo build --release "$@"
ls -1 "$OUT/hello" "$OUT/kernel" "$OUT/evm-conformance"
cp "$OUT/hello" ../crates/solo-recompile/tests/fixtures/hello.elf
"$OBJCOPY" --strip-debug "$OUT/kernel" ../crates/solo-node/tests/fixtures/kernel.elf
mkdir -p ../crates/solo-conformance/tests/fixtures
"$OBJCOPY" --strip-debug "$OUT/evm-conformance" ../crates/solo-conformance/tests/fixtures/evm-conformance.elf
echo "fixtures refreshed"
