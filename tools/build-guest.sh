#!/usr/bin/env bash
# Builds every guest program for the Solo target (hello, the kernel, the
# example module and the conformance guest), refreshes the test fixtures and
# prints the ELF paths. The kernel is built twice: as is, and with the
# `upgrade-test` feature, the next kernel version the upgrade tests switch to.
# The example module `counter` (spec 16) becomes the module tests' fixture,
# and the bridge's two modules (spec 18) the bridge tests'. The kernel embeds
# contracts/fixtures/SoloInbox.runtime: run tools/build-contracts.sh first
# when the contracts change.
set -euo pipefail
cd "$(dirname "$0")/../guest"
OBJCOPY=$(dirname "$(rustup which rustc)")/../lib/rustlib/$(rustc -vV | sed -n "s/host: //p")/bin/rust-objcopy
OUT=target/riscv64imac-unknown-none-elf/release
cargo build --release -p kernel --features upgrade-test "$@"
"$OBJCOPY" --strip-debug "$OUT/kernel" ../crates/solo-node/tests/fixtures/kernel_v2.elf
cargo build --release "$@"
ls -1 "$OUT/hello" "$OUT/kernel" "$OUT/counter" "$OUT/eth-light-client" "$OUT/eth-message-verifier" "$OUT/evm-conformance"
cp "$OUT/hello" ../crates/solo-recompile/tests/fixtures/hello.elf
"$OBJCOPY" --strip-debug "$OUT/kernel" ../crates/solo-node/tests/fixtures/kernel.elf
"$OBJCOPY" --strip-debug "$OUT/counter" ../crates/solo-node/tests/fixtures/counter.elf
"$OBJCOPY" --strip-debug "$OUT/eth-light-client" ../crates/solo-node/tests/fixtures/eth-light-client.elf
"$OBJCOPY" --strip-debug "$OUT/eth-message-verifier" ../crates/solo-node/tests/fixtures/eth-message-verifier.elf
mkdir -p ../crates/solo-conformance/tests/fixtures
"$OBJCOPY" --strip-debug "$OUT/evm-conformance" ../crates/solo-conformance/tests/fixtures/evm-conformance.elf
echo "fixtures refreshed"
