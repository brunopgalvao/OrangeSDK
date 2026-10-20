#!/usr/bin/env bash
# Builds every guest program for the Solo target and prints the ELF paths.
set -euo pipefail
cd "$(dirname "$0")/../guest"
cargo build --release "$@"
OBJCOPY=$(dirname "$(rustup which rustc)")/../lib/rustlib/$(rustc -vV | sed -n "s/host: //p")/bin/rust-objcopy
ls -1 target/riscv64imac-unknown-none-elf/release/hello target/riscv64imac-unknown-none-elf/release/kernel
cp target/riscv64imac-unknown-none-elf/release/hello ../crates/solo-recompile/tests/fixtures/hello.elf
"$OBJCOPY" --strip-debug target/riscv64imac-unknown-none-elf/release/kernel ../crates/solo-node/tests/fixtures/kernel.elf
mkdir -p ../crates/solo-conformance/tests/fixtures
"$OBJCOPY" --strip-debug target/riscv64imac-unknown-none-elf/release/evm-conformance ../crates/solo-conformance/tests/fixtures/evm-conformance.elf
echo "fixtures refreshed"
