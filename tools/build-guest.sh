#!/usr/bin/env bash
# Builds every guest program for the Solo target and prints the ELF paths.
set -euo pipefail
cd "$(dirname "$0")/../guest"
cargo build --release "$@"
ls -1 target/riscv64imac-unknown-none-elf/release/hello
