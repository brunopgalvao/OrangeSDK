# The solo host, built once in release mode, with the committed kernel
# fixtures: every service of docker-compose.yml runs this image.
#
#   docker build -f ops/Dockerfile -t solo:devnet .
#
# The build context is the repository root (see .dockerignore). The
# toolchain is the one rust-toolchain.toml pins; RUSTUP_TOOLCHAIN names it
# so that rustup does not fetch the RISC-V and wasm targets the host build
# does not need.
FROM rust:1.95-bookworm AS build
ENV RUSTUP_TOOLCHAIN=1.95.0
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p solo-cli

FROM debian:bookworm-slim
COPY --from=build /src/target/release/solo /usr/local/bin/solo
# The reference kernel (version 1) and the kernel the upgrade rehearsal
# switches to (version 2), as the tests pin them.
COPY --from=build /src/crates/solo-node/tests/fixtures/kernel.elf /solo/kernel.elf
COPY --from=build /src/crates/solo-node/tests/fixtures/kernel_v2.elf /solo/kernel_v2.elf
EXPOSE 8545 30333
ENTRYPOINT ["solo"]
CMD ["doctor"]
