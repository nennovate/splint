# check=skip=InvalidDefaultArgInFrom
# A host and Postgres in one image, so one container's limit is shared by both, as on a small server.
# Build it through server.py, which passes the version from packages/rust-toolchain.toml.
ARG RUST_VERSION

FROM rust:${RUST_VERSION}-bookworm AS build
WORKDIR /build
COPY . .
# docker build can't mount a named volume, so the cache lives in named cache mounts. A code change
# then recompiles only what changed, and an unchanged tree doesn't reach this step at all.
# Every worktree shares that cache and cargo goes by file times, so the touch makes the workspace
# compile from this tree's source. Dependencies stay cached.
RUN --mount=type=cache,id=splint-test-cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=splint-test-cargo-target,target=/build/target,sharing=locked \
    find . -path ./target -prune -o -type f -exec touch {} + \
    && cargo build --release --locked -p host -p signet --features host/test-network,signet/test-network \
    && install -D -t /out target/release/host target/release/signet

# The same major version as sim/e2e.py, on the same Debian as the build so the binaries' libc matches.
FROM postgres:16-bookworm
COPY --from=build /out/ /usr/local/bin/
COPY --from=scripts --chmod=755 start-server.sh /usr/local/bin/start-server
RUN useradd --create-home splint
EXPOSE 8080
CMD ["start-server"]
