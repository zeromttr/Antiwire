# firew-rs Linux integration test image
#
# Build from the firew-rs package root:
#   docker build -f docker/linux-test.Dockerfile -t firew-rs-linux-test .
#
# Run offline tests only:
#   docker run --rm firew-rs-linux-test offline
#
# Run privileged live firewall tests (requires NET_ADMIN):
#   docker run --rm --cap-add=NET_ADMIN firew-rs-linux-test live

FROM rust:1.90-bookworm AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        iptables \
        nftables \
        iproute2 \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . /src

ENV RUST_BACKTRACE=1

# Offline crate tests (always run in CI image build).
RUN cargo test --manifest-path crates/firew-core/Cargo.toml \
    && cargo test --manifest-path crates/firew-sys/Cargo.toml \
    && cargo test --manifest-path crates/firew/Cargo.toml --no-default-features --features linux \
    && cargo test --manifest-path crates/firew-linux/Cargo.toml --test detect_offline

FROM builder AS runtime

WORKDIR /src

COPY docker/linux-test-entrypoint.sh /entrypoint.sh
RUN sed -i 's/\r$//' /entrypoint.sh && chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["offline"]
