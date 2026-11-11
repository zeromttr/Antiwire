# antiwire-rs Linux test image
#
# The only way to exercise the Linux code paths from a Windows workstation, and the only way
# to run the privileged Linux tests at all. Covers all three workspaces: antiwire-rs, and the
# nested netmet-rs and firew-rs.
#
# Build from the antiwire-rs root (not the repo root):
#   docker build -f docker/linux-test.Dockerfile -t antiwire-rs-linux-test .
#
# Unprivileged tests (default):
#   docker run --rm antiwire-rs-linux-test
#
# Privileged firewall tests — nftables and iptables need NET_ADMIN:
#   docker run --rm --cap-add=NET_ADMIN antiwire-rs-linux-test live
#
# Build the eBPF CO-RE object — needs host BTF, so mount it read-only:
#   docker run --rm -v /sys/kernel/btf:/sys/kernel/btf:ro antiwire-rs-linux-test ebpf
#
# Load both eBPF objects and assert live successful-send accounting:
#   docker run --rm --cap-add=BPF --cap-add=PERFMON --cap-add=NET_RAW \
#     --security-opt seccomp=unconfined -v /sys/kernel/btf:/sys/kernel/btf:ro \
#     antiwire-rs-linux-test ebpf-live
#
# Everything:
#   docker run --rm --cap-add=NET_ADMIN --cap-add=BPF --cap-add=PERFMON \
#     --cap-add=NET_RAW --security-opt seccomp=unconfined \
#     -v /sys/kernel/btf:/sys/kernel/btf:ro antiwire-rs-linux-test all
#
# CI uses PRECOMPILE=live so the image only builds firew live-test binaries (offline
# suites already ran on the host). Local full images use the default PRECOMPILE=all.

# 1.90 is the antiwire-rs MSRV; it also covers netmet-rs and firew-rs.
FROM rust:1.90-bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        # firew-linux live tests drive these directly
        iptables \
        nftables \
        iproute2 \
        # capsh, used by the entrypoint to report a missing NET_ADMIN clearly
        libcap2-bin \
        # runtime-loaded libpcap backend used by antiwire-capture
        libpcap-dev \
        # eBPF CO-RE object build for netmetrics-linux
        clang \
        llvm \
        libbpf-dev \
        bpftool \
        ca-certificates \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

# rusqlite is vendored ("bundled") and protoc is supplied by protoc-bin-vendored, so no
# system SQLite, OpenSSL, or protobuf packages are required.

WORKDIR /src
COPY . /src

ENV RUST_BACKTRACE=1

# `all` precompiles every workspace (local offline/all use). `live` only builds the
# privileged firew tests so CI fits on GitHub's ~14GB runners.
ARG PRECOMPILE=all
RUN set -eu; \
    case "$PRECOMPILE" in \
      live) \
        cargo test --manifest-path packages/firew-rs/Cargo.toml \
          -p firew-linux --test live_linux --no-run; \
        cargo test --manifest-path packages/firew-rs/Cargo.toml \
          -p firew-rs --test integration --no-default-features --features linux --no-run; \
        ;; \
      all) \
        cargo test --workspace --all-features --no-run; \
        cargo test --manifest-path packages/netmet-rs/Cargo.toml --workspace --all-features --no-run; \
        cargo test --manifest-path packages/firew-rs/Cargo.toml --workspace --all-features --no-run; \
        ;; \
      *) \
        echo "unknown PRECOMPILE=$PRECOMPILE (expected live|all)" >&2; \
        exit 2; \
        ;; \
    esac; \
    # Drop download/src caches that are not needed to re-run already-built tests.
    rm -rf /usr/local/cargo/registry/src \
           /usr/local/cargo/git/checkouts \
           /tmp/*; \
    find /src -type d -name incremental -prune -exec rm -rf {} +

COPY docker/linux-test-entrypoint.sh /entrypoint.sh
RUN sed -i 's/\r$//' /entrypoint.sh && chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["offline"]
