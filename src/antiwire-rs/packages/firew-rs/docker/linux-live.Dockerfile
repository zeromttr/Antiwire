# Privileged Linux live-test image for firew-rs.
#
# Build from the firew-rs package root:
#   docker build -f docker/linux-live.Dockerfile -t firew-rs-linux-live .
#
# Run live tests (requires NET_ADMIN):
#   docker run --rm --cap-add=NET_ADMIN firew-rs-linux-live

FROM rust:1.90-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    iptables \
    nftables \
    iproute2 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . /src

COPY docker/linux-test-entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["live"]
