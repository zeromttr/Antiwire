#!/usr/bin/env bash
# The elevated tests of one suite (daemon, netmet or firew) on a Linux or macOS CI runner, and
# nothing else: each is an #[ignore]d test the guides list as needing root. Cargo builds as the
# runner's user and runs each test binary through `sudo -E`, so target/ stays the user's. Only a
# dispatch of ci.yml with `elevated` runs this. On Linux the firew-rs tests run in the Linux
# image instead (the firew-live job); Windows uses docker/windows-test-entrypoint.ps1.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

SUITE="${1:?usage: ci-elevated-unix.sh daemon|netmet|firew}"
NETMET="packages/netmet-rs/Cargo.toml"
FIREW="packages/firew-rs/Cargo.toml"
EBPF="packages/netmet-rs/crates/netmetrics-linux/ebpf"
FLAGS=(--ignored --test-threads=1 --nocapture)

HOST="$(rustc -vV | sed -n 's/^host: //p')"
export "CARGO_TARGET_$(echo "$HOST" | tr '[:lower:]-' '[:upper:]_')_RUNNER=sudo -E"

run() {
  echo "== $1 =="
  shift
  cargo test "$@"
}

case "$SUITE:$(uname -s)" in
  daemon:*)
    run "antiwire-enforce live firewall" -p antiwire-enforce --test live_firewall -- "${FLAGS[@]}"
    run "antiwire-enforce shutdown" -p antiwire-enforce --lib -- firew::shutdown_tests "${FLAGS[@]}"
    run "antiwire-capture live capture" -p antiwire-capture --test live_capture -- "${FLAGS[@]}"
    run "antiwire-dns-redirect live redirect" -p antiwire-dns-redirect --test live_redirect -- "${FLAGS[@]}"
    ;;
  netmet:Linux)
    bash ./scripts/ci-install-ebpf-deps.sh
    (cd "$EBPF" && sh ./build.sh)
    export NETMETRICS_BPF_OBJECT="$ROOT/$EBPF/netmetrics.bpf.o"
    export NETMETRICS_DNS_FILTER_OBJECT="$ROOT/$EBPF/dns_filter.bpf.o"
    RECOVERY=elevated_ebpf_that_cannot_start_falls_back_and_takes_over
    run "netmetrics eBPF live" --manifest-path "$NETMET" -p netmetrics --test native_linux \
      --all-features -- --skip "$RECOVERY" "${FLAGS[@]}"
    # Nothing is at the path the collector is given, so eBPF cannot start until the test
    # installs the object there.
    (
      export NETMETRICS_BPF_OBJECT_TO_INSTALL="$NETMETRICS_BPF_OBJECT"
      INSTALL_DIR="$(mktemp -d)"
      trap 'rm -rf "$INSTALL_DIR"' EXIT
      export NETMETRICS_BPF_OBJECT="$INSTALL_DIR/netmetrics.bpf.o"
      run "netmetrics eBPF fallback and recovery" --manifest-path "$NETMET" -p netmetrics \
        --test native_linux --all-features -- "$RECOVERY" --exact "${FLAGS[@]}"
    )
    run "netmetrics endpoint owner" --manifest-path "$NETMET" -p netmetrics --test endpoint_owner \
      -- "${FLAGS[@]}"
    run "netmetrics native Unix" --manifest-path "$NETMET" -p netmetrics --test native_unix \
      -- "${FLAGS[@]}"
    # The divert is installed with nft, which a runner image does not have to carry.
    test -x /usr/sbin/nft || sudo apt-get install -y --no-install-recommends nftables
    run "netmetrics port 53 divert" --manifest-path "$NETMET" -p netmetrics --test dns_divert \
      -- "${FLAGS[@]}"
    ;;
  netmet:Darwin)
    export NETMETRICS_PKTAP_INTERFACE=pktap0
    run "netmetrics endpoint owner" --manifest-path "$NETMET" -p netmetrics --test endpoint_owner \
      -- "${FLAGS[@]}"
    run "netmetrics native Unix" --manifest-path "$NETMET" -p netmetrics --test native_unix \
      -- "${FLAGS[@]}"
    # A name no interface cloner matches, so PKTAP cannot start and the host is not changed.
    (
      export NETMETRICS_PKTAP_INTERFACE=nmnocapture0
      run "netmetrics PKTAP fallback" --manifest-path "$NETMET" -p netmetrics \
        --test pktap_fallback -- "${FLAGS[@]}"
    )
    run "netmetrics port 53 divert" --manifest-path "$NETMET" -p netmetrics --test dns_divert \
      -- "${FLAGS[@]}"
    ;;
  firew:Darwin)
    run "firew-macos live" --manifest-path "$FIREW" -p firew-macos --test live_macos -- "${FLAGS[@]}"
    run "firew integration live" --manifest-path "$FIREW" -p firew-rs --test integration \
      --no-default-features --features macos -- "${FLAGS[@]}"
    ;;
  *)
    echo "error: no elevated $SUITE tests run here on $(uname -s)" >&2
    exit 2
    ;;
esac
