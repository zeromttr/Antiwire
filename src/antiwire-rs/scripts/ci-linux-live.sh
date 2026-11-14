#!/usr/bin/env bash
# Privileged Linux CI tier — requires CAP_NET_ADMIN (nftables / iptables).
# Local/Docker helper; GitHub Actions runs the same coverage via
# docker/linux-test-entrypoint.sh (see the firew-live job in .github/workflows/ci.yml).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if command -v capsh >/dev/null 2>&1; then
  if ! capsh --print 2>/dev/null | grep -q 'cap_net_admin'; then
    echo "error: live tests need CAP_NET_ADMIN" >&2
    exit 2
  fi
fi

echo "== firew-linux live =="
cargo test --manifest-path packages/firew-rs/Cargo.toml -p firew-linux --test live_linux \
  -- --ignored --test-threads=1 --nocapture

echo "== firew integration live =="
cargo test --manifest-path packages/firew-rs/Cargo.toml -p firew-rs --test integration \
  --no-default-features --features linux \
  -- --ignored --test-threads=1 --nocapture
