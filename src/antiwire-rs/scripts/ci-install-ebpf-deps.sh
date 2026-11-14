#!/usr/bin/env bash
# Installs what netmetrics-linux/ebpf/build.sh needs on a GitHub Ubuntu runner: clang, libbpf
# headers, and a working bpftool. Used by the eBPF object build and the elevated Linux netmet-rs
# tests (see .github/workflows/ci.yml).
set -euo pipefail

sudo apt-get update
sudo apt-get install -y --no-install-recommends \
  clang \
  llvm \
  libbpf-dev \
  linux-tools-common \
  linux-tools-generic \
  pkg-config
# Do not install bare `bpftool`: it is a virtual package with no candidate on current Azure
# runner kernels. Their bpftool wrapper often has no matching kernel binary either, so link a
# generic tools payload into place.
if ! /usr/sbin/bpftool -V >/dev/null 2>&1; then
  FALLBACK="$(find /usr/lib -type f -name bpftool -perm -111 2>/dev/null | sort -V | tail -n 1 || true)"
  test -n "$FALLBACK"
  sudo ln -sf "$FALLBACK" /usr/local/bin/bpftool
else
  sudo ln -sf /usr/sbin/bpftool /usr/local/bin/bpftool
fi
bpftool -V
