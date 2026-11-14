#!/usr/bin/env bash
# Builds the release daemon for Linux on the runner's architecture, against an old glibc.
#
#   scripts/build-linux-daemon.sh        (from the repository root; release.yml, packages.yml)
#
# A binary runs on the glibc it was built against and on every newer one, so the build
# happens in a container of the oldest distribution the packages support, not on the runner.
# AlmaLinux 9 has glibc 2.34, which also covers Ubuntu 22.04 (2.35) and Debian 12 (2.36).
# The toolchain is the one the workflow installed on the runner, so the version is written
# once. Leaves src/antiwire-rs/target/release/antiwire-daemon, and fails if it needs a newer
# glibc than GLIBC_MAX.
set -euo pipefail

IMAGE=almalinux:9
GLIBC_MAX=2.34
RUST_VERSION="$(rustc --version | awk '{print $2}')"
DAEMON=src/antiwire-rs/target/release/antiwire-daemon

# The key is compiled into the daemon; `-e NAME` passes it only when the caller set it.
docker run --rm \
  -e ANTIWIRE_UPDATE_PUBLIC_KEY \
  -e RUST_BACKTRACE=1 \
  -e RUST_VERSION="$RUST_VERSION" \
  -e OWNER="$(id -u):$(id -g)" \
  -v "$PWD:/repo" \
  -w /repo/src/antiwire-rs \
  "$IMAGE" bash -euo pipefail -c '
    # The container builds as root; hand target/ back to the runner user whatever happens.
    trap "chown -R \"$OWNER\" /repo/src/antiwire-rs/target" EXIT
    # gcc for the C sources crates compile (SQLite, ring) and clang for bindgen.
    dnf install -y --setopt=install_weak_deps=False gcc gcc-c++ make clang >/dev/null
    curl --proto "=https" --tlsv1.2 --fail --silent --show-error https://sh.rustup.rs |
      sh -s -- -y --profile minimal --default-toolchain "$RUST_VERSION"
    . "$HOME/.cargo/env"
    cargo build --release -p antiwire-daemon
  '

NEEDS="$(objdump -T "$DAEMON" | grep -o 'GLIBC_[0-9.]*' | sed 's/^GLIBC_//' | sort -u -V | tail -n 1)"
if [ "$(printf '%s\n' "$NEEDS" "$GLIBC_MAX" | sort -V | tail -n 1)" != "$GLIBC_MAX" ]; then
  echo "error: $DAEMON needs glibc $NEEDS, newer than the $GLIBC_MAX the packages promise" >&2
  exit 1
fi
echo "antiwire-daemon needs glibc $NEEDS (limit $GLIBC_MAX)"
