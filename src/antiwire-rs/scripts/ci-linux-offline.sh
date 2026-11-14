#!/usr/bin/env bash
# Offline Linux CI for the antiwire-rs workspace.
# Windows and macOS run this same full suite (see ci-windows-os.sh /
# ci-macos-os.sh). netmet-rs and firew-rs are separate
# CI jobs (see .github/workflows/ci.yml).
# The local Docker image still runs all three workspaces; GitHub does not.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "== antiwire-rs =="
cargo test --workspace --all-features
