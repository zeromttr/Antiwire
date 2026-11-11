#!/usr/bin/env bash
# macOS CI for the antiwire-rs workspace. Building once in the test profile
# avoids recompiling selected crates after a separate dev-profile check.
# netmet-rs and firew-rs are separate CI jobs, and the live macOS firewall
# tests run in the firew-rs job (see .github/workflows/ci.yml).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "== antiwire-rs tests =="
cargo test --workspace --all-features
