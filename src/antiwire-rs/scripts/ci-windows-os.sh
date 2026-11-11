#!/usr/bin/env bash
# Windows CI for the antiwire-rs workspace. Building once in the test profile
# is substantially faster than checking in the dev profile and recompiling
# selected crates for tests. netmet-rs and firew-rs are separate
# CI jobs (see .github/workflows/ci.yml).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "== antiwire-rs tests =="
cargo test --workspace --all-features
