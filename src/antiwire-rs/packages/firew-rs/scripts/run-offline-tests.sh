#!/usr/bin/env sh
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "Running firew-rs offline tests from $ROOT"

cargo test --manifest-path crates/firew-core/Cargo.toml
cargo test --manifest-path crates/firew-sys/Cargo.toml
cargo test --manifest-path crates/firew-linux/Cargo.toml --lib
cargo test --manifest-path crates/firew-linux/Cargo.toml --test detect_offline
cargo test --manifest-path crates/firew-macos/Cargo.toml --lib

case "$(uname -s)" in
    Linux)
        cargo test --manifest-path crates/firew/Cargo.toml --no-default-features --features linux
        ;;
    Darwin)
        cargo test --manifest-path crates/firew/Cargo.toml --no-default-features --features macos
        ;;
    MINGW*|MSYS*|Windows_NT*)
        cargo test --manifest-path crates/firew/Cargo.toml
        cargo test --manifest-path crates/firew-windows/Cargo.toml --lib
        cargo test --manifest-path crates/firew-windows/Cargo.toml --test rule_naming
        ;;
    *)
        cargo test --manifest-path crates/firew/Cargo.toml
        ;;
esac

echo "firew-rs offline tests completed."
