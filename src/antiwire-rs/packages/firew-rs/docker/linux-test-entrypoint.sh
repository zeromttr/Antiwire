#!/bin/sh
set -eu

MODE="${1:-offline}"
ROOT="/src"

cd "$ROOT"

run_offline() {
    cargo test --manifest-path crates/firew-core/Cargo.toml
    cargo test --manifest-path crates/firew-sys/Cargo.toml
    cargo test --manifest-path crates/firew/Cargo.toml --no-default-features --features linux
    cargo test --manifest-path crates/firew-linux/Cargo.toml --test detect_offline
}

run_live() {
    cargo test --manifest-path crates/firew-linux/Cargo.toml --test live_linux \
        -- --ignored --test-threads=1 --nocapture
    cargo test --manifest-path crates/firew/Cargo.toml --test integration \
        --no-default-features --features linux \
        -- --ignored --test-threads=1 --nocapture
}

case "$MODE" in
    offline)
        run_offline
        ;;
    live)
        run_offline
        run_live
        ;;
    *)
        echo "usage: $0 [offline|live]" >&2
        exit 2
        ;;
esac
