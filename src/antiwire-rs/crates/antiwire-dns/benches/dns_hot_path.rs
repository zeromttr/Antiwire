//! Manual DNS hot-path benchmark harness.
//!
//! Run with:
//! `cargo bench -p antiwire-dns --features bench-internals --bench dns_hot_path`
//!
//! Pass group names after `--` to run only those: `hot`, `attribution`, `listener`,
//! `upstream`, `failover`, `verdicts`, or the opt-in `upstream-live`.
fn main() {
    antiwire_dns::bench_support::run();
}
