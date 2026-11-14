//! End-to-end coverage for the daemon crash log.
//!
//! Unit tests cover formatting and rotation; this exercises the real panic hook,
//! which is the part that has to work when the daemon disappears with no console
//! and no tracing subscriber.

use antiwire_platform::{crash, DataPaths};

/// The panic hook and the data directory are process-wide, so both assertions
/// live in one test: a second test racing to re-point either would flake.
#[test]
fn crashes_are_recorded_beside_the_database() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data_paths = DataPaths::new(dir.path());

    crash::set_data_dir(dir.path());
    crash::install_panic_hook();

    let outcome = std::panic::catch_unwind(|| panic!("crash-log-probe-1729"));
    assert!(outcome.is_err(), "the probe has to panic");

    crash::record_fatal_error("fatal probe: simulated startup failure");

    let log = std::fs::read_to_string(data_paths.crash_log()).expect("crash log beside database");
    assert!(
        log.contains("crash-log-probe-1729"),
        "panic message missing: {log}"
    );
    assert!(log.contains("thread '"), "panicking thread missing: {log}");
    assert!(
        log.contains("backtrace:"),
        "backtrace header missing: {log}"
    );
    assert!(
        log.contains("crash_log.rs"),
        "panic location missing: {log}"
    );
    assert!(
        log.contains("fatal probe: simulated startup failure"),
        "fatal error missing: {log}"
    );
}
