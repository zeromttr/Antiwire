//! Best-effort crash log for errors that take the daemon down completely.
//!
//! A daemon that dies as a detached process or a Windows service has no console
//! to print to, and `daemon.log` is only installed on the detached path, so a
//! panic or a fatal startup error otherwise leaves nothing behind. This module
//! appends to `crash.log` in the data directory, next to the database, so the
//! evidence survives the process that produced it.

use std::fmt::Display;
use std::fs;
use std::io::Write;
use std::panic::PanicHookInfo;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock, RwLock};

use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::config::DataPaths;

/// Size of the current crash log at which it is rotated to `crash.log.old`.
///
/// A daemon that crashes on every start would otherwise grow the file without
/// bound; one previous generation is enough to keep the latest crash readable
/// without filling the data directory.
pub const MAX_CRASH_LOG_BYTES: u64 = 1024 * 1024;

/// Serializes writes so entries from several panicking threads do not interleave.
static WRITE_LOCK: Mutex<()> = Mutex::new(());

/// Directory the crash log is written to, set as soon as the daemon resolves it.
static DATA_DIR: RwLock<Option<PathBuf>> = RwLock::new(None);

/// Set once the panic hook has been installed; further installs become no-ops.
static HOOK_INSTALLED: OnceLock<()> = OnceLock::new();

/// Signature of the hook [`std::panic::set_hook`] accepts.
type PanicHook = Box<dyn Fn(&PanicHookInfo<'_>) + Sync + Send>;

/// Panic hook that was in place before this module replaced it, chained for the
/// benefit of anything watching stderr.
static PREVIOUS_HOOK: OnceLock<PanicHook> = OnceLock::new();

/// Points crash logging at the directory that holds the database.
///
/// Calling this more than once is expected: the daemon records an early guess
/// from the environment before argument parsing and replaces it with the
/// resolved `--data-dir` afterwards. Entries written in between land in the
/// early directory.
pub fn set_data_dir(dir: impl AsRef<Path>) {
    if let Ok(mut guard) = DATA_DIR.write() {
        *guard = Some(dir.as_ref().to_path_buf());
    }
}

/// Installs the process-wide panic hook, once.
///
/// The previous hook is called after the crash log entry is written rather than
/// replaced: it is what prints to a console or service debug log, and removing
/// it would change what an operator sees while watching the daemon run.
pub fn install_panic_hook() {
    if HOOK_INSTALLED.set(()).is_err() {
        return;
    }

    let previous = std::panic::take_hook();
    let _ = PREVIOUS_HOOK.set(previous);

    std::panic::set_hook(Box::new(|info| {
        record_entry(&format_panic(info));
        if let Some(previous) = PREVIOUS_HOOK.get() {
            previous(info);
        }
    }));
}

/// Records a fatal error that is about to end the process.
///
/// Use this when `main` returns an error, or before the process exits
/// non-zero for any other reason, so the failure is not only visible on a
/// console that may not exist.
pub fn record_fatal_error(message: impl Display) {
    record_entry(&format!("fatal error: {message}"));
}

/// Records an error the process survives but has nowhere else to report,
/// such as a log file it could not open while it has no console.
pub fn record_error(message: impl Display) {
    record_entry(&format!("error: {message}"));
}

fn record_entry(entry: &str) {
    let dir = DATA_DIR.read().ok().and_then(|guard| guard.clone());
    if let Some(dir) = dir {
        append_entry(&dir, entry);
    }
}

fn append_entry(dir: &Path, entry: &str) {
    // A poisoned lock only means an earlier writer panicked mid-write. The log
    // is append-only, so continuing is safe and preferable to losing a crash.
    let _guard = WRITE_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    let path = DataPaths::new(dir).crash_log();
    rotate_if_needed(&path, MAX_CRASH_LOG_BYTES);

    let timestamp = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "unknown-time".to_owned());

    let written = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .and_then(|mut file| writeln!(file, "[{timestamp}] pid={} {entry}", std::process::id()));

    if written.is_err() {
        // This can run inside a panic hook, where panicking again would abort.
        // A failed write gets a best-effort note on stderr and nothing more.
        let mut stderr = std::io::stderr();
        let _ = writeln!(
            stderr,
            "antiwire: could not append to crash log {}",
            path.display()
        );
    }
}

/// Rotates the log to `crash.log.old` once it is full, dropping the generation
/// before that.
fn rotate_if_needed(path: &Path, max_bytes: u64) {
    let size = fs::metadata(path).map_or(0, |metadata| metadata.len());
    if size < max_bytes {
        return;
    }

    let rotated = rotated_path(path);
    // Windows refuses to rename over an existing file, so the previous
    // generation has to be removed first. Both steps are best-effort: failing
    // to rotate must not stop the crash from being written.
    let _ = fs::remove_file(&rotated);
    let _ = fs::rename(path, &rotated);
}

/// `crash.log` becomes `crash.log.old`, the same way SQLite names its sidecars.
fn rotated_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".old");
    PathBuf::from(name)
}

fn format_panic(info: &PanicHookInfo<'_>) -> String {
    let thread = std::thread::current();
    let thread = thread.name().unwrap_or("<unnamed>");
    let location = info
        .location()
        .map_or_else(|| "<unknown location>".to_owned(), ToString::to_string);
    // Captured unconditionally: a crashing service rarely has `RUST_BACKTRACE`
    // set, and even an unsymbolized trace identifies the failing frame.
    let backtrace = std::backtrace::Backtrace::force_capture();

    format!(
        "panic: thread '{thread}' at {location}\nmessage: {}\nbacktrace:\n{backtrace}",
        payload_message(info.payload())
    )
}

fn payload_message(payload: &(dyn std::any::Any + Send)) -> &str {
    payload
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("<non-string panic payload>")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CRASH_LOG_FILE;
    use tempfile::tempdir;

    #[test]
    fn append_entry_creates_the_log_next_to_the_database() {
        let dir = tempdir().expect("tempdir");
        append_entry(dir.path(), "fatal error: probe");

        let log = fs::read_to_string(dir.path().join(CRASH_LOG_FILE)).expect("crash log");
        assert!(log.contains("fatal error: probe"), "entry missing: {log}");
        assert!(log.contains("pid="), "process id missing: {log}");
    }

    #[test]
    fn append_entry_keeps_previous_entries() {
        let dir = tempdir().expect("tempdir");
        append_entry(dir.path(), "first");
        append_entry(dir.path(), "second");

        let log = fs::read_to_string(dir.path().join(CRASH_LOG_FILE)).expect("crash log");
        assert!(log.contains("first"), "first entry lost: {log}");
        assert!(log.contains("second"), "second entry lost: {log}");
    }

    #[test]
    fn rotate_if_needed_leaves_a_small_log_alone() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join(CRASH_LOG_FILE);
        fs::write(&path, "kept").expect("seed log");

        rotate_if_needed(&path, 1_024);

        assert!(path.exists());
        assert!(!dir.path().join("crash.log.old").exists());
    }

    #[test]
    fn rotate_if_needed_moves_a_full_log_to_the_previous_generation() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join(CRASH_LOG_FILE);
        fs::write(&path, "old evidence").expect("seed log");

        rotate_if_needed(&path, 1);

        assert!(!path.exists(), "full log must be rotated away");
        let rotated =
            fs::read_to_string(dir.path().join("crash.log.old")).expect("rotated crash log");
        assert_eq!(rotated, "old evidence");
    }

    #[test]
    fn rotate_if_needed_replaces_the_previous_generation() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join(CRASH_LOG_FILE);
        fs::write(dir.path().join("crash.log.old"), "older evidence").expect("seed rotated log");
        fs::write(&path, "new evidence").expect("seed log");

        rotate_if_needed(&path, 1);

        let rotated =
            fs::read_to_string(dir.path().join("crash.log.old")).expect("rotated crash log");
        assert_eq!(rotated, "new evidence");
    }

    #[test]
    fn payload_message_reads_static_and_owned_strings() {
        let static_payload: &(dyn std::any::Any + Send) = &"static message";
        assert_eq!(payload_message(static_payload), "static message");

        let owned = String::from("owned message");
        let owned_payload: &(dyn std::any::Any + Send) = &owned;
        assert_eq!(payload_message(owned_payload), "owned message");
    }
}
