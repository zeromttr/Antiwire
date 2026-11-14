//! Where the daemon's log goes: the console, or, for a process that has
//! none, a file in the data directory.

use std::path::Path;

use antiwire_platform::crash;
use tracing::Level;
use tracing_subscriber::EnvFilter;

/// Sends tracing to the console, or, for a process with none, to its log
/// file in `data_dir`.
pub(crate) fn init_tracing(data_dir: &Path) {
    use tracing_subscriber::fmt::writer::BoxMakeWriter;

    let filter = EnvFilter::builder()
        .with_default_directive(Level::INFO.into())
        .from_env_lossy();
    // Detached children have no console — log to the data directory instead.
    let writer = match detached_log(data_dir) {
        Some(file) => BoxMakeWriter::new(std::sync::Mutex::new(file)),
        None => BoxMakeWriter::new(std::io::stdout),
    };
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_writer(writer)
        .init();
}

/// The log file for a process with no console to log to, or `None` when
/// logging goes to the console.
///
/// Those are the processes that restore host state when nobody is watching:
/// the service, the reaper, the heal helper and the update helper. Without
/// a file their warnings, such as an adapter whose DNS would not restore, are
/// lost. A log that cannot be opened is noted in the crash log, which is all
/// such a process has, and does not stop it.
fn detached_log(data_dir: &Path) -> Option<std::fs::File> {
    let name = detached_log_name()?;
    match open_log(data_dir, name) {
        Ok(file) => Some(file),
        Err(error) => {
            crash::record_error(format_args!(
                "could not open {} in {}: {error}",
                name,
                data_dir.display()
            ));
            None
        }
    }
}

/// Which log a process without a console writes, chosen from the raw
/// arguments: tracing starts before clap has parsed them.
fn detached_log_name() -> Option<&'static str> {
    if crate::update_helper::is_helper_invocation() {
        return Some(crate::update_helper::LOG_FILE);
    }
    // The reaper's standard streams are the null device.
    if has_arg(crate::reaper::REAP_PARENT_FLAG) {
        return Some("reaper.log");
    }
    #[cfg(windows)]
    if has_arg(crate::daemon::windows::detach::DETACHED_CHILD_FLAG) {
        return Some("daemon.log");
    }
    // A service started by the SCM, and the boot heal task, have no console.
    #[cfg(windows)]
    if !has_console_output() {
        return Some(if has_arg(antiwire_dns_redirect::HEAL_HOST_STATE_FLAG) {
            "heal.log"
        } else {
            "daemon.log"
        });
    }
    None
}

fn has_arg(flag: &str) -> bool {
    std::env::args_os().any(|arg| arg == flag)
}

/// Size past which a log is moved aside to `<name>.old` when it is opened.
const LOG_ROTATE_BYTES: u64 = 8 * 1024 * 1024;

/// Opens `name` in `data_dir` for appending, moving it aside first once it
/// has grown past [`LOG_ROTATE_BYTES`].
///
/// # Errors
///
/// When the directory cannot be created, or the file opened. A failed
/// rotation is not an error: the log keeps growing instead.
fn open_log(data_dir: &Path, name: &str) -> std::io::Result<std::fs::File> {
    std::fs::create_dir_all(data_dir)?;
    let path = data_dir.join(name);
    if std::fs::metadata(&path).is_ok_and(|meta| meta.len() > LOG_ROTATE_BYTES) {
        if let Err(error) = std::fs::rename(&path, data_dir.join(format!("{name}.old"))) {
            crash::record_error(format_args!("could not rotate {}: {error}", path.display()));
        }
    }
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
}

/// Whether standard error leads anywhere. A process the SCM or Task
/// Scheduler starts has no standard handles.
#[cfg(windows)]
#[expect(unsafe_code, reason = "FFI call to GetStdHandle")]
fn has_console_output() -> bool {
    use windows::Win32::System::Console::{GetStdHandle, STD_ERROR_HANDLE};
    // SAFETY: `GetStdHandle` only reads this process's standard handle table.
    unsafe { GetStdHandle(STD_ERROR_HANDLE) }
        .is_ok_and(|handle| !handle.is_invalid() && !handle.0.is_null())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_large_log_is_moved_aside_when_opened() {
        use std::io::Write;

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("daemon.log");
        let big = vec![b'x'; usize::try_from(LOG_ROTATE_BYTES).expect("size") + 1];
        std::fs::write(&path, &big).expect("write");

        let mut file = open_log(dir.path(), "daemon.log").expect("open");
        writeln!(file, "fresh").expect("append");

        assert_eq!(std::fs::read_to_string(&path).expect("read"), "fresh\n");
        assert_eq!(
            std::fs::metadata(dir.path().join("daemon.log.old"))
                .expect("old")
                .len(),
            big.len() as u64
        );
    }

    #[test]
    fn opening_a_log_creates_its_directory() {
        let dir = tempfile::tempdir().expect("tempdir");
        let nested = dir.path().join("a").join("b");
        open_log(&nested, "update.log").expect("open");
        assert!(nested.join("update.log").exists());
    }
}
