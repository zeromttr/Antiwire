//! Detached process that reverts host state when the daemon dies.
//!
//! Kill, crash, and abort skip `Drop`. This process sits in its own process
//! group, waits until the daemon exits, and then restores DNS, removes the
//! port-53 divert, and removes the firewall rules. With "persist rules
//! offline" set, only the rules that depend on the resolver are removed.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use antiwire_tuning::{REAPER_RETRY_INITIAL_DELAY, REAPER_RETRY_MAX_DELAY};
use anyhow::{Context, Result};

use crate::process_lock::try_daemon_lock;

mod process_exit;

/// The flag that starts a process as the reaper of the pid that follows it.
pub(crate) const REAP_PARENT_FLAG: &str = "--reap-parent";

/// Spawns the reaper for this process.
///
/// # Errors
///
/// When the current executable cannot be located, or the reaper cannot be
/// spawned. A reaper link that cannot be made is not an error: the daemon's
/// own executable runs the reaper instead.
pub fn spawn(data_dir: &Path) -> Result<()> {
    let exe = std::env::current_exe().context("current exe")?;
    let exe = reaper_executable(&exe);
    let pid = std::process::id();
    let mut command = Command::new(exe);
    command
        .arg(REAP_PARENT_FLAG)
        .arg(pid.to_string())
        .arg("--data-dir")
        .arg(data_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    detach(&mut command);
    command.spawn().context("spawn host-state reaper")?;
    Ok(())
}

/// Blocks until `pid` exits, then reverts host state.
///
/// A DNS restore that is not confirmed, or a firewall cleanup that failed, is
/// retried with growing delays until it succeeds, or until a daemon starts:
/// that daemon then owns the recovery, and the reaper exits. The reaper does
/// not give up on its own, because once it exits nothing else retries until
/// the daemon next starts.
///
/// # Errors
///
/// Returns an error when the store cannot be opened for the revert.
pub fn reap(pid: u32, data_dir: &Path) -> Result<()> {
    set_process_name();
    tracing::info!(
        reaper = std::process::id(),
        daemon = pid,
        "host-state reaper waiting for the daemon to exit"
    );
    process_exit::wait_until_dead(pid);
    tracing::info!(daemon = pid, "daemon exited; reverting host state");
    // A replacement daemon may already be running. Reverting now would remove
    // the rules and DNS redirect it just installed. Holding the same lock the
    // daemon uses makes a restart wait until this revert finishes.
    let mut backoff = Backoff::new();
    let instance = loop {
        match try_daemon_lock() {
            Ok(Some(instance)) => break instance,
            Ok(None) => {
                tracing::info!(
                    "host-state reaper left host state alone; another daemon is running"
                );
                return Ok(());
            }
            Err(error) => lock_unavailable(&error, &mut backoff),
        }
    };
    let reverted = antiwire_runtime::revert_orphaned_host_state(data_dir);
    drop(instance);

    let mut pending = reverted.pending;
    let mut backoff = Backoff::new();
    while pending.any() {
        tracing::warn!(
            retry_in = ?backoff.next(),
            dns = pending.dns,
            firewall = pending.firewall,
            "host state is not fully reverted yet; the reaper will retry"
        );
        backoff.wait();
        // Released between attempts so a starting daemon is not kept waiting.
        // Only a held lock hands recovery over; a lock that could not be
        // created says nothing about a daemon, and the host is still dirty.
        let instance = match try_daemon_lock() {
            Ok(Some(instance)) => instance,
            Ok(None) => {
                tracing::info!("a daemon started; it recovers host state from here");
                return reverted.result;
            }
            Err(error) => {
                // The pause at the top of the loop covers this one.
                tracing::warn!(error = %format!("{error:#}"), "could not take the daemon lock; retrying");
                continue;
            }
        };
        pending = antiwire_runtime::retry_orphaned_host_state(data_dir, pending);
        drop(instance);
    }
    tracing::info!("host-state reaper finished");
    reverted.result
}

/// The reaper's pause between attempts, doubling from
/// [`REAPER_RETRY_INITIAL_DELAY`] up to [`REAPER_RETRY_MAX_DELAY`].
struct Backoff(Duration);

impl Backoff {
    const fn new() -> Self {
        Self(REAPER_RETRY_INITIAL_DELAY)
    }

    /// The pause the next [`Self::wait`] takes.
    const fn next(&self) -> Duration {
        self.0
    }

    /// Waits out the pause, then doubles the next one.
    fn wait(&mut self) {
        std::thread::sleep(self.0);
        self.0 = self.0.saturating_mul(2).min(REAPER_RETRY_MAX_DELAY);
    }
}

/// Logs a lock that could not be created and waits out the next pause
/// before the caller tries again.
fn lock_unavailable(error: &anyhow::Error, backoff: &mut Backoff) {
    tracing::warn!(
        error = %format!("{error:#}"),
        retry_in = ?backoff.next(),
        "could not take the daemon lock; retrying"
    );
    backoff.wait();
}

/// File name Task Manager and `ps` show for the reaper.
const REAPER_NAME: &str = "antiwire-reaper";

/// Hard-links the daemon binary as `antiwire-reaper` so the OS reports that name.
///
/// The process image name comes from the executable path. A hard link is the
/// same file, so a rebuild of the daemon is what the reaper runs. When the
/// link cannot be brought up to date, the reaper runs the daemon's own
/// executable instead: under the daemon's name, but never a stale build.
fn reaper_executable(daemon: &Path) -> PathBuf {
    let reaper = daemon.with_file_name(reaper_file_name());
    match link_reaper(daemon, &reaper) {
        Ok(()) => reaper,
        Err(error) => {
            tracing::warn!(
                error = %error,
                "could not link {REAPER_NAME}; the reaper will run as the daemon's executable"
            );
            daemon.to_path_buf()
        }
    }
}

fn reaper_file_name() -> String {
    if cfg!(windows) {
        format!("{REAPER_NAME}.exe")
    } else {
        REAPER_NAME.to_owned()
    }
}

/// Makes `reaper` the same file as `daemon`.
///
/// Nothing is done when it already is. Otherwise a new link is made beside
/// it under a temporary name and renamed over it, so `reaper` is never
/// missing. When the rename fails, for example because a running reaper
/// still holds the old file on Windows, the old file is kept and the error
/// returned.
fn link_reaper(daemon: &Path, reaper: &Path) -> std::io::Result<()> {
    if is_same_file(daemon, reaper) {
        return Ok(());
    }
    let staged =
        reaper.with_file_name(format!("{}.{}.tmp", reaper_file_name(), std::process::id()));
    // A leftover from an earlier run of this pid; the link below needs the name.
    let _ = std::fs::remove_file(&staged);
    std::fs::hard_link(daemon, &staged)?;
    std::fs::rename(&staged, reaper).inspect_err(|_| {
        let _ = std::fs::remove_file(&staged);
    })
}

/// Whether `reaper` is already a link to `daemon`.
///
/// Hard links share one file record, so they report the same size and
/// modification time; a stale build would not.
fn is_same_file(daemon: &Path, reaper: &Path) -> bool {
    let (Ok(daemon), Ok(reaper)) = (std::fs::metadata(daemon), std::fs::metadata(reaper)) else {
        return false;
    };
    daemon.len() == reaper.len()
        && matches!((daemon.modified(), reaper.modified()), (Ok(a), Ok(b)) if a == b)
}

/// Renames the reaper's thread so `ps` shows [`REAPER_NAME`].
///
/// Cosmetic: a rename that fails is logged, and the reaper still waits and
/// reverts.
fn set_process_name() {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let name = reaper_name_buffer();
    #[cfg(target_os = "linux")]
    {
        // SAFETY: `prctl` is variadic and declared so by libc. `PR_SET_NAME`
        // reads a NUL-terminated string of at most 16 bytes, which `name` is.
        let result = unsafe { libc::prctl(libc::PR_SET_NAME, name.as_ptr()) };
        if result != 0 {
            tracing::warn!(
                error = %std::io::Error::last_os_error(),
                "could not rename the reaper"
            );
        }
    }
    #[cfg(target_os = "macos")]
    {
        // SAFETY: `name` is NUL-terminated and within the 64-byte limit.
        let result = unsafe { libc::pthread_setname_np(name.as_ptr().cast()) };
        if result != 0 {
            tracing::warn!(
                error = %std::io::Error::from_raw_os_error(result),
                "could not rename the reaper"
            );
        }
    }
}

/// [`REAPER_NAME`] NUL-terminated in the 16 bytes Linux `comm` holds.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn reaper_name_buffer() -> [u8; 16] {
    const { assert!(REAPER_NAME.len() <= 15, "REAPER_NAME must fit in comm") };
    let mut name = [0u8; 16];
    name[..REAPER_NAME.len()].copy_from_slice(REAPER_NAME.as_bytes());
    name
}

#[cfg(unix)]
fn detach(command: &mut Command) {
    use std::os::unix::process::CommandExt;
    // A new process group survives `kill` of the daemon's group.
    command.process_group(0);
}

#[cfg(windows)]
fn detach(command: &mut Command) {
    antiwire_update::launcher::detach_breakaway(command);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn daemon_build(dir: &Path, contents: &str) -> PathBuf {
        let daemon = dir.join("antiwire-daemon.exe");
        // A rebuild replaces the file, as the linker does, rather than
        // writing through the existing links.
        let _ = std::fs::remove_file(&daemon);
        std::fs::write(&daemon, contents).expect("write daemon");
        daemon
    }

    #[test]
    fn the_reaper_link_is_made_and_follows_a_rebuild() {
        let dir = tempfile::tempdir().expect("tempdir");
        let reaper = dir.path().join("antiwire-reaper.exe");

        let daemon = daemon_build(dir.path(), "build 1");
        link_reaper(&daemon, &reaper).expect("first link");
        assert_eq!(std::fs::read_to_string(&reaper).expect("read"), "build 1");

        std::thread::sleep(std::time::Duration::from_millis(20));
        let daemon = daemon_build(dir.path(), "build two");
        link_reaper(&daemon, &reaper).expect("relink");
        assert_eq!(std::fs::read_to_string(&reaper).expect("read"), "build two");

        let leftovers = std::fs::read_dir(dir.path())
            .expect("list")
            .filter(|entry| {
                entry
                    .as_ref()
                    .is_ok_and(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            })
            .count();
        assert_eq!(leftovers, 0, "no staged link is left behind");
    }

    /// The regression this guards: a failure to replace the link was
    /// reported as success, and the next reaper ran a stale binary, or the
    /// old name was deleted before the new link failed.
    #[cfg(windows)]
    #[test]
    fn a_reaper_link_that_cannot_be_replaced_is_kept_and_reported() {
        use std::os::windows::fs::OpenOptionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let reaper = dir.path().join("antiwire-reaper.exe");
        let daemon = daemon_build(dir.path(), "build 1");
        link_reaper(&daemon, &reaper).expect("first link");

        std::thread::sleep(std::time::Duration::from_millis(20));
        let daemon = daemon_build(dir.path(), "build two");
        // No sharing, as a running image holds its file.
        let held = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(&reaper)
            .expect("hold the old reaper");

        assert!(link_reaper(&daemon, &reaper).is_err());
        drop(held);
        assert_eq!(std::fs::read_to_string(&reaper).expect("read"), "build 1");
        assert_eq!(reaper_executable(&daemon), reaper, "replaced once free");
    }
}
