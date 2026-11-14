//! Locks that keep two Antiwire processes from doing the same work at once:
//! the daemon's single-instance lock, which the reaper and the heal also
//! take, and the update helper's lock.
//!
//! Each is released when its holder drops it or exits, however it exits, and
//! a process the holder starts never inherits it: the daemon starts its
//! reaper while it holds the daemon lock.
//!
//! Windows uses a named mutex, through `single_instance`. Linux and macOS
//! take a `flock` on a file in a directory only root can write, `/run` and
//! `/var/run`, and the file itself is readable by root only.
//!
//! Not `single_instance` on Unix. On Linux it binds an abstract socket, which
//! has no permissions, so any local user could bind the name first: the
//! reaper and the heal would then take the daemon for running and revert
//! nothing. Its socket is not close-on-exec either, so the reaper inherited
//! it and found the lock still held once the daemon died. On macOS it names
//! the file relative to the working directory, which under launchd is the
//! read-only root volume.
//!
//! A `flock` needs only an open file, read-only or not, so the file must not
//! be readable by other users: they could otherwise hold the lock too.

use std::time::Duration;

use anyhow::{Context, Result};

/// The daemon's single-instance lock. The reaper and the heal take it too,
/// so no daemon starts while they revert host state.
const DAEMON_LOCK: &str = if cfg!(windows) {
    "Global\\AntiwireDaemonMutex"
} else {
    "antiwire-daemon"
};

/// How long a starting daemon waits for [`DAEMON_LOCK`].
///
/// The host-state reaper holds it while it reverts DNS and firewall rules
/// after the previous daemon exits. A service restart can land inside that
/// window, and failing at once would leave the service stopped, so the daemon
/// waits for the revert to finish instead.
const DAEMON_LOCK_WAIT: Duration = Duration::from_secs(30);
/// How often the lock is retried while waiting.
const DAEMON_LOCK_POLL: Duration = Duration::from_millis(250);

/// The daemon lock, or `None` while a daemon (or a reaper or heal reverting
/// for one) holds it.
///
/// # Errors
///
/// When the lock cannot be created or checked.
pub(crate) fn try_daemon_lock() -> Result<Option<ProcessLock>> {
    ProcessLock::try_acquire(DAEMON_LOCK).context("create single-instance guard")
}

/// Waits up to [`DAEMON_LOCK_WAIT`] for the daemon lock, for a starting
/// daemon.
///
/// # Errors
///
/// When the lock cannot be created, or another daemon still holds it.
pub(crate) async fn wait_for_daemon_lock() -> Result<ProcessLock> {
    let deadline = tokio::time::Instant::now() + DAEMON_LOCK_WAIT;
    loop {
        if let Some(lock) = try_daemon_lock()? {
            return Ok(lock);
        }
        if tokio::time::Instant::now() >= deadline {
            anyhow::bail!("another instance of antiwire-daemon is already running");
        }
        tokio::time::sleep(DAEMON_LOCK_POLL).await;
    }
}

/// Runs `f` while holding the daemon lock, so no daemon starts until it
/// returns. `None`, without running `f`, while a daemon holds the lock: that
/// daemon owns the host state.
///
/// For one attempt at a time. A caller that retries releases the lock in
/// between, so a starting daemon, which waits only so long for the lock, is
/// not kept waiting through the pauses.
///
/// # Errors
///
/// When the lock cannot be created or checked.
pub(crate) fn while_no_daemon<R>(f: impl FnOnce() -> R) -> Result<Option<R>> {
    let Some(lock) = try_daemon_lock()? else {
        return Ok(None);
    };
    let result = f();
    drop(lock);
    Ok(Some(result))
}

/// A held lock. Dropping it releases the lock.
pub(crate) struct ProcessLock {
    #[cfg(windows)]
    _held: single_instance::SingleInstance,
    #[cfg(unix)]
    _held: std::fs::File,
}

impl ProcessLock {
    /// Takes the lock named `name`, or returns `None` while another holder
    /// has it.
    ///
    /// # Errors
    ///
    /// When the lock cannot be created or checked. That says nothing about
    /// whether another process holds it.
    pub(crate) fn try_acquire(name: &str) -> Result<Option<Self>> {
        imp::try_acquire(name).map(|held| held.map(|held| Self { _held: held }))
    }
}

#[cfg(windows)]
mod imp {
    use anyhow::{Context, Result};
    use single_instance::SingleInstance;

    /// The mutex handle is not inheritable, so a child never holds it.
    pub(super) fn try_acquire(name: &str) -> Result<Option<SingleInstance>> {
        let lock = SingleInstance::new(name).with_context(|| format!("create lock {name}"))?;
        Ok(lock.is_single().then_some(lock))
    }
}

#[cfg(unix)]
mod imp {
    use std::fs::{File, OpenOptions, Permissions, TryLockError};
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    use std::path::PathBuf;

    use anyhow::{Context, Result};

    /// Only the owner, root, may open a lock file.
    const LOCK_MODE: u32 = 0o600;

    /// Where the lock files live. Only root can write here, so no other user
    /// can create a lock file first. Tests use the temporary directory
    /// instead.
    fn lock_dir() -> PathBuf {
        if cfg!(test) {
            std::env::temp_dir()
        } else if cfg!(target_os = "macos") {
            PathBuf::from("/var/run")
        } else {
            PathBuf::from("/run")
        }
    }

    pub(super) fn try_acquire(name: &str) -> Result<Option<File>> {
        let path = lock_dir().join(format!("{name}.lock"));
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(LOCK_MODE)
            .open(&path)
            .with_context(|| format!("open lock {}", path.display()))?;
        // `mode` applies only when the file is created, and through the
        // umask; a file left by an earlier build may be readable by others.
        file.set_permissions(Permissions::from_mode(LOCK_MODE))
            .with_context(|| format!("restrict lock {}", path.display()))?;
        match file.try_lock() {
            Ok(()) => Ok(Some(file)),
            Err(TryLockError::WouldBlock) => Ok(None),
            Err(TryLockError::Error(error)) => {
                Err(error).with_context(|| format!("lock {}", path.display()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A lock name no other test or process uses.
    fn unique_name(test: &str) -> String {
        format!("antiwire-lock-test-{}-{test}", std::process::id())
    }

    /// The environment variable that turns [`lock_probe_child`] into a probe
    /// of the lock it names.
    const PROBE_ENV: &str = "ANTIWIRE_LOCK_PROBE";
    const PROBE_ACQUIRED: i32 = 10;
    const PROBE_BUSY: i32 = 11;

    /// Run by [`another_process_sees_a_held_lock_as_busy`] in a child
    /// process: tries the lock named by [`PROBE_ENV`] and exits with what it
    /// found. Does nothing in an ordinary run.
    #[test]
    #[ignore = "a helper process for another test"]
    fn lock_probe_child() {
        let Ok(name) = std::env::var(PROBE_ENV) else {
            return;
        };
        let code = match ProcessLock::try_acquire(&name) {
            Ok(Some(_)) => PROBE_ACQUIRED,
            Ok(None) => PROBE_BUSY,
            Err(_) => 1,
        };
        std::process::exit(code);
    }

    /// How long a lock that was just released may still look held.
    ///
    /// A `flock` belongs to the open file, not to the descriptor. A child
    /// process starts out with a copy of every descriptor its parent has
    /// open, and loses the close-on-exec ones only when it starts its
    /// program. These tests run in parallel and several start children, so
    /// a lock one test releases can stay held for that moment by another
    /// test's child, which never asked for it.
    ///
    /// Much shorter than [`long_running_child`] lives: a child that really
    /// kept the lock still has it when this runs out.
    const RELEASE_SETTLES_WITHIN: Duration = Duration::from_secs(5);

    /// Asks `free` until it says the lock is free, or a lock just released
    /// has had time to stop looking held. Returns its last answer.
    fn once_released<T>(mut attempt: impl FnMut() -> T, free: impl Fn(&T) -> bool) -> T {
        let deadline = std::time::Instant::now() + RELEASE_SETTLES_WITHIN;
        loop {
            let answer = attempt();
            if free(&answer) || std::time::Instant::now() >= deadline {
                return answer;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// [`probe_from_another_process`] for a lock that was just released.
    fn probe_once_released(name: &str) -> i32 {
        once_released(
            || probe_from_another_process(name),
            |probed| *probed != PROBE_BUSY,
        )
    }

    /// Whether a separate process finds the lock named `name` busy.
    fn probe_from_another_process(name: &str) -> i32 {
        let status = std::process::Command::new(std::env::current_exe().expect("test binary"))
            .args([
                "--exact",
                "process_lock::tests::lock_probe_child",
                "--ignored",
                "--test-threads=1",
            ])
            .env(PROBE_ENV, name)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .expect("run the probe");
        status.code().expect("the probe exits with a code")
    }

    /// Daemons, reapers, heals and update helpers are separate processes;
    /// this is the exclusion they rely on.
    #[test]
    fn another_process_sees_a_held_lock_as_busy() {
        let name = unique_name("busy");
        let held = ProcessLock::try_acquire(&name)
            .expect("create")
            .expect("free");
        assert_eq!(probe_from_another_process(&name), PROBE_BUSY);

        drop(held);
        assert_eq!(probe_once_released(&name), PROBE_ACQUIRED);
    }

    /// A child that outlives the test's checks, standing in for the reaper.
    fn long_running_child() -> std::process::Child {
        #[cfg(windows)]
        let mut command = {
            let mut command = std::process::Command::new("cmd");
            command.args(["/c", "ping -n 30 127.0.0.1 >nul"]);
            command
        };
        #[cfg(unix)]
        let mut command = {
            let mut command = std::process::Command::new("sleep");
            command.arg("30");
            command
        };
        command
            .stdout(std::process::Stdio::null())
            .spawn()
            .expect("spawn child")
    }

    /// The regression this guards: on Linux the lock was once a socket
    /// without close-on-exec, so a process started while it was held, the
    /// reaper above all, kept it once its holder let go. The reaper then
    /// found the daemon lock still held, by its own copy, and reverted
    /// nothing.
    #[test]
    fn a_child_started_while_the_lock_is_held_does_not_keep_it() {
        let name = unique_name("inherit");
        let held = ProcessLock::try_acquire(&name)
            .expect("create")
            .expect("free");
        let mut child = long_running_child();
        drop(held);

        let probed = probe_once_released(&name);
        let _ = child.kill();
        let _ = child.wait();
        assert_eq!(probed, PROBE_ACQUIRED, "the child kept the lock");
    }

    /// The regression this guards: the reaper and the heal release the lock
    /// between attempts and take it again. On macOS the lock could not be
    /// taken again in the same process, however long it waited.
    #[test]
    fn a_released_lock_can_be_taken_again() {
        let name = unique_name("again");
        for attempt in 0..3 {
            let held = once_released(
                || ProcessLock::try_acquire(&name).expect("create"),
                Option::is_some,
            );
            assert!(held.is_some(), "attempt {attempt} found the lock busy");
        }
    }

    /// The regression this guards: a lock file other users could open let
    /// them hold the daemon lock, since `flock` needs only a read-only file.
    #[cfg(unix)]
    #[test]
    fn a_lock_file_only_its_owner_can_open() {
        use std::os::unix::fs::PermissionsExt;

        let name = unique_name("mode");
        let path = std::env::temp_dir().join(format!("{name}.lock"));
        std::fs::write(&path, b"").expect("an earlier lock file");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
            .expect("make it readable by others");

        let held = ProcessLock::try_acquire(&name)
            .expect("create")
            .expect("free");
        let mode = std::fs::metadata(&path).expect("stat").permissions().mode();
        drop(held);
        let _ = std::fs::remove_file(&path);
        assert_eq!(mode & 0o777, 0o600);
    }
}
