//! Waiting for another process to exit on Windows.
//!
//! Waits on the process object rather than probing the pid: it is signaled
//! the moment the process exits, whoever else still holds handles, and
//! holding it pins the process's identity against pid reuse.
//!
//! Only a pid that no longer exists counts as exited. A process that cannot
//! be opened, most often for lack of access, is still running as far as
//! anyone can tell, so the open is retried rather than read as its death.

#![allow(unsafe_code)]

use std::time::{Duration, Instant};

use tracing::warn;
use windows::Win32::Foundation::{
    CloseHandle, ERROR_INVALID_PARAMETER, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows::Win32::System::Threading::{
    OpenProcess, WaitForSingleObject, INFINITE, PROCESS_SYNCHRONIZE,
};

/// First pause before retrying a process that could not be opened or waited on.
const RETRY_INITIAL: Duration = Duration::from_millis(250);
/// Cap on the doubling pause between retries.
const RETRY_MAX: Duration = Duration::from_secs(5);

/// How [`wait_for_exit`] ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessWait {
    /// The process exited, or no process with that pid exists.
    Exited,
    /// `deadline` passed first.
    TimedOut,
}

/// Blocks until the process `pid` exits, or `deadline` passes. `None` waits
/// with no deadline.
///
/// `OpenProcess` reports a pid that does not exist as
/// `ERROR_INVALID_PARAMETER`; that alone counts as exited. Any other open
/// failure, such as `ERROR_ACCESS_DENIED`, is logged and the open retried. A
/// wait that fails closes the handle and reopens it, so it falls back to
/// polling the open instead of spinning on a broken handle.
#[must_use]
pub fn wait_for_exit(pid: u32, deadline: Option<Instant>) -> ProcessWait {
    let mut pause = RETRY_INITIAL;
    let mut reported: Option<String> = None;
    loop {
        // SAFETY: `OpenProcess` only reads its arguments; a returned handle is
        // closed once, below.
        match unsafe { OpenProcess(PROCESS_SYNCHRONIZE, false, pid) } {
            Ok(handle) => {
                let millis = deadline.map_or(INFINITE, |deadline| {
                    let left = deadline.saturating_duration_since(Instant::now());
                    u32::try_from(left.as_millis()).unwrap_or(INFINITE - 1)
                });
                // SAFETY: `handle` is open until the `CloseHandle` below.
                let waited = unsafe { WaitForSingleObject(handle, millis) };
                let error = std::io::Error::last_os_error();
                // SAFETY: `handle` came from a successful `OpenProcess` and is
                // closed exactly once.
                let _ = unsafe { CloseHandle(handle) };
                if waited == WAIT_OBJECT_0 {
                    return ProcessWait::Exited;
                }
                if waited == WAIT_TIMEOUT {
                    return ProcessWait::TimedOut;
                }
                let detail = if waited == WAIT_FAILED {
                    format!("wait failed: {error}")
                } else {
                    format!("wait returned {:#x}", waited.0)
                };
                report(pid, &detail, &mut reported);
            }
            Err(error) if error.code() == ERROR_INVALID_PARAMETER.to_hresult() => {
                return ProcessWait::Exited;
            }
            Err(error) => report(
                pid,
                &format!("cannot open the process: {error}"),
                &mut reported,
            ),
        }
        let Some(pause_for) = pause_before_retry(pause, deadline) else {
            return ProcessWait::TimedOut;
        };
        std::thread::sleep(pause_for);
        pause = pause.saturating_mul(2).min(RETRY_MAX);
    }
}

/// Logs a failure once per distinct cause, so a retry loop does not flood
/// the log.
fn report(pid: u32, detail: &str, reported: &mut Option<String>) {
    if reported.as_deref() != Some(detail) {
        warn!(pid, %detail, "cannot wait on the process yet; retrying");
        *reported = Some(detail.to_owned());
    }
}

/// How long to pause before the next attempt, or `None` once `deadline`
/// has passed.
fn pause_before_retry(pause: Duration, deadline: Option<Instant>) -> Option<Duration> {
    match deadline {
        None => Some(pause),
        Some(deadline) => {
            let left = deadline.saturating_duration_since(Instant::now());
            (!left.is_zero()).then(|| pause.min(left))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};

    fn long_running() -> std::process::Child {
        Command::new("cmd")
            .args(["/c", "ping -n 30 127.0.0.1 >nul"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn")
    }

    #[test]
    fn a_process_that_exits_is_seen_to_exit() {
        let mut child = long_running();
        let pid = child.id();
        let waiter = std::thread::spawn(move || {
            wait_for_exit(pid, Some(Instant::now() + Duration::from_secs(20)))
        });
        child.kill().expect("kill");
        let _ = child.wait();
        assert_eq!(waiter.join().expect("waiter"), ProcessWait::Exited);
    }

    #[test]
    fn a_running_process_times_out() {
        let mut child = long_running();
        let waited = wait_for_exit(
            child.id(),
            Some(Instant::now() + Duration::from_millis(200)),
        );
        let _ = child.kill();
        let _ = child.wait();
        assert_eq!(waited, ProcessWait::TimedOut);
    }

    /// The regression this guards: any failed open, including access denied,
    /// was read as "already exited". The System process (pid 4) never exits,
    /// and an unelevated process cannot open it.
    #[test]
    fn a_process_that_cannot_be_opened_is_not_taken_for_dead() {
        let waited = wait_for_exit(4, Some(Instant::now() + Duration::from_millis(300)));
        assert_eq!(waited, ProcessWait::TimedOut);
    }

    /// No process has this pid, so there is nothing to wait for.
    #[test]
    fn a_pid_that_does_not_exist_has_exited() {
        let waited = wait_for_exit(0xFFFF_FFFC, Some(Instant::now() + Duration::from_secs(5)));
        assert_eq!(waited, ProcessWait::Exited);
    }

    #[test]
    fn retries_stop_at_the_deadline() {
        let past = Instant::now();
        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(pause_before_retry(RETRY_INITIAL, Some(past)), None);
        assert_eq!(pause_before_retry(RETRY_INITIAL, None), Some(RETRY_INITIAL));
        let soon = Instant::now() + Duration::from_millis(50);
        assert!(pause_before_retry(RETRY_MAX, Some(soon))
            .is_some_and(|p| p <= Duration::from_millis(50)));
    }
}
