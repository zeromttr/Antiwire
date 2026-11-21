//! The `com.antiwire.daemon` launchd job on macOS.
//!
//! The job has `KeepAlive`, so it cannot simply be killed: launchd would start
//! the old binary again at once. A stop is a `bootout` (which unloads the job),
//! a repoint rewrites `ProgramArguments` in the plist while it is unloaded, and
//! a start is a `bootstrap` of that plist. Only tools that ship with macOS are
//! used: `launchctl` and `plutil`.

use std::path::Path;
#[cfg(target_os = "macos")]
use std::{
    ffi::OsStr,
    path::PathBuf,
    process::{Command, Output},
    time::{Duration, Instant},
};

#[cfg(target_os = "macos")]
use super::{DaemonService, POLL_INTERVAL};
use crate::UpdateError;

/// The job label, as installed by `packaging/macos/install.sh`.
#[cfg(target_os = "macos")]
pub const LABEL: &str = "com.antiwire.daemon";

/// The job's plist, as installed by `packaging/macos/install.sh`.
#[cfg(target_os = "macos")]
pub const PLIST: &str = "/Library/LaunchDaemons/com.antiwire.daemon.plist";

/// The daemon's launchd job.
#[cfg(target_os = "macos")]
#[derive(Debug, Clone)]
pub struct LaunchdDaemonService {
    plist: PathBuf,
}

#[cfg(target_os = "macos")]
impl Default for LaunchdDaemonService {
    fn default() -> Self {
        Self {
            plist: PathBuf::from(PLIST),
        }
    }
}

/// What `launchctl print` says about a loaded job.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct JobStatus {
    pub running: bool,
    pub pid: Option<u32>,
}

/// Reads the job's own `state` and `pid` from `launchctl print` output.
///
/// The job's keys are indented by exactly one tab. Nested blocks (endpoints,
/// event triggers) are indented further and can repeat the same key names, so
/// they are skipped.
pub(crate) fn parse_print(output: &str) -> JobStatus {
    let mut status = JobStatus {
        running: false,
        pid: None,
    };
    for line in output.lines() {
        let Some(entry) = line.strip_prefix('\t') else {
            continue;
        };
        if entry.starts_with('\t') {
            continue;
        }
        if let Some(state) = entry.strip_prefix("state = ") {
            status.running = state.trim() == "running";
        } else if let Some(pid) = entry.strip_prefix("pid = ") {
            status.pid = pid.trim().parse().ok();
        }
    }
    status
}

/// How long a `launchctl bootstrap` that [`bootstrap_should_retry`] accepts is
/// retried before the start fails.
#[cfg(target_os = "macos")]
const BOOTSTRAP_RETRY: Duration = Duration::from_secs(10);

/// Whether a failed `launchctl bootstrap` is worth trying again.
///
/// launchctl reports `Bootstrap failed: <code>: <reason>`. Code 5 (EIO,
/// "Input/output error") and 37 (EALREADY on macOS, "Operation already in
/// progress") are what it reports while launchd is still tearing down a job
/// with the same label. Apple does not document these codes for `bootstrap`,
/// so the retry is short and any other code fails at once.
pub(crate) fn bootstrap_should_retry(stderr: &str) -> bool {
    const EIO: u32 = 5;
    const EALREADY: u32 = 37;
    stderr.lines().any(|line| {
        line.trim()
            .strip_prefix("Bootstrap failed: ")
            .and_then(|rest| rest.split(':').next())
            .and_then(|code| code.trim().parse::<u32>().ok())
            .is_some_and(|code| code == EIO || code == EALREADY)
    })
}

/// The `ProgramArguments` value for `plutil -replace … -json`.
///
/// # Errors
///
/// [`UpdateError::Service`] when a path is not UTF-8, which JSON cannot carry.
pub(crate) fn program_arguments_json(
    daemon_exe: &Path,
    data_dir: &Path,
) -> Result<String, UpdateError> {
    let utf8 = |path: &Path| {
        path.to_str()
            .map(str::to_owned)
            .ok_or_else(|| UpdateError::Service(format!("{} is not a UTF-8 path", path.display())))
    };
    let arguments = [utf8(daemon_exe)?, "--data-dir".to_owned(), utf8(data_dir)?];
    serde_json::to_string(&arguments).map_err(|error| UpdateError::Service(error.to_string()))
}

#[cfg(target_os = "macos")]
impl LaunchdDaemonService {
    fn target() -> String {
        format!("system/{LABEL}")
    }

    /// `None` when the job is not loaded.
    fn status() -> Result<Option<JobStatus>, UpdateError> {
        let output = run(
            "/bin/launchctl",
            &[OsStr::new("print"), OsStr::new(&Self::target())],
        )?;
        if !output.status.success() {
            return Ok(None);
        }
        Ok(Some(parse_print(&String::from_utf8_lossy(&output.stdout))))
    }
}

#[cfg(target_os = "macos")]
impl DaemonService for LaunchdDaemonService {
    fn stop(&self, timeout: Duration) -> Result<(), UpdateError> {
        let Some(status) = Self::status()? else {
            return Ok(());
        };
        let deadline = Instant::now() + timeout;
        // An unloaded job cannot be revived by KeepAlive.
        let output = run(
            "/bin/launchctl",
            &[OsStr::new("bootout"), OsStr::new(&Self::target())],
        )?;
        if !output.status.success() && Self::status()?.is_some() {
            return Err(command_error("unload the daemon job", &output));
        }
        // launchctl(1) does not say whether `bootout` returns before launchd
        // has removed the job, and a `bootstrap` while it still lists the label
        // can fail. So wait until `print` no longer finds the job.
        while Self::status()?.is_some() {
            if Instant::now() >= deadline {
                return Err(UpdateError::Service(format!(
                    "{LABEL} was still loaded {} seconds after bootout",
                    timeout.as_secs()
                )));
            }
            std::thread::sleep(POLL_INTERVAL);
        }
        match status.pid {
            Some(pid) => wait_for_process_exit(pid, deadline),
            None => Ok(()),
        }
    }

    fn image(&self) -> Result<PathBuf, UpdateError> {
        let output = run(
            "/usr/bin/plutil",
            &[
                OsStr::new("-extract"),
                OsStr::new("ProgramArguments.0"),
                OsStr::new("raw"),
                OsStr::new("-o"),
                OsStr::new("-"),
                self.plist.as_os_str(),
            ],
        )?;
        if !output.status.success() {
            return Err(command_error("read the daemon job", &output));
        }
        Ok(PathBuf::from(
            String::from_utf8_lossy(&output.stdout).trim_end(),
        ))
    }

    fn set_image(&self, daemon_exe: &Path, data_dir: &Path) -> Result<(), UpdateError> {
        let arguments = program_arguments_json(daemon_exe, data_dir)?;
        // Edit a copy and rename it over the original, so a failure never
        // leaves a half-written plist that launchd cannot load.
        let staged = self.plist.with_extension("plist.new");
        std::fs::copy(&self.plist, &staged)
            .map_err(|error| UpdateError::io("copy", &self.plist, error))?;
        let output = run(
            "/usr/bin/plutil",
            &[
                OsStr::new("-replace"),
                OsStr::new("ProgramArguments"),
                OsStr::new("-json"),
                OsStr::new(&arguments),
                staged.as_os_str(),
            ],
        )?;
        if !output.status.success() {
            let _ = std::fs::remove_file(&staged);
            return Err(command_error("rewrite the daemon job", &output));
        }
        std::fs::rename(&staged, &self.plist)
            .map_err(|error| UpdateError::io("replace", &self.plist, error))
    }

    fn start_healthy(&self, start_timeout: Duration, settle: Duration) -> Result<(), UpdateError> {
        let retry_until = Instant::now() + BOOTSTRAP_RETRY;
        loop {
            let output = run(
                "/bin/launchctl",
                &[
                    OsStr::new("bootstrap"),
                    OsStr::new("system"),
                    self.plist.as_os_str(),
                ],
            )?;
            if output.status.success() {
                break;
            }
            let stderr = String::from_utf8_lossy(&output.stderr);
            if Instant::now() >= retry_until || !bootstrap_should_retry(&stderr) {
                return Err(UpdateError::Unhealthy(format!(
                    "the daemon job did not load: {}",
                    stderr.trim()
                )));
            }
            std::thread::sleep(POLL_INTERVAL);
        }

        let deadline = Instant::now() + start_timeout;
        let pid = loop {
            if let Some(JobStatus {
                running: true,
                pid: Some(pid),
            }) = Self::status()?
            {
                break pid;
            }
            if Instant::now() >= deadline {
                return Err(UpdateError::Unhealthy(format!(
                    "the daemon did not start within {} seconds",
                    start_timeout.as_secs()
                )));
            }
            std::thread::sleep(POLL_INTERVAL);
        };

        // launchd reports running as soon as the process exists, and KeepAlive
        // restarts a crash with a new pid, so health is the same process still
        // running after the settle window.
        std::thread::sleep(settle);
        match Self::status()? {
            Some(JobStatus {
                running: true,
                pid: Some(now),
            }) if now == pid => Ok(()),
            _ => Err(UpdateError::Unhealthy(
                "the daemon stopped or restarted during the settle window".to_owned(),
            )),
        }
    }
}

#[cfg(target_os = "macos")]
fn run(program: &str, args: &[&std::ffi::OsStr]) -> Result<Output, UpdateError> {
    Command::new(program)
        .args(args)
        .output()
        .map_err(|error| UpdateError::io("run", program, error))
}

#[cfg(target_os = "macos")]
fn command_error(action: &str, output: &Output) -> UpdateError {
    UpdateError::Service(format!(
        "could not {action}: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    ))
}

/// Waits until `pid` is gone, or `deadline` passes.
#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
fn wait_for_process_exit(pid: u32, deadline: Instant) -> Result<(), UpdateError> {
    let Ok(pid) = libc::pid_t::try_from(pid) else {
        return Ok(());
    };
    loop {
        // SAFETY: signal 0 only checks that the process exists; nothing is sent.
        let alive = unsafe { libc::kill(pid, 0) } == 0
            || std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH);
        if !alive {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(UpdateError::Service(format!(
                "process {pid} did not exit within the stop timeout"
            )));
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PRINT: &str = "system/com.antiwire.daemon = {\n\
        \tactive count = 1\n\
        \tpath = /Library/LaunchDaemons/com.antiwire.daemon.plist\n\
        \tstate = running\n\
        \n\
        \tprogram = /usr/local/libexec/antiwire/versions/0.2.0/daemon/antiwire-daemon\n\
        \tendpoints = {\n\
        \t\tstate = waiting\n\
        \t\tpid = 1\n\
        \t}\n\
        \tpid = 4242\n\
        }\n";

    #[test]
    fn reads_the_jobs_own_state_and_pid() {
        assert_eq!(
            parse_print(PRINT),
            JobStatus {
                running: true,
                pid: Some(4242),
            }
        );
    }

    #[test]
    fn a_stopped_job_has_no_pid() {
        let output = "system/com.antiwire.daemon = {\n\tstate = not running\n}\n";
        assert_eq!(
            parse_print(output),
            JobStatus {
                running: false,
                pid: None,
            }
        );
    }

    #[test]
    fn program_arguments_keep_spaces_inside_one_argument() {
        let json = program_arguments_json(
            Path::new("/Applications/My Tools/antiwire-daemon"),
            Path::new("/var/lib/antiwire"),
        )
        .expect("utf-8 paths");
        assert_eq!(
            json,
            r#"["/Applications/My Tools/antiwire-daemon","--data-dir","/var/lib/antiwire"]"#
        );
    }

    #[test]
    fn retries_a_bootstrap_only_while_launchd_tears_the_job_down() {
        assert!(bootstrap_should_retry(
            "Bootstrap failed: 5: Input/output error\n\
             Try re-running the command as root for richer errors.\n"
        ));
        assert!(bootstrap_should_retry(
            "Bootstrap failed: 37: Operation already in progress\n"
        ));
        assert!(!bootstrap_should_retry(
            "Bootstrap failed: 2: No such file or directory\n"
        ));
        assert!(!bootstrap_should_retry(""));
    }
}
