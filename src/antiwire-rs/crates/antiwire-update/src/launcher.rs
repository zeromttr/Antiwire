//! Starts the one-shot apply helper outside the daemon's lifetime.
//!
//! On Windows and macOS the helper is a detached child. On Linux a detached
//! child is not enough: systemd stops every process in a unit's control group
//! when the unit stops, and the package manager stops `antiwire-daemon.service`
//! partway through the install. The helper therefore runs as its own transient
//! unit, started with `systemd-run`.

use std::ffi::{OsStr, OsString};
use std::path::Path;
use std::process::{Command, Stdio};

use semver::Version;

use crate::state::new_request_id;

/// Command-line flag that selects the apply helper in `antiwire-daemon`.
pub const APPLY_FLAG: &str = "--apply-update";
/// Command-line flag carrying the request id to the helper.
pub const REQUEST_FLAG: &str = "--update-request";
/// Command-line flag that runs only crash recovery of an unfinished swap.
pub const RECOVER_FLAG: &str = "--recover-update";

/// Starts the helper. A trait so tests can record launches instead.
pub trait HelperLauncher: Send + Sync {
    /// Runs `daemon_exe --apply-update {version} --update-request {request_id}
    /// --data-dir {data_dir}` detached from the daemon, so stopping the daemon
    /// service does not stop it.
    ///
    /// # Errors
    ///
    /// When the process cannot be started.
    fn launch_apply(
        &self,
        daemon_exe: &Path,
        data_dir: &Path,
        version: &Version,
        request_id: &str,
    ) -> std::io::Result<()>;

    /// Runs `daemon_exe --recover-update --data-dir {data_dir}` detached.
    ///
    /// # Errors
    ///
    /// When the process cannot be started.
    fn launch_recover(&self, daemon_exe: &Path, data_dir: &Path) -> std::io::Result<()>;
}

/// Launches real detached processes.
#[derive(Debug, Default, Clone, Copy)]
pub struct DetachedLauncher;

impl HelperLauncher for DetachedLauncher {
    fn launch_apply(
        &self,
        daemon_exe: &Path,
        data_dir: &Path,
        version: &Version,
        request_id: &str,
    ) -> std::io::Result<()> {
        let version = version.to_string();
        let mode = [
            OsStr::new(APPLY_FLAG),
            OsStr::new(&version),
            OsStr::new(REQUEST_FLAG),
            OsStr::new(request_id),
        ];
        spawn_helper(daemon_exe, data_dir, &mode, &format!("apply-{request_id}"))
    }

    fn launch_recover(&self, daemon_exe: &Path, data_dir: &Path) -> std::io::Result<()> {
        // Every daemon start during a swap launches one, and the last may still
        // be running. systemd-run refuses a unit name that is still loaded,
        // and still exits 0, so a fixed name would lose this one unseen.
        let unit = format!("recover-{}", new_request_id());
        spawn_helper(daemon_exe, data_dir, &[OsStr::new(RECOVER_FLAG)], &unit)
    }
}

/// Prefix of the transient units the Linux helper runs in.
pub const UNIT_PREFIX: &str = "antiwire-update-";

/// `systemd-run` arguments that run the helper as the transient unit
/// `antiwire-update-{name}`.
///
/// `--collect` removes the unit once it ends, even when it failed, so the next
/// update can reuse the name. The unit name keeps `[A-Za-z0-9-]` only, which
/// request ids already are.
#[must_use]
pub fn systemd_run_args(
    name: &str,
    daemon_exe: &Path,
    data_dir: &Path,
    mode: &[&OsStr],
) -> Vec<OsString> {
    let name: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect();
    let mut setenv = OsString::from("--setenv=ANTIWIRE_DATA_DIR=");
    setenv.push(data_dir);
    let mut args: Vec<OsString> = vec![
        format!("--unit={UNIT_PREFIX}{name}").into(),
        "--collect".into(),
        "--quiet".into(),
        "--description=Antiwire update helper".into(),
        setenv,
        "--".into(),
        daemon_exe.into(),
    ];
    args.extend(mode.iter().map(|arg| arg.to_os_string()));
    args.push("--data-dir".into());
    args.push(data_dir.into());
    args
}

/// Builds the helper command line shared by every helper mode.
///
/// The data directory is passed as `--data-dir` and also as the environment
/// variable the daemon reads before it parses arguments, so the helper's log
/// lands beside the daemon's.
#[cfg(not(target_os = "linux"))]
fn helper_command(daemon_exe: &Path, data_dir: &Path, mode: &[&OsStr]) -> Command {
    let mut command = Command::new(daemon_exe);
    command
        .args(mode)
        .arg("--data-dir")
        .arg(data_dir)
        .env("ANTIWIRE_DATA_DIR", data_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    detach(&mut command);
    command
}

/// Spawns the helper and drops the handle without waiting. The helper is meant
/// to outlive the daemon, so nothing here reaps it.
#[cfg(not(target_os = "linux"))]
fn spawn_helper(
    daemon_exe: &Path,
    data_dir: &Path,
    mode: &[&OsStr],
    _unit: &str,
) -> std::io::Result<()> {
    helper_command(daemon_exe, data_dir, mode).spawn()?;
    Ok(())
}

/// Starts the helper as a transient systemd unit. `systemd-run` returns once
/// the unit has started, so its exit status says whether the helper is running.
#[cfg(target_os = "linux")]
fn spawn_helper(
    daemon_exe: &Path,
    data_dir: &Path,
    mode: &[&OsStr],
    unit: &str,
) -> std::io::Result<()> {
    let output = Command::new(crate::system_program::require_system_program(
        "systemd-run",
    )?)
    .args(systemd_run_args(unit, daemon_exe, data_dir, mode))
    .stdin(Stdio::null())
    .output()?;
    if output.status.success() {
        Ok(())
    } else {
        Err(std::io::Error::other(format!(
            "systemd-run exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }
}

/// Puts the child in its own process group, so a `kill` of the daemon's group
/// leaves it running.
#[cfg(all(unix, not(target_os = "linux")))]
fn detach(command: &mut Command) {
    use std::os::unix::process::CommandExt;
    command.process_group(0);
}

#[cfg(windows)]
fn detach(command: &mut Command) {
    detach_breakaway(command);
}

/// Starts `command` outside the daemon's lifetime: in a new process group,
/// with no console, and broken away from the daemon's job object, so a
/// service stop does not end it. Used for this helper and the host-state
/// reaper.
#[cfg(windows)]
pub fn detach_breakaway(command: &mut Command) {
    use std::os::windows::process::CommandExt;
    use windows::Win32::System::Threading::{
        CREATE_BREAKAWAY_FROM_JOB, CREATE_NEW_PROCESS_GROUP, DETACHED_PROCESS,
    };
    command.creation_flags(
        (CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS | CREATE_BREAKAWAY_FROM_JOB).0,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn systemd_run_runs_the_helper_in_its_own_unit() {
        let args: Vec<String> = systemd_run_args(
            "apply-18a2f-4d2",
            Path::new("/usr/bin/antiwire-daemon"),
            Path::new("/var/lib/antiwire"),
            &[
                OsStr::new(APPLY_FLAG),
                OsStr::new("0.3.0"),
                OsStr::new(REQUEST_FLAG),
                OsStr::new("18a2f-4d2"),
            ],
        )
        .into_iter()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect();
        assert_eq!(
            args,
            [
                "--unit=antiwire-update-apply-18a2f-4d2",
                "--collect",
                "--quiet",
                "--description=Antiwire update helper",
                "--setenv=ANTIWIRE_DATA_DIR=/var/lib/antiwire",
                "--",
                "/usr/bin/antiwire-daemon",
                "--apply-update",
                "0.3.0",
                "--update-request",
                "18a2f-4d2",
                "--data-dir",
                "/var/lib/antiwire",
            ]
        );
    }

    #[test]
    fn unit_names_keep_only_safe_characters() {
        let args = systemd_run_args("a/b c", Path::new("x"), Path::new("y"), &[]);
        assert_eq!(args[0], OsString::from("--unit=antiwire-update-a-b-c"));
    }
}
