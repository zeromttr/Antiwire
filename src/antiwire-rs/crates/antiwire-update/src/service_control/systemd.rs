//! The `antiwire-daemon.service` systemd unit on Linux.
//!
//! The unit belongs to the package, so the updater never edits it: an upgrade
//! installs a new package, whose files replace the old ones under the same
//! paths. [`DaemonService::set_image`] is therefore refused. Stop, start, and
//! the health check go through `systemctl`.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Duration, Instant};

use super::{DaemonService, POLL_INTERVAL};
use crate::system_program::require_system_program;
use crate::UpdateError;

/// The unit in `packaging/linux/antiwire-daemon.service`.
pub const UNIT: &str = "antiwire-daemon.service";

/// The daemon's systemd unit.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemdDaemonService;

/// The unit properties the swap reads.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct UnitStatus {
    pub active_state: String,
    pub sub_state: String,
    pub main_pid: Option<u32>,
}

impl UnitStatus {
    fn running(&self) -> Option<u32> {
        (self.active_state == "active" && self.sub_state == "running")
            .then_some(self.main_pid)
            .flatten()
    }

    fn stopped(&self) -> bool {
        matches!(self.active_state.as_str(), "inactive" | "failed")
    }
}

/// Reads `systemctl show --property=…` output: one `Key=value` per line.
pub(crate) fn parse_show(output: &str) -> UnitStatus {
    let mut status = UnitStatus::default();
    for line in output.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        match key {
            "ActiveState" => value.clone_into(&mut status.active_state),
            "SubState" => value.clone_into(&mut status.sub_state),
            "MainPID" => status.main_pid = value.trim().parse().ok().filter(|pid| *pid != 0),
            _ => {}
        }
    }
    status
}

/// The executable in `systemctl show --property=ExecStart --value` output,
/// which looks like `{ path=/usr/bin/antiwire-daemon ; argv[]=… ; … }`.
pub(crate) fn parse_exec_start(output: &str) -> Option<PathBuf> {
    output
        .split(';')
        .find_map(|field| {
            field
                .trim()
                .trim_start_matches('{')
                .trim()
                .strip_prefix("path=")
        })
        .map(|path| PathBuf::from(path.trim()))
}

impl SystemdDaemonService {
    fn status() -> Result<UnitStatus, UpdateError> {
        let output = systemctl(&["show", UNIT, "--property=ActiveState,SubState,MainPID"])?;
        if !output.status.success() {
            return Err(command_error("read the daemon unit", &output));
        }
        Ok(parse_show(&String::from_utf8_lossy(&output.stdout)))
    }
}

impl DaemonService for SystemdDaemonService {
    fn stop(&self, timeout: Duration) -> Result<(), UpdateError> {
        let deadline = Instant::now() + timeout;
        let output = systemctl(&["stop", "--no-block", UNIT])?;
        if !output.status.success() {
            return Err(command_error("stop the daemon unit", &output));
        }
        loop {
            if Self::status()?.stopped() {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(UpdateError::Service(format!(
                    "{UNIT} did not stop within {} seconds",
                    timeout.as_secs()
                )));
            }
            std::thread::sleep(POLL_INTERVAL);
        }
    }

    fn image(&self) -> Result<PathBuf, UpdateError> {
        let output = systemctl(&["show", UNIT, "--property=ExecStart", "--value"])?;
        if !output.status.success() {
            return Err(command_error("read the daemon unit", &output));
        }
        parse_exec_start(&String::from_utf8_lossy(&output.stdout))
            .ok_or_else(|| UpdateError::Service(format!("{UNIT} has no ExecStart")))
    }

    fn set_image(&self, _daemon_exe: &Path, _data_dir: &Path) -> Result<(), UpdateError> {
        Err(UpdateError::Service(format!(
            "{UNIT} belongs to the antiwire package; install a package to change it"
        )))
    }

    /// Enables and starts the unit, then waits until the same process has run
    /// for `settle`.
    ///
    /// Enabling is part of starting because a package from before
    /// `preremove.sh` checked its argument disables the unit during an RPM
    /// upgrade. The package's post-install script may already have started the
    /// new daemon; `start` leaves a running unit alone.
    fn start_healthy(&self, start_timeout: Duration, settle: Duration) -> Result<(), UpdateError> {
        // The package may have replaced the unit file.
        let reload = systemctl(&["daemon-reload"])?;
        if !reload.status.success() {
            return Err(command_error("reload systemd", &reload));
        }
        let enable = systemctl(&["enable", UNIT])?;
        if !enable.status.success() {
            return Err(command_error("enable the daemon unit", &enable));
        }
        // A build that kept crashing, restarted by `Restart=on-failure`, the
        // package scripts and the swap, can leave the unit over its start rate
        // limit, and systemd then refuses this start. `reset-failed` "also
        // resets ... the start rate limit counter" (systemctl(1)). A failure
        // here is only logged: the start below reports what matters.
        let reset = systemctl(&["reset-failed", UNIT])?;
        if !reset.status.success() {
            tracing::warn!(
                error = %String::from_utf8_lossy(&reset.stderr).trim(),
                "could not reset the daemon unit's failed state"
            );
        }
        let start = systemctl(&["start", UNIT])?;
        if !start.status.success() {
            return Err(UpdateError::Unhealthy(format!(
                "{UNIT} did not start: {}",
                String::from_utf8_lossy(&start.stderr).trim()
            )));
        }

        let deadline = Instant::now() + start_timeout;
        let pid = loop {
            if let Some(pid) = Self::status()?.running() {
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

        // `Restart=on-failure` brings a crashed daemon back with a new pid, so
        // health is the same process still running after the settle window.
        std::thread::sleep(settle);
        if Self::status()?.running() == Some(pid) {
            Ok(())
        } else {
            Err(UpdateError::Unhealthy(
                "the daemon stopped or restarted during the settle window".to_owned(),
            ))
        }
    }
}

fn systemctl(args: &[&str]) -> Result<Output, UpdateError> {
    let systemctl = require_system_program("systemctl")
        .map_err(|error| UpdateError::io("find", "systemctl", error))?;
    Command::new(systemctl)
        .args(args)
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|error| UpdateError::io("run", "systemctl", error))
}

fn command_error(action: &str, output: &Output) -> UpdateError {
    UpdateError::Service(format!(
        "could not {action}: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_a_running_unit() {
        let status = parse_show("ActiveState=active\nSubState=running\nMainPID=4242\n");
        assert_eq!(status.running(), Some(4242));
        assert!(!status.stopped());
    }

    #[test]
    fn a_restarting_unit_is_not_running() {
        let status = parse_show("ActiveState=activating\nSubState=auto-restart\nMainPID=0\n");
        assert_eq!(status.running(), None);
        assert!(!status.stopped());
    }

    #[test]
    fn inactive_and_failed_are_stopped() {
        assert!(parse_show("ActiveState=inactive\nSubState=dead\nMainPID=0").stopped());
        assert!(parse_show("ActiveState=failed\nSubState=failed\nMainPID=0").stopped());
    }

    #[test]
    fn reads_the_exec_start_path() {
        let output = "{ path=/usr/bin/antiwire-daemon ; argv[]=/usr/bin/antiwire-daemon \
                      --data-dir /var/lib/antiwire ; ignore_errors=no ; start_time=[n/a] }\n";
        assert_eq!(
            parse_exec_start(output),
            Some(PathBuf::from("/usr/bin/antiwire-daemon"))
        );
        assert_eq!(parse_exec_start(""), None);
    }
}
