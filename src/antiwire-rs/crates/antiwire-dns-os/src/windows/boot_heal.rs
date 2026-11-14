//! SYSTEM ONSTART task that restores dirty DNS after a hard-killed reboot.
//!
//! Only for **interactive** (non-service) runs. A Windows service already gets
//! `SERVICE_CONTROL_PRESHUTDOWN` with a long timeout; a parallel ONSTART heal
//! can race the service at next boot and undo a live redirect.

use std::ffi::{OsStr, OsString};
use std::os::windows::ffi::OsStringExt;
use std::path::Path;
use std::process::Command;

use tracing::{info, warn};

use super::command_line::command_line;

const TASK_NAME: &str = "AntiwireDnsHeal";

/// The daemon flag the boot task runs it with.
pub const HEAL_HOST_STATE_FLAG: &str = "--heal-host-state";

/// Registers a one-shot ONSTART task, run as SYSTEM, that heals host DNS from
/// `data_dir` at the next boot.
///
/// For an interactive daemon, which nothing stops cleanly at shutdown. A
/// service restores in `SERVICE_CONTROL_PRESHUTDOWN` instead, so the caller
/// does not register one for it.
pub fn register(data_dir: &Path) {
    let Ok(exe) = std::env::current_exe() else {
        warn!("boot heal: current_exe failed");
        return;
    };
    // Task Scheduler splits `/TR` with the `CommandLineToArgvW` rules, so a
    // trailing backslash in a path must not swallow the closing quote.
    let tr = OsString::from_wide(&command_line(
        exe.as_os_str(),
        &[
            OsString::from(HEAL_HOST_STATE_FLAG),
            OsString::from("--data-dir"),
            data_dir.as_os_str().to_owned(),
        ],
    ));
    let args: [&OsStr; 12] = [
        "/Create".as_ref(),
        "/TN".as_ref(),
        TASK_NAME.as_ref(),
        "/SC".as_ref(),
        "ONSTART".as_ref(),
        "/RU".as_ref(),
        "SYSTEM".as_ref(),
        "/RL".as_ref(),
        "HIGHEST".as_ref(),
        "/TR".as_ref(),
        &tr,
        "/F".as_ref(),
    ];
    match super::command::status(Command::new("schtasks").args(args)) {
        Ok(s) if s.success() => info!(task = TASK_NAME, "registered boot DNS heal task"),
        Ok(s) => warn!(task = TASK_NAME, %s, "schtasks create failed"),
        Err(error) => warn!(task = TASK_NAME, %error, "schtasks create could not start"),
    }
}

/// Remove the boot heal task after a successful restore.
pub fn unregister() {
    match super::command::status(Command::new("schtasks").args(["/Delete", "/TN", TASK_NAME, "/F"]))
    {
        Ok(s) if s.success() => info!(task = TASK_NAME, "unregistered boot DNS heal task"),
        Ok(_) => {}
        Err(error) => warn!(task = TASK_NAME, %error, "schtasks delete could not start"),
    }
}
