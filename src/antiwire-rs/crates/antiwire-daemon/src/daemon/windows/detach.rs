//! Detach the interactive daemon from its parent console / job object.
//!
//! ## Why this exists
//!
//! Closing a terminal window delivers `CTRL_CLOSE` to the console process group,
//! which Tokio parks long enough for DNS restore. **System restart is different:**
//! Windows Terminal / `conhost` / `cargo` typically sit in a Job Object. On reboot
//! the job is torn down with `TerminateProcess` on every member — no
//! `WM_QUERYENDSESSION`, no console control event, no chance to restore DNS.
//!
//! Re-spawning ourselves with `CREATE_BREAKAWAY_FROM_JOB | DETACHED_PROCESS`
//! makes the daemon a first-class process that receives normal session-end
//! messages and is not killed merely because the terminal died.

#![allow(unsafe_code)]

use std::env;
use std::ffi::OsString;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use antiwire_dns_os::windows::command_line::command_line;
use anyhow::Context;
use tracing::{info, warn};
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Console::FreeConsole;
use windows::Win32::System::Threading::{
    CreateProcessW, CREATE_BREAKAWAY_FROM_JOB, CREATE_NEW_PROCESS_GROUP, DETACHED_PROCESS,
    PROCESS_INFORMATION, STARTF_USESHOWWINDOW, STARTUPINFOW,
};
use windows::Win32::UI::WindowsAndMessaging::SW_HIDE;

/// Passed to the breakaway copy, so it runs the daemon instead of detaching
/// again.
pub const DETACHED_CHILD_FLAG: &str = "--detached-child";

/// If we are still attached to a parent job/console, re-launch ourselves as a
/// breakaway detached process and exit the parent with success.
/// `detached_child` is whether this process is that breakaway copy.
///
/// Returns `true` when this process should continue running the daemon.
pub fn ensure_detached_or_continue(foreground: bool, detached_child: bool) -> bool {
    if foreground {
        info!("--foreground: staying attached to the parent console/job");
        return true;
    }
    if detached_child {
        // Child process: drop the console so CSRSS treats us as a GUI-class
        // process for shutdown (session-end window owns notifications).
        match unsafe { FreeConsole() } {
            Ok(()) => info!("detached daemon: freed console; session-end window owns shutdown"),
            Err(error) => warn!(%error, "FreeConsole failed after detach"),
        }
        return true;
    }

    match relaunch_detached() {
        Ok(()) => {
            info!("spawned breakaway detached antiwire-daemon; parent exiting");
            false
        }
        Err(error) => {
            warn!(
                error = %format!("{error:#}"),
                "could not detach from parent job/console; continuing attached \
                 (system restart may hard-kill this process before DNS restore)"
            );
            true
        }
    }
}

fn relaunch_detached() -> anyhow::Result<()> {
    let exe = env::current_exe().context("current_exe")?;
    let mut args: Vec<OsString> = env::args_os().skip(1).collect();
    if !args.iter().any(|a| a == "--no-service") {
        args.push(OsString::from("--no-service"));
    }
    args.push(OsString::from(DETACHED_CHILD_FLAG));
    create_process_breakaway(&exe, &args)
}

fn create_process_breakaway(exe: &Path, args: &[OsString]) -> anyhow::Result<()> {
    // The parent exits once the child starts, so an argument the child parses
    // differently is not recovered here: a lost `--no-service` would send it
    // down the SCM path. Quote by the rules the child's parser applies.
    let mut cmd_wide = command_line(exe.as_os_str(), args);
    cmd_wide.push(0);
    let exe_wide: Vec<u16> = exe
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let startup = STARTUPINFOW {
        cb: u32::try_from(std::mem::size_of::<STARTUPINFOW>()).unwrap_or(u32::MAX),
        dwFlags: STARTF_USESHOWWINDOW,
        // `SW_HIDE` is 0.
        wShowWindow: u16::try_from(SW_HIDE.0).unwrap_or_default(),
        ..Default::default()
    };
    let mut process_info = PROCESS_INFORMATION::default();

    // No CREATE_NO_WINDOW: it is ignored alongside DETACHED_PROCESS, which
    // already gives the child no console.
    let flags = CREATE_BREAKAWAY_FROM_JOB | DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP;

    // SAFETY: wide buffers are NUL-terminated and live for the call; handles
    // from a successful CreateProcess are closed below.
    let created = unsafe {
        CreateProcessW(
            PCWSTR(exe_wide.as_ptr()),
            Some(PWSTR(cmd_wide.as_mut_ptr())),
            None,
            None,
            false,
            flags,
            None,
            None,
            &raw const startup,
            &raw mut process_info,
        )
    };

    created.context("CreateProcessW breakaway")?;

    // SAFETY: close process/thread handles we do not keep.
    unsafe {
        let _ = CloseHandle(process_info.hThread);
        let _ = CloseHandle(process_info.hProcess);
    }
    Ok(())
}
