//! Waiting for another process to exit.
//!
//! The reaper must act the moment the daemon dies. Probing the pid is not
//! enough on any platform: a Windows process object outlives the process while
//! anyone holds a handle to it, and a Unix process lingers as a zombie until
//! its parent collects it. A probe reports both as alive, which would leave DNS
//! redirected to a dead resolver for as long as they linger. Windows, Linux
//! and macOS instead wait for the kernel's exit notification. Where there is
//! none (Linux before 5.3, other Unix systems), the fallback polls, and only
//! on Linux can it tell a zombie from a live process.

#![allow(unsafe_code)]

#[cfg(unix)]
use std::thread;
#[cfg(unix)]
use std::time::Duration;

#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

/// Blocks until the process `pid` terminates, or returns at once if it
/// already has.
///
/// See [`antiwire_platform::process_wait::wait_for_exit`]: only a pid that
/// no longer exists counts as exited, so a daemon this reaper cannot open,
/// for lack of access, is waited for rather than reverted under.
#[cfg(windows)]
pub(crate) fn wait_until_dead(pid: u32) {
    let _ = antiwire_platform::process_wait::wait_for_exit(pid, None);
}

/// Blocks until the process `pid` terminates, or returns at once if it
/// already has.
///
/// A pidfd becomes readable when the process exits, before any parent
/// collects the zombie. Kernels older than 5.3 have no `pidfd_open` and fall
/// back to polling.
#[cfg(target_os = "linux")]
pub(crate) fn wait_until_dead(pid: u32) {
    let Ok(pid) = libc::pid_t::try_from(pid) else {
        return;
    };
    // SAFETY: `pidfd_open` takes a pid and flags and returns a new descriptor
    // or -1; it touches no memory of ours.
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    let Ok(fd) = libc::c_int::try_from(raw) else {
        return poll_until_dead(pid);
    };
    if fd < 0 {
        if last_errno() == libc::ESRCH {
            return;
        }
        return poll_until_dead(pid);
    }
    // SAFETY: `fd` is a new descriptor from `pidfd_open` that nothing else
    // owns; `OwnedFd` closes it once, on every path from here.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut pollfd = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    let exited = loop {
        // SAFETY: one valid `pollfd`; a timeout of -1 blocks until the
        // process exits.
        let ready = unsafe { libc::poll(&raw mut pollfd, 1, -1) };
        if ready > 0 {
            break true;
        }
        if ready < 0 && last_errno() == libc::EINTR {
            continue;
        }
        break false;
    };
    drop(fd);
    if !exited {
        poll_until_dead(pid);
    }
}

/// Blocks until the process `pid` terminates, or returns at once if it
/// already has.
///
/// A `NOTE_EXIT` kevent fires when the process exits, before any parent
/// collects the zombie.
#[cfg(target_os = "macos")]
pub(crate) fn wait_until_dead(pid: u32) {
    let Ok(pid) = libc::pid_t::try_from(pid) else {
        return;
    };
    // SAFETY: `kqueue` takes no arguments and returns a new descriptor or -1.
    let kq = unsafe { libc::kqueue() };
    if kq < 0 {
        return poll_until_dead(pid);
    }
    // SAFETY: `kq` is a new descriptor from `kqueue` that nothing else owns;
    // `OwnedFd` closes it once, on every path from here.
    let kq = unsafe { OwnedFd::from_raw_fd(kq) };
    let Ok(ident) = usize::try_from(pid) else {
        return;
    };
    let change = libc::kevent {
        ident,
        filter: libc::EVFILT_PROC,
        flags: libc::EV_ADD | libc::EV_ONESHOT,
        fflags: libc::NOTE_EXIT,
        data: 0,
        udata: std::ptr::null_mut(),
    };
    let exited = loop {
        // SAFETY: an all-zero `kevent` is a valid value for the kernel to
        // overwrite.
        let mut event: libc::kevent = unsafe { std::mem::zeroed() };
        // SAFETY: one change and room for one event, both valid for the call;
        // a null timeout blocks until the event arrives. Re-adding the same
        // filter after an interruption is idempotent.
        let ready = unsafe {
            libc::kevent(
                kq.as_raw_fd(),
                &raw const change,
                1,
                &raw mut event,
                1,
                std::ptr::null(),
            )
        };
        if ready > 0 {
            if event.flags & libc::EV_ERROR == 0 {
                break true;
            }
            // The filter could not be attached; ESRCH means the process is
            // already gone.
            break event.data == libc::ESRCH as isize;
        }
        // An interrupted wait loops around and registers again.
        if ready < 0 {
            match last_errno() {
                libc::EINTR => {}
                libc::ESRCH => break true,
                _ => break false,
            }
        }
    };
    drop(kq);
    if !exited {
        poll_until_dead(pid);
    }
}

/// Other Unix systems poll.
#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
pub(crate) fn wait_until_dead(pid: u32) {
    if let Ok(pid) = libc::pid_t::try_from(pid) {
        poll_until_dead(pid);
    }
}

/// Fallback when the kernel offers no exit notification. A zombie still
/// answers `kill(pid, 0)`, so on Linux its `/proc` state is checked as well.
#[cfg(unix)]
fn poll_until_dead(pid: libc::pid_t) {
    while process_alive(pid) {
        thread::sleep(Duration::from_millis(200));
    }
}

#[cfg(unix)]
fn process_alive(pid: libc::pid_t) -> bool {
    // SAFETY: signal 0 only checks that `pid` exists and may be signaled.
    let exists = unsafe { libc::kill(pid, 0) } == 0 || last_errno() == libc::EPERM;
    exists && !is_zombie(pid)
}

#[cfg(target_os = "linux")]
fn is_zombie(pid: libc::pid_t) -> bool {
    // The state follows the parenthesized command name, which may itself
    // contain spaces or parentheses.
    std::fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|stat| {
        stat.rsplit_once(')')
            .is_some_and(|(_, rest)| rest.trim_start().starts_with('Z'))
    })
}

#[cfg(all(unix, not(target_os = "linux")))]
fn is_zombie(_pid: libc::pid_t) -> bool {
    false
}

#[cfg(unix)]
fn last_errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use std::process::{Command, Stdio};
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    use super::*;

    /// A long-running child. It is killed but never waited on, so the test
    /// keeps its handle open (Windows) or leaves it a zombie (Unix), the two
    /// states in which a pid probe wrongly reports a dead process alive.
    fn long_running_child() -> std::process::Child {
        #[cfg(windows)]
        let mut command = {
            let mut command = Command::new("cmd");
            command.args(["/c", "ping -n 30 127.0.0.1 >nul"]);
            command
        };
        #[cfg(unix)]
        let mut command = {
            let mut command = Command::new("sleep");
            command.arg("30");
            command
        };
        command.stdout(Stdio::null()).spawn().expect("spawn child")
    }

    fn returns_promptly(pid: u32) -> bool {
        let (done, finished) = mpsc::channel();
        thread::spawn(move || {
            wait_until_dead(pid);
            let _ = done.send(());
        });
        finished.recv_timeout(Duration::from_secs(5)).is_ok()
    }

    #[test]
    fn a_killed_process_is_dead_even_before_anyone_collects_it() {
        let mut child = long_running_child();
        child.kill().expect("kill child");
        assert!(
            returns_promptly(child.id()),
            "waited on a process that had already been killed"
        );
        drop(child);
    }

    #[test]
    fn a_live_process_is_waited_on_until_it_exits() {
        let mut child = long_running_child();
        let pid = child.id();
        let (done, finished) = mpsc::channel();
        thread::spawn(move || {
            wait_until_dead(pid);
            let _ = done.send(());
        });
        assert!(
            finished.recv_timeout(Duration::from_millis(500)).is_err(),
            "returned while the process was still running"
        );
        child.kill().expect("kill child");
        assert!(
            finished.recv_timeout(Duration::from_secs(5)).is_ok(),
            "did not notice the process exit"
        );
        let _ = child.wait();
    }
}
