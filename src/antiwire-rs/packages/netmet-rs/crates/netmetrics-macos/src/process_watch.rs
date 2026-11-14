//! Process descriptions from libproc, and exec and exit notifications from kqueue.

use crate::processes::{ProcessChange, ProcessDescription, ProcessSource, Watch};
use libc::c_int;
use std::io;
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::ptr;

/// Notifications taken from the queue in one call.
const EVENT_BATCH: usize = 32;

/// The kernel's account of processes: `proc_pidinfo` and `proc_pidpath` describe one, and
/// a kqueue with `EVFILT_PROC` says when a watched one execs or exits.
#[derive(Debug)]
pub(crate) struct KernelProcesses {
    /// `None` when the queue could not be created; exits are then found by polling.
    queue: Option<OwnedFd>,
}

impl KernelProcesses {
    /// Creates the notification queue. Returns the source without one, and the reason,
    /// when kqueue(2) fails.
    pub(crate) fn new() -> (Self, Option<io::Error>) {
        // SAFETY: kqueue(2) takes no arguments and returns a new descriptor or -1.
        let fd = unsafe { libc::kqueue() };
        if fd < 0 {
            return (Self { queue: None }, Some(io::Error::last_os_error()));
        }
        // SAFETY: the successful `kqueue` call returned a new descriptor nothing else owns.
        let queue = unsafe { OwnedFd::from_raw_fd(fd) };
        (Self { queue: Some(queue) }, None)
    }

    /// The descriptor that becomes readable when a watched process execs or exits, or -1,
    /// which poll(2) ignores, when there is no queue.
    pub(crate) fn readiness_fd(&self) -> RawFd {
        self.queue.as_ref().map_or(-1, AsRawFd::as_raw_fd)
    }

    /// Adds or deletes the `EVFILT_PROC` filter for `pid`.
    fn change(&self, pid: u32, flags: u16) -> io::Result<()> {
        let queue = self
            .queue
            .as_ref()
            .ok_or_else(|| io::Error::from(io::ErrorKind::Unsupported))?;
        let change = libc::kevent {
            ident: usize::try_from(pid).map_err(io::Error::other)?,
            filter: libc::EVFILT_PROC,
            flags,
            fflags: libc::NOTE_EXIT | libc::NOTE_EXEC,
            data: 0,
            udata: ptr::null_mut(),
        };
        // SAFETY: `change` is one initialized `struct kevent`, the event list is empty, and
        // `queue` is an open kqueue. With no room for an `EV_ERROR` event, kevent(2)
        // reports a failed change by returning -1 with `errno` set.
        let result = unsafe {
            libc::kevent(
                queue.as_raw_fd(),
                &raw const change,
                1,
                ptr::null_mut(),
                0,
                ptr::null(),
            )
        };
        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

impl ProcessSource for KernelProcesses {
    fn describe(&self, pid: u32) -> Option<ProcessDescription> {
        Some(ProcessDescription {
            start_ts: process_start_ms(pid)?,
            executable: process_path(pid).unwrap_or_default(),
        })
    }

    /// kqueue(2): `EVFILT_PROC` takes the PID as the identifier and reports the events in
    /// `fflags`; adding it for a process that does not exist fails with `ESRCH`.
    fn watch(&mut self, pid: u32) -> Watch {
        match self.change(pid, libc::EV_ADD) {
            Ok(()) => Watch::Watching,
            Err(error) if error.raw_os_error() == Some(libc::ESRCH) => Watch::Gone,
            Err(_) => Watch::Unavailable,
        }
    }

    fn unwatch(&mut self, pid: u32) {
        // The filter is already gone if the process exited, which is the only failure.
        let _ = self.change(pid, libc::EV_DELETE);
    }

    fn take_changes(&mut self) -> Vec<(u32, ProcessChange)> {
        let Some(queue) = &self.queue else {
            return Vec::new();
        };
        let mut changes = Vec::new();
        // SAFETY: all-zero is a valid `struct kevent`: integers and a null pointer.
        let mut events: [libc::kevent; EVENT_BATCH] = unsafe { mem::zeroed() };
        let no_wait = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        loop {
            // SAFETY: `events` is writable for `EVENT_BATCH` entries, the change list is
            // empty, `no_wait` is a valid zero timeout, and `queue` is an open kqueue.
            // kevent(2) writes at most that many events and returns how many.
            let count = unsafe {
                libc::kevent(
                    queue.as_raw_fd(),
                    ptr::null(),
                    0,
                    events.as_mut_ptr(),
                    c_int::try_from(EVENT_BATCH).unwrap_or(c_int::MAX),
                    &raw const no_wait,
                )
            };
            let Ok(count) = usize::try_from(count) else {
                break;
            };
            for event in events.iter().take(count) {
                // `struct kevent` is packed, so its fields are copied out before use.
                let (ident, filter, fflags) = (event.ident, event.filter, event.fflags);
                let Ok(pid) = u32::try_from(ident) else {
                    continue;
                };
                if filter != libc::EVFILT_PROC {
                    continue;
                }
                // An exit ends the process whatever else happened to it since the last
                // call; its filter is removed with it.
                if fflags & libc::NOTE_EXIT != 0 {
                    changes.push((pid, ProcessChange::Exited));
                } else if fflags & libc::NOTE_EXEC != 0 {
                    changes.push((pid, ProcessChange::Replaced));
                }
            }
            if count < EVENT_BATCH {
                break;
            }
        }
        changes
    }
}

/// When `pid` started, in Unix epoch milliseconds, or `None` once it has exited. A zombie
/// has exited: it only waits for its parent to collect it.
fn process_start_ms(pid: u32) -> Option<u64> {
    let pid = i32::try_from(pid).ok()?;
    let mut info = mem::MaybeUninit::<libc::proc_bsdinfo>::uninit();
    let size = c_int::try_from(mem::size_of::<libc::proc_bsdinfo>()).ok()?;
    // SAFETY: `info` points to a buffer of `size` bytes for the requested
    // PROC_PIDTBSDINFO structure. A full-size return initializes the buffer.
    let bytes = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast(),
            size,
        )
    };
    if bytes != size {
        return None;
    }
    // SAFETY: proc_pidinfo returned the full size of `proc_bsdinfo`.
    let info = unsafe { info.assume_init() };
    if info.pbi_status == libc::SZOMB {
        return None;
    }
    Some(
        info.pbi_start_tvsec
            .saturating_mul(1_000)
            .saturating_add(info.pbi_start_tvusec / 1_000),
    )
}

/// The executable `pid` is running, from `proc_pidpath`. `libproc.h` in the macOS SDK
/// declares it: it writes the path into a buffer of at most `PROC_PIDPATHINFO_MAXSIZE`
/// bytes and returns the path's length, or zero on failure.
fn process_path(pid: u32) -> Option<String> {
    const BUFFER_LEN: usize = 4 * 1024;
    const _: () = assert!(BUFFER_LEN == libc::PROC_PIDPATHINFO_MAXSIZE as usize);
    let pid = i32::try_from(pid).ok()?;
    let mut buffer = [0_u8; BUFFER_LEN];
    // SAFETY: `buffer` is writable for the length passed, which is the largest
    // `proc_pidpath` accepts, and it writes no more than that.
    let length = unsafe {
        libc::proc_pidpath(
            pid,
            buffer.as_mut_ptr().cast(),
            u32::try_from(BUFFER_LEN).ok()?,
        )
    };
    let length = usize::try_from(length).ok().filter(|length| *length > 0)?;
    Some(String::from_utf8_lossy(buffer.get(..length)?).into_owned())
}
