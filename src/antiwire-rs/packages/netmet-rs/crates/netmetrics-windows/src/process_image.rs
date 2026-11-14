//! Best-effort process-start image resolution with PID reuse validation.
use std::sync::atomic::{AtomicU64, Ordering};

use crate::filetime::filetime_to_unix_ms;
use windows::Win32::Foundation::{
    CloseHandle, ERROR_ACCESS_DENIED, ERROR_INSUFFICIENT_BUFFER, FILETIME, HANDLE,
};
use windows::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
    QueryFullProcessImageNameW,
};
use windows::core::{Error, PWSTR};

static ATTEMPTED: AtomicU64 = AtomicU64::new(0);
static RESOLVED: AtomicU64 = AtomicU64::new(0);
static DENIED: AtomicU64 = AtomicU64::new(0);

/// Cumulative best-effort image queries for process start and rundown events.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ProcessImageResolutionStats {
    /// Non-system start/DCStart events for which a query was attempted.
    pub attempted: u64,
    /// Queries that returned a full image path after creation-time validation.
    pub resolved: u64,
    /// Access-denied API results encountered during resolution.
    pub denied: u64,
}

/// Reads process image query counters without resetting them.
#[must_use]
pub fn process_image_resolution_stats() -> ProcessImageResolutionStats {
    ProcessImageResolutionStats {
        attempted: ATTEMPTED.load(Ordering::Relaxed),
        resolved: RESOLVED.load(Ordering::Relaxed),
        denied: DENIED.load(Ordering::Relaxed),
    }
}

struct ProcessHandle(HANDLE);
impl Drop for ProcessHandle {
    fn drop(&mut self) {
        // SAFETY: this guard uniquely owns a successfully opened process handle.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

fn record_error(error: &Error) {
    if error.code() == ERROR_ACCESS_DENIED.to_hresult() {
        DENIED.fetch_add(1, Ordering::Relaxed);
    }
}

/// Image path and creation time for a process that is still running.
pub(crate) struct LiveProcessImage {
    /// Full executable path.
    pub path: String,
    /// Process creation time, Unix epoch milliseconds.
    pub start_unix_ms: u64,
}

/// Resolves the image path and creation time while `pid` is still alive.
#[cfg(target_arch = "x86_64")]
pub(crate) fn resolve_live_process_image(pid: u32) -> Option<LiveProcessImage> {
    let (handle, created) = open_process_image(pid)?;
    let path = match query_full_image_path(&handle) {
        Ok(path) => path,
        Err(error) => {
            record_error(&error);
            return None;
        }
    };
    RESOLVED.fetch_add(1, Ordering::Relaxed);
    Some(LiveProcessImage {
        path,
        start_unix_ms: filetime_to_unix_ms(created).unwrap_or(0),
    })
}

fn open_process_image(pid: u32) -> Option<(ProcessHandle, u64)> {
    if matches!(pid, 0 | 4) {
        return None;
    }
    ATTEMPTED.fetch_add(1, Ordering::Relaxed);
    // SAFETY: query-only access; the returned handle is immediately guarded.
    let handle = match unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) } {
        Ok(handle) => ProcessHandle(handle),
        Err(error) => {
            record_error(&error);
            return None;
        }
    };
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    // SAFETY: valid process handle and writable FILETIME outputs.
    let times = unsafe {
        GetProcessTimes(
            handle.0,
            &raw mut creation,
            &raw mut exit,
            &raw mut kernel,
            &raw mut user,
        )
    };
    if let Err(error) = &times {
        record_error(error);
    }
    let created = (u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime);
    times.is_ok().then_some((handle, created))
}

/// `created` is the raw event FILETIME, before conversion to milliseconds.
pub(crate) fn resolve_process_image(pid: u32, created: Option<u64>) -> Option<LiveProcessImage> {
    let (handle, actual) = open_process_image(pid)?;
    if !creation_matches(created, Some(actual)) {
        return None;
    }
    match query_full_image_path(&handle) {
        Ok(path) => {
            RESOLVED.fetch_add(1, Ordering::Relaxed);
            Some(LiveProcessImage {
                path,
                start_unix_ms: filetime_to_unix_ms(actual).unwrap_or(0),
            })
        }
        Err(error) => {
            record_error(&error);
            None
        }
    }
}

fn creation_matches(expected: Option<u64>, actual: Option<u64>) -> bool {
    expected.is_none() || expected == actual
}

fn query_full_image_path(handle: &ProcessHandle) -> Result<String, Error> {
    let mut capacity = 1024u32;
    loop {
        let mut buffer = vec![0u16; capacity as usize];
        let mut size = capacity;
        // SAFETY: the guard keeps the handle alive and size describes the writable buffer.
        match unsafe {
            QueryFullProcessImageNameW(
                handle.0,
                PROCESS_NAME_WIN32,
                PWSTR(buffer.as_mut_ptr()),
                &raw mut size,
            )
        } {
            Ok(()) => return Ok(String::from_utf16_lossy(&buffer[..size as usize])),
            Err(error)
                if error.code() == ERROR_INSUFFICIENT_BUFFER.to_hresult() && capacity < 32_768 =>
            {
                capacity *= 2;
            }
            Err(error) => return Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creation_validation_rejects_reuse_and_failed_queries() {
        assert!(creation_matches(None, None));
        assert!(creation_matches(None, Some(123)));
        assert!(creation_matches(Some(123), Some(123)));
        assert!(!creation_matches(Some(123), Some(124)));
        assert!(!creation_matches(Some(123), None));
    }

    #[test]
    fn sentinel_processes_do_not_query_handles() {
        assert!(resolve_process_image(0, None).is_none());
        assert!(resolve_process_image(4, None).is_none());
    }
}
