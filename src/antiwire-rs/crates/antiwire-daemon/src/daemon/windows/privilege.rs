//! The token privilege the Windows daemon enables for itself, as a service
//! or interactively.

/// Enables `SeDebugPrivilege` on this process's token, if the token holds it (disabled by
/// default even for an elevated/SYSTEM token). This lets `OpenProcess` succeed against
/// UAC-elevated and cross-session/cross-account processes that would otherwise be denied,
/// which improves executable-path resolution for those processes.
pub(crate) fn enable_debug_privilege() {
    use tracing::{info, warn};
    use windows::core::w;
    use windows::Win32::Foundation::{
        CloseHandle, GetLastError, ERROR_NOT_ALL_ASSIGNED, HANDLE, LUID,
    };
    use windows::Win32::Security::{
        AdjustTokenPrivileges, LookupPrivilegeValueW, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED,
        TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    // SAFETY: `GetCurrentProcess` returns a pseudo-handle owned by the OS; no cleanup required.
    let process = unsafe { GetCurrentProcess() };

    let mut token = HANDLE::default();
    // SAFETY: `process` is a valid pseudo-handle and `token` is a valid out-pointer.
    if let Err(error) =
        unsafe { OpenProcessToken(process, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut token) }
    {
        warn!(error = %error, "failed to open process token; SeDebugPrivilege not enabled");
        return;
    }

    let mut luid = LUID::default();
    // SAFETY: `w!` yields a valid null-terminated wide string and `luid` is a valid out-pointer.
    let lookup = unsafe { LookupPrivilegeValueW(None, w!("SeDebugPrivilege"), &mut luid) };
    if let Err(error) = lookup {
        warn!(error = %error, "failed to look up SeDebugPrivilege LUID");
        // SAFETY: `token` was opened above and has not been closed yet.
        let _ = unsafe { CloseHandle(token) };
        return;
    }

    let privileges = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: SE_PRIVILEGE_ENABLED,
        }],
    };

    // SAFETY: `token` holds TOKEN_ADJUST_PRIVILEGES access and `privileges` describes one entry.
    let adjusted = unsafe { AdjustTokenPrivileges(token, false, Some(&privileges), 0, None, None) };
    // `CloseHandle` is documented to reset the thread's last-error code, so
    // capture it before closing the token: reading it afterwards reports the
    // close (usually success) instead of the privilege adjustment, which made
    // a missing SeDebugPrivilege look granted.
    // SAFETY: `GetLastError` reads thread-local state set by the call above.
    let adjust_error = unsafe { GetLastError() };
    // SAFETY: `token` is closed exactly once, after every use above.
    let _ = unsafe { CloseHandle(token) };

    match adjusted {
        Ok(()) => {
            // AdjustTokenPrivileges reports success via its return value even when the
            // privilege wasn't actually granted; the real signal is this specific error code.
            if adjust_error == ERROR_NOT_ALL_ASSIGNED {
                warn!(
                    "SeDebugPrivilege is not held by this process token; some elevated \
                     processes will remain unresolvable"
                );
            } else {
                info!("enabled SeDebugPrivilege");
            }
        }
        Err(error) => warn!(error = %error, "failed to enable SeDebugPrivilege"),
    }
}
