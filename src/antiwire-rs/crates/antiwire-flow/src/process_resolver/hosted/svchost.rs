//! Names the SCM services an `svchost.exe` instance hosts.
//!
//! A process hosting several services gets one stable, sorted group label,
//! because ETW attributes flows to the process rather than a service thread.

use std::mem::size_of;

use windows::Win32::System::Services::{
    CloseServiceHandle, EnumServicesStatusExW, OpenSCManagerW, ENUM_SERVICE_STATUS_PROCESSW,
    SC_ENUM_PROCESS_INFO, SC_HANDLE, SC_MANAGER_ENUMERATE_SERVICE, SERVICE_STATE_ALL,
    SERVICE_WIN32,
};

/// Labels the instance with this PID by the services the service control
/// manager reports running in it, or `None` when it reports none.
#[expect(unsafe_code, reason = "FFI calls into the SCM service-enumeration API")]
pub(super) fn hosted_services(pid: u32) -> Option<String> {
    // SAFETY: no pointer arguments; the request is enumeration-only, and a failed or
    // invalid handle is rejected by the `ok()` and `is_invalid()` filters before use.
    // A valid handle is closed by `ServiceHandleGuard` on every return path.
    let manager = unsafe {
        OpenSCManagerW(None, None, SC_MANAGER_ENUMERATE_SERVICE)
            .ok()
            .filter(|handle| !handle.is_invalid())
    }?;
    let _manager = ServiceHandleGuard(manager);
    #[cfg(test)]
    crate::test_support::native_probe("scm");

    let mut bytes_needed = 0u32;
    let mut services_returned = 0u32;
    let mut resume_handle = 0u32;
    // SAFETY: `manager` is the valid handle checked above. A `None` buffer is the
    // documented sizing call, so SCM writes only the out-params, which are live
    // locals whose addresses are passed as `&raw mut`.
    let _ = unsafe {
        EnumServicesStatusExW(
            manager,
            SC_ENUM_PROCESS_INFO,
            SERVICE_WIN32,
            SERVICE_STATE_ALL,
            None,
            &raw mut bytes_needed,
            &raw mut services_returned,
            Some(&raw mut resume_handle),
            None,
        )
    };
    if bytes_needed == 0 {
        return None;
    }

    let byte_len = usize::try_from(bytes_needed).ok()?;
    let capacity = byte_len.div_ceil(size_of::<ENUM_SERVICE_STATUS_PROCESSW>());
    let mut storage = vec![ENUM_SERVICE_STATUS_PROCESSW::default(); capacity];
    let storage_bytes = storage
        .len()
        .checked_mul(size_of::<ENUM_SERVICE_STATUS_PROCESSW>())?;

    // SAFETY: `storage` has service-entry alignment and at least the byte length
    // reported by the sizing call. It remains alive while SCM writes into it.
    let buffer =
        unsafe { std::slice::from_raw_parts_mut(storage.as_mut_ptr().cast::<u8>(), storage_bytes) };
    // SAFETY: the output slice is valid for the size passed to SCM.
    unsafe {
        EnumServicesStatusExW(
            manager,
            SC_ENUM_PROCESS_INFO,
            SERVICE_WIN32,
            SERVICE_STATE_ALL,
            Some(buffer),
            &raw mut bytes_needed,
            &raw mut services_returned,
            Some(&raw mut resume_handle),
            None,
        )
    }
    .ok()?;

    let count = usize::try_from(services_returned).ok()?;
    if count > storage.len() {
        return None;
    }

    let mut matches: Vec<String> = storage[..count]
        .iter()
        .filter(|entry| entry.ServiceStatusProcess.dwProcessId == pid)
        // SAFETY: `lpServiceName` points into `storage`, which SCM filled in the
        // successful call above and which is still alive. Each entry's name is a
        // NUL-terminated UTF-16 string inside that buffer, and `count` was checked
        // against `storage.len()`, so only written entries are read.
        .filter_map(|entry| unsafe { entry.lpServiceName.to_string().ok() })
        .filter(|name| !name.is_empty())
        .collect();
    stable_service_label(&mut matches)
}

fn stable_service_label(services: &mut Vec<String>) -> Option<String> {
    services.sort_unstable_by_key(|name| name.to_ascii_lowercase());
    services.dedup_by(|left, right| left.eq_ignore_ascii_case(right));
    match services.len() {
        0 => None,
        1 => services.pop(),
        _ => Some(services.join(",")),
    }
}

struct ServiceHandleGuard(SC_HANDLE);

impl Drop for ServiceHandleGuard {
    #[expect(unsafe_code, reason = "FFI call to CloseServiceHandle")]
    fn drop(&mut self) {
        // SAFETY: this guard uniquely owns the valid SCM handle.
        unsafe {
            let _ = CloseServiceHandle(self.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_group_identity_is_stable_and_deduplicated() {
        let mut services = vec![
            "Dnscache".to_owned(),
            "BITS".to_owned(),
            "dnscache".to_owned(),
        ];
        assert_eq!(
            stable_service_label(&mut services).as_deref(),
            Some("BITS,Dnscache")
        );
    }

    #[test]
    fn single_service_keeps_its_name() {
        let mut services = vec!["WdiSystemHost".to_owned()];
        assert_eq!(
            stable_service_label(&mut services).as_deref(),
            Some("WdiSystemHost")
        );
    }
}
