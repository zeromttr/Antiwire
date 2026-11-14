//! Access for the local group whose members may use the daemon.
//!
//! The daemon runs privileged and its API reconfigures the firewall, so the credential
//! that unlocks the API must not be readable by every local account. Membership of one
//! local group, created by the installer, is what grants it instead.

#![allow(unsafe_code)]

use std::io;
#[cfg(windows)]
use std::path::Path;

/// Whether a file was opened up to the client group or left to administrators alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupAccess {
    /// Members of the group can read the file.
    Granted,
    /// The group does not exist, so only administrators can read the file.
    GroupMissing,
}

/// Restricts `path` to `SYSTEM`, Administrators and its owner, plus read access for `group`.
///
/// The DACL is protected, so nothing inherited from the parent directory survives:
/// in particular not the `BUILTIN\Users` read the data directory grants. The owner ACE
/// is what lets the creating process still rename the file into place; for the daemon
/// that owner is `SYSTEM` or Administrators, so it grants nobody new. When `group` does
/// not exist, or names something other than a local group, no one else gets access and
/// [`GroupAccess::GroupMissing`] is returned.
///
/// # Errors
///
/// Returns the underlying OS error when the group cannot be looked up for a reason other
/// than not existing, or when the DACL cannot be applied.
#[cfg(windows)]
pub fn restrict_to_admins_and_group(path: &Path, group: &str) -> io::Result<GroupAccess> {
    const ADMINS_ONLY: &str = "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;S-1-3-4)";

    if let Some(sid) = local_group_sid(group)? {
        crate::acl::apply_sddl(path, &format!("{ADMINS_ONLY}(A;;FR;;;{sid})"))?;
        Ok(GroupAccess::Granted)
    } else {
        crate::acl::apply_sddl(path, ADMINS_ONLY)?;
        Ok(GroupAccess::GroupMissing)
    }
}

/// The string SID of the local group `name`, or `None` when no local group has it.
///
/// Only a local group (`SidTypeAlias`) counts. A user account, or a domain object that
/// happens to share the name, is not what the installer created.
#[cfg(windows)]
fn local_group_sid(name: &str) -> io::Result<Option<String>> {
    use windows::core::{PCWSTR, PWSTR};
    use windows::Win32::Foundation::{
        LocalFree, ERROR_INSUFFICIENT_BUFFER, ERROR_NONE_MAPPED, HLOCAL,
    };
    use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows::Win32::Security::{LookupAccountNameW, SidTypeAlias, PSID, SID_NAME_USE};

    let wide_name: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    let mut sid_len = 0_u32;
    let mut domain_len = 0_u32;
    let mut kind = SID_NAME_USE(0);

    // SAFETY: the name is NUL-terminated and outlives the call. This first call only
    // reports the buffer sizes, so both buffers are absent and the lengths are zero.
    let sized = unsafe {
        LookupAccountNameW(
            PCWSTR::null(),
            PCWSTR(wide_name.as_ptr()),
            None,
            &raw mut sid_len,
            None,
            &raw mut domain_len,
            &raw mut kind,
        )
    };
    match sized {
        Err(error) if error.code() == ERROR_NONE_MAPPED.to_hresult() => return Ok(None),
        Err(error) if error.code() == ERROR_INSUFFICIENT_BUFFER.to_hresult() => {}
        Err(error) => return Err(io::Error::other(error)),
        Ok(()) => return Err(io::Error::other("account lookup reported no SID size")),
    }

    let mut sid = vec![0_u8; sid_len as usize];
    let mut domain = vec![0_u16; domain_len as usize];
    let sid_ptr = PSID(sid.as_mut_ptr().cast());

    // SAFETY: both buffers are sized from the call above and live until the end of this
    // function, past every use of `sid_ptr`.
    let looked_up = unsafe {
        LookupAccountNameW(
            PCWSTR::null(),
            PCWSTR(wide_name.as_ptr()),
            Some(sid_ptr),
            &raw mut sid_len,
            Some(PWSTR(domain.as_mut_ptr())),
            &raw mut domain_len,
            &raw mut kind,
        )
    };
    match looked_up {
        Err(error) if error.code() == ERROR_NONE_MAPPED.to_hresult() => return Ok(None),
        Err(error) => return Err(io::Error::other(error)),
        Ok(()) => {}
    }
    if kind != SidTypeAlias {
        return Ok(None);
    }

    let mut text = PWSTR::null();
    // SAFETY: `sid_ptr` points at the SID written above, and `text` is a valid
    // out-pointer for a `LocalAlloc`ed string freed below.
    unsafe { ConvertSidToStringSidW(sid_ptr, &raw mut text) }.map_err(io::Error::other)?;
    // SAFETY: `text` is the NUL-terminated string the call above returned.
    let converted = unsafe { text.to_string() }.map_err(io::Error::other);
    // SAFETY: freed exactly once, after the copy.
    let _ = unsafe { LocalFree(Some(HLOCAL(text.0.cast()))) };
    converted.map(Some)
}

/// The id of the group `name`, or `None` when it does not exist.
///
/// Uses the system's group database (`getgrnam_r`), so groups held by directory services
/// rather than `/etc/group` — every group `dseditgroup` creates on macOS — are found too.
///
/// # Errors
///
/// Returns the OS error when the lookup itself fails.
#[cfg(unix)]
pub fn group_id(name: &str) -> io::Result<Option<u32>> {
    use std::ffi::CString;

    let name = CString::new(name).map_err(|_| io::Error::other("group name contains NUL"))?;
    let mut buffer = vec![0_u8; 1024];
    loop {
        // SAFETY: `libc::group` is plain data, so all-zero is a valid value to overwrite.
        let mut group: libc::group = unsafe { std::mem::zeroed() };
        let mut result: *mut libc::group = std::ptr::null_mut();
        // SAFETY: `name` is NUL-terminated, `buffer` is valid for its whole length, and
        // both out-pointers are valid. Nothing borrowed from `buffer` outlives the loop.
        let status = unsafe {
            libc::getgrnam_r(
                name.as_ptr(),
                &raw mut group,
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &raw mut result,
            )
        };
        match status {
            0 if result.is_null() => return Ok(None),
            0 => return Ok(Some(group.gr_gid)),
            libc::ERANGE if buffer.len() < 1 << 20 => buffer.resize(buffer.len() * 2, 0),
            // Some platforms report "no such group" through these instead of a null result.
            libc::ENOENT | libc::ESRCH | libc::EBADF | libc::EPERM => return Ok(None),
            code => return Err(io::Error::from_raw_os_error(code)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(windows)]
    #[test]
    fn a_missing_group_leaves_the_file_to_administrators() {
        let file = tempfile::NamedTempFile::new().expect("temp file");
        let access = restrict_to_admins_and_group(file.path(), "antiwire-no-such-group-7f3a")
            .expect("restrict");
        assert_eq!(access, GroupAccess::GroupMissing);
        let sddl = crate::acl::dacl_sddl(file.path()).expect("read back");
        assert!(
            sddl.starts_with("D:P"),
            "inheritance must be cut, got {sddl}"
        );
        assert!(
            !sddl.contains(";BU)"),
            "Users must not keep access, got {sddl}"
        );
    }

    /// `Users` is a local group (an alias) every Windows install has, so it stands in
    /// for the installer-created group.
    #[cfg(windows)]
    #[test]
    fn an_existing_local_group_is_granted_read() {
        let sid = local_group_sid("Users").expect("lookup");
        assert_eq!(sid.as_deref(), Some("S-1-5-32-545"));
    }

    #[cfg(windows)]
    #[test]
    fn a_user_account_is_not_mistaken_for_the_group() {
        let user = std::env::var("USERNAME").expect("USERNAME");
        assert_eq!(local_group_sid(&user).expect("lookup"), None);
    }

    #[cfg(unix)]
    #[test]
    fn looks_up_groups_by_name() {
        let superuser_group = if cfg!(target_os = "macos") {
            "wheel"
        } else {
            "root"
        };
        assert_eq!(group_id(superuser_group).expect("lookup"), Some(0));
        assert_eq!(
            group_id("antiwire-no-such-group-7f3a").expect("lookup"),
            None
        );
    }
}
