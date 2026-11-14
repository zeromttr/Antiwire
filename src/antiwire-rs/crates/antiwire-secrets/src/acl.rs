//! Windows counterpart to the unix `0600` mode used for on-disk secrets.
//!
//! The daemon's data directory has to stay readable by the interactive user, because the
//! UI reads `ipc.token` and `ipc.crt` out of it to authenticate over gRPC. That rules out
//! protecting the database key and the connection database with a directory ACL — the
//! files that must not be readable share a directory with files that must be. So they
//! carry their own.

#![allow(unsafe_code)]

use std::io;
use std::path::Path;

/// Full control for `SYSTEM`, the local Administrators group, and the file's owner, with
/// inheritance from the parent directory switched off.
///
/// `S-1-3-4` is the OWNER RIGHTS SID, written literally rather than as the `OW` alias so
/// the string does not depend on how a given Windows version resolves aliases. Naming the
/// owner rather than a fixed account is what makes this the analogue of `0600`: in a real
/// install the daemon runs as `SYSTEM` and the ACE is redundant with `SY`, while under
/// `cargo test` the file belongs to whoever ran the tests and stays reachable without
/// elevation.
#[cfg(windows)]
const OWNER_AND_ADMINS_ONLY: &str = "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;S-1-3-4)";

/// Restricts `path` so only `SYSTEM`, Administrators, and the file's owner can open it.
///
/// Does nothing off Windows; the unix key provider sets its modes at open time instead.
///
/// # Errors
///
/// Never, on this platform.
#[cfg(not(windows))]
#[allow(clippy::missing_const_for_fn)]
pub fn restrict_to_owner_and_admins(_path: &Path) -> io::Result<()> {
    Ok(())
}

/// Restricts `path` so only `SYSTEM`, Administrators, and the file's owner can open it.
///
/// Applying this to a file that is already restricted is a no-op, which is what lets it
/// run on every load and repair an install created before the file carried its own ACL.
///
/// # Errors
///
/// Returns the underlying OS error when `path` does not exist, when the caller lacks
/// `WRITE_DAC` on it, or when the volume does not carry ACLs at all — a file on FAT or
/// exFAT cannot be protected, and reporting that is better than implying it was.
#[cfg(windows)]
pub fn restrict_to_owner_and_admins(path: &Path) -> io::Result<()> {
    apply_sddl(path, OWNER_AND_ADMINS_ONLY)
}

/// Replaces `path`'s DACL with the one in `sddl`.
#[cfg(windows)]
pub(crate) fn apply_sddl(path: &Path, sddl: &str) -> io::Result<()> {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows::Win32::Security::PSECURITY_DESCRIPTOR;

    let sddl = wide(sddl);
    let mut descriptor = PSECURITY_DESCRIPTOR(std::ptr::null_mut());

    // SAFETY: `sddl` is NUL-terminated and outlives the call, and `descriptor` is a valid
    // out-pointer. On success the callee hands back a `LocalAlloc`ed descriptor, released
    // below on both the success and failure paths.
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl.as_ptr()),
            SDDL_REVISION_1,
            &raw mut descriptor,
            None,
        )
        .map_err(io::Error::other)?;
    }

    let applied = apply_dacl(path, descriptor);

    // SAFETY: `descriptor` came from the conversion above and is freed exactly once.
    let _ = unsafe { LocalFree(Some(HLOCAL(descriptor.0))) };

    applied
}

/// Whether `file` belongs to an account an unprivileged user cannot act as.
///
/// For files a privileged process writes and later trusts: the data directory is
/// writable by ordinary users, so a file there is only as trustworthy as its owner.
/// On Windows the owner must be `SYSTEM` or the local Administrators group, which an
/// unprivileged process cannot assign. On unix the owner must be root and the file must
/// not be writable by its group or by others.
///
/// Takes an open file rather than a path so the check covers the file actually read,
/// not whatever the path names a moment later.
///
/// # Errors
///
/// Returns the underlying OS error when the owner cannot be read.
#[cfg(windows)]
pub fn is_privileged_owner(file: &std::fs::File) -> io::Result<bool> {
    use std::os::windows::io::AsRawHandle as _;
    use windows::Win32::Foundation::{LocalFree, HANDLE, HLOCAL};
    use windows::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
    use windows::Win32::Security::{
        IsWellKnownSid, WinBuiltinAdministratorsSid, WinLocalSystemSid, OWNER_SECURITY_INFORMATION,
        PSECURITY_DESCRIPTOR, PSID,
    };

    let mut owner = PSID(std::ptr::null_mut());
    let mut descriptor = PSECURITY_DESCRIPTOR(std::ptr::null_mut());

    // SAFETY: the handle belongs to `file`, which outlives the call, and both
    // out-pointers are valid. On success the callee returns a `LocalAlloc`ed
    // descriptor that `owner` points into, freed below.
    let status = unsafe {
        GetSecurityInfo(
            HANDLE(file.as_raw_handle()),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            Some(&raw mut owner),
            None,
            None,
            None,
            Some(&raw mut descriptor),
        )
    };
    if status.is_err() {
        return Err(io::Error::from_raw_os_error(status.0.cast_signed()));
    }

    // SAFETY: `owner` points into `descriptor`, which is still alive here.
    let privileged = unsafe {
        IsWellKnownSid(owner, WinLocalSystemSid).as_bool()
            || IsWellKnownSid(owner, WinBuiltinAdministratorsSid).as_bool()
    };

    // SAFETY: `descriptor` came from `GetSecurityInfo` and is freed exactly once.
    let _ = unsafe { LocalFree(Some(HLOCAL(descriptor.0))) };

    Ok(privileged)
}

/// Whether `file` belongs to an account an unprivileged user cannot act as.
///
/// For files a privileged process writes and later trusts: the owner must be root and
/// the file must not be writable by its group or by others.
///
/// # Errors
///
/// Returns the underlying OS error when the file's metadata cannot be read.
#[cfg(unix)]
pub fn is_privileged_owner(file: &std::fs::File) -> io::Result<bool> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = file.metadata()?;
    Ok(metadata.is_file() && metadata.uid() == 0 && metadata.mode() & 0o022 == 0)
}

/// Writes `descriptor`'s DACL onto `path`, replacing whatever was inherited.
#[cfg(windows)]
fn apply_dacl(
    path: &Path,
    descriptor: windows::Win32::Security::PSECURITY_DESCRIPTOR,
) -> io::Result<()> {
    use windows::core::{BOOL, PCWSTR};
    use windows::Win32::Security::Authorization::{SetNamedSecurityInfoW, SE_FILE_OBJECT};
    use windows::Win32::Security::{
        GetSecurityDescriptorDacl, ACL, DACL_SECURITY_INFORMATION,
        PROTECTED_DACL_SECURITY_INFORMATION,
    };

    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut present = BOOL(0);
    let mut defaulted = BOOL(0);

    // SAFETY: `descriptor` is a valid descriptor built from a fixed SDDL string, and the
    // three out-pointers are valid for the duration of the call.
    unsafe {
        GetSecurityDescriptorDacl(
            descriptor,
            &raw mut present,
            &raw mut dacl,
            &raw mut defaulted,
        )
        .map_err(io::Error::other)?;
    }

    if !present.as_bool() || dacl.is_null() {
        return Err(io::Error::other(
            "security descriptor was built without a DACL",
        ));
    }

    let wide_path = wide_os(path);

    // PROTECTED_DACL_SECURITY_INFORMATION is what makes `D:P` take effect: without it the
    // ACEs inherited from the data directory — which grant BUILTIN\Users read — survive
    // alongside the ones being set here.
    //
    // SAFETY: `wide_path` is NUL-terminated, and `dacl` points into `descriptor`, which
    // the caller keeps alive across this call.
    let status = unsafe {
        SetNamedSecurityInfoW(
            PCWSTR(wide_path.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(dacl),
            None,
        )
    };

    if status.is_ok() {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(status.0.cast_signed()))
    }
}

#[cfg(windows)]
fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(windows)]
fn wide_os(path: &Path) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt as _;
    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// Reads `path`'s DACL back as an SDDL string. Test-only: nothing in the daemon needs to
/// inspect an ACL, but asserting on the applied one is the only way to prove the ACEs
/// landed rather than merely that the call returned success.
#[cfg(all(test, windows))]
pub(crate) fn dacl_sddl(path: &Path) -> io::Result<String> {
    use windows::core::{PCWSTR, PWSTR};
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Authorization::{
        ConvertSecurityDescriptorToStringSecurityDescriptorW, GetNamedSecurityInfoW,
        SDDL_REVISION_1, SE_FILE_OBJECT,
    };
    use windows::Win32::Security::{
        DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    };

    let wide_path = wide_os(path);
    let mut descriptor = PSECURITY_DESCRIPTOR(std::ptr::null_mut());

    // SAFETY: `wide_path` is NUL-terminated and `descriptor` is a valid out-pointer. On
    // success the callee returns a `LocalAlloc`ed descriptor, freed below.
    let status = unsafe {
        GetNamedSecurityInfoW(
            PCWSTR(wide_path.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            None,
            None,
            None,
            None,
            &raw mut descriptor,
        )
    };
    if status.is_err() {
        return Err(io::Error::from_raw_os_error(status.0.cast_signed()));
    }

    let mut text = PWSTR(std::ptr::null_mut());
    // SAFETY: `descriptor` is the descriptor just returned, and `text` is a valid
    // out-pointer for another `LocalAlloc`ed buffer.
    let converted = unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor,
            SDDL_REVISION_1,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            &raw mut text,
            None,
        )
    };

    let sddl = match converted {
        Ok(()) => {
            // SAFETY: `text` points at a NUL-terminated string owned by the call above.
            let value = unsafe { text.to_string() }.map_err(io::Error::other);
            // SAFETY: freed exactly once, after the copy.
            let _ = unsafe { LocalFree(Some(HLOCAL(text.0.cast()))) };
            value
        }
        Err(error) => Err(io::Error::other(error)),
    };

    // SAFETY: `descriptor` came from `GetNamedSecurityInfoW` and is freed exactly once.
    let _ = unsafe { LocalFree(Some(HLOCAL(descriptor.0))) };

    sddl
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    /// A file created by an ordinary user must not pass, or anyone could plant one.
    ///
    /// A new file takes the token's default owner, so that decides the result, not
    /// elevation alone: an elevated split admin token defaults to Administrators and
    /// must pass, while an admin account with UAC off, as on CI runners, defaults to
    /// its own user SID and must not.
    #[test]
    fn a_new_file_is_privileged_only_when_the_token_owner_is() {
        let file = tempfile::NamedTempFile::new().expect("temp file");
        let privileged = is_privileged_owner(file.as_file()).expect("owner readable");
        assert_eq!(privileged, token_owner_is_privileged());
    }

    /// Whether this process's default owner for new objects is `SYSTEM` or the
    /// local Administrators group.
    fn token_owner_is_privileged() -> bool {
        use windows::Win32::Foundation::{CloseHandle, HANDLE};
        use windows::Win32::Security::{
            GetTokenInformation, IsWellKnownSid, TokenOwner, WinBuiltinAdministratorsSid,
            WinLocalSystemSid, TOKEN_OWNER, TOKEN_QUERY,
        };
        use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

        let mut token = HANDLE::default();
        // SAFETY: the process pseudo handle is always valid, and `token` is a valid
        // out-pointer; the opened handle is closed below.
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) }
            .expect("process token");

        // Large enough for TOKEN_OWNER and any SID; u64 keeps it pointer aligned.
        let mut buffer = [0_u64; 16];
        let mut length = 0;
        // SAFETY: `token` is open for query, and the buffer is valid and aligned for
        // TOKEN_OWNER for the stated size.
        let queried = unsafe {
            GetTokenInformation(
                token,
                TokenOwner,
                Some(buffer.as_mut_ptr().cast()),
                u32::try_from(std::mem::size_of_val(&buffer)).expect("buffer size"),
                &raw mut length,
            )
        };
        // SAFETY: `token` came from `OpenProcessToken` and is closed exactly once.
        let _ = unsafe { CloseHandle(token) };
        queried.expect("token owner readable");

        // SAFETY: the query succeeded, so the buffer starts with a TOKEN_OWNER whose
        // SID points into the same buffer.
        unsafe {
            let owner = (*buffer.as_ptr().cast::<TOKEN_OWNER>()).Owner;
            IsWellKnownSid(owner, WinLocalSystemSid).as_bool()
                || IsWellKnownSid(owner, WinBuiltinAdministratorsSid).as_bool()
        }
    }

    /// The SDDL is a compile-time constant, so a typo in it would fail every call at
    /// runtime rather than at build time. This is the test that catches that.
    #[test]
    fn restricts_a_real_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("secret.bin");
        std::fs::write(&path, b"payload").expect("write");

        restrict_to_owner_and_admins(&path).expect("restrict");

        // The owner keeps full control, so the file this process created stays readable
        // whether or not the test run is elevated.
        assert_eq!(std::fs::read(&path).expect("read back"), b"payload");
    }

    /// The property that matters: no standard user can read the file, and the ACEs that
    /// would have been inherited from the data directory are gone.
    #[test]
    fn grants_nobody_but_system_admins_and_the_owner() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("secret.bin");
        std::fs::write(&path, b"payload").expect("write");

        restrict_to_owner_and_admins(&path).expect("restrict");
        let sddl = dacl_sddl(&path).expect("read back dacl");

        // `P` is the protected flag. Without it the ACEs inherited from the data
        // directory survive alongside these and BUILTIN\Users keeps its read.
        assert!(sddl.starts_with("D:P"), "DACL is not protected: {sddl}");

        // Three ACEs and no others: any fourth would be an account this file is not
        // meant to be reachable from.
        assert_eq!(
            sddl.matches("(A;").count(),
            3,
            "unexpected ACE count: {sddl}"
        );
        for expected in ["(A;;FA;;;SY)", "(A;;FA;;;BA)", "(A;;FA;;;OW)"] {
            assert!(sddl.contains(expected), "missing {expected}: {sddl}");
        }
    }

    /// The regression this whole module exists for.
    ///
    /// A temp directory has no inheritable ACE for `BUILTIN\Users`, so the test above
    /// would still pass if inheritance were left switched on. `C:\ProgramData\Antiwire`
    /// does have one — the installer grants Users read+execute there so the UI can reach
    /// `ipc.token` — and every file created in it picks that up. This reproduces that
    /// shape and checks the inherited read is actually gone afterwards.
    #[test]
    fn strips_a_read_inherited_from_the_parent_directory() {
        let dir = tempfile::tempdir().expect("tempdir");

        // (OI)(CI)(RX) on the directory is what C:\ProgramData\Antiwire carries.
        let granted = std::process::Command::new("icacls.exe")
            .arg(dir.path())
            .arg("/grant")
            .arg("*S-1-5-32-545:(OI)(CI)(RX)")
            .output()
            .expect("run icacls");
        assert!(
            granted.status.success(),
            "icacls failed: {}",
            String::from_utf8_lossy(&granted.stdout)
        );

        let path = dir.path().join("db.key");
        std::fs::write(&path, b"protected key").expect("write");

        // Guards the guard: if the inherited ACE never landed, the assertion below would
        // pass without the restriction doing anything.
        let inherited = dacl_sddl(&path).expect("read back inherited dacl");
        assert!(
            inherited.contains("BU"),
            "expected an inherited BUILTIN\\Users ACE to strip: {inherited}"
        );

        restrict_to_owner_and_admins(&path).expect("restrict");

        let sddl = dacl_sddl(&path).expect("read back dacl");
        assert!(
            !sddl.contains("BU"),
            "BUILTIN\\Users still has access: {sddl}"
        );
        assert_eq!(
            std::fs::read(&path).expect("still readable"),
            b"protected key"
        );
    }

    #[test]
    fn is_idempotent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("secret.bin");
        std::fs::write(&path, b"payload").expect("write");

        restrict_to_owner_and_admins(&path).expect("first");
        restrict_to_owner_and_admins(&path).expect("second");
    }

    #[test]
    fn reports_a_missing_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let error =
            restrict_to_owner_and_admins(&dir.path().join("absent.bin")).expect_err("must fail");
        assert_eq!(
            error.raw_os_error(),
            Some(
                windows::Win32::Foundation::ERROR_FILE_NOT_FOUND
                    .0
                    .cast_signed()
            )
        );
    }
}
