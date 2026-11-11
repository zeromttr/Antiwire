//! Who signed an executable, as far as the operating system can verify it.
//!
//! Used before an application's allow rules follow it to a new executable: an
//! update is trusted to be the same application only when both binaries carry a
//! valid signature from the same publisher. A path alone proves nothing, because
//! the install directories that version their executables are often writable by
//! the user running the application.

#![allow(unsafe_code)]

use std::path::Path;

/// Whether both executables carry a valid signature from the same publisher.
///
/// `false` whenever either signature is missing, invalid, or cannot be checked,
/// including on platforms without executable signatures.
#[must_use]
pub fn same_verified_publisher(first: &Path, second: &Path) -> bool {
    match (verified_publisher(first), verified_publisher(second)) {
        (Some(first), Some(second)) => first == second,
        _ => false,
    }
}

/// The publisher of a validly signed executable, or `None`.
///
/// On Windows this is the subject name of the Authenticode signing certificate,
/// accepted only when the signature verifies against a trusted root. Revocation
/// is not checked, so the call never waits on the network.
#[cfg(windows)]
#[must_use]
pub fn verified_publisher(path: &Path) -> Option<String> {
    use std::os::windows::ffi::OsStrExt as _;

    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{HWND, INVALID_HANDLE_VALUE};
    use windows::Win32::Security::WinTrust::{
        WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_FILE_INFO,
        WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_FILE, WTD_REVOCATION_CHECK_NONE, WTD_REVOKE_NONE,
        WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
    };

    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut file = WINTRUST_FILE_INFO {
        cbStruct: struct_size::<WINTRUST_FILE_INFO>(),
        pcwszFilePath: PCWSTR(wide.as_ptr()),
        ..Default::default()
    };
    let mut data = WINTRUST_DATA {
        cbStruct: struct_size::<WINTRUST_DATA>(),
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: WTD_CHOICE_FILE,
        dwStateAction: WTD_STATEACTION_VERIFY,
        dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE,
        ..Default::default()
    };
    data.Anonymous.pFile = &raw mut file;
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    let no_window = HWND(INVALID_HANDLE_VALUE.0);

    // SAFETY: `data` and the `file` it points at are initialized for a file
    // verification and outlive both calls, as does `wide`, which `file` borrows.
    let status = unsafe { WinVerifyTrust(no_window, &raw mut action, (&raw mut data).cast()) };
    let publisher = if status == 0 {
        // SAFETY: a successful verify leaves its state open until the close below.
        unsafe { signer_subject(data.hWVTStateData) }
    } else {
        None
    };

    data.dwStateAction = WTD_STATEACTION_CLOSE;
    // SAFETY: closes the state the verify call opened, with the same structures.
    let _ = unsafe { WinVerifyTrust(no_window, &raw mut action, (&raw mut data).cast()) };
    publisher
}

#[cfg(windows)]
fn struct_size<T>() -> u32 {
    u32::try_from(std::mem::size_of::<T>()).unwrap_or(u32::MAX)
}

/// The X.500 subject of the leaf certificate that signed the verified file.
///
/// # Safety
///
/// `state` must be the open state of a successful `WinVerifyTrust` verify call.
#[cfg(windows)]
unsafe fn signer_subject(state: windows::Win32::Foundation::HANDLE) -> Option<String> {
    use windows::Win32::Security::Cryptography::{
        CertNameToStrW, CERT_X500_NAME_STR, X509_ASN_ENCODING,
    };
    use windows::Win32::Security::WinTrust::{
        WTHelperGetProvSignerFromChain, WTHelperProvDataFromStateData,
    };

    // SAFETY: the caller guarantees `state` is open, so the provider data, its
    // signer, certificate chain and certificate stay valid until it is closed.
    unsafe {
        let provider = WTHelperProvDataFromStateData(state);
        if provider.is_null() {
            return None;
        }
        let signer = WTHelperGetProvSignerFromChain(provider, 0, false, 0);
        if signer.is_null() || (*signer).csCertChain == 0 || (*signer).pasCertChain.is_null() {
            return None;
        }
        let certificate = (*(*signer).pasCertChain).pCert;
        if certificate.is_null() || (*certificate).pCertInfo.is_null() {
            return None;
        }
        let subject = &raw const (*(*certificate).pCertInfo).Subject;

        let length = CertNameToStrW(X509_ASN_ENCODING, subject, CERT_X500_NAME_STR, None);
        if length <= 1 {
            return None;
        }
        let mut buffer = vec![0_u16; length as usize];
        let written = CertNameToStrW(
            X509_ASN_ENCODING,
            subject,
            CERT_X500_NAME_STR,
            Some(&mut buffer),
        );
        let text = buffer.get(..(written as usize).saturating_sub(1))?;
        String::from_utf16(text)
            .ok()
            .filter(|name| !name.is_empty())
    }
}

/// The publisher of a validly signed executable, or `None`.
///
/// On macOS this is the Team ID of a signature `codesign` verifies strictly.
/// Ad-hoc signatures have no Team ID and so never count.
#[cfg(target_os = "macos")]
#[must_use]
pub fn verified_publisher(path: &Path) -> Option<String> {
    use std::process::Command;

    const CODESIGN: &str = "/usr/bin/codesign";

    let verified = Command::new(CODESIGN)
        .args(["--verify", "--strict", "--"])
        .arg(path)
        .output()
        .ok()?;
    if !verified.status.success() {
        return None;
    }
    let details = Command::new(CODESIGN)
        .args(["--display", "--verbose=2", "--"])
        .arg(path)
        .output()
        .ok()?;
    // codesign writes its details to stderr.
    String::from_utf8_lossy(&details.stderr)
        .lines()
        .find_map(|line| line.strip_prefix("TeamIdentifier="))
        .map(str::trim)
        .filter(|team| !team.is_empty() && *team != "not set")
        .map(|team| format!("team:{team}"))
}

/// The publisher of a validly signed executable, or `None`.
///
/// Linux executables carry no signature to check, so there is never a publisher.
#[cfg(not(any(windows, target_os = "macos")))]
#[must_use]
pub fn verified_publisher(_path: &Path) -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unsigned_file_has_no_publisher() {
        let file = tempfile::NamedTempFile::new().expect("temp file");
        std::fs::write(file.path(), b"MZ not really a program").expect("write");
        assert_eq!(verified_publisher(file.path()), None);
        assert!(!same_verified_publisher(file.path(), file.path()));
    }

    #[test]
    fn a_missing_file_has_no_publisher() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert_eq!(verified_publisher(&dir.path().join("absent.exe")), None);
    }

    /// The kernel image carries an embedded Microsoft Authenticode signature.
    #[cfg(windows)]
    #[test]
    fn a_microsoft_signed_binary_names_its_publisher() {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_owned());
        let kernel = Path::new(&root).join(r"System32\ntoskrnl.exe");
        let publisher = verified_publisher(&kernel).expect("ntoskrnl.exe is signed");
        assert!(publisher.contains("Microsoft"), "{publisher}");
        assert!(same_verified_publisher(&kernel, &kernel));
    }
}
