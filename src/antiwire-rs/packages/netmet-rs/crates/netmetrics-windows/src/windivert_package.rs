//! One download of the official `WinDivert` 2.2.2 package.
//!
//! Flow accounting and the DNS divert both load this DLL. The install is serialized
//! so a second caller waits and then reuses the files instead of downloading again.
//! The archive comes from <https://reqrypt.org/download/WinDivert-2.2.2-A.zip>.
//!
//! The archive is checked and unpacked in memory, and only the x64 DLL and driver
//! are written to disk. Windows Defender has flagged the archive itself
//! (`Misleading:Win32/Malgent!AMTB`), not the DLL or driver, and nothing reads it
//! once they are out.

use std::fs;
use std::io::Read;
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use sha2::{Digest, Sha256};

use crate::divert_error::DivertError;

const PACKAGE_URL: &str = "https://reqrypt.org/download/WinDivert-2.2.2-A.zip";
const PACKAGE_SHA256: &str = "63cb41763bb4b20f600b6de04e991a9c2be73279e317d4d82f237b150c5f3f15";
const DLL_SHA256: &str = "c1e060ee19444a259b2162f8af0f3fe8c4428a1c6f694dce20de194ac8d7d9a2";
const SYS_SHA256: &str = "8da085332782708d8767bcace5327a6ec7283c17cfb85e40b03cd2323a90ddc2";
const ZIP_DLL: &str = "WinDivert-2.2.2-A/x64/WinDivert.dll";
const ZIP_SYS: &str = "WinDivert-2.2.2-A/x64/WinDivert64.sys";
/// The archive earlier versions saved beside the DLL and driver, and left there.
const LEFTOVER_ARCHIVE: &str = "WinDivert-2.2.2-A.zip";

/// Flow tracking and the DNS divert both wait on the install lock, so a stalled
/// server must not hold it for long.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(120);
/// The official archive is well under 1 MiB; a much larger body is not it.
const MAX_ARCHIVE_BYTES: u64 = 16 * 1024 * 1024;

static INSTALL: Mutex<()> = Mutex::new(());

/// Directory containing the checked official x64 DLL and driver.
///
/// Compiled only for `x86_64` (see `lib.rs`): `WinDivert` 2.2.2 has no ARM64 driver.
/// Its one caller, `Divert::open`, refuses first while `WinDivert` is turned off, so
/// nothing is fetched then.
///
/// # Errors
///
/// Only a download that failed can pass. A package that does not match its hash is the
/// same package at the next try, so it lasts, and is not fetched again.
pub(crate) fn ensure_official_package() -> Result<PathBuf, DivertError> {
    let _guard = INSTALL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    ensure_unlocked()
}

/// Holds both verified files open without write/delete sharing while the DLL and
/// driver are loaded. This closes the gap between hash verification and loading
/// from a directory writable by the interactive user.
pub(crate) fn lock_verified_files(directory: &Path) -> Result<(fs::File, fs::File), String> {
    let dll = lock_verified_file(&directory.join("WinDivert.dll"), DLL_SHA256)?;
    let driver = lock_verified_file(&directory.join("WinDivert64.sys"), SYS_SHA256)?;
    Ok((dll, driver))
}

fn lock_verified_file(path: &Path, expected_hash: &str) -> Result<fs::File, String> {
    const FILE_SHARE_READ: u32 = 0x0000_0001;
    let mut file = fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .open(path)
        .map_err(|error| format!("open {}: {error}", path.display()))?;
    if hash_file(&mut file)? != expected_hash {
        return Err(format!(
            "{} changed after package verification",
            path.display()
        ));
    }
    Ok(file)
}

fn ensure_unlocked() -> Result<PathBuf, DivertError> {
    let directory = install_directory()?;
    remove_leftover_archive(&directory);
    let dll = directory.join("WinDivert.dll");
    let sys = directory.join("WinDivert64.sys");
    if file_sha256(&dll).ok().as_deref() == Some(DLL_SHA256)
        && file_sha256(&sys).ok().as_deref() == Some(SYS_SHA256)
    {
        return Ok(directory);
    }
    fs::create_dir_all(&directory).map_err(|error| error.to_string())?;
    let archive = download_official_archive().map_err(DivertError::passing)?;
    if sha256_hex(&archive) != PACKAGE_SHA256 {
        return Err(DivertError::lasting(format!(
            "WinDivert archive from {PACKAGE_URL} did not match the official SHA-256"
        )));
    }
    extract_official_files(&archive, &directory)?;
    if file_sha256(&dll)?.as_str() != DLL_SHA256 || file_sha256(&sys)?.as_str() != SYS_SHA256 {
        let _ = fs::remove_file(&dll);
        let _ = fs::remove_file(&sys);
        return Err(DivertError::lasting(
            "extracted WinDivert files did not match the official SHA-256",
        ));
    }
    Ok(directory)
}

fn install_directory() -> Result<PathBuf, String> {
    let root = std::env::var_os("LOCALAPPDATA").ok_or("LOCALAPPDATA is not set")?;
    Ok(PathBuf::from(root)
        .join("antiwire")
        .join("windivert")
        .join("2.2.2-A"))
}

/// Deletes an archive an earlier version left beside the DLL and driver. Best
/// effort: antivirus may already have removed it.
fn remove_leftover_archive(directory: &Path) {
    let _ = fs::remove_file(directory.join(LEFTOVER_ARCHIVE));
}

/// Downloads the archive into memory, trusting the Windows certificate store and
/// honouring proxy environment variables and the Windows proxy settings.
fn download_official_archive() -> Result<Vec<u8>, String> {
    let tls = ureq::tls::TlsConfig::builder()
        .root_certs(ureq::tls::RootCerts::PlatformVerifier)
        .build();
    let agent = ureq::Agent::new_with_config(
        ureq::Agent::config_builder()
            .timeout_connect(Some(CONNECT_TIMEOUT))
            .timeout_global(Some(DOWNLOAD_TIMEOUT))
            .tls_config(tls)
            .build(),
    );
    agent
        .get(PACKAGE_URL)
        .call()
        .and_then(|mut response| {
            response
                .body_mut()
                .with_config()
                .limit(MAX_ARCHIVE_BYTES)
                .read_to_vec()
        })
        .map_err(|error| format!("download of {PACKAGE_URL} failed: {error}"))
}

/// Writes the x64 DLL and driver out of the verified `archive`, which stays in
/// memory.
fn extract_official_files(archive: &[u8], directory: &Path) -> Result<(), String> {
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(archive))
        .map_err(|error| format!("read the WinDivert archive: {error}"))?;
    for (entry, file_name) in [(ZIP_DLL, "WinDivert.dll"), (ZIP_SYS, "WinDivert64.sys")] {
        let mut source = archive
            .by_name(entry)
            .map_err(|error| format!("WinDivert archive entry {entry}: {error}"))?;
        let destination = directory.join(file_name);
        let mut output = fs::File::create(&destination)
            .map_err(|error| format!("create {}: {error}", destination.display()))?;
        std::io::copy(&mut source, &mut output)
            .map_err(|error| format!("extract {entry}: {error}"))?;
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn file_sha256(path: &Path) -> Result<String, String> {
    let mut file = fs::File::open(path).map_err(|error| error.to_string())?;
    hash_file(&mut file)
}

fn hash_file(file: &mut fs::File) -> Result<String, String> {
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(|error| error.to_string())?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stand-in archive laid out like the official one.
    fn archive(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        for (name, contents) in entries {
            writer
                .start_file(*name, zip::write::SimpleFileOptions::default())
                .expect("start entry");
            std::io::Write::write_all(&mut writer, contents).expect("write entry");
        }
        writer.finish().expect("finish archive").into_inner()
    }

    /// The names of the files in `directory`, sorted.
    fn files_in(directory: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(directory)
            .expect("read dir")
            .map(|entry| {
                entry
                    .expect("entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        names.sort();
        names
    }

    /// The regression this guards: the archive was saved beside the files and
    /// left there, where Windows Defender flagged it. Only the DLL and driver
    /// reach the disk.
    #[test]
    fn extraction_writes_only_the_x64_dll_and_driver() {
        let directory = tempdir();
        let package = archive(&[
            (ZIP_DLL, b"dll bytes"),
            (ZIP_SYS, b"driver bytes"),
            ("WinDivert-2.2.2-A/x86/WinDivert.dll", b"wrong architecture"),
        ]);
        extract_official_files(&package, &directory).expect("extract");
        assert_eq!(files_in(&directory), ["WinDivert.dll", "WinDivert64.sys"]);
        assert_eq!(
            fs::read(directory.join("WinDivert.dll")).expect("dll"),
            b"dll bytes"
        );
        assert_eq!(
            fs::read(directory.join("WinDivert64.sys")).expect("driver"),
            b"driver bytes"
        );
        let _ = fs::remove_dir_all(&directory);
    }

    #[test]
    fn extraction_fails_when_an_expected_file_is_missing() {
        let directory = tempdir();
        let package = archive(&[(ZIP_DLL, b"dll bytes")]);
        let error = extract_official_files(&package, &directory).expect_err("missing driver");
        assert!(error.contains(ZIP_SYS), "{error}");
        let _ = fs::remove_dir_all(&directory);
    }

    #[test]
    fn an_archive_an_earlier_version_left_is_removed() {
        let directory = tempdir();
        fs::write(directory.join(LEFTOVER_ARCHIVE), b"old archive").expect("leftover");
        fs::write(directory.join("WinDivert.dll"), b"dll bytes").expect("dll");

        remove_leftover_archive(&directory);
        remove_leftover_archive(&directory);

        assert_eq!(files_in(&directory), ["WinDivert.dll"]);
        let _ = fs::remove_dir_all(&directory);
    }

    /// Fetches the real archive into memory and unpacks it into a scratch
    /// directory, leaving the installed copy alone.
    #[test]
    #[ignore = "downloads the official WinDivert package over the network"]
    fn official_download_matches_the_pinned_hashes() {
        let directory = tempdir();
        let package = download_official_archive().expect("download");
        assert_eq!(sha256_hex(&package), PACKAGE_SHA256);
        extract_official_files(&package, &directory).expect("extract");
        assert_eq!(files_in(&directory), ["WinDivert.dll", "WinDivert64.sys"]);
        assert_eq!(
            file_sha256(&directory.join("WinDivert.dll")).expect("dll hash"),
            DLL_SHA256
        );
        assert_eq!(
            file_sha256(&directory.join("WinDivert64.sys")).expect("driver hash"),
            SYS_SHA256
        );
        let _ = fs::remove_dir_all(&directory);
    }

    fn tempdir() -> PathBuf {
        let directory = std::env::temp_dir().join(format!(
            "netmetrics-windivert-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        fs::create_dir_all(&directory).expect("temp dir");
        directory
    }
}
