//! Directory junctions, which `{install}/current` is on Windows.
//!
//! No std API creates one (`std::os::windows::fs::junction_point` is
//! unstable), and running `mklink /J` would go through `cmd`. A junction is an
//! empty directory with a mount-point reparse point, set with
//! `FSCTL_SET_REPARSE_POINT`:
//! <https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_set_reparse_point>.
//! Its buffer is `REPARSE_DATA_BUFFER` with `MountPointReparseBuffer`:
//! <https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_reparse_data_buffer>.
//! Reparse points "can be established for a directory, but the directory must
//! be empty":
//! <https://learn.microsoft.com/en-us/windows/win32/fileio/reparse-points>.
//!
//! **Undocumented:** Learn does not say what form the substitute name takes.
//! It is the NT path `\??\` followed by the absolute target, which is what
//! `mklink /J` writes. So every junction made here is checked to lead to its
//! target, and removed if it does not.

use std::fs;
use std::io;
use std::os::windows::ffi::OsStrExt as _;
use std::path::{Component, Path, Prefix};

/// Makes `link`, which must not exist, a junction to the directory `target`.
///
/// # Errors
///
/// When `target` is not an absolute path on a local drive, when the junction
/// cannot be made, or when it does not lead to `target`. `link` does not exist
/// afterwards in any of those cases.
pub(crate) fn create(link: &Path, target: &Path) -> io::Result<()> {
    let print = drive_path(target)?;
    let mut substitute: Vec<u16> = r"\??\".encode_utf16().collect();
    substitute.extend_from_slice(&print);
    let buffer = mount_point_buffer(&substitute, &print)?;
    fs::create_dir(link)?;
    let made = set_reparse_point(link, &buffer).and_then(|()| leads_to(link, target));
    if made.is_err() {
        // Removing a junction removes only the link, never its target.
        let _ = fs::remove_dir(link);
    }
    made
}

/// `path` as UTF-16 when it is an absolute path on a drive letter, without a
/// `\\?\` prefix. A junction cannot lead to a network share.
fn drive_path(path: &Path) -> io::Result<Vec<u16>> {
    let refuse = || {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "{} is not an absolute path on a local drive",
                path.display()
            ),
        )
    };
    let mut components = path.components();
    let drive = match components.next() {
        Some(Component::Prefix(prefix)) => match prefix.kind() {
            Prefix::Disk(letter) | Prefix::VerbatimDisk(letter) => letter,
            _ => return Err(refuse()),
        },
        _ => return Err(refuse()),
    };
    if components.next() != Some(Component::RootDir) {
        return Err(refuse());
    }
    let mut text: Vec<u16> = format!("{}:\\", char::from(drive)).encode_utf16().collect();
    text.extend(components.as_path().as_os_str().encode_wide());
    if text.contains(&0) {
        return Err(refuse());
    }
    Ok(text)
}

/// The `REPARSE_DATA_BUFFER` of a mount point, byte by byte in its documented
/// order: `ReparseTag` (u32), `ReparseDataLength` (u16), `Reserved` (u16),
/// then `SubstituteNameOffset`, `SubstituteNameLength`, `PrintNameOffset` and
/// `PrintNameLength` (u16 each, in bytes into `PathBuffer`, lengths without
/// the terminating null), then `PathBuffer` with both names null-terminated.
/// `ReparseDataLength` counts what follows the first 8 bytes.
fn mount_point_buffer(substitute: &[u16], print: &[u16]) -> io::Result<Vec<u8>> {
    use windows::Win32::System::SystemServices::IO_REPARSE_TAG_MOUNT_POINT;

    let too_long = || {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "the junction target is too long",
        )
    };
    let bytes = |units: usize| units.checked_mul(2).and_then(|n| u16::try_from(n).ok());
    let substitute_length = bytes(substitute.len()).ok_or_else(too_long)?;
    let print_length = bytes(print.len()).ok_or_else(too_long)?;
    let print_offset = substitute_length.checked_add(2).ok_or_else(too_long)?;
    let path_buffer = bytes(substitute.len() + print.len() + 2).ok_or_else(too_long)?;
    let data_length = path_buffer.checked_add(8).ok_or_else(too_long)?;

    let mut buffer = Vec::with_capacity(8 + usize::from(data_length));
    buffer.extend_from_slice(&IO_REPARSE_TAG_MOUNT_POINT.to_le_bytes());
    buffer.extend_from_slice(&data_length.to_le_bytes());
    buffer.extend_from_slice(&0_u16.to_le_bytes());
    for field in [0, substitute_length, print_offset, print_length] {
        buffer.extend_from_slice(&field.to_le_bytes());
    }
    for unit in substitute.iter().chain(&[0]).chain(print).chain(&[0]) {
        buffer.extend_from_slice(&unit.to_le_bytes());
    }
    Ok(buffer)
}

/// Sets `buffer` as the reparse point of the empty directory `dir`.
#[expect(
    unsafe_code,
    reason = "FSCTL_SET_REPARSE_POINT has no safe wrapper in std or the windows crate"
)]
fn set_reparse_point(dir: &Path, buffer: &[u8]) -> io::Result<()> {
    use std::os::windows::fs::OpenOptionsExt as _;
    use std::os::windows::io::AsRawHandle as _;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    };
    use windows::Win32::System::Ioctl::FSCTL_SET_REPARSE_POINT;
    use windows::Win32::System::IO::DeviceIoControl;

    // A directory opens only with FILE_FLAG_BACKUP_SEMANTICS, and
    // FILE_FLAG_OPEN_REPARSE_POINT opens it rather than what it may lead to.
    let handle = fs::OpenOptions::new()
        .write(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS.0 | FILE_FLAG_OPEN_REPARSE_POINT.0)
        .open(dir)?;
    let length = u32::try_from(buffer.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "reparse buffer too large"))?;
    let mut returned = 0_u32;
    // SAFETY: `handle` is an open handle to the directory and outlives the
    // call. The input pointer and `length` describe `buffer`, which lives
    // across the call and is only read. There is no output buffer. Without
    // an OVERLAPPED the call is synchronous, and then `lpBytesReturned` must
    // not be null: `returned` is a valid out-pointer.
    unsafe {
        DeviceIoControl(
            HANDLE(handle.as_raw_handle()),
            FSCTL_SET_REPARSE_POINT,
            Some(buffer.as_ptr().cast()),
            length,
            None,
            0,
            Some(&raw mut returned),
            None,
        )
    }
    .map_err(io::Error::other)
}

/// Checks that `link` resolves to the directory `target`.
fn leads_to(link: &Path, target: &Path) -> io::Result<()> {
    if fs::canonicalize(link)? == fs::canonicalize(target)? {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "{} does not lead to {}",
            link.display(),
            target.display()
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_junction_leads_to_its_target() {
        let dir = tempfile::tempdir().expect("temp dir");
        let target = dir.path().join("versions").join("1.1.0");
        fs::create_dir_all(&target).expect("target");
        fs::write(target.join("antiwire.exe"), b"client").expect("file");
        let link = dir.path().join("current");

        create(&link, &target).expect("junction");

        assert_eq!(
            fs::read(link.join("antiwire.exe")).expect("through"),
            b"client"
        );
        assert!(fs::symlink_metadata(&link)
            .expect("link")
            .file_type()
            .is_symlink());
        fs::remove_dir(&link).expect("remove the link");
        assert!(target.join("antiwire.exe").is_file(), "only the link goes");
    }

    #[test]
    fn a_junction_to_a_missing_target_is_not_left_behind() {
        let dir = tempfile::tempdir().expect("temp dir");
        let link = dir.path().join("current");

        create(&link, &dir.path().join("absent")).expect_err("nothing to lead to");

        assert!(fs::symlink_metadata(&link).is_err());
    }

    #[test]
    fn only_a_path_on_a_local_drive_can_be_a_target() {
        let dir = tempfile::tempdir().expect("temp dir");
        let link = dir.path().join("current");
        for target in [r"relative\versions", r"\\server\share\versions"] {
            let error = create(&link, Path::new(target)).expect_err("refused");
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput, "{target}");
        }
        assert!(fs::symlink_metadata(&link).is_err());
    }

    #[test]
    fn the_buffer_follows_the_documented_layout() {
        let wide = |text: &str| text.encode_utf16().collect::<Vec<u16>>();
        let buffer = mount_point_buffer(&wide(r"\??\C:\a"), &wide(r"C:\a")).expect("buffer");

        let u16_at = |at: usize| u16::from_le_bytes([buffer[at], buffer[at + 1]]);
        assert_eq!(
            u32::from_le_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]),
            0xA000_0003,
            "IO_REPARSE_TAG_MOUNT_POINT"
        );
        // Substitute (8 units) and print (4 units) names, each with a null.
        let path_buffer = (8 + 1 + 4 + 1) * 2;
        assert_eq!(usize::from(u16_at(4)), 8 + path_buffer, "ReparseDataLength");
        assert_eq!(u16_at(6), 0, "Reserved");
        assert_eq!(u16_at(8), 0, "SubstituteNameOffset");
        assert_eq!(u16_at(10), 16, "SubstituteNameLength");
        assert_eq!(u16_at(12), 18, "PrintNameOffset");
        assert_eq!(u16_at(14), 8, "PrintNameLength");
        assert_eq!(buffer.len(), 16 + path_buffer);
    }

    #[test]
    fn a_verbatim_drive_path_loses_its_prefix() {
        let wide = drive_path(Path::new(r"\\?\C:\Program Files\Antiwire")).expect("path");
        assert_eq!(
            String::from_utf16(&wide).expect("utf-16"),
            r"C:\Program Files\Antiwire"
        );
    }
}
