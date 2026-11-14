//! Publishing a file that only privileged accounts may read.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write as _};
use std::path::Path;
use std::time::Duration;

/// Replaces `target` with `contents`, restricting the file before anything is
/// written into it.
///
/// The contents go to a staging file beside `target`, created `0600` on unix.
/// `restrict` runs on that file while it is still empty, so the contents are
/// never readable under the directory's inherited permissions, even briefly.
/// The file is then synced and renamed over `target`, so a reader never sees a
/// partial file, and a file someone else created at `target` is replaced rather
/// than written through. Nothing is left at the staging path on failure.
///
/// # Errors
///
/// Returns the I/O error from creating the directory, writing, restricting, or
/// moving the file into place, and [`io::ErrorKind::InvalidInput`] when `target`
/// has no file name.
pub fn write_private_file<T>(
    target: &Path,
    contents: &[u8],
    restrict: impl FnOnce(&Path, &File) -> io::Result<T>,
) -> io::Result<T> {
    let Some(file_name) = target.file_name() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "a private file needs a file name",
        ));
    };
    if let Some(parent) = target
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    let staging = target.with_file_name(format!(
        "{}.{}.tmp",
        file_name.to_string_lossy(),
        std::process::id()
    ));
    let _ = fs::remove_file(&staging);

    let published = (|| {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut file = options.open(&staging)?;
        let restricted = restrict(&staging, &file)?;
        file.write_all(contents)?;
        file.sync_all()?;
        drop(file);
        rename_into_place(&staging, target)?;
        Ok(restricted)
    })();
    if published.is_err() {
        let _ = fs::remove_file(&staging);
    }
    published
}

/// Replaces `target` with `staging`.
///
/// A reader holding the old file open can briefly block the replace on Windows,
/// so a failed rename is retried a few times before it is reported.
fn rename_into_place(staging: &Path, target: &Path) -> io::Result<()> {
    const ATTEMPTS: u32 = 5;
    let mut attempt = 1;
    loop {
        match fs::rename(staging, target) {
            Ok(()) => return Ok(()),
            Err(error) if attempt >= ATTEMPTS => return Err(error),
            Err(_) => {
                std::thread::sleep(Duration::from_millis(50));
                attempt += 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restricts_the_empty_file_then_writes_and_replaces_the_target() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("nested").join("secret.json");
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::write(&target, "old").unwrap();

        let seen = write_private_file(&target, b"new", |staging, file| {
            assert_ne!(staging, target.as_path());
            assert_eq!(file.metadata()?.len(), 0, "restricted before writing");
            Ok(7)
        })
        .expect("write");

        assert_eq!(seen, 7);
        assert_eq!(fs::read_to_string(&target).unwrap(), "new");
        let leftovers: Vec<_> = fs::read_dir(target.parent().unwrap())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(leftovers, [std::ffi::OsString::from("secret.json")]);
    }

    #[test]
    fn a_failed_restriction_leaves_the_target_and_no_staging_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("secret.json");
        fs::write(&target, "old").unwrap();

        let error = write_private_file(&target, b"new", |_, _| -> io::Result<()> {
            Err(io::Error::other("denied"))
        })
        .expect_err("restriction failed");

        assert_eq!(error.to_string(), "denied");
        assert_eq!(fs::read_to_string(&target).unwrap(), "old");
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn creates_a_missing_parent_directory() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("a").join("b").join("secret");
        write_private_file(&target, b"x", |_, _| Ok(())).expect("write");
        assert_eq!(fs::read(&target).unwrap(), b"x");
    }
}
