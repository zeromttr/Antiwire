//! A copy of the DNS redirect snapshot that does not depend on the database.
//!
//! The snapshot of the adapters' real DNS servers normally lives only in the
//! encrypted database. If the database cannot be opened after the daemon dies,
//! because its key is lost or the file is damaged, the reaper would have nothing
//! to restore from and the adapters would stay pointed at a loopback resolver
//! that no longer exists. This file is the fallback.
//!
//! The data directory is writable by ordinary users, and a privileged process
//! applies whatever DNS servers this file names. So it carries the same
//! owner-and-administrators ACL as the database (`0600` on unix), and a reader
//! trusts it only when a privileged account owns it.

use std::fs::{self, File};
use std::io::{self, Read as _};
use std::path::{Path, PathBuf};

use tracing::warn;

const FILE_NAME: &str = "dns-redirect-state.json";

/// Far larger than any real snapshot. A bigger file is not one this module wrote.
const MAX_BYTES: u64 = 1024 * 1024;

fn journal_path(data_dir: &Path) -> PathBuf {
    data_dir.join(FILE_NAME)
}

/// Replaces the journal with `snapshot`.
///
/// The file is restricted to its owner and administrators while still empty,
/// then written and renamed into place (see
/// [`antiwire_secrets::write_private_file`]), so the snapshot is never readable
/// under the data directory's inherited permissions and a reader never sees a
/// partial one.
///
/// # Errors
///
/// Returns the I/O error when the file cannot be written, restricted, or moved
/// into place. Nothing is left at the staging path on failure.
pub fn write(data_dir: &Path, snapshot: &str) -> io::Result<()> {
    antiwire_secrets::write_private_file(
        &journal_path(data_dir),
        snapshot.as_bytes(),
        |staging, _| antiwire_secrets::restrict_to_owner_and_admins(staging),
    )
}

/// The journaled snapshot, when one exists and a privileged account owns it.
#[must_use]
pub fn read(data_dir: &Path) -> Option<String> {
    let path = journal_path(data_dir);
    let file = match File::open(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return None,
        Err(error) => {
            warn!(%error, path = %path.display(), "could not open the DNS redirect journal");
            return None;
        }
    };
    match antiwire_secrets::is_privileged_owner(&file) {
        Ok(true) => {}
        Ok(false) => {
            warn!(
                path = %path.display(),
                "ignoring a DNS redirect journal that a privileged account does not own"
            );
            return None;
        }
        Err(error) => {
            warn!(%error, path = %path.display(), "could not check the DNS redirect journal's owner");
            return None;
        }
    }

    let mut contents = String::new();
    if let Err(error) = file.take(MAX_BYTES + 1).read_to_string(&mut contents) {
        warn!(%error, path = %path.display(), "could not read the DNS redirect journal");
        return None;
    }
    if u64::try_from(contents.len()).unwrap_or(u64::MAX) > MAX_BYTES {
        warn!(path = %path.display(), "ignoring an oversized DNS redirect journal");
        return None;
    }
    Some(contents)
}

/// Deletes the journal once nothing is left to restore.
pub fn remove(data_dir: &Path) {
    match fs::remove_file(journal_path(data_dir)) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => warn!(%error, "could not delete the DNS redirect journal"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_replaces_the_journal_and_remove_deletes_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        write(dir.path(), "[1]").expect("first write");
        write(dir.path(), "[2]").expect("second write");
        assert_eq!(
            fs::read_to_string(journal_path(dir.path())).expect("journal"),
            "[2]"
        );
        assert_eq!(
            fs::read_dir(dir.path()).expect("list").count(),
            1,
            "no staging file is left behind"
        );

        remove(dir.path());
        assert!(!journal_path(dir.path()).exists());
        remove(dir.path());
    }

    /// Tests run as an ordinary user, so the file they write is exactly the kind
    /// an unprivileged process could plant. It must not be trusted.
    #[test]
    fn a_journal_an_ordinary_user_owns_is_not_trusted() {
        let dir = tempfile::tempdir().expect("tempdir");
        write(dir.path(), "[]").expect("write");
        let file = File::open(journal_path(dir.path())).expect("open");
        let privileged = antiwire_secrets::is_privileged_owner(&file).expect("owner");
        assert_eq!(read(dir.path()).is_some(), privileged);
    }

    #[test]
    fn a_missing_journal_reads_as_none() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert_eq!(read(dir.path()), None);
    }
}
