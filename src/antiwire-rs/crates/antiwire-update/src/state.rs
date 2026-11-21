//! `install-state.json`: which version is installed and what is in flight.
//!
//! The daemon writes `pending` in phase [`ApplyPhase::Requested`] when the client
//! asks for an install. The helper accepts only a request whose id matches and
//! moves it to [`ApplyPhase::Swapping`] before touching the service, so the same
//! request can never be applied twice. The file lives in the data directory,
//! which only SYSTEM/root and administrators can write.

use std::io::Write;
use std::path::Path;

use semver::Version;
use serde::{Deserialize, Serialize};

use crate::UpdateError;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstallState {
    /// The version the daemon service points at. `None` before the first
    /// versioned install recorded it.
    pub current: Option<Version>,
    /// The version to roll back to. Its tree is never deleted while it is here.
    pub previous: Option<Version>,
    pub pending: Option<PendingInstall>,
    /// Why the last install failed, shown until the next install request.
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingInstall {
    pub version: Version,
    pub request_id: String,
    pub phase: ApplyPhase,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplyPhase {
    /// Files are verified and in the version tree; the helper has not started.
    Requested,
    /// The helper accepted the request and may have stopped the service. A
    /// leftover `Swapping` after a crash or reboot is rolled back.
    Swapping,
}

impl InstallState {
    /// Reads the state file. A missing file is an empty state.
    ///
    /// # Errors
    ///
    /// Fails when the file exists but cannot be read or parsed.
    pub fn load(path: &Path) -> Result<Self, UpdateError> {
        match std::fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(|error| {
                UpdateError::io(
                    "parse",
                    path,
                    std::io::Error::new(std::io::ErrorKind::InvalidData, error),
                )
            }),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(error) => Err(UpdateError::io("read", path, error)),
        }
    }

    /// Replaces the state file atomically and durably.
    ///
    /// # Errors
    ///
    /// Fails when the file cannot be written or committed.
    pub fn store(&self, path: &Path) -> Result<(), UpdateError> {
        let bytes = serde_json::to_vec_pretty(self).map_err(|error| {
            UpdateError::io(
                "serialize",
                path,
                std::io::Error::new(std::io::ErrorKind::InvalidData, error),
            )
        })?;
        let mut file = atomic_write_file::AtomicWriteFile::options()
            .open(path)
            .map_err(|error| UpdateError::io("open", path, error))?;
        file.write_all(&bytes)
            .map_err(|error| UpdateError::io("write", path, error))?;
        file.commit()
            .map_err(|error| UpdateError::io("commit", path, error))
    }

    /// Whether a helper has accepted a request and not finished it: `pending`
    /// in phase [`ApplyPhase::Swapping`].
    #[must_use]
    pub fn swapping(&self) -> bool {
        self.pending
            .as_ref()
            .is_some_and(|pending| pending.phase == ApplyPhase::Swapping)
    }

    /// Whether `version` is the installed version: `current`, or the version a
    /// helper is swapping in (`pending` in phase [`ApplyPhase::Swapping`]).
    ///
    /// The helper starts the new daemon and waits for it to stay healthy before
    /// it records the version as `current`, so that daemon finds itself in
    /// `pending`. The helper then either records it or stops it and rolls back.
    #[must_use]
    pub fn names_installed(&self, version: &Version) -> bool {
        self.current.as_ref() == Some(version)
            || self.pending.as_ref().is_some_and(|pending| {
                pending.phase == ApplyPhase::Swapping && pending.version == *version
            })
    }
}

/// A fresh id for one install request.
///
/// The id is not a secret: anyone who can read it can already write the data
/// directory. It only has to be unique, so a request cannot be replayed.
#[must_use]
pub fn new_request_id() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_nanos());
    format!("{nanos:x}-{:x}", std::process::id())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_file_is_empty_state() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = InstallState::load(&dir.path().join("install-state.json")).expect("load");
        assert_eq!(state, InstallState::default());
    }

    #[test]
    fn round_trips_pending_install() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("install-state.json");
        let state = InstallState {
            current: Some(Version::new(0, 2, 0)),
            previous: Some(Version::new(0, 1, 0)),
            pending: Some(pending(Version::new(0, 3, 0), ApplyPhase::Swapping)),
            last_error: None,
        };
        state.store(&path).expect("store");
        assert_eq!(InstallState::load(&path).expect("load"), state);
    }

    fn pending(version: Version, phase: ApplyPhase) -> PendingInstall {
        PendingInstall {
            version,
            request_id: new_request_id(),
            phase,
        }
    }

    #[test]
    fn names_the_current_version_installed() {
        let state = InstallState {
            current: Some(Version::new(0, 2, 0)),
            ..InstallState::default()
        };
        assert!(state.names_installed(&Version::new(0, 2, 0)));
        assert!(!state.names_installed(&Version::new(0, 3, 0)));
        assert!(!InstallState::default().names_installed(&Version::new(0, 2, 0)));
    }

    #[test]
    fn names_the_version_a_swap_is_putting_in_place_installed() {
        let swapping = InstallState {
            current: Some(Version::new(0, 2, 0)),
            pending: Some(pending(Version::new(0, 3, 0), ApplyPhase::Swapping)),
            ..InstallState::default()
        };
        assert!(swapping.names_installed(&Version::new(0, 3, 0)));
        assert!(swapping.names_installed(&Version::new(0, 2, 0)));
    }

    #[test]
    fn does_not_name_a_version_the_helper_has_not_accepted() {
        let requested = InstallState {
            current: Some(Version::new(0, 2, 0)),
            pending: Some(pending(Version::new(0, 3, 0), ApplyPhase::Requested)),
            ..InstallState::default()
        };
        assert!(!requested.names_installed(&Version::new(0, 3, 0)));
    }
}
