//! What the daemon reports to the client about updates.

use std::time::SystemTime;

use semver::Version;

use crate::Channel;

/// Mirrors `antiwire.UpdateStatus.State`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateState {
    Unknown,
    UpToDate,
    Available,
    Installing,
    Failed,
    Unsupported,
}

/// A newer release named by a verified manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AvailableRelease {
    pub version: Version,
    pub notes: String,
}

/// Snapshot returned by `GetUpdateStatus`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateStatus {
    pub state: UpdateState,
    pub current_version: Version,
    pub available: Option<AvailableRelease>,
    /// User-facing reason for `Failed` or `Unsupported`; empty otherwise.
    pub detail: String,
    /// The channel the user chose, which the status describes.
    pub channel: Channel,
    /// When the last check finished, successfully or not.
    pub last_checked: Option<SystemTime>,
    /// Why the last check could not read the update feeds; empty when it could.
    pub check_error: String,
}
