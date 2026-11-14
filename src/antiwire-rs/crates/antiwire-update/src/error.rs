//! Errors from checking, staging, and applying updates.

use std::path::PathBuf;

/// Every failure the updater reports. The `Display` text is shown to the user
/// as `UpdateStatus::detail`, so it should say what went wrong in plain words.
#[derive(Debug, thiserror::Error)]
pub enum UpdateError {
    #[error("updates are not supported here: {0}")]
    Unsupported(String),
    #[error("the release manifest signature is not valid")]
    BadSignature,
    #[error("the release manifest could not be read: {0}")]
    BadManifest(String),
    #[error("{name} does not match the release manifest")]
    HashMismatch { name: String },
    #[error("version {requested} is not the available update")]
    VersionMismatch { requested: String },
    #[error("an update is already being installed")]
    AlreadyInstalling,
    #[error("no matching install request was found")]
    NoRequest,
    #[error("download failed: {0}")]
    Download(String),
    /// The release host answered 404: nothing is published at that address
    /// yet, such as a channel feed before its first release.
    #[error("nothing has been published there yet")]
    NotPublished,
    #[error("the daemon service could not be controlled: {0}")]
    Service(String),
    #[error("the new version did not start correctly: {0}")]
    Unhealthy(String),
    #[error("{action} {path}: {source}")]
    Io {
        action: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

impl UpdateError {
    /// Wraps an I/O error with what was being done and to which path.
    pub fn io(action: &'static str, path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::Io {
            action,
            path: path.into(),
            source,
        }
    }
}
