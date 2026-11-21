use thiserror::Error;

/// Errors returned by blocklist download operations.
#[derive(Debug, Error)]
pub enum DownloadError {
    #[error("HTTP request failed: {0}")]
    Http(#[source] antiwire_http::HttpError),
    #[error("download refused: {0}")]
    Refused(String),
    #[error("download idle timeout")]
    IdleTimeout,
    #[error("blocklist exceeds max download size ({0} bytes)")]
    SizeLimitExceeded(u64),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("{name}: all {mirror_count} mirrors failed ({details})")]
    AllMirrorsFailed {
        name: String,
        mirror_count: usize,
        details: String,
    },
    #[error("downloaded file did not match its published SHA-256")]
    HashMismatch,
    #[error("remote hash file was missing or malformed")]
    InvalidHashFile,
    #[error("downloaded list contained no usable names")]
    EmptyList,
}

impl From<antiwire_http::HttpError> for DownloadError {
    fn from(error: antiwire_http::HttpError) -> Self {
        match error {
            antiwire_http::HttpError::BodyTooLarge { limit } => Self::SizeLimitExceeded(limit),
            refused @ antiwire_http::HttpError::Refused { .. } => {
                Self::Refused(refused.to_string())
            }
            other => Self::Http(other),
        }
    }
}

/// Maps an I/O error from a `ByteLimitedReader`-wrapped stream to a
/// [`DownloadError`].
pub(crate) fn map_stream_io_error(
    error: std::io::Error,
    limit_exceeded: bool,
    max_bytes: u64,
) -> DownloadError {
    if limit_exceeded {
        DownloadError::SizeLimitExceeded(max_bytes)
    } else {
        error.into()
    }
}

/// Collapses per-mirror failures into a single download error for one list.
pub(crate) fn aggregate_mirror_errors(
    name: &str,
    mut attempts: Vec<(String, DownloadError)>,
) -> DownloadError {
    match attempts.len() {
        0 => DownloadError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "no mirror URLs configured",
        )),
        1 => attempts.pop().expect("one attempt").1,
        mirror_count => {
            let details = attempts
                .iter()
                .map(|(url, error)| format!("{url}: {error}"))
                .collect::<Vec<_>>()
                .join("; ");
            DownloadError::AllMirrorsFailed {
                name: name.to_owned(),
                mirror_count,
                details,
            }
        }
    }
}
