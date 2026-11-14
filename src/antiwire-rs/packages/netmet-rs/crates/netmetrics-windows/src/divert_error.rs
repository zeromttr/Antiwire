//! Why `WinDivert` could not be used, and whether trying again could help.

use std::fmt;

/// Why `WinDivert` could not be installed, loaded or opened.
#[derive(Debug)]
pub(crate) struct DivertError {
    detail: String,
    passes: bool,
}

impl DivertError {
    /// A failure the same call could get past later with nothing changed on this side: the
    /// package could not be downloaded, or the driver could not be opened yet.
    #[cfg(target_arch = "x86_64")]
    pub(crate) fn passing(detail: impl Into<String>) -> Self {
        Self {
            detail: detail.into(),
            passes: true,
        }
    }

    /// A failure that repeats for as long as this process runs: a missing privilege, a
    /// package that does not match its hash, an architecture without a driver.
    pub(crate) fn lasting(detail: impl Into<String>) -> Self {
        Self {
            detail: detail.into(),
            passes: false,
        }
    }

    /// Whether trying again later could succeed.
    pub(crate) const fn passes(&self) -> bool {
        self.passes
    }
}

impl fmt::Display for DivertError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.detail)
    }
}

/// A failure nothing says can pass is taken to last, so it is never tried again.
impl From<String> for DivertError {
    fn from(detail: String) -> Self {
        Self::lasting(detail)
    }
}

impl From<DivertError> for String {
    fn from(error: DivertError) -> Self {
        error.detail
    }
}
