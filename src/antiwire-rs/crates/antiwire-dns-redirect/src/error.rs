use antiwire_store::StoreError;

/// Why a redirect or a restore did not do what was asked.
#[derive(Debug, thiserror::Error)]
pub enum RedirectError {
    /// The record of an earlier redirect could not be read, so nothing was
    /// changed. Without it, adapters an earlier run left on loopback would be
    /// captured as their own originals.
    #[error("the DNS redirect record could not be read: {0}")]
    RecordUnreadable(StoreError),
    /// A restore ran and was not confirmed. The record is kept, and the
    /// restore is worth trying again.
    #[error("OS DNS restore was not confirmed; recovery will retry")]
    RestoreNotConfirmed,
    /// System DNS was restored, but its record could not be cleared. The
    /// record and boot recovery are kept, so the next start or boot restores
    /// again, which writes back the same servers.
    #[error("DNS was restored, but its redirect record could not be cleared: {0}")]
    RecordNotCleared(StoreError),
    /// Nothing records a redirect to restore: the database could not be read,
    /// and there is no journal beside it.
    #[error("the DNS redirect record could not be read, and there is no redirect journal")]
    NoRecord,
}

impl RedirectError {
    /// Whether a restore is still owed and worth trying again.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        matches!(self, Self::RestoreNotConfirmed)
    }

    /// Whether system DNS was restored despite the error.
    #[must_use]
    pub const fn dns_restored(&self) -> bool {
        matches!(self, Self::RecordNotCleared(_))
    }
}
