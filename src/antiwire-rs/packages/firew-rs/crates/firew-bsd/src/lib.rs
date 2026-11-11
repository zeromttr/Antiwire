//! BSD firewall stub (deferred).

use firew_core::{Error, ErrorKind};

/// Deferred BSD backend stub.
#[derive(Debug, Default)]
pub struct BsdBackend;

firew_sys::unavailable_backend!(
    BsdBackend,
    name = "bsd-stub",
    reason = "deferred",
    open = |_| {
        Error::new(
            ErrorKind::BackendUnavailable,
            "BSD firewall backend is deferred",
        )
    }
);
