//! The eBPF source in a build without the `ebpf` feature, which has no loader: it never
//! starts, so the backend runs the procfs fallback.

use super::StartFailure;
use super::procfs::ProcfsListing;
use netmetrics_sys::{BackendError, BackendErrorKind, EventSink, StopFlag};
use std::path::Path;
use std::time::Duration;

/// Attached programs, of which there are none without a loader.
pub(super) enum Probes {}

#[expect(
    clippy::needless_pass_by_value,
    reason = "Probes has no values, so none is ever passed to consume"
)]
pub(super) fn read(
    probes: Probes,
    _: &mut ProcfsListing,
    _: Duration,
    _: &EventSink,
    _: &StopFlag,
) {
    match probes {}
}

/// Refuses to start, in a way loading the object again would not change.
pub(super) fn start(_: &Path, _: &EventSink) -> Result<Probes, StartFailure> {
    Err(StartFailure {
        error: BackendError::new(
            BackendErrorKind::Unavailable,
            "aya",
            "crate built without the ebpf feature",
        ),
        passes: false,
    })
}
