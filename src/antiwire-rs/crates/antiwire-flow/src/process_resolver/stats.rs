//! Failure-stage telemetry for process identity resolution.
//!
//! Every stage at which resolution can fail has its own counter, so the
//! remaining unknowns can be measured before another recovery source is
//! added. A new fallback is only justified by these numbers, never by the
//! mere existence of an unresolved row.

use std::sync::atomic::{AtomicU64, Ordering};

/// One way [`super::ProcessIdentities::resolve`] can fail to produce a real executable path.
///
/// The variants are ordered by pipeline stage. A resolution can encounter
/// multiple failed stages before a later source supplies an identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ResolutionFailure {
    /// Untrusted metadata carried only a bare file name (or nothing usable),
    /// and no lifecycle, cache, or live source could supply the path.
    BasenameOnlyImage,
    /// No cached or tracked identity existed for the PID: its lifecycle event
    /// was missed, predates the daemon, or already expired.
    MissingLifecycleEvent,
    /// The live process query was denied: elevated, protected, or
    /// cross-session target the token cannot open.
    AccessDenied,
    /// The process exited before any source could resolve it.
    ExitedProcess,
    /// A cached, tracked, or live identity existed but its creation timestamp
    /// proved the PID has been recycled onto a different process.
    StartTsMismatch,
    /// An NT device path could not be converted to a DOS path because the
    /// drive map does not (yet) know the volume.
    PathConversionFailed,
}

/// Cumulative resolution counters.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct ResolutionStats {
    /// Total resolutions attempted.
    pub attempts: u64,
    /// Calls that returned a real (non-synthetic) executable path.
    pub authoritative_hits: u64,
    /// Calls that fell back to the recoverable basename placeholder.
    pub placeholder_fallbacks: u64,
    /// Calls that ended in an `unknown.exe` identity.
    pub unknown_results: u64,
    pub basename_only_image: u64,
    pub missing_lifecycle_event: u64,
    pub access_denied: u64,
    pub exited_process: u64,
    pub start_ts_mismatch: u64,
    pub path_conversion_failed: u64,
}

/// Live resolution counters for one [`super::ProcessIdentities`].
#[derive(Default)]
pub(crate) struct ResolutionCounters {
    attempts: AtomicU64,
    authoritative_hits: AtomicU64,
    placeholder_fallbacks: AtomicU64,
    unknown_results: AtomicU64,
    basename_only_image: AtomicU64,
    missing_lifecycle_event: AtomicU64,
    access_denied: AtomicU64,
    exited_process: AtomicU64,
    start_ts_mismatch: AtomicU64,
    path_conversion_failed: AtomicU64,
}

impl ResolutionCounters {
    pub(crate) fn record_attempt(&self) {
        self.attempts.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_authoritative_hit(&self) {
        self.authoritative_hits.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_placeholder_fallback(&self) {
        self.placeholder_fallbacks.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_unknown_result(&self) {
        self.unknown_results.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_failure(&self, failure: ResolutionFailure) {
        let counter = match failure {
            ResolutionFailure::BasenameOnlyImage => &self.basename_only_image,
            ResolutionFailure::MissingLifecycleEvent => &self.missing_lifecycle_event,
            ResolutionFailure::AccessDenied => &self.access_denied,
            ResolutionFailure::ExitedProcess => &self.exited_process,
            ResolutionFailure::StartTsMismatch => &self.start_ts_mismatch,
            ResolutionFailure::PathConversionFailed => &self.path_conversion_failed,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// Reads the cumulative counters without resetting them.
    pub(crate) fn snapshot(&self) -> ResolutionStats {
        ResolutionStats {
            attempts: self.attempts.load(Ordering::Relaxed),
            authoritative_hits: self.authoritative_hits.load(Ordering::Relaxed),
            placeholder_fallbacks: self.placeholder_fallbacks.load(Ordering::Relaxed),
            unknown_results: self.unknown_results.load(Ordering::Relaxed),
            basename_only_image: self.basename_only_image.load(Ordering::Relaxed),
            missing_lifecycle_event: self.missing_lifecycle_event.load(Ordering::Relaxed),
            access_denied: self.access_denied.load(Ordering::Relaxed),
            exited_process: self.exited_process.load(Ordering::Relaxed),
            start_ts_mismatch: self.start_ts_mismatch.load(Ordering::Relaxed),
            path_conversion_failed: self.path_conversion_failed.load(Ordering::Relaxed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failures_land_on_their_own_counters() {
        let counters = ResolutionCounters::default();
        counters.record_attempt();
        counters.record_failure(ResolutionFailure::AccessDenied);
        counters.record_failure(ResolutionFailure::StartTsMismatch);
        counters.record_authoritative_hit();
        counters.record_placeholder_fallback();
        counters.record_unknown_result();

        assert_eq!(
            counters.snapshot(),
            ResolutionStats {
                attempts: 1,
                authoritative_hits: 1,
                placeholder_fallbacks: 1,
                unknown_results: 1,
                access_denied: 1,
                start_ts_mismatch: 1,
                ..ResolutionStats::default()
            }
        );
    }
}
