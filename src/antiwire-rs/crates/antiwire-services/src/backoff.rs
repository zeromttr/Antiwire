//! Exponential deferral of automatic syncs after failures.

use parking_lot::Mutex;
use time::OffsetDateTime;

/// How long automatic syncs wait after failures.
///
/// The first failure defers automatic retries by `base_minutes`; each further
/// failure doubles the deferral, capped at `cap_minutes`. Manual syncs ignore
/// the deferral; a successful sync resets it. Every method takes the current
/// time, so the schedule is testable without a clock.
pub(crate) struct SyncBackoff {
    base_minutes: f64,
    cap_minutes: f64,
    state: Mutex<BackoffState>,
}

#[derive(Default)]
struct BackoffState {
    consecutive_failures: u32,
    deferred_until: Option<OffsetDateTime>,
}

impl SyncBackoff {
    pub(crate) fn new(base_minutes: f64, cap_minutes: f64) -> Self {
        Self {
            base_minutes,
            cap_minutes,
            state: Mutex::new(BackoffState::default()),
        }
    }

    /// Records a failure at `now`, and returns when automatic syncs resume.
    pub(crate) fn register_failure(&self, now: OffsetDateTime) -> OffsetDateTime {
        let mut state = self.state.lock();
        state.consecutive_failures = state.consecutive_failures.saturating_add(1);
        let exponent = i32::try_from(state.consecutive_failures - 1).unwrap_or(i32::MAX);
        let minutes = (self.base_minutes * 2.0f64.powi(exponent)).min(self.cap_minutes);
        let resume = now + time::Duration::seconds_f64(minutes * 60.0);
        state.deferred_until = Some(resume);
        resume
    }

    /// When automatic syncs resume, if they are deferred at `now`.
    pub(crate) fn deferred_until(&self, now: OffsetDateTime) -> Option<OffsetDateTime> {
        self.state
            .lock()
            .deferred_until
            .filter(|resume| now < *resume)
    }

    /// Clears the deferral after a successful sync.
    pub(crate) fn reset(&self) {
        *self.state.lock() = BackoffState::default();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    #[test]
    fn each_failure_doubles_the_deferral_up_to_the_cap() {
        let backoff = SyncBackoff::new(10.0, 30.0);
        let now = datetime!(2026-01-01 00:00:00 UTC);

        assert_eq!(backoff.deferred_until(now), None);
        let first = backoff.register_failure(now);
        assert_eq!(first, now + time::Duration::minutes(10));
        assert_eq!(
            backoff.register_failure(now),
            now + time::Duration::minutes(20)
        );
        assert_eq!(
            backoff.register_failure(now),
            now + time::Duration::minutes(30),
            "capped"
        );

        assert!(backoff.deferred_until(now).is_some());
        assert_eq!(
            backoff.deferred_until(now + time::Duration::minutes(31)),
            None,
            "the deferral lifts on its own"
        );
        backoff.reset();
        assert_eq!(backoff.deferred_until(now), None);
        assert_eq!(
            backoff.register_failure(now),
            first,
            "a success starts over"
        );
    }
}
