//! How far a source's event times run behind the system clock.
//!
//! Some sources stamp events on a clock of their own and convert to wall time
//! from a reference taken when they started. Windows kernel ETW is one: it uses
//! the performance counter. Process creation times and socket-table times are
//! system time, which the time service keeps adjusting, so the two can separate
//! over a long-running session, and comparisons between them go wrong.
//!
//! Each event's time is compared with the system time it is decoded at. That
//! gap is delivery latency plus drift. Its minimum over a window is close to the
//! drift alone, because the quickest-delivered events have almost no latency.
//! How far that minimum has moved since the session's first window is the drift.

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

/// Minimum event-to-decode gaps a [`ClockLagGauge`] has measured.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ClockLag {
    /// Smallest gap in the newest completed window, in milliseconds. Positive
    /// means event times run behind the system clock.
    pub latest_ms: Option<i64>,
    /// Smallest gap in the session's first completed window.
    pub baseline_ms: Option<i64>,
    /// Windows completed since the session started.
    pub windows: u64,
}

impl ClockLag {
    /// How far event times have moved against the system clock since the
    /// session started, in milliseconds. Positive means they now run further
    /// behind it.
    #[must_use]
    pub fn drift_ms(&self) -> Option<i64> {
        Some(self.latest_ms?.saturating_sub(self.baseline_ms?))
    }
}

const NONE: i64 = i64::MIN;

/// Lock-free minimum-gap tracker, cheap enough to feed from every event.
#[derive(Debug)]
pub struct ClockLagGauge {
    window_ms: u64,
    window_start_ms: AtomicU64,
    current_min_ms: AtomicI64,
    latest_ms: AtomicI64,
    baseline_ms: AtomicI64,
    windows: AtomicU64,
}

impl ClockLagGauge {
    /// A gauge that closes a window every `window_ms`.
    #[must_use]
    pub const fn new(window_ms: u64) -> Self {
        Self {
            window_ms,
            window_start_ms: AtomicU64::new(0),
            current_min_ms: AtomicI64::new(i64::MAX),
            latest_ms: AtomicI64::new(NONE),
            baseline_ms: AtomicI64::new(NONE),
            windows: AtomicU64::new(0),
        }
    }

    /// Starts a new session at `now_ms`: a restarted source converts from a new
    /// reference, so earlier measurements no longer apply.
    pub fn reset(&self, now_ms: u64) {
        self.window_start_ms.store(now_ms, Ordering::Relaxed);
        self.current_min_ms.store(i64::MAX, Ordering::Relaxed);
        self.latest_ms.store(NONE, Ordering::Relaxed);
        self.baseline_ms.store(NONE, Ordering::Relaxed);
        self.windows.store(0, Ordering::Relaxed);
    }

    /// Records an event stamped `event_ms` and decoded at `now_ms`, both Unix
    /// milliseconds.
    pub fn observe(&self, event_ms: u64, now_ms: u64) {
        let gap = i64::try_from(i128::from(now_ms) - i128::from(event_ms)).unwrap_or(NONE);
        if gap == NONE {
            return;
        }
        let start = self.window_start_ms.load(Ordering::Relaxed);
        if start == 0 {
            // First event since construction without a reset.
            let _ = self.window_start_ms.compare_exchange(
                0,
                now_ms,
                Ordering::Relaxed,
                Ordering::Relaxed,
            );
        } else if now_ms.saturating_sub(start) >= self.window_ms
            && self
                .window_start_ms
                .compare_exchange(start, now_ms, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            // Only the thread that moved the window closes it.
            let closed = self.current_min_ms.swap(i64::MAX, Ordering::Relaxed);
            if closed != i64::MAX {
                self.latest_ms.store(closed, Ordering::Relaxed);
                let _ = self.baseline_ms.compare_exchange(
                    NONE,
                    closed,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                );
                self.windows.fetch_add(1, Ordering::Relaxed);
            }
        }
        self.current_min_ms.fetch_min(gap, Ordering::Relaxed);
    }

    /// The minimums measured so far.
    #[must_use]
    pub fn snapshot(&self) -> ClockLag {
        let load = |value: &AtomicI64| Some(value.load(Ordering::Relaxed)).filter(|v| *v != NONE);
        ClockLag {
            latest_ms: load(&self.latest_ms),
            baseline_ms: load(&self.baseline_ms),
            windows: self.windows.load(Ordering::Relaxed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_minimum_gap_per_window_tracks_drift_from_the_first_window() {
        let gauge = ClockLagGauge::new(1_000);
        gauge.reset(10_000);
        // First window: delivery latency 3..40 ms, so its minimum is 3.
        for (event, now) in [(10_000, 10_040), (10_100, 10_103), (10_500, 10_520)] {
            gauge.observe(event, now);
        }
        assert_eq!(gauge.snapshot().latest_ms, None, "no window closed yet");
        // Events now arrive 250 ms behind as well: the clock has drifted.
        for (event, now) in [(10_800, 11_060), (11_000, 11_253), (11_500, 11_900)] {
            gauge.observe(event, now);
        }
        gauge.observe(12_000, 12_300); // closes the second window
        let lag = gauge.snapshot();
        assert_eq!(lag.baseline_ms, Some(3));
        assert_eq!(lag.latest_ms, Some(253));
        assert_eq!(lag.windows, 2);
        assert_eq!(lag.drift_ms(), Some(250));
    }

    #[test]
    fn event_times_ahead_of_the_system_clock_are_a_negative_gap() {
        let gauge = ClockLagGauge::new(1_000);
        gauge.reset(10_000);
        gauge.observe(10_020, 10_000);
        gauge.observe(11_500, 11_500);
        assert_eq!(gauge.snapshot().latest_ms, Some(-20));
    }

    #[test]
    fn a_reset_starts_a_new_session() {
        let gauge = ClockLagGauge::new(1_000);
        gauge.reset(10_000);
        gauge.observe(10_000, 10_005);
        gauge.observe(11_000, 11_005);
        assert!(gauge.snapshot().baseline_ms.is_some());
        gauge.reset(20_000);
        assert_eq!(gauge.snapshot(), ClockLag::default());
        assert_eq!(gauge.snapshot().drift_ms(), None);
    }
}
