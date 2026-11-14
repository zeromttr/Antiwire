//! Wakeable cancellation for native backend threads.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

/// Cooperative stop signal that can interrupt a deadline wait.
///
/// An atomic flag alone cannot wake a sleeping backend. Callers wait until the
/// earlier of a monotonic deadline and [`StopFlag::stop`].
#[derive(Clone, Debug)]
pub struct StopFlag {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    stopped: AtomicBool,
    mutex: Mutex<()>,
    cv: Condvar,
}

impl StopFlag {
    /// Creates a flag in the running state.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Inner {
                stopped: AtomicBool::new(false),
                mutex: Mutex::new(()),
                cv: Condvar::new(),
            }),
        }
    }

    /// Returns true once stop has been requested.
    #[must_use]
    pub fn is_stop_requested(&self) -> bool {
        self.inner.stopped.load(Ordering::Acquire)
    }

    /// Requests stop and wakes every waiter.
    pub fn stop(&self) {
        self.inner.stopped.store(true, Ordering::Release);
        let _guard = self
            .inner
            .mutex
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.inner.cv.notify_all();
    }

    /// Clears a previous stop so a collector can be restarted.
    pub fn reset(&self) {
        self.inner.stopped.store(false, Ordering::Release);
    }

    /// Waits until `deadline` or until stop is requested.
    pub fn wait_deadline(&self, deadline: Instant) {
        let mut guard = self
            .inner
            .mutex
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        loop {
            if self.is_stop_requested() {
                return;
            }
            let now = Instant::now();
            if now >= deadline {
                return;
            }
            let remaining = deadline.saturating_duration_since(now);
            let (next, result) = self
                .inner
                .cv
                .wait_timeout(guard, remaining)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            guard = next;
            if result.timed_out() {
                return;
            }
        }
    }

    /// Waits until `duration` elapses or stop is requested.
    pub fn wait_timeout(&self, duration: Duration) {
        self.wait_deadline(Instant::now() + duration);
    }
}

impl Default for StopFlag {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn stop_wakes_a_long_deadline_wait() {
        let flag = StopFlag::new();
        let waiter = flag.clone();
        let started = Instant::now();
        let worker = thread::spawn(move || {
            waiter.wait_deadline(Instant::now() + Duration::from_secs(30));
        });
        thread::sleep(Duration::from_millis(20));
        flag.stop();
        worker.join().expect("waiter");
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(flag.is_stop_requested());
    }

    #[test]
    fn deadline_elapses_without_stop() {
        let flag = StopFlag::new();
        let started = Instant::now();
        flag.wait_deadline(Instant::now() + Duration::from_millis(30));
        assert!(started.elapsed() >= Duration::from_millis(20));
        assert!(!flag.is_stop_requested());
    }
}
