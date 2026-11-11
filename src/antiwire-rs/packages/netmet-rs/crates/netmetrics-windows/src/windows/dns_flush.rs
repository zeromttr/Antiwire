//! Delivers DNS-Client events ahead of the session's flush timer.
//!
//! ETW hands a real-time consumer a buffer when it fills or when the session's
//! flush timer fires, and that timer cannot be set below one second. DNS-Client
//! events are few, so they nearly always wait out the timer. A connection is
//! then open before the event naming the process that asked for its address
//! has arrived, and it is named from weaker evidence.
//!
//! A caller that knows such an event is due, because it has just answered the
//! query the event describes, asks for a flush with
//! [`request_dns_event_flush`]. Requests are served by one thread per running
//! DNS trace, so asking never blocks, and requests close together share a
//! flush.

use super::session::control_session;
use netmetrics_core::DnsFlushStats;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use windows::Win32::System::Diagnostics::Etw::EVENT_TRACE_CONTROL_FLUSH;

/// How long a request waits before its flush. The answer the request is about
/// has to reach the DNS Client service, which then logs the events; a flush
/// that ran first would deliver nothing and leave them to the timer. Requests
/// in this window share the flush, which also bounds the flush rate.
const FLUSH_DELAY: Duration = Duration::from_millis(25);

static REQUESTS: AtomicU64 = AtomicU64::new(0);
static FLUSHES: AtomicU64 = AtomicU64::new(0);
static FAILURES: AtomicU64 = AtomicU64::new(0);

/// The running DNS trace's flusher, if a trace is running.
static ACTIVE: Mutex<Option<Arc<Shared>>> = Mutex::new(None);

fn active() -> MutexGuard<'static, Option<Arc<Shared>>> {
    ACTIVE.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Asks for the DNS-Client events logged so far to be delivered now instead
/// of on the session's flush timer. Returns at once; the flush runs on another
/// thread shortly after. Does nothing when no DNS trace is running.
pub fn request_dns_event_flush() {
    // Clone out of the registry so a request never holds it while signalling.
    let Some(shared) = active().clone() else {
        return;
    };
    REQUESTS.fetch_add(1, Ordering::Relaxed);
    shared.request();
}

/// Cumulative flush requests and their outcomes since the process started.
#[must_use]
pub fn dns_event_flush_stats() -> DnsFlushStats {
    DnsFlushStats {
        requests: REQUESTS.load(Ordering::Relaxed),
        flushes: FLUSHES.load(Ordering::Relaxed),
        failures: FAILURES.load(Ordering::Relaxed),
    }
}

#[derive(Debug, Default)]
struct State {
    requested: bool,
    stopped: bool,
}

#[derive(Debug, Default)]
struct Shared {
    state: Mutex<State>,
    wake: Condvar,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn request(&self) {
        self.lock().requested = true;
        self.wake.notify_one();
    }

    /// Serves requests until stopped. `flush` reports whether it succeeded.
    fn run(&self, delay: Duration, mut flush: impl FnMut() -> bool) {
        let mut state = self.lock();
        loop {
            while !state.requested && !state.stopped {
                state = self
                    .wake
                    .wait(state)
                    .unwrap_or_else(PoisonError::into_inner);
            }
            // Wait out the delay even though later requests wake the thread.
            let flush_at = Instant::now().checked_add(delay);
            loop {
                if state.stopped {
                    return;
                }
                let left = flush_at.map_or(Duration::ZERO, |at| {
                    at.saturating_duration_since(Instant::now())
                });
                if left.is_zero() {
                    break;
                }
                state = self
                    .wake
                    .wait_timeout(state, left)
                    .unwrap_or_else(PoisonError::into_inner)
                    .0;
            }
            state.requested = false;
            drop(state);
            let counter = if flush() { &FLUSHES } else { &FAILURES };
            counter.fetch_add(1, Ordering::Relaxed);
            state = self.lock();
        }
    }
}

/// Flushes one DNS trace session on request. Dropping it stops the thread.
#[derive(Debug)]
pub(super) struct DnsFlusher {
    shared: Arc<Shared>,
    thread: Option<JoinHandle<()>>,
}

impl DnsFlusher {
    /// Starts flushing the session named `session` on request and makes it
    /// the one [`request_dns_event_flush`] reaches.
    ///
    /// `None` when the thread cannot be started. Events then arrive on the
    /// session's timer, as they did before, so the trace is still worth running.
    pub(super) fn start(session: &str) -> Option<Self> {
        let session = session.to_owned();
        let flusher = Self::spawn(FLUSH_DELAY, move || {
            control_session(&session, EVENT_TRACE_CONTROL_FLUSH) == 0
        })?;
        *active() = Some(Arc::clone(&flusher.shared));
        Some(flusher)
    }

    fn spawn(delay: Duration, flush: impl FnMut() -> bool + Send + 'static) -> Option<Self> {
        let shared = Arc::new(Shared::default());
        let worker = Arc::clone(&shared);
        let thread = std::thread::Builder::new()
            .name("netmetrics-etw-dns-flush".to_owned())
            .spawn(move || worker.run(delay, flush))
            .ok()?;
        Some(Self {
            shared,
            thread: Some(thread),
        })
    }
}

impl Drop for DnsFlusher {
    fn drop(&mut self) {
        {
            // A newer trace's flusher may already have replaced this one.
            let mut active = active();
            if active
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(current, &self.shared))
            {
                *active = None;
            }
        }
        self.shared.lock().stopped = true;
        self.shared.wake.notify_one();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    const DELAY: Duration = Duration::from_millis(40);

    fn counting_flusher() -> (DnsFlusher, Arc<AtomicUsize>) {
        let count = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&count);
        let flusher = DnsFlusher::spawn(DELAY, move || {
            counted.fetch_add(1, Ordering::SeqCst);
            true
        })
        .expect("flush thread");
        (flusher, count)
    }

    fn wait_for(count: &AtomicUsize, wanted: usize) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while count.load(Ordering::SeqCst) < wanted {
            assert!(Instant::now() < deadline, "no flush within ten seconds");
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    #[test]
    fn requests_close_together_share_one_flush_after_the_delay() {
        let (flusher, count) = counting_flusher();
        let asked = Instant::now();
        for _ in 0..50 {
            flusher.shared.request();
        }
        wait_for(&count, 1);
        assert!(
            asked.elapsed() >= DELAY,
            "the flush must leave the events time to be logged"
        );
        // Long enough for a second flush, had the burst queued one.
        std::thread::sleep(DELAY * 4);
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn a_request_after_a_flush_gets_its_own() {
        let (flusher, count) = counting_flusher();
        flusher.shared.request();
        wait_for(&count, 1);
        flusher.shared.request();
        wait_for(&count, 2);
    }

    #[test]
    fn nothing_is_flushed_unasked_and_dropping_stops_a_waiting_flush() {
        let (flusher, count) = counting_flusher();
        std::thread::sleep(DELAY * 2);
        assert_eq!(count.load(Ordering::SeqCst), 0);

        let count_after_drop = {
            let flusher = DnsFlusher::spawn(Duration::from_secs(3_600), {
                let count = Arc::clone(&count);
                move || {
                    count.fetch_add(1, Ordering::SeqCst);
                    true
                }
            })
            .expect("flush thread");
            flusher.shared.request();
            // Dropping joins the thread, which is inside its hour-long delay.
            drop(flusher);
            count.load(Ordering::SeqCst)
        };
        assert_eq!(count_after_drop, 0);
        drop(flusher);
    }

    /// ETW accepts the flush request as formed: the only thing wrong with it
    /// is that no session has this name.
    #[test]
    fn flushing_a_session_that_does_not_exist_reports_it_missing() {
        const ERROR_WMI_INSTANCE_NOT_FOUND: u32 = 4201;
        assert_eq!(
            control_session("netmetrics-test-no-such-session", EVENT_TRACE_CONTROL_FLUSH),
            ERROR_WMI_INSTANCE_NOT_FOUND
        );
    }
}
