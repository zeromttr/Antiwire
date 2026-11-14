//! Starting the `WinDivert` FLOW listener, and starting it again.

use crate::divert_error::DivertError;
use crate::flow_owner::FlowOwnerCache;
use crate::windivert::{self, FlowListener};
use netmetrics_core::DegradeReason;
use netmetrics_sys::{BackendEvent, BackgroundRead, EventSink};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

/// The listener's name in the events about it.
const SOURCE: &str = "windivert-flow";
/// How long after a start fails, or the listener exits, the next start is tried.
const FIRST_RETRY: Duration = Duration::from_secs(1);
/// The longest wait between two starts. A start can ask the package's site for the
/// archive, so one that keeps failing asks no more than hourly.
const LONGEST_RETRY: Duration = Duration::from_secs(60 * 60);

/// When to try a start again: [`FIRST_RETRY`] after the first failure, then twice as long
/// after each further one, up to [`LONGEST_RETRY`].
#[derive(Debug)]
struct RetrySchedule {
    at: Option<Instant>,
    delay: Duration,
}

impl Default for RetrySchedule {
    fn default() -> Self {
        Self {
            at: None,
            delay: FIRST_RETRY,
        }
    }
}

impl RetrySchedule {
    /// Schedules the next start after a failure at `now`.
    fn failed(&mut self, now: Instant) {
        self.at = now.checked_add(self.delay);
        self.delay = self.delay.saturating_mul(2).min(LONGEST_RETRY);
    }

    /// Whether a start is due at `now`. A due start is due once.
    fn due(&mut self, now: Instant) -> bool {
        let due = self.at.is_some_and(|at| now >= at);
        if due {
            self.at = None;
        }
        due
    }
}

/// The `WinDivert` FLOW listener, which records who established each flow, and the starts
/// that bring it up.
///
/// A start can download the package and wait on the network for as long as the download's
/// timeouts allow, so every start runs on a thread of its own and the backend's thread
/// keeps polling. A start that fails for a reason that can pass is tried again on a
/// [`RetrySchedule`]: the package's site cannot be reached, or the driver cannot be opened
/// yet, as when the Base Filtering Engine has not started. The first failure is reported;
/// the retries that fail after it are not.
pub(super) struct FlowListening {
    owners: Arc<Mutex<FlowOwnerCache>>,
    listener: Option<FlowListener>,
    /// Runs the starts. `None` when its thread could not be created, which was reported.
    starter: Option<BackgroundRead<Result<FlowListener, DivertError>>>,
    retry: RetrySchedule,
    /// Whether the listener being down has been reported since it last ran.
    reported: bool,
}

impl FlowListening {
    /// Asks for the first start. The listener records into `owners` once it is up.
    pub(super) fn start(owners: Arc<Mutex<FlowOwnerCache>>, sink: &EventSink) -> Self {
        let (cache, starter_sink) = (Arc::clone(&owners), sink.clone());
        let starter = BackgroundRead::start("netmetrics-windivert-start", move || {
            windivert::start(Arc::clone(&cache), starter_sink.clone())
        });
        let mut listening = Self {
            owners,
            listener: None,
            starter: None,
            retry: RetrySchedule::default(),
            reported: false,
        };
        match starter {
            Ok(mut starter) => {
                starter.request();
                listening.starter = Some(starter);
            }
            Err(error) => listening.report_down(sink, error.to_string()),
        }
        listening
    }

    /// Takes a finished start, asks for one that is due, and notices a listener that
    /// exited. Never waits.
    pub(super) fn poll(&mut self, sink: &EventSink) {
        let now = Instant::now();
        if self
            .listener
            .as_ref()
            .is_some_and(FlowListener::is_finished)
        {
            // Dropping it joins the receive thread and withdraws its owner feed. The flow
            // deletes it missed can leave recycled tuples in the cache, so the next
            // listener starts from an empty one.
            self.listener = None;
            *self.owners.lock().unwrap_or_else(PoisonError::into_inner) = FlowOwnerCache::default();
            self.report_down(
                sink,
                "WinDivert FLOW receive loop exited; restarting".to_owned(),
            );
            self.retry = RetrySchedule::default();
            self.retry.failed(now);
        }
        let Some(starter) = &mut self.starter else {
            return;
        };
        if self.retry.due(now) {
            starter.request();
        }
        match starter.take() {
            Some(Ok(listener)) => {
                self.listener = Some(listener);
                self.retry = RetrySchedule::default();
                self.reported = false;
            }
            Some(Err(error)) => {
                if error.passes() {
                    self.retry.failed(now);
                }
                self.report_down(sink, error.into());
            }
            None => {}
        }
    }

    /// Reports the listener down, unless that has been reported since it last ran.
    fn report_down(&mut self, sink: &EventSink, detail: String) {
        if self.reported {
            return;
        }
        self.reported = true;
        sink.emit(BackendEvent::Degraded(DegradeReason::SourceUnavailable {
            source: SOURCE.to_owned(),
            detail,
        }));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_failure_doubles_the_wait_up_to_the_longest() {
        let start = Instant::now();
        let mut retry = RetrySchedule::default();
        assert!(!retry.due(start), "nothing is due before a failure");

        retry.failed(start);
        assert!(!retry.due(start));
        assert!(retry.due(start + FIRST_RETRY));
        assert!(!retry.due(start + FIRST_RETRY), "a due start is due once");

        retry.failed(start);
        assert!(!retry.due(start + FIRST_RETRY));
        assert!(retry.due(start + FIRST_RETRY * 2));

        for _ in 0..64 {
            retry.failed(start);
        }
        assert!(!retry.due(start + LONGEST_RETRY / 2));
        assert!(retry.due(start + LONGEST_RETRY));
    }
}
