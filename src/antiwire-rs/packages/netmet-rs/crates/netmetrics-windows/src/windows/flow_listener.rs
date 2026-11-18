//! Starting the `WinDivert` FLOW listener, starting it again, and stopping it, as
//! [`crate::set_windivert_enabled`] says.

use crate::divert_error::DivertError;
use crate::flow_owner::FlowOwnerCache;
use crate::windivert::{self, FlowListener};
use crate::windivert_opt_in::windivert_enabled;
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

/// Starts the listener, which records into the cache it is given.
type Start = fn(Arc<Mutex<FlowOwnerCache>>, EventSink) -> Result<FlowListener, DivertError>;

/// The `WinDivert` FLOW listener, which records who established each flow, and the starts
/// that bring it up.
///
/// It runs only while `WinDivert` is turned on. Until it first is, nothing here starts: no
/// thread, no download, no driver. Turning it on asks for a start, and turning it off
/// closes the listener and forgets the owners it recorded.
///
/// A start can download the package and wait on the network for as long as the download's
/// timeouts allow, so every start runs on a thread of its own and the backend's thread
/// keeps polling. A start that fails for a reason that can pass is tried again on a
/// [`RetrySchedule`]: the package's site cannot be reached, or the driver cannot be opened
/// yet, as when the Base Filtering Engine has not started. The first failure is reported;
/// the retries that fail after it are not.
pub(super) struct FlowListening {
    owners: Arc<Mutex<FlowOwnerCache>>,
    start: Start,
    listener: Option<FlowListener>,
    /// Runs the starts. `None` until `WinDivert` is first turned on, and when its thread
    /// could not be created, which was reported.
    starter: Option<BackgroundRead<Result<FlowListener, DivertError>>>,
    retry: RetrySchedule,
    /// Whether the listener being down has been reported since it last ran.
    reported: bool,
    /// Whether `WinDivert` was turned on at the last poll.
    enabled: bool,
}

impl FlowListening {
    /// Starts nothing. [`poll`](Self::poll) brings the listener up once `WinDivert` is
    /// turned on, and it then records into `owners`.
    pub(super) fn new(owners: Arc<Mutex<FlowOwnerCache>>) -> Self {
        Self::starting_with(owners, windivert::start)
    }

    fn starting_with(owners: Arc<Mutex<FlowOwnerCache>>, start: Start) -> Self {
        Self {
            owners,
            start,
            listener: None,
            starter: None,
            retry: RetrySchedule::default(),
            reported: false,
            enabled: false,
        }
    }

    /// Follows `WinDivert` being turned on or off, takes a finished start, asks for one
    /// that is due, and notices a listener that exited. Never waits.
    pub(super) fn poll(&mut self, sink: &EventSink) {
        let enabled = windivert_enabled();
        if enabled != self.enabled {
            self.enabled = enabled;
            if enabled {
                self.turn_on(sink);
            } else {
                self.turn_off();
            }
        }
        if !enabled {
            // A start that was under way when `WinDivert` was turned off may still open
            // the driver. Its listener is dropped here, which closes it, and what it
            // recorded goes too.
            let opened = self
                .starter
                .as_mut()
                .and_then(BackgroundRead::take)
                .is_some_and(|started| started.is_ok());
            if opened {
                self.forget_owners();
            }
            return;
        }
        let now = Instant::now();
        if self
            .listener
            .as_ref()
            .is_some_and(FlowListener::is_finished)
        {
            // Dropping it joins the receive thread and withdraws its owner feed.
            self.listener = None;
            self.forget_owners();
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
            // The start ran while `WinDivert` was turned off, and it has been turned on
            // again since. That is no failure of the driver: start anew.
            Some(Err(error)) if error.is_turned_off() => starter.request(),
            Some(Err(error)) => {
                if error.passes() {
                    self.retry.failed(now);
                }
                self.report_down(sink, error.into());
            }
            None => {}
        }
    }

    /// Asks for a start, creating the thread that runs the starts if there is none yet.
    fn turn_on(&mut self, sink: &EventSink) {
        self.retry = RetrySchedule::default();
        self.reported = false;
        if self.starter.is_none() {
            let (start, cache, starter_sink) = (self.start, Arc::clone(&self.owners), sink.clone());
            match BackgroundRead::start("netmetrics-windivert-start", move || {
                start(Arc::clone(&cache), starter_sink.clone())
            }) {
                Ok(starter) => self.starter = Some(starter),
                Err(error) => self.report_down(sink, error.to_string()),
            }
        }
        if let Some(starter) = &mut self.starter {
            starter.request();
        }
    }

    /// Closes the listener. Dropping it joins the receive thread and withdraws its owner
    /// feed. The thread that runs the starts is kept: dropping it would wait for a
    /// download under way.
    fn turn_off(&mut self) {
        self.listener = None;
        self.forget_owners();
    }

    /// Empties the cache a listener that has stopped recorded into. The flows it did not
    /// see end leave recycled tuples there, so the next listener starts from an empty one.
    fn forget_owners(&self) {
        *self.owners.lock().unwrap_or_else(PoisonError::into_inner) = FlowOwnerCache::default();
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
    use crate::set_windivert_enabled;
    use crate::windivert_opt_in::testing;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::mpsc::{Receiver, sync_channel};

    /// How many starts [`failing_start`] has run.
    static STARTS: AtomicUsize = AtomicUsize::new(0);

    /// A start that fails as a driver that cannot be opened does, for good.
    fn failing_start(
        cache: Arc<Mutex<FlowOwnerCache>>,
        sink: EventSink,
    ) -> Result<FlowListener, DivertError> {
        drop((cache, sink));
        STARTS.fetch_add(1, Ordering::SeqCst);
        Err(DivertError::lasting("no driver in this test"))
    }

    fn sink() -> (EventSink, Receiver<BackendEvent>) {
        let (tx, rx) = sync_channel(16);
        (EventSink::new(tx, Arc::new(AtomicU64::new(0))), rx)
    }

    /// Polls until `wanted` starts have run and the failure of the last one was reported.
    /// Every start in these tests fails, so the report is what shows its result was taken.
    fn poll_until_started(listening: &mut FlowListening, sink: &EventSink, wanted: usize) {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            listening.poll(sink);
            if STARTS.load(Ordering::SeqCst) >= wanted && listening.reported {
                return;
            }
            assert!(Instant::now() < deadline, "the start never ran");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn the_listener_follows_windivert_being_turned_on_and_off() {
        let _switch = testing::alone();
        STARTS.store(0, Ordering::SeqCst);
        let owners = Arc::new(Mutex::new(FlowOwnerCache::default()));
        let (sink, events) = sink();
        let mut listening = FlowListening::starting_with(Arc::clone(&owners), failing_start);

        // Off, which is how it starts: no thread, no start, nothing reported.
        for _ in 0..3 {
            listening.poll(&sink);
        }
        assert!(listening.starter.is_none(), "no thread while off");
        assert_eq!(STARTS.load(Ordering::SeqCst), 0);
        assert!(events.try_recv().is_err(), "being off is not a failure");

        // On: one start, and its failure is reported once.
        set_windivert_enabled(true);
        poll_until_started(&mut listening, &sink, 1);
        let Ok(BackendEvent::Degraded(DegradeReason::SourceUnavailable { source, detail })) =
            events.try_recv()
        else {
            panic!("the failed start was not reported");
        };
        assert_eq!(source, SOURCE);
        assert_eq!(detail, "no driver in this test");
        listening.poll(&sink);
        assert_eq!(
            STARTS.load(Ordering::SeqCst),
            1,
            "a lasting failure is final"
        );
        assert!(events.try_recv().is_err());

        // Off: nothing more starts.
        set_windivert_enabled(false);
        listening.poll(&sink);
        assert_eq!(STARTS.load(Ordering::SeqCst), 1);

        // On again: a new start, reported anew.
        set_windivert_enabled(true);
        poll_until_started(&mut listening, &sink, 2);
        assert!(matches!(
            events.try_recv(),
            Ok(BackendEvent::Degraded(
                DegradeReason::SourceUnavailable { .. }
            ))
        ));
    }

    /// A start under way when `WinDivert` is turned off is refused. If `WinDivert` is on
    /// again by the time that refusal is taken, the listener must still come up.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn a_start_refused_while_windivert_was_off_is_run_again_once_it_is_on() {
        fn refused_once(
            cache: Arc<Mutex<FlowOwnerCache>>,
            sink: EventSink,
        ) -> Result<FlowListener, DivertError> {
            drop((cache, sink));
            if STARTS.fetch_add(1, Ordering::SeqCst) == 0 {
                Err(DivertError::turned_off())
            } else {
                Err(DivertError::lasting("no driver in this test"))
            }
        }

        let _switch = testing::alone();
        STARTS.store(0, Ordering::SeqCst);
        let owners = Arc::new(Mutex::new(FlowOwnerCache::default()));
        let (sink, events) = sink();
        let mut listening = FlowListening::starting_with(owners, refused_once);

        set_windivert_enabled(true);
        poll_until_started(&mut listening, &sink, 2);

        let Ok(BackendEvent::Degraded(DegradeReason::SourceUnavailable { detail, .. })) =
            events.try_recv()
        else {
            panic!("the second start's failure was not reported");
        };
        assert_eq!(
            detail, "no driver in this test",
            "the refusal is not a failure"
        );
        assert!(events.try_recv().is_err());
    }

    /// Only the x64 listener records owners, so only there is there anything to forget.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn turning_windivert_off_forgets_the_owners_it_recorded() {
        use crate::flow_owner::FlowOwner;
        use netmetrics_core::{FlowKey, Protocol};

        let _switch = testing::alone();
        let owners = Arc::new(Mutex::new(FlowOwnerCache::default()));
        let (sink, _events) = sink();
        let mut listening = FlowListening::starting_with(Arc::clone(&owners), failing_start);
        set_windivert_enabled(true);
        listening.poll(&sink);

        let key = FlowKey {
            protocol: Protocol::Tcp,
            local_addr: "192.0.2.1".parse().expect("local"),
            local_port: 50_000,
            remote_addr: "203.0.113.9".parse().expect("remote"),
            remote_port: 443,
        };
        let owner = FlowOwner {
            pid: 77,
            executable: String::new(),
            name: String::new(),
            start_ts: 0,
        };
        let now = Instant::now();
        owners.lock().expect("owners").insert(key, owner, now);
        assert!(owners.lock().expect("owners").lookup(&key, now).is_some());

        set_windivert_enabled(false);
        listening.poll(&sink);
        assert!(
            owners.lock().expect("owners").lookup(&key, now).is_none(),
            "owners recorded before it was turned off are stale"
        );
    }

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
