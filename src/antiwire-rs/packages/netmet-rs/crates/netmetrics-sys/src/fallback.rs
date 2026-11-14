//! Snapshot polling while a backend's native source is down, and the retries that end it.
//!
//! Every backend whose native source can fail at start or mid-run (kernel ETW, eBPF, PKTAP)
//! falls back the same way: it reports why once, polls the socket table so connections are
//! still listed, tries the native source again every [`NATIVE_RETRY_INTERVAL`], and says so
//! when the native source is back. [`run_with_fallback`] is that switching for a backend whose
//! two sources sit behind [`FlowSources`].

use crate::{BackendError, BackendEvent, EventSink, StopFlag};
use netmetrics_core::DegradeReason;
use std::time::{Duration, Instant};

/// How long a backend polls snapshots before it tries its native source again.
///
/// A start can fail for reasons that pass, such as another run still tearing its session
/// down. Retrying keeps one bad start from costing byte accounting for the life of the
/// process, and a minute apart is rare enough that a source that stays unavailable costs
/// almost nothing.
pub const NATIVE_RETRY_INTERVAL: Duration = Duration::from_secs(60);

/// Why [`SnapshotFallback::run`] returned.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FallbackExit {
    /// Stop was requested.
    Stopped,
    /// The retry interval passed, so the native source should be tried again.
    RetryNative,
}

/// Whether a backend is polling snapshots in place of its native source, and the events that
/// tell the consumer when that changes.
///
/// Entering the fallback reports [`DegradeReason::SnapshotOnly`] once, however many retries
/// of the native source fail before it starts again. A backend reports why its native source
/// failed only while [`Self::is_active`] is false, so a retry that fails the same way is not
/// reported again either.
#[derive(Debug)]
pub struct SnapshotFallback {
    source: &'static str,
    active: bool,
}

impl SnapshotFallback {
    /// A fallback that polls `source`, the name its events carry.
    #[must_use]
    pub const fn new(source: &'static str) -> Self {
        Self {
            source,
            active: false,
        }
    }

    /// Whether the backend is in the fallback: its native source failed and has not started
    /// since.
    #[must_use]
    pub const fn is_active(&self) -> bool {
        self.active
    }

    /// The native source started, which ends the fallback if the backend was in it.
    ///
    /// Reports [`BackendEvent::Restored`] every time, as that event's contract requires; the
    /// collector decides whether it ends a fallback a consumer was told about.
    pub fn native_started(&mut self, sink: &EventSink) {
        self.active = false;
        sink.emit(BackendEvent::Restored {
            source: self.source.to_owned(),
        });
    }

    /// Enters the fallback, then calls `poll` at once and every `interval` after, until stop
    /// is requested or `retry_after` has passed.
    ///
    /// # Errors
    ///
    /// Returns the first error `poll` returns.
    pub fn run<E>(
        &mut self,
        sink: &EventSink,
        stop: &StopFlag,
        interval: Duration,
        retry_after: Duration,
        mut poll: impl FnMut() -> Result<(), E>,
    ) -> Result<FallbackExit, E> {
        if !self.active {
            self.active = true;
            sink.emit(BackendEvent::Degraded(DegradeReason::SnapshotOnly {
                source: self.source.to_owned(),
            }));
        }
        // A retry time past the end of the clock is never reached.
        let retry_at = Instant::now().checked_add(retry_after);
        while !stop.is_stop_requested() {
            poll()?;
            if retry_at.is_some_and(|at| Instant::now() >= at) {
                return Ok(FallbackExit::RetryNative);
            }
            stop.wait_timeout(interval);
        }
        Ok(FallbackExit::Stopped)
    }
}

/// A backend's native flow source and the snapshot source that stands in while it is down,
/// as [`run_with_fallback`] switches between them.
pub trait FlowSources {
    /// The backend's name, as [`crate::Backend::name`] reports it.
    const BACKEND_NAME: &'static str;
    /// The snapshot source's name, as [`DegradeReason::SnapshotOnly`] and
    /// [`BackendEvent::Restored`] carry it.
    const SNAPSHOT_SOURCE: &'static str;

    /// A native source that has started. It holds what it publishes while it runs, such as an
    /// [`EndpointOwnerSource`](crate::endpoint_owner::EndpointOwnerSource), and withdraws it
    /// when dropped.
    type Native;
    /// What both sources keep, so that each takes over the flows the other announced instead
    /// of announcing them again or leaving them open.
    type Flows;

    /// Starts the native source.
    ///
    /// # Errors
    ///
    /// Returns why the native source cannot start.
    fn start_native(&mut self, sink: &EventSink) -> Result<Self::Native, BackendError>;

    /// Reads `native` until stop is requested, keeping `flows` current.
    ///
    /// # Errors
    ///
    /// Returns why reading stopped, when anything but a stop request stopped it.
    fn read_native(
        &mut self,
        native: Self::Native,
        flows: &mut Self::Flows,
        sink: &EventSink,
        stop: &StopFlag,
    ) -> Result<(), BackendError>;

    /// Reads the snapshot source once while the native source is down, and applies what it
    /// lists to `flows`.
    ///
    /// # Errors
    ///
    /// Returns why the snapshot source could not be read.
    fn poll_snapshot(
        &mut self,
        flows: &mut Self::Flows,
        sink: &EventSink,
    ) -> Result<(), BackendError>;
}

/// Reads the native source until stop is requested, polling the snapshot source every
/// `poll_interval` while the native source is down and trying it again `retry_after` into
/// each fallback.
///
/// Why the native source failed is reported once per outage, as the fallback itself is, and
/// [`BackendEvent::Restored`] each time the native source starts. A native source is dropped
/// before the snapshot source is polled, so what it published is withdrawn for as long as the
/// backend falls back. Both sources keep the one `flows`.
///
/// # Errors
///
/// Returns the first error the snapshot source returns.
pub fn run_with_fallback<S: FlowSources>(
    sources: &mut S,
    flows: &mut S::Flows,
    sink: &EventSink,
    stop: &StopFlag,
    poll_interval: Duration,
    retry_after: Duration,
) -> Result<(), BackendError> {
    let mut fallback = SnapshotFallback::new(S::SNAPSHOT_SOURCE);
    while !stop.is_stop_requested() {
        match sources.start_native(sink) {
            Ok(native) => {
                fallback.native_started(sink);
                if let Err(error) = sources.read_native(native, flows, sink, stop) {
                    sink.emit(BackendEvent::Degraded(
                        error.degrade_reason(S::BACKEND_NAME),
                    ));
                }
            }
            // A retry that fails is not news: the fallback already said the source is down.
            Err(error) if !fallback.is_active() => {
                sink.emit(BackendEvent::Degraded(
                    error.degrade_reason(S::BACKEND_NAME),
                ));
            }
            Err(_) => {}
        }
        if stop.is_stop_requested() {
            break;
        }
        let exit = fallback.run(sink, stop, poll_interval, retry_after, || {
            sources.poll_snapshot(flows, sink)
        })?;
        if exit == FallbackExit::Stopped {
            break;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BackendErrorKind;
    use crate::endpoint_owner::{EndpointOwnerSource, take_publishing_turn};
    use netmetrics_core::endpoint_owner::endpoint_owners_available;
    use netmetrics_core::{FlowKey, Protocol};
    use std::collections::{BTreeSet, VecDeque};
    use std::convert::Infallible;
    use std::net::Ipv4Addr;
    use std::sync::Arc;
    use std::sync::atomic::AtomicU64;
    use std::sync::mpsc::{Receiver, sync_channel};

    const SOURCE: &str = "test-snapshot";

    fn sink() -> (EventSink, Receiver<BackendEvent>) {
        let (sender, receiver) = sync_channel(64);
        (
            EventSink::new(sender, Arc::new(AtomicU64::new(0))),
            receiver,
        )
    }

    fn snapshot_only() -> BackendEvent {
        BackendEvent::Degraded(DegradeReason::SnapshotOnly {
            source: SOURCE.to_owned(),
        })
    }

    fn restored() -> BackendEvent {
        BackendEvent::Restored {
            source: SOURCE.to_owned(),
        }
    }

    fn poll_counting(polls: &mut u32) -> impl FnMut() -> Result<(), Infallible> + '_ {
        || {
            *polls += 1;
            Ok(())
        }
    }

    #[test]
    fn the_fallback_is_reported_once_however_many_retries_fail() {
        let (sink, events) = sink();
        let stop = StopFlag::new();
        let mut fallback = SnapshotFallback::new(SOURCE);
        let mut polls = 0;
        for _ in 0..3 {
            let Ok(exit) = fallback.run(
                &sink,
                &stop,
                Duration::from_secs(1),
                Duration::ZERO,
                poll_counting(&mut polls),
            );
            assert_eq!(exit, FallbackExit::RetryNative);
        }
        assert_eq!(polls, 3, "each run polls once before it hands back");
        assert!(fallback.is_active());
        assert_eq!(events.try_iter().collect::<Vec<_>>(), vec![snapshot_only()]);
    }

    #[test]
    fn a_native_start_ends_the_fallback_and_a_later_loss_is_reported_again() {
        let (sink, events) = sink();
        let stop = StopFlag::new();
        let mut fallback = SnapshotFallback::new(SOURCE);
        let mut polls = 0;
        let interval = Duration::from_secs(1);
        let _ = fallback.run(
            &sink,
            &stop,
            interval,
            Duration::ZERO,
            poll_counting(&mut polls),
        );
        fallback.native_started(&sink);
        assert!(!fallback.is_active());
        let _ = fallback.run(
            &sink,
            &stop,
            interval,
            Duration::ZERO,
            poll_counting(&mut polls),
        );
        assert_eq!(
            events.try_iter().collect::<Vec<_>>(),
            vec![snapshot_only(), restored(), snapshot_only()]
        );
    }

    /// The collector, not the backend, knows whether an earlier run left a fallback unended.
    #[test]
    fn a_native_start_is_reported_even_without_a_fallback() {
        let (sink, events) = sink();
        SnapshotFallback::new(SOURCE).native_started(&sink);
        assert_eq!(events.try_iter().collect::<Vec<_>>(), vec![restored()]);
    }

    #[test]
    fn stop_ends_the_fallback_between_polls() {
        let (sink, _events) = sink();
        let stop = StopFlag::new();
        let mut fallback = SnapshotFallback::new(SOURCE);
        let mut polls = 0;
        let Ok(exit) = fallback.run(
            &sink,
            &stop,
            Duration::from_millis(1),
            NATIVE_RETRY_INTERVAL,
            || {
                polls += 1;
                if polls == 2 {
                    stop.stop();
                }
                Ok::<(), Infallible>(())
            },
        );
        assert_eq!(exit, FallbackExit::Stopped);
        assert_eq!(polls, 2);
    }

    #[test]
    fn a_poll_error_ends_the_fallback_with_that_error() {
        let (sink, _events) = sink();
        let stop = StopFlag::new();
        let result = SnapshotFallback::new(SOURCE).run(
            &sink,
            &stop,
            Duration::from_millis(1),
            NATIVE_RETRY_INTERVAL,
            || Err("socket table unreadable"),
        );
        assert_eq!(result, Err("socket table unreadable"));
    }

    #[test]
    fn a_retry_time_past_the_end_of_the_clock_never_comes() {
        let (sink, _events) = sink();
        let stop = StopFlag::new();
        let mut polls = 0;
        let Ok(exit) = SnapshotFallback::new(SOURCE).run(
            &sink,
            &stop,
            Duration::from_millis(1),
            Duration::MAX,
            || {
                polls += 1;
                if polls == 3 {
                    stop.stop();
                }
                Ok::<(), Infallible>(())
            },
        );
        assert_eq!(exit, FallbackExit::Stopped);
        assert_eq!(polls, 3);
    }

    /// The process every fake flow belongs to.
    const PID: u32 = 7;
    const TIMESTAMP: u64 = 1_000_000;
    const NATIVE: &str = "test-native";

    /// A flow from one fixed local address, told apart by `local_port`.
    fn key(local_port: u16) -> FlowKey {
        FlowKey {
            protocol: Protocol::Tcp,
            local_addr: Ipv4Addr::new(192, 0, 2, 10).into(),
            local_port,
            remote_addr: Ipv4Addr::new(198, 51, 100, 20).into(),
            remote_port: 443,
        }
    }

    /// The one table both fake sources keep: the flows announced and not yet closed, by port.
    #[derive(Debug, Default)]
    struct Announced(BTreeSet<u16>);

    impl Announced {
        /// A source saw `port`'s flow, which is announced the first time either source sees it.
        fn saw(&mut self, port: u16, sink: &EventSink) {
            if self.0.insert(port) {
                sink.emit(BackendEvent::Opened {
                    key: key(port),
                    pid: PID,
                    cookie: None,
                    timestamp: TIMESTAMP,
                    if_index: None,
                });
            }
        }

        /// The snapshot lists `ports`. A flow it does not list has ended, whichever source
        /// announced it.
        fn listed(&mut self, ports: &[u16], sink: &EventSink) {
            for port in ports {
                self.saw(*port, sink);
            }
            self.0.retain(|port| {
                let listed = ports.contains(port);
                if !listed {
                    sink.emit(BackendEvent::Closed {
                        key: key(*port),
                        pid: 0,
                        timestamp: TIMESTAMP,
                    });
                }
                listed
            });
        }
    }

    /// How a scripted native source ends.
    enum End {
        Fails,
        Stops,
    }

    /// A native source that sees the flows of `ports`, then ends.
    struct Script {
        ports: Vec<u16>,
        end: End,
    }

    /// A started fake native source, publishing endpoint owners as a real one does.
    struct FakeNative {
        script: Script,
        owners: EndpointOwnerSource,
    }

    /// Sources that do what the test scripted, and record what the loop asked of them.
    struct FakeSources {
        /// What each attempt to start the native source returns, in order.
        starts: VecDeque<Result<Script, BackendError>>,
        /// What each poll of the snapshot source reads, in order. A poll after the last asks
        /// to stop.
        snapshots: VecDeque<Result<Vec<u16>, BackendError>>,
        stop: StopFlag,
        /// Whether endpoint owners were available while each native source was read.
        owners_while_reading: Vec<bool>,
        /// Whether endpoint owners were available at each poll.
        owners_while_polling: Vec<bool>,
    }

    impl FakeSources {
        fn new(
            starts: impl IntoIterator<Item = Result<Script, BackendError>>,
            snapshots: impl IntoIterator<Item = Result<Vec<u16>, BackendError>>,
        ) -> Self {
            Self {
                starts: starts.into_iter().collect(),
                snapshots: snapshots.into_iter().collect(),
                stop: StopFlag::new(),
                owners_while_reading: Vec::new(),
                owners_while_polling: Vec::new(),
            }
        }
    }

    impl FlowSources for FakeSources {
        const BACKEND_NAME: &'static str = NATIVE;
        const SNAPSHOT_SOURCE: &'static str = SOURCE;
        type Native = FakeNative;
        type Flows = Announced;

        fn start_native(&mut self, _: &EventSink) -> Result<FakeNative, BackendError> {
            let script = self
                .starts
                .pop_front()
                .expect("the loop started the native source more often than the script allows")?;
            Ok(FakeNative {
                script,
                owners: EndpointOwnerSource::default(),
            })
        }

        fn read_native(
            &mut self,
            native: FakeNative,
            flows: &mut Announced,
            sink: &EventSink,
            stop: &StopFlag,
        ) -> Result<(), BackendError> {
            let FakeNative { script, owners } = native;
            self.owners_while_reading.push(endpoint_owners_available());
            for port in script.ports {
                flows.saw(port, sink);
            }
            // As a real source's are, the owners are withdrawn when reading ends.
            drop(owners);
            match script.end {
                End::Fails => Err(BackendError::new(
                    BackendErrorKind::SessionLost,
                    NATIVE,
                    "read failed",
                )),
                End::Stops => {
                    stop.stop();
                    Ok(())
                }
            }
        }

        fn poll_snapshot(
            &mut self,
            flows: &mut Announced,
            sink: &EventSink,
        ) -> Result<(), BackendError> {
            self.owners_while_polling.push(endpoint_owners_available());
            match self.snapshots.pop_front() {
                Some(listed) => flows.listed(&listed?, sink),
                None => self.stop.stop(),
            }
            Ok(())
        }
    }

    /// What the loop reported, in a form a test can compare.
    #[derive(Debug, Eq, PartialEq)]
    enum Seen {
        /// Why a source failed, by the source or backend the reason names.
        Cause(String),
        SnapshotOnly,
        Restored,
        Opened(u16),
        Closed(u16),
    }

    /// Runs the loop to its end and returns its result and what it reported.
    fn run(
        sources: &mut FakeSources,
        retry_after: Duration,
    ) -> (Result<(), BackendError>, Vec<Seen>) {
        let (sink, receiver) = sink();
        let stop = sources.stop.clone();
        let mut flows = Announced::default();
        let result = run_with_fallback(
            sources,
            &mut flows,
            &sink,
            &stop,
            Duration::from_millis(1),
            retry_after,
        );
        assert!(sources.starts.is_empty(), "the script expected more starts");
        let seen = receiver
            .try_iter()
            .map(|event| match event {
                BackendEvent::Degraded(DegradeReason::SnapshotOnly { source }) => {
                    assert_eq!(source, SOURCE);
                    Seen::SnapshotOnly
                }
                BackendEvent::Degraded(
                    DegradeReason::SourceUnavailable { source, .. }
                    | DegradeReason::PermissionDenied { source }
                    | DegradeReason::SessionLost {
                        backend: source, ..
                    },
                ) => Seen::Cause(source),
                BackendEvent::Restored { source } => {
                    assert_eq!(source, SOURCE);
                    Seen::Restored
                }
                BackendEvent::Opened { key, .. } => Seen::Opened(key.local_port),
                BackendEvent::Closed { key, .. } => Seen::Closed(key.local_port),
                other => panic!("unexpected event {other:?}"),
            })
            .collect();
        (result, seen)
    }

    fn cannot_start(kind: BackendErrorKind, source: &str) -> Result<Script, BackendError> {
        Err(BackendError::new(kind, source, "cannot start"))
    }

    #[test]
    fn a_native_source_that_cannot_start_falls_back_once_and_takes_over_when_it_can() {
        let _turn = take_publishing_turn();
        let mut sources = FakeSources::new(
            [
                cannot_start(BackendErrorKind::Unavailable, "test-loader"),
                cannot_start(BackendErrorKind::Unavailable, "test-loader"),
                Ok(Script {
                    ports: vec![1, 2],
                    end: End::Stops,
                }),
            ],
            [Ok(vec![1]), Ok(vec![1])],
        );
        let (result, seen) = run(&mut sources, Duration::ZERO);
        assert_eq!(result, Ok(()));
        assert_eq!(
            seen,
            [
                Seen::Cause("test-loader".to_owned()),
                Seen::SnapshotOnly,
                Seen::Opened(1),
                Seen::Restored,
                Seen::Opened(2),
            ],
            "the cause and the fallback are reported once, the flow the snapshot announced is \
             not announced again, and recovery is reported once"
        );
        assert_eq!(sources.owners_while_polling, [false, false]);
        assert_eq!(sources.owners_while_reading, [true]);
        assert!(!endpoint_owners_available(), "withdrawn when reading ends");
    }

    /// The first `Restored` ends no fallback; the collector drops it (see
    /// [`SnapshotFallback::native_started`]).
    #[test]
    fn a_native_source_that_fails_while_reading_hands_its_flows_to_the_snapshot() {
        let _turn = take_publishing_turn();
        let mut sources = FakeSources::new(
            [
                Ok(Script {
                    ports: vec![1, 2],
                    end: End::Fails,
                }),
                Ok(Script {
                    ports: vec![1],
                    end: End::Stops,
                }),
            ],
            [Ok(vec![1])],
        );
        let (result, seen) = run(&mut sources, Duration::ZERO);
        assert_eq!(result, Ok(()));
        assert_eq!(
            seen,
            [
                Seen::Restored,
                Seen::Opened(1),
                Seen::Opened(2),
                Seen::Cause(NATIVE.to_owned()),
                Seen::SnapshotOnly,
                Seen::Closed(2),
                Seen::Restored,
            ],
            "a flow the snapshot no longer lists is closed, and one it still lists is neither \
             closed nor announced again"
        );
        assert_eq!(sources.owners_while_reading, [true, true]);
        assert_eq!(sources.owners_while_polling, [false]);
    }

    #[test]
    fn a_later_loss_is_reported_again() {
        let _turn = take_publishing_turn();
        let empty = || Ok(Vec::new());
        let mut sources = FakeSources::new(
            [
                cannot_start(BackendErrorKind::Unavailable, "test-loader"),
                Ok(Script {
                    ports: Vec::new(),
                    end: End::Fails,
                }),
                cannot_start(BackendErrorKind::Unavailable, "test-loader"),
                Ok(Script {
                    ports: Vec::new(),
                    end: End::Stops,
                }),
            ],
            [empty(), empty(), empty()],
        );
        let (result, seen) = run(&mut sources, Duration::ZERO);
        assert_eq!(result, Ok(()));
        assert_eq!(
            seen,
            [
                Seen::Cause("test-loader".to_owned()),
                Seen::SnapshotOnly,
                Seen::Restored,
                Seen::Cause(NATIVE.to_owned()),
                Seen::SnapshotOnly,
                Seen::Restored,
            ]
        );
    }

    #[test]
    fn stop_in_the_fallback_does_not_start_the_native_source_again() {
        let _turn = take_publishing_turn();
        let mut sources = FakeSources::new(
            [cannot_start(
                BackendErrorKind::PermissionDenied,
                "test-loader",
            )],
            [Ok(vec![1])],
        );
        let (result, seen) = run(&mut sources, NATIVE_RETRY_INTERVAL);
        assert_eq!(result, Ok(()));
        assert_eq!(
            seen,
            [
                Seen::Cause("test-loader".to_owned()),
                Seen::SnapshotOnly,
                Seen::Opened(1),
            ]
        );
        assert_eq!(sources.owners_while_polling, [false, false]);
    }

    #[test]
    fn stop_while_reading_does_not_report_a_fallback() {
        let _turn = take_publishing_turn();
        let mut sources = FakeSources::new(
            [Ok(Script {
                ports: vec![1],
                end: End::Stops,
            })],
            [],
        );
        let (result, seen) = run(&mut sources, Duration::ZERO);
        assert_eq!(result, Ok(()));
        assert_eq!(seen, [Seen::Restored, Seen::Opened(1)]);
        assert!(sources.owners_while_polling.is_empty());
    }

    #[test]
    fn a_snapshot_that_cannot_be_read_ends_the_run_with_its_error() {
        let _turn = take_publishing_turn();
        let unreadable = BackendError::new(BackendErrorKind::Io, SOURCE, "unreadable");
        let mut sources = FakeSources::new(
            [cannot_start(BackendErrorKind::Unavailable, "test-loader")],
            [Ok(vec![1]), Err(unreadable.clone())],
        );
        let (result, seen) = run(&mut sources, NATIVE_RETRY_INTERVAL);
        assert_eq!(result, Err(unreadable));
        assert_eq!(
            seen,
            [
                Seen::Cause("test-loader".to_owned()),
                Seen::SnapshotOnly,
                Seen::Opened(1),
            ]
        );
    }
}
