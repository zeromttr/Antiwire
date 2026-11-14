//! The processes behind captured packets.
//!
//! Every PKTAP packet names its process, so a process is known from its first packet. What
//! the packet does not carry, the executable path and the start time, is read once, and
//! the kernel then says when the process execs or exits.

use netmetrics_core::{ProcessIdentity, ProcessInfo};
use netmetrics_sys::{BackendEvent, EventSink};
use std::collections::HashMap;

/// How long a PID found already gone is left alone. More of its packets are usually still
/// in the capture buffer, and each would otherwise cost a lookup and repeat the report.
const GONE_RETRY_MS: u64 = 1_000;
/// PIDs remembered as gone at once.
const MAX_GONE: usize = 1_024;

/// What the kernel reported about a watched process.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProcessChange {
    /// It exited.
    Exited,
    /// It replaced its program, keeping its PID and start time.
    Replaced,
}

/// The answer to a request to watch a process.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Watch {
    /// Its exec and exit will be reported.
    Watching,
    /// It has already exited.
    Gone,
    /// It cannot be watched, so its exit has to be looked for.
    Unavailable,
}

/// What a running process is, beyond the name its packets carry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProcessDescription {
    /// Creation time, in Unix epoch milliseconds.
    pub start_ts: u64,
    /// Executable path, empty when it cannot be read.
    pub executable: String,
}

/// The operating system's account of processes.
pub(crate) trait ProcessSource {
    /// Describes `pid`, or returns `None` once it has exited.
    fn describe(&self, pid: u32) -> Option<ProcessDescription>;

    /// Asks to be told when `pid` execs or exits.
    fn watch(&mut self, pid: u32) -> Watch;

    /// Stops watching `pid`.
    fn unwatch(&mut self, pid: u32);

    /// Takes what watched processes have done since the last call, without blocking.
    fn take_changes(&mut self) -> Vec<(u32, ProcessChange)>;
}

#[derive(Debug)]
struct Known {
    identity: ProcessIdentity,
    /// The name its packets carried when it was described. Emptied when the kernel
    /// reports an exec, so that the next packet describes it again.
    command: String,
    /// Whether the kernel reports its exit. If not, [`Processes::sweep`] looks for it.
    watched: bool,
}

/// The processes reported so far.
#[derive(Debug)]
pub(crate) struct Processes<S> {
    source: S,
    known: HashMap<u32, Known>,
    /// PIDs found already gone, and when to look again.
    gone: HashMap<u32, u64>,
    capacity: usize,
}

impl<S: ProcessSource> Processes<S> {
    /// Tracks at most `capacity` processes, reporting the oldest as stopped beyond that.
    pub(crate) fn new(source: S, capacity: usize) -> Self {
        Self {
            source,
            known: HashMap::new(),
            gone: HashMap::new(),
            capacity: capacity.max(1),
        }
    }

    /// The source, for the descriptor a caller waits on.
    pub(crate) fn source(&self) -> &S {
        &self.source
    }

    /// Reports the process a packet named, the first time it is seen and when its name
    /// changes. A packet from a known process under the same name costs one map lookup.
    pub(crate) fn saw(&mut self, pid: u32, command: &str, timestamp: u64, sink: &EventSink) {
        if pid == 0 || command.is_empty() {
            return;
        }
        if self
            .known
            .get(&pid)
            .is_some_and(|known| known.command == command)
            || self
                .gone
                .get(&pid)
                .is_some_and(|retry_at| timestamp < *retry_at)
        {
            return;
        }
        let Some(description) = self.source.describe(pid) else {
            self.saw_gone(pid, command, timestamp, sink);
            return;
        };
        self.gone.remove(&pid);
        let identity = ProcessIdentity {
            executable: description.executable,
            name: command.to_owned(),
            start_ts: description.start_ts,
        };
        match self.known.get(&pid) {
            // exec keeps the PID and the start time: the same process under a new program
            // replaces its identity in place and stays watched.
            Some(known) if known.identity.start_ts == identity.start_ts => {}
            // A later process on a reused PID. The earlier one's exit removed its watch.
            Some(known) => {
                sink.emit(BackendEvent::ProcessStopped {
                    pid,
                    timestamp,
                    identity: Some(known.identity.clone()),
                });
                self.known.remove(&pid);
            }
            None => {}
        }
        let watch = match self.known.get(&pid) {
            Some(known) if known.watched => Watch::Watching,
            Some(_) => Watch::Unavailable,
            None => {
                self.make_room(timestamp, sink);
                self.source.watch(pid)
            }
        };
        sink.emit(BackendEvent::ProcessStarted(ProcessInfo {
            pid,
            identity: identity.clone(),
        }));
        if watch == Watch::Gone {
            // It exited between being described and being watched.
            sink.emit(BackendEvent::ProcessStopped {
                pid,
                timestamp,
                identity: Some(identity),
            });
            return;
        }
        self.known.insert(
            pid,
            Known {
                identity,
                command: command.to_owned(),
                watched: watch == Watch::Watching,
            },
        );
    }

    /// A packet named a process that no longer exists. Its name is all that is left, and
    /// is still reported, so its flows are not left without a process.
    fn saw_gone(&mut self, pid: u32, command: &str, timestamp: u64, sink: &EventSink) {
        let identity = if let Some(known) = self.known.remove(&pid) {
            known.identity
        } else {
            let identity = ProcessIdentity {
                executable: String::new(),
                name: command.to_owned(),
                start_ts: 0,
            };
            sink.emit(BackendEvent::ProcessStarted(ProcessInfo {
                pid,
                identity: identity.clone(),
            }));
            identity
        };
        sink.emit(BackendEvent::ProcessStopped {
            pid,
            timestamp,
            identity: Some(identity),
        });
        if self.gone.len() >= MAX_GONE {
            self.gone.clear();
        }
        self.gone
            .insert(pid, timestamp.saturating_add(GONE_RETRY_MS));
    }

    /// Reports the oldest process as stopped when there is no room for another.
    fn make_room(&mut self, timestamp: u64, sink: &EventSink) {
        if self.known.len() < self.capacity {
            return;
        }
        let Some(evicted) = self
            .known
            .iter()
            .min_by_key(|(pid, known)| (known.identity.start_ts, **pid))
            .map(|(pid, _)| *pid)
        else {
            return;
        };
        let Some(known) = self.known.remove(&evicted) else {
            return;
        };
        if known.watched {
            self.source.unwatch(evicted);
        }
        sink.emit(BackendEvent::ProcessStopped {
            pid: evicted,
            timestamp,
            identity: Some(known.identity),
        });
    }

    /// Applies the execs and exits the kernel has reported.
    pub(crate) fn apply_changes(&mut self, timestamp: u64, sink: &EventSink) {
        for (pid, change) in self.source.take_changes() {
            let Some(known) = self.known.get_mut(&pid) else {
                continue;
            };
            match change {
                ProcessChange::Replaced => known.command.clear(),
                ProcessChange::Exited => {
                    // The exit of an earlier process with this PID can arrive after a
                    // later one was described under it. That one is still running.
                    let start_ts = known.identity.start_ts;
                    if self
                        .source
                        .describe(pid)
                        .is_some_and(|description| description.start_ts == start_ts)
                    {
                        continue;
                    }
                    sink.emit(BackendEvent::ProcessStopped {
                        pid,
                        timestamp,
                        identity: self.known.remove(&pid).map(|known| known.identity),
                    });
                }
            }
        }
    }

    /// Reports the processes the kernel is not watching that are gone, or whose PID now
    /// names another. With every process watched this looks at nothing.
    pub(crate) fn sweep(&mut self, timestamp: u64, sink: &EventSink) {
        let stale: Vec<u32> =
            self.known
                .iter()
                .filter(|(pid, known)| {
                    !known.watched
                        && self.source.describe(**pid).is_none_or(|description| {
                            description.start_ts != known.identity.start_ts
                        })
                })
                .map(|(pid, _)| *pid)
                .collect();
        for pid in stale {
            sink.emit(BackendEvent::ProcessStopped {
                pid,
                timestamp,
                identity: self.known.remove(&pid).map(|known| known.identity),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::AtomicU64;
    use std::sync::mpsc::{Receiver, sync_channel};

    /// A process table the test edits, with or without exit notifications.
    #[derive(Default)]
    struct FakeSource {
        running: HashMap<u32, ProcessDescription>,
        watched: Vec<u32>,
        changes: Vec<(u32, ProcessChange)>,
        polls_only: bool,
    }

    impl FakeSource {
        fn run(&mut self, pid: u32, start_ts: u64, executable: &str) {
            self.running.insert(
                pid,
                ProcessDescription {
                    start_ts,
                    executable: executable.to_owned(),
                },
            );
        }

        fn exit(&mut self, pid: u32) {
            self.running.remove(&pid);
            if self.watched.contains(&pid) {
                self.changes.push((pid, ProcessChange::Exited));
            }
            self.watched.retain(|watched| *watched != pid);
        }
    }

    impl ProcessSource for FakeSource {
        fn describe(&self, pid: u32) -> Option<ProcessDescription> {
            self.running.get(&pid).cloned()
        }

        fn watch(&mut self, pid: u32) -> Watch {
            if self.polls_only {
                return Watch::Unavailable;
            }
            if !self.running.contains_key(&pid) {
                return Watch::Gone;
            }
            self.watched.push(pid);
            Watch::Watching
        }

        fn unwatch(&mut self, pid: u32) {
            self.watched.retain(|watched| *watched != pid);
        }

        fn take_changes(&mut self) -> Vec<(u32, ProcessChange)> {
            std::mem::take(&mut self.changes)
        }
    }

    fn sink() -> (EventSink, Receiver<BackendEvent>) {
        let (sender, receiver) = sync_channel(32);
        (
            EventSink::new(sender, Arc::new(AtomicU64::new(0))),
            receiver,
        )
    }

    /// Each event as `(started, pid, name, executable, start time)`.
    fn summary(events: &Receiver<BackendEvent>) -> Vec<(bool, u32, String, String, u64)> {
        events
            .try_iter()
            .filter_map(|event| match event {
                BackendEvent::ProcessStarted(process) => Some((
                    true,
                    process.pid,
                    process.identity.name,
                    process.identity.executable,
                    process.identity.start_ts,
                )),
                BackendEvent::ProcessStopped {
                    pid,
                    identity: Some(identity),
                    ..
                } => Some((
                    false,
                    pid,
                    identity.name,
                    identity.executable,
                    identity.start_ts,
                )),
                _ => None,
            })
            .collect()
    }

    fn row(
        started: bool,
        pid: u32,
        name: &str,
        path: &str,
        start: u64,
    ) -> (bool, u32, String, String, u64) {
        (started, pid, name.to_owned(), path.to_owned(), start)
    }

    #[test]
    fn a_process_is_described_once_and_stopped_when_the_kernel_says_it_exited() {
        let (sink, events) = sink();
        let mut source = FakeSource::default();
        source.run(7, 500, "/usr/bin/curl");
        let mut processes = Processes::new(source, 8);
        processes.saw(7, "curl", 1_000, &sink);
        processes.saw(7, "curl", 1_001, &sink);
        assert_eq!(
            summary(&events),
            [row(true, 7, "curl", "/usr/bin/curl", 500)]
        );

        processes.source.exit(7);
        processes.apply_changes(1_002, &sink);
        assert_eq!(
            summary(&events),
            [row(false, 7, "curl", "/usr/bin/curl", 500)]
        );
        assert!(processes.known.is_empty());
    }

    /// The packet is all that is left of a process that has already exited.
    #[test]
    fn a_process_already_gone_is_reported_by_the_name_its_packet_carried() {
        let (sink, events) = sink();
        let mut processes = Processes::new(FakeSource::default(), 8);
        processes.saw(7, "curl", 1_000, &sink);
        assert_eq!(
            summary(&events),
            [row(true, 7, "curl", "", 0), row(false, 7, "curl", "", 0)]
        );
        // The rest of its packets say nothing new.
        processes.saw(7, "curl", 1_001, &sink);
        assert!(summary(&events).is_empty());
        // A later process with the same PID is looked up once the pause is over.
        processes.source.run(7, 2_000, "/usr/bin/dig");
        processes.saw(7, "dig", 1_000 + GONE_RETRY_MS, &sink);
        assert_eq!(
            summary(&events),
            [row(true, 7, "dig", "/usr/bin/dig", 2_000)]
        );
    }

    /// A process that can be described and is gone by the time it is watched.
    struct Vanishing(FakeSource);

    impl ProcessSource for Vanishing {
        fn describe(&self, pid: u32) -> Option<ProcessDescription> {
            self.0.describe(pid)
        }

        fn watch(&mut self, _pid: u32) -> Watch {
            Watch::Gone
        }

        fn unwatch(&mut self, pid: u32) {
            self.0.unwatch(pid);
        }

        fn take_changes(&mut self) -> Vec<(u32, ProcessChange)> {
            Vec::new()
        }
    }

    #[test]
    fn a_process_that_exits_before_it_can_be_watched_is_started_and_stopped() {
        let (sink, events) = sink();
        let mut source = FakeSource::default();
        source.run(7, 500, "/usr/bin/curl");
        let mut processes = Processes::new(Vanishing(source), 8);
        processes.saw(7, "curl", 1_000, &sink);
        assert_eq!(
            summary(&events),
            [
                row(true, 7, "curl", "/usr/bin/curl", 500),
                row(false, 7, "curl", "/usr/bin/curl", 500)
            ]
        );
        assert!(processes.known.is_empty());
    }

    #[test]
    fn exec_replaces_the_identity_without_stopping_the_process() {
        let (sink, events) = sink();
        let mut source = FakeSource::default();
        source.run(7, 500, "/bin/sh");
        let mut processes = Processes::new(source, 8);
        processes.saw(7, "sh", 1_000, &sink);
        processes.source.run(7, 500, "/usr/bin/curl");
        processes.saw(7, "curl", 1_001, &sink);
        assert_eq!(
            summary(&events),
            [
                row(true, 7, "sh", "/bin/sh", 500),
                row(true, 7, "curl", "/usr/bin/curl", 500)
            ]
        );
        assert_eq!(processes.source().watched, [7], "it is watched once");

        // A new program under the same name is noticed through the kernel's report.
        processes.source.run(7, 500, "/opt/curl");
        processes.saw(7, "curl", 1_002, &sink);
        assert!(summary(&events).is_empty());
        processes.source.changes.push((7, ProcessChange::Replaced));
        processes.apply_changes(1_003, &sink);
        processes.saw(7, "curl", 1_004, &sink);
        assert_eq!(summary(&events), [row(true, 7, "curl", "/opt/curl", 500)]);
    }

    #[test]
    fn a_reused_pid_stops_the_earlier_process_and_ignores_its_late_exit() {
        let (sink, events) = sink();
        let mut source = FakeSource::default();
        source.run(7, 500, "/usr/bin/curl");
        let mut processes = Processes::new(source, 8);
        processes.saw(7, "curl", 1_000, &sink);
        // The first process exits and its PID is reused before the exit is applied.
        processes.source.exit(7);
        processes.source.run(7, 900, "/usr/bin/dig");
        processes.saw(7, "dig", 1_001, &sink);
        assert_eq!(
            summary(&events),
            [
                row(true, 7, "curl", "/usr/bin/curl", 500),
                row(false, 7, "curl", "/usr/bin/curl", 500),
                row(true, 7, "dig", "/usr/bin/dig", 900)
            ]
        );
        processes.apply_changes(1_002, &sink);
        assert!(
            summary(&events).is_empty(),
            "the earlier process's exit does not stop the later one"
        );
        assert!(processes.known.contains_key(&7));
    }

    #[test]
    fn the_oldest_process_makes_room_for_a_new_one() {
        let (sink, events) = sink();
        let mut source = FakeSource::default();
        source.run(1, 100, "/bin/a");
        source.run(2, 200, "/bin/b");
        let mut processes = Processes::new(source, 1);
        processes.saw(1, "a", 1_000, &sink);
        processes.saw(2, "b", 1_001, &sink);
        assert_eq!(
            summary(&events),
            [
                row(true, 1, "a", "/bin/a", 100),
                row(false, 1, "a", "/bin/a", 100),
                row(true, 2, "b", "/bin/b", 200)
            ]
        );
        assert_eq!(processes.source().watched, [2]);
    }

    #[test]
    fn watched_processes_are_not_swept() {
        let (sink, events) = sink();
        let mut source = FakeSource::default();
        source.run(7, 500, "/usr/bin/curl");
        let mut processes = Processes::new(source, 8);
        processes.saw(7, "curl", 1_000, &sink);
        let _ = summary(&events);
        // Gone, but the kernel has not said so yet: its report is what stops it.
        processes.source.running.clear();
        processes.sweep(1_001, &sink);
        assert!(summary(&events).is_empty());
    }

    #[test]
    fn a_source_without_exit_reports_is_swept() {
        let (sink, events) = sink();
        let mut source = FakeSource {
            polls_only: true,
            ..FakeSource::default()
        };
        source.run(7, 500, "/usr/bin/curl");
        source.run(8, 600, "/usr/bin/dig");
        let mut processes = Processes::new(source, 8);
        processes.saw(7, "curl", 1_000, &sink);
        processes.saw(8, "dig", 1_000, &sink);
        let _ = summary(&events);
        processes.sweep(1_001, &sink);
        assert!(summary(&events).is_empty(), "both are still running");
        processes.source.exit(7);
        processes.sweep(1_002, &sink);
        assert_eq!(
            summary(&events),
            [row(false, 7, "curl", "/usr/bin/curl", 500)]
        );
    }
}
