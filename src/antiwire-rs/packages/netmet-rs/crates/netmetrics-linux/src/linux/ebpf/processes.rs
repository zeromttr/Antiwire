//! Processes seen on the network, kept current from `/proc` and from the kernel's exec and
//! exit records.

use crate::linux::process::{ProcessReading, boottime_ticks, exited_process, read_process};
use netmetrics_core::{ProcessInfo, unix_now_ms};
use netmetrics_sys::{BackendEvent, EventSink, WireProcessKind, WireProcessRecord};
use std::collections::{HashMap, HashSet};
use std::path::Path;

/// PIDs remembered as having used the network before `/proc` could name them.
const MAX_UNNAMED: usize = 4_096;

/// Whether two start times, in clock ticks since boot, belong to one process. `None`
/// when either is unknown: nothing then says whether a PID was reused in between.
fn same_start(known: Option<u64>, seen: Option<u64>) -> Option<bool> {
    Some(known? == seen?)
}

/// The processes reported so far, and those waiting for a name.
#[derive(Debug, Default)]
pub(super) struct Processes {
    named: HashMap<u32, ProcessReading>,
    /// PIDs that used the network and were gone from `/proc` when it was read. Their exit
    /// record comes later in the ring and names them.
    unnamed: HashSet<u32>,
}

impl Processes {
    /// Takes over the processes the procfs fallback reported, so none is reported started
    /// again and each one's exit is reported, whether or not it uses the network again.
    pub(super) fn adopting(reported: HashMap<u32, ProcessReading>) -> Self {
        Self {
            named: reported,
            unnamed: HashSet::new(),
        }
    }

    /// Whether `pid` has been reported and not stopped since.
    pub(super) fn knows(&self, pid: u32) -> bool {
        self.named.contains_key(&pid)
    }

    /// Reads `pid` from `/proc` and reports it when it is new or has changed.
    pub(super) fn refresh(&mut self, pid: u32, timestamp: u64, sink: &EventSink) {
        self.refresh_from(Path::new("/proc"), pid, timestamp, sink);
    }

    fn refresh_from(&mut self, proc_root: &Path, pid: u32, timestamp: u64, sink: &EventSink) {
        let Some(mut reading) = read_process(proc_root, pid) else {
            if !self.named.contains_key(&pid) && self.unnamed.len() < MAX_UNNAMED {
                self.unnamed.insert(pid);
            }
            return;
        };
        self.unnamed.remove(&pid);
        if let Some(current) = self.named.get(&pid) {
            let same_process = same_start(current.start_ticks, reading.start_ticks) == Some(true);
            if same_process {
                // The start time first reported stands. Read again it can differ: it is
                // counted from a boot time that follows the wall clock.
                reading.identity.start_ts = current.identity.start_ts;
            }
            if current.identity == reading.identity {
                return;
            }
            // exec keeps the PID and the start, so the same process under a new program
            // replaces its identity in place. Any other change is a new process on a
            // reused PID, and the one known until now has ended.
            if !same_process {
                sink.emit(BackendEvent::ProcessStopped {
                    pid,
                    timestamp,
                    identity: Some(current.identity.clone()),
                });
            }
        }
        let identity = reading.identity.clone();
        self.named.insert(pid, reading);
        sink.emit(BackendEvent::ProcessStarted(ProcessInfo { pid, identity }));
    }

    /// Applies an exec or exit record.
    pub(super) fn observe(&mut self, record: &WireProcessRecord, timestamp: u64, sink: &EventSink) {
        self.observe_from(Path::new("/proc"), record, timestamp, sink);
    }

    fn observe_from(
        &mut self,
        proc_root: &Path,
        record: &WireProcessRecord,
        timestamp: u64,
        sink: &EventSink,
    ) {
        let pid = record.pid;
        match record.kind {
            // Every process on the host execs. Only one already seen on the network is
            // read again; the rest are read if they ever use it.
            WireProcessKind::Exec => {
                if self.named.contains_key(&pid) || self.unnamed.contains(&pid) {
                    self.refresh_from(proc_root, pid, timestamp, sink);
                }
            }
            WireProcessKind::Exit => {
                // A PID is reused, and `/proc` may have been read after that happened: the
                // record then describes an earlier holder of the PID than the one known.
                // The two are compared in ticks since boot, which setting the wall clock
                // cannot move; the start times derived from them can differ for one
                // process, and an exit that went unmatched would leave it running forever.
                let exit_ticks = boottime_ticks(record.start_boottime_ns);
                let is_known = self
                    .named
                    .get(&pid)
                    .is_some_and(|known| same_start(known.start_ticks, exit_ticks) != Some(false));
                let identity = if is_known {
                    self.named.remove(&pid).map(|known| known.identity)
                } else if self.unnamed.remove(&pid) {
                    // It used the network and exited before `/proc` was read. The record
                    // still names it, so its flows are not left without a process.
                    exited_process(proc_root, &record.name, record.start_boottime_ns).map(
                        |exited| {
                            sink.emit(BackendEvent::ProcessStarted(ProcessInfo {
                                pid,
                                identity: exited.identity.clone(),
                            }));
                            exited.identity
                        },
                    )
                } else {
                    None
                };
                if let Some(identity) = identity {
                    sink.emit(BackendEvent::ProcessStopped {
                        pid,
                        timestamp,
                        identity: Some(identity),
                    });
                }
            }
        }
    }

    /// Reports the processes `/proc` no longer lists. Only for a kernel whose exits are
    /// not reported as they happen.
    pub(super) fn sweep(&mut self, sink: &EventSink) {
        let stopped_at = unix_now_ms();
        self.named.retain(|pid, known| {
            let live = Path::new("/proc").join(pid.to_string()).exists();
            if !live {
                sink.emit(BackendEvent::ProcessStopped {
                    pid: *pid,
                    timestamp: stopped_at,
                    identity: Some(known.identity.clone()),
                });
            }
            live
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
    use std::sync::mpsc::{Receiver, sync_channel};

    /// Ten seconds after boot, in the nanoseconds an exit record carries.
    const STARTED_AT_NS: u64 = 10_000_000_000;

    fn sink() -> (EventSink, Receiver<BackendEvent>) {
        let (sender, receiver) = sync_channel(16);
        (
            EventSink::new(sender, Arc::new(AtomicU64::new(0))),
            receiver,
        )
    }

    /// A `/proc` stand-in for a host booted at second 1,000 of the epoch.
    fn proc_root() -> PathBuf {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let root = std::env::temp_dir().join(format!(
            "netmetrics-processes-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).expect("create proc root");
        set_boot_time(&root, 1_000);
        root
    }

    /// Sets the boot time `/proc/stat` reports, as setting the wall clock does.
    fn set_boot_time(root: &Path, seconds: u64) {
        fs::write(root.join("stat"), format!("cpu 0 0 0 0\nbtime {seconds}\n"))
            .expect("write stat");
    }

    /// Adds a live process called `name` that started ten seconds after boot.
    fn add_process(root: &Path, pid: u32, name: &str) {
        // SAFETY: sysconf with _SC_CLK_TCK has no pointer arguments or side effects.
        let ticks_per_second =
            u64::try_from(unsafe { libc::sysconf(libc::_SC_CLK_TCK) }).expect("clock ticks");
        let directory = root.join(pid.to_string());
        fs::create_dir_all(&directory).expect("create process");
        fs::write(directory.join("comm"), format!("{name}\n")).expect("write comm");
        let start_ticks = STARTED_AT_NS / (1_000_000_000 / ticks_per_second);
        let fields = ["0"; 18].join(" ");
        fs::write(
            directory.join("stat"),
            format!("{pid} ({name}) S {fields} {start_ticks} 0\n"),
        )
        .expect("write process stat");
    }

    fn record(
        kind: WireProcessKind,
        pid: u32,
        name: &str,
        start_boottime_ns: u64,
    ) -> WireProcessRecord {
        WireProcessRecord {
            kind,
            pid,
            timestamp: 1,
            start_boottime_ns,
            name: name.to_owned(),
        }
    }

    fn started(event: &BackendEvent) -> Option<(u32, &str, u64)> {
        match event {
            BackendEvent::ProcessStarted(process) => Some((
                process.pid,
                process.identity.name.as_str(),
                process.identity.start_ts,
            )),
            _ => None,
        }
    }

    #[test]
    fn a_process_that_exits_is_stopped_by_its_exit_record() {
        let root = proc_root();
        add_process(&root, 7, "curl");
        let (sink, events) = sink();
        let mut processes = Processes::default();
        processes.refresh_from(&root, 7, 5, &sink);
        assert!(processes.knows(7));
        processes.observe_from(
            &root,
            &record(WireProcessKind::Exit, 7, "curl", STARTED_AT_NS),
            9,
            &sink,
        );
        fs::remove_dir_all(&root).expect("remove proc root");

        let events: Vec<_> = events.try_iter().collect();
        assert_eq!(started(&events[0]), Some((7, "curl", 1_010_000)));
        assert!(matches!(
            &events[1],
            BackendEvent::ProcessStopped { pid: 7, timestamp: 9, identity: Some(identity) }
                if identity.name == "curl"
        ));
        assert_eq!(events.len(), 2);
        assert!(!processes.knows(7));
    }

    /// The kernel counts a start time from boot. The time of day it becomes moves with
    /// the wall clock, so it cannot be what says whose exit this is.
    #[test]
    fn an_exit_stops_its_process_after_the_wall_clock_was_set() {
        let root = proc_root();
        add_process(&root, 7, "curl");
        let (sink, events) = sink();
        let mut processes = Processes::default();
        processes.refresh_from(&root, 7, 5, &sink);
        set_boot_time(&root, 5_000);
        processes.observe_from(
            &root,
            &record(WireProcessKind::Exit, 7, "curl", STARTED_AT_NS),
            9,
            &sink,
        );
        fs::remove_dir_all(&root).expect("remove proc root");

        let events: Vec<_> = events.try_iter().collect();
        assert_eq!(started(&events[0]), Some((7, "curl", 1_010_000)));
        assert!(
            matches!(
                &events[1],
                BackendEvent::ProcessStopped { pid: 7, identity: Some(identity), .. }
                    if identity.start_ts == 1_010_000
            ),
            "the exit stops the process under the start time it was reported with: {events:?}"
        );
        assert!(!processes.knows(7));
    }

    #[test]
    fn a_process_read_again_after_the_wall_clock_was_set_is_not_reported_as_new() {
        let root = proc_root();
        add_process(&root, 7, "curl");
        let (sink, events) = sink();
        let mut processes = Processes::default();
        processes.refresh_from(&root, 7, 5, &sink);
        set_boot_time(&root, 5_000);
        processes.refresh_from(&root, 7, 6, &sink);
        fs::remove_dir_all(&root).expect("remove proc root");

        assert_eq!(
            events.try_iter().count(),
            1,
            "only the first reading is news"
        );
    }

    /// The process sent a packet and exited before its record was read from the ring.
    #[test]
    fn a_process_gone_before_proc_was_read_is_named_by_its_exit_record() {
        let root = proc_root();
        let (sink, events) = sink();
        let mut processes = Processes::default();
        processes.refresh_from(&root, 7, 5, &sink);
        assert!(events.try_iter().next().is_none(), "nothing names it yet");
        processes.observe_from(
            &root,
            &record(WireProcessKind::Exit, 7, "curl", STARTED_AT_NS),
            9,
            &sink,
        );
        fs::remove_dir_all(&root).expect("remove proc root");

        let events: Vec<_> = events.try_iter().collect();
        assert_eq!(
            started(&events[0]),
            Some((7, "curl", 1_010_000)),
            "the start time is the one /proc would have given"
        );
        assert!(matches!(
            &events[1],
            BackendEvent::ProcessStopped { pid: 7, timestamp: 9, identity: Some(identity) }
                if identity.name == "curl" && identity.executable.is_empty()
        ));
    }

    #[test]
    fn an_exit_of_a_process_never_seen_on_the_network_is_not_reported() {
        let root = proc_root();
        let (sink, events) = sink();
        let mut processes = Processes::default();
        processes.observe_from(
            &root,
            &record(WireProcessKind::Exit, 7, "true", STARTED_AT_NS),
            9,
            &sink,
        );
        processes.observe_from(
            &root,
            &record(WireProcessKind::Exec, 8, "true", STARTED_AT_NS),
            9,
            &sink,
        );
        fs::remove_dir_all(&root).expect("remove proc root");
        assert!(events.try_iter().next().is_none());
    }

    /// `/proc` was read after the PID had been reused, so the process known under it is
    /// the later one. The earlier one's exit must not stop it.
    #[test]
    fn an_exit_of_an_earlier_holder_of_the_pid_leaves_the_known_process_running() {
        let root = proc_root();
        add_process(&root, 7, "later");
        let (sink, events) = sink();
        let mut processes = Processes::default();
        processes.refresh_from(&root, 7, 5, &sink);
        processes.observe_from(
            &root,
            &record(WireProcessKind::Exit, 7, "earlier", STARTED_AT_NS / 2),
            9,
            &sink,
        );
        fs::remove_dir_all(&root).expect("remove proc root");

        assert_eq!(events.try_iter().count(), 1, "only the start was reported");
        assert!(processes.knows(7));
    }

    /// The fallback reported the process; the eBPF source that takes over neither reports it
    /// again when it uses the network nor misses its exit.
    #[test]
    fn a_process_the_fallback_reported_is_not_reported_again_and_its_exit_is() {
        let root = proc_root();
        add_process(&root, 7, "curl");
        let reported = read_process(&root, 7).expect("read process");
        let (sink, events) = sink();
        let mut processes = Processes::adopting(HashMap::from([(7, reported)]));
        assert!(processes.knows(7));
        processes.refresh_from(&root, 7, 5, &sink);
        assert!(events.try_iter().next().is_none(), "already reported");
        processes.observe_from(
            &root,
            &record(WireProcessKind::Exit, 7, "curl", STARTED_AT_NS),
            9,
            &sink,
        );
        fs::remove_dir_all(&root).expect("remove proc root");

        let events: Vec<_> = events.try_iter().collect();
        assert!(
            matches!(
                events.as_slice(),
                [BackendEvent::ProcessStopped { pid: 7, timestamp: 9, identity: Some(identity) }]
                    if identity.name == "curl"
            ),
            "{events:?}"
        );
        assert!(!processes.knows(7));
    }

    #[test]
    fn exec_replaces_the_identity_of_a_known_process_without_stopping_it() {
        let root = proc_root();
        add_process(&root, 7, "sh");
        let (sink, events) = sink();
        let mut processes = Processes::default();
        processes.refresh_from(&root, 7, 5, &sink);
        add_process(&root, 7, "curl");
        processes.observe_from(
            &root,
            &record(WireProcessKind::Exec, 7, "curl", STARTED_AT_NS),
            6,
            &sink,
        );
        fs::remove_dir_all(&root).expect("remove proc root");

        let events: Vec<_> = events.try_iter().collect();
        assert_eq!(
            events.iter().filter_map(started).collect::<Vec<_>>(),
            [(7, "sh", 1_010_000), (7, "curl", 1_010_000)]
        );
        assert_eq!(events.len(), 2, "the process did not stop");
    }
}
