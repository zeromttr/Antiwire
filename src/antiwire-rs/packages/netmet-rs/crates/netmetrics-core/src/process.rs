use crate::{ProcessIdentity, ProcessInfo};
use std::collections::{BTreeSet, HashMap};

#[derive(Clone, Debug)]
struct ProcessEntry {
    identity: ProcessIdentity,
    stop_ts: Option<u64>,
    generation: u64,
}

/// What [`ProcessTable::stopped_with_identity`] did with a stop.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StopOutcome {
    /// The PID's process is now stopped.
    Stopped,
    /// The PID is not tracked, and the stop carries no usable identity to
    /// record. Another consumer may still track it.
    Untracked,
    /// The stop belongs to an earlier process with this PID: it ended before
    /// the tracked one started, or names a different creation time. The
    /// tracked process is still running.
    Stale,
}

/// PID table that preserves process identity for a grace period after exit.
#[derive(Debug)]
pub struct ProcessTable {
    entries: HashMap<u32, ProcessEntry>,
    stopped: BTreeSet<(u64, u64, u32)>,
    active: BTreeSet<(u64, u64, u32)>,
    generation: u64,
    grace_ms: u64,
    max_entries: usize,
}

impl ProcessTable {
    /// Creates a process table with a fixed retention and memory bound.
    ///
    /// # Panics
    ///
    /// Panics when `max_entries` is zero.
    pub fn new(grace_ms: u64, max_entries: usize) -> Self {
        assert!(max_entries > 0, "process capacity must be non-zero");
        Self {
            entries: HashMap::with_capacity(max_entries.min(1024)),
            stopped: BTreeSet::new(),
            active: BTreeSet::new(),
            generation: 0,
            grace_ms,
            max_entries,
        }
    }

    /// Inserts a process, replacing stale data when a PID is reused.
    pub fn started(&mut self, process: ProcessInfo) {
        if self.entries.get(&process.pid).is_some_and(|current| {
            current.identity.start_ts != 0
                && (process.identity.start_ts == 0
                    || current.identity.start_ts > process.identity.start_ts)
        }) {
            return;
        }
        if let Some(current) = self.entries.get_mut(&process.pid)
            && process.identity.start_ts != 0
            && (current.identity.start_ts == process.identity.start_ts
                || (current.identity.start_ts == 0
                    && current
                        .stop_ts
                        .is_some_and(|stop| process.identity.start_ts <= stop)))
        {
            // Independent start sources may arrive after the stop. Enrich
            // this generation without reviving it or discarding a full path
            // in favour of the legacy source's basename.
            if !current.identity.executable.contains(['\\', '/'])
                || process.identity.executable.contains(['\\', '/'])
            {
                current.identity = process.identity;
            }
            return;
        }
        if self.entries.len() >= self.max_entries && !self.entries.contains_key(&process.pid) {
            self.evict_one();
        }
        if let Some(previous) = self.entries.remove(&process.pid) {
            self.remove_index(process.pid, &previous);
        }
        self.generation = self.generation.wrapping_add(1);
        let generation = self.generation;
        let start_ts = process.identity.start_ts;
        let pid = process.pid;
        self.entries.insert(
            pid,
            ProcessEntry {
                identity: process.identity,
                stop_ts: None,
                generation,
            },
        );
        self.active.insert((start_ts, generation, pid));
    }

    /// Marks a PID stopped. Unknown PIDs are ignored unless `identity` is supplied.
    ///
    /// Kernel process-end events carry an image name even when start/rundown was
    /// missed. Recording that identity here keeps delayed flow attribution from
    /// falling through to an unattributed row during the grace window.
    pub fn stopped(&mut self, pid: u32, stop_ts: u64) {
        self.stopped_with_identity(pid, stop_ts, None);
    }

    /// Marks a PID stopped, recording `identity` when the process was not yet tracked.
    pub fn stopped_with_identity(
        &mut self,
        pid: u32,
        stop_ts: u64,
        identity: Option<ProcessIdentity>,
    ) -> StopOutcome {
        if let Some(current) = self.entries.get(&pid) {
            let mismatched_generation = identity.as_ref().is_some_and(|stopped| {
                stopped.start_ts != 0
                    && current.identity.start_ts != 0
                    && stopped.start_ts != current.identity.start_ts
            });
            if stop_ts < current.identity.start_ts || mismatched_generation {
                return StopOutcome::Stale;
            }
        } else {
            let Some(identity) = identity.filter(ProcessIdentity::is_usable) else {
                return StopOutcome::Untracked;
            };
            if identity.start_ts > stop_ts {
                return StopOutcome::Untracked;
            }
            self.started(ProcessInfo { pid, identity });
        }
        let index = self.entries.get_mut(&pid).map(|entry| {
            let active = (entry.identity.start_ts, entry.generation, pid);
            let previous = entry.stop_ts.map(|previous| {
                (
                    previous.saturating_add(self.grace_ms),
                    entry.generation,
                    pid,
                )
            });
            entry.stop_ts = Some(stop_ts);
            let stopped = (stop_ts.saturating_add(self.grace_ms), entry.generation, pid);
            (active, previous, stopped)
        });
        if let Some((active, previous, stopped)) = index {
            self.active.remove(&active);
            if let Some(previous) = previous {
                self.stopped.remove(&previous);
            }
            self.stopped.insert(stopped);
        }
        StopOutcome::Stopped
    }

    /// Resolves an active or recently stopped PID.
    pub fn resolve(&self, pid: u32, now: u64) -> Option<ProcessIdentity> {
        self.resolve_ref(pid, now).cloned()
    }

    /// Resolves without cloning process path and name strings.
    pub fn resolve_ref(&self, pid: u32, now: u64) -> Option<&ProcessIdentity> {
        self.entries
            .get(&pid)
            .and_then(|entry| match entry.stop_ts {
                None => Some(&entry.identity),
                Some(stop_ts) if now.saturating_sub(stop_ts) <= self.grace_ms => {
                    Some(&entry.identity)
                }
                Some(_) => None,
            })
    }

    /// Removes processes whose grace window has elapsed.
    pub fn sweep(&mut self, now: u64) -> usize {
        let before = self.entries.len();
        while self
            .stopped
            .first()
            .is_some_and(|(deadline, _, _)| *deadline < now)
        {
            let Some((_, generation, pid)) = self.stopped.pop_first() else {
                break;
            };
            if self.entries.get(&pid).is_some_and(|entry| {
                entry.generation == generation
                    && entry
                        .stop_ts
                        .is_some_and(|stop_ts| now.saturating_sub(stop_ts) > self.grace_ms)
            }) {
                self.entries.remove(&pid);
            }
        }
        before - self.entries.len()
    }

    /// Returns the number of retained PID rows.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns true when no PID rows are retained.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn evict_one(&mut self) {
        while let Some((_, generation, pid)) = self.stopped.pop_first() {
            if self
                .entries
                .get(&pid)
                .is_some_and(|entry| entry.generation == generation && entry.stop_ts.is_some())
            {
                self.entries.remove(&pid);
                return;
            }
        }
        while let Some((_, generation, pid)) = self.active.pop_first() {
            if self
                .entries
                .get(&pid)
                .is_some_and(|entry| entry.generation == generation && entry.stop_ts.is_none())
            {
                self.entries.remove(&pid);
                return;
            }
        }
    }

    fn remove_index(&mut self, pid: u32, entry: &ProcessEntry) {
        if let Some(stop_ts) = entry.stop_ts {
            self.stopped
                .remove(&(stop_ts.saturating_add(self.grace_ms), entry.generation, pid));
        } else {
            self.active
                .remove(&(entry.identity.start_ts, entry.generation, pid));
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn same_instance_basename_does_not_replace_captured_path() {
        let mut table = super::ProcessTable::new(60_000, 10);
        for executable in [r"C:\apps\quick.exe", "quick.exe"] {
            table.started(crate::ProcessInfo {
                pid: 910_001,
                identity: crate::ProcessIdentity {
                    executable: executable.to_owned(),
                    name: "quick.exe".to_owned(),
                    start_ts: 10_000,
                },
            });
        }
        assert_eq!(
            table.resolve(910_001, 10_001).expect("identity").executable,
            r"C:\apps\quick.exe"
        );
    }

    use super::*;

    #[test]
    fn delayed_known_start_does_not_revive_a_stopped_unknown_generation() {
        let mut table = ProcessTable::new(100, 4);
        table.started(ProcessInfo {
            pid: 42,
            identity: ProcessIdentity {
                executable: "quick".into(),
                name: "quick".into(),
                start_ts: 0,
            },
        });
        table.stopped(42, 30);
        table.started(ProcessInfo {
            pid: 42,
            identity: ProcessIdentity {
                executable: "/bin/quick".into(),
                name: "quick".into(),
                start_ts: 20,
            },
        });
        assert_eq!(
            table.resolve(42, 50).expect("in grace").executable,
            "/bin/quick"
        );
        assert!(
            table.resolve(42, 131).is_none(),
            "enrichment cannot restart the grace window"
        );
        assert_eq!(table.sweep(131), 1);
    }

    fn process(pid: u32, start_ts: u64) -> ProcessInfo {
        ProcessInfo {
            pid,
            identity: ProcessIdentity {
                executable: format!("/proc/{pid}/exe"),
                name: format!("p{pid}"),
                start_ts,
            },
        }
    }

    #[test]
    fn resolves_during_grace_then_sweeps() {
        let mut table = ProcessTable::new(100, 4);
        table.started(process(7, 10));
        table.stopped(7, 20);
        assert!(table.resolve(7, 120).is_some());
        assert!(table.resolve(7, 121).is_none());
        assert_eq!(table.sweep(121), 1);
        assert!(table.is_empty());
    }

    #[test]
    fn pid_reuse_replaces_stopped_identity() {
        let mut table = ProcessTable::new(1_000, 4);
        table.started(process(7, 10));
        table.stopped(7, 20);
        table.started(process(7, 30));
        assert_eq!(table.resolve(7, 31).expect("identity").start_ts, 30);
    }

    #[test]
    fn capacity_prefers_eviction_of_stopped_processes() {
        let mut table = ProcessTable::new(1_000, 2);
        table.started(process(1, 1));
        table.started(process(2, 2));
        table.stopped(2, 3);
        table.started(process(3, 4));
        assert!(table.resolve(1, 4).is_some());
        assert!(table.resolve(2, 4).is_none());
        assert!(table.resolve(3, 4).is_some());
    }

    #[test]
    fn pid_reuse_replaces_retention_index_entries() {
        let mut table = ProcessTable::new(100, 2);
        for start_ts in 0..10_000 {
            table.started(process(7, start_ts));
            table.stopped(7, start_ts + 1);
        }
        assert_eq!(table.len(), 1);
        assert!(table.active.is_empty());
        assert_eq!(table.stopped.len(), 1);
    }

    #[test]
    fn stale_lifecycle_events_do_not_replace_or_stop_newer_process() {
        let mut table = ProcessTable::new(100, 2);
        table.started(process(7, 30));
        table.started(process(7, 10));
        table.stopped(7, 20);
        assert_eq!(table.resolve(7, 40).unwrap().start_ts, 30);
    }

    #[test]
    fn stop_without_prior_start_records_identity_for_grace_window() {
        let mut table = ProcessTable::new(100, 4);
        table.stopped_with_identity(
            7,
            20,
            Some(ProcessIdentity {
                executable: r"C:\Apps\gone.exe".to_owned(),
                name: "gone.exe".to_owned(),
                start_ts: 10,
            }),
        );
        let identity = table.resolve(7, 50).expect("closed identity");
        assert_eq!(identity.executable, r"C:\Apps\gone.exe");
        assert_eq!(identity.name, "gone.exe");
        assert!(table.resolve(7, 121).is_none());
    }

    #[test]
    fn stop_without_identity_still_ignores_unknown_pids() {
        let mut table = ProcessTable::new(100, 4);
        table.stopped(7, 20);
        table.stopped_with_identity(8, 20, None);
        table.stopped_with_identity(
            9,
            20,
            Some(ProcessIdentity {
                executable: String::new(),
                name: String::new(),
                start_ts: 0,
            }),
        );
        assert!(table.is_empty());
    }

    #[test]
    fn stop_with_future_identity_ignores_an_unknown_pid() {
        let mut table = ProcessTable::new(100, 4);
        table.stopped_with_identity(
            7,
            20,
            Some(ProcessIdentity {
                executable: r"C:\Apps\future.exe".to_owned(),
                name: "future.exe".to_owned(),
                start_ts: 30,
            }),
        );

        assert!(table.is_empty());
    }

    #[test]
    fn stop_identity_does_not_replace_a_newer_tracked_process() {
        let mut table = ProcessTable::new(100, 4);
        table.started(process(7, 30));
        table.stopped_with_identity(
            7,
            20,
            Some(ProcessIdentity {
                executable: r"C:\Apps\old.exe".to_owned(),
                name: "old.exe".to_owned(),
                start_ts: 10,
            }),
        );
        assert_eq!(table.resolve(7, 40).unwrap().start_ts, 30);
        assert_eq!(table.resolve(7, 40).unwrap().name, "p7");
    }

    #[test]
    fn delayed_stop_identity_does_not_stop_a_reused_pid() {
        let mut table = ProcessTable::new(100, 4);
        table.started(process(7, 30));
        table.stopped_with_identity(
            7,
            40,
            Some(ProcessIdentity {
                executable: r"C:\Apps\old.exe".to_owned(),
                name: "old.exe".to_owned(),
                start_ts: 10,
            }),
        );

        assert_eq!(table.resolve(7, 141).expect("active process").start_ts, 30);
    }

    #[test]
    fn a_stop_for_an_earlier_process_with_the_pid_is_stale() {
        let mut table = ProcessTable::new(100, 4);
        table.started(process(7, 200));
        let earlier = Some(process(7, 100).identity);
        assert_eq!(
            table.stopped_with_identity(7, 250, earlier),
            StopOutcome::Stale,
            "a different creation time names another process"
        );
        assert_eq!(
            table.stopped_with_identity(7, 150, None),
            StopOutcome::Stale,
            "a stop before the tracked process started cannot be its stop"
        );
        assert_eq!(
            table.resolve(7, 10_000).expect("still running").start_ts,
            200
        );

        let current = Some(process(7, 200).identity);
        assert_eq!(
            table.stopped_with_identity(7, 300, current),
            StopOutcome::Stopped
        );
        assert!(table.resolve(7, 401).is_none());
    }

    #[test]
    fn a_stop_without_a_creation_time_still_stops_the_tracked_process() {
        let mut table = ProcessTable::new(100, 4);
        table.started(process(7, 200));
        let unknown = ProcessIdentity {
            executable: "p7".into(),
            name: "p7".into(),
            start_ts: 0,
        };
        assert_eq!(
            table.stopped_with_identity(7, 300, Some(unknown)),
            StopOutcome::Stopped
        );
    }

    #[test]
    fn a_stop_for_an_untracked_pid_is_untracked_unless_it_names_the_process() {
        let mut table = ProcessTable::new(100, 4);
        assert_eq!(
            table.stopped_with_identity(7, 300, None),
            StopOutcome::Untracked
        );
        assert_eq!(
            table.stopped_with_identity(8, 300, Some(process(8, 200).identity)),
            StopOutcome::Stopped
        );
        assert_eq!(table.resolve(8, 350).expect("in grace").start_ts, 200);
    }
}
