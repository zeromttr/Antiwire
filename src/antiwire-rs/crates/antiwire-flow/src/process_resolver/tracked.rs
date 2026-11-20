//! ETW-fed PID map with post-exit retention so late flow events still resolve.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use antiwire_tuning::{
    PROCESS_STOP_RETENTION_MS, PROCESS_SWEEP_EVERY_N_STOPS, PROCESS_SWEEP_WHEN_COUNT_EXCEEDS,
};
use parking_lot::Mutex;

use super::path::{
    executable_name, has_path_separators, is_nt_device_path, normalize_process_name,
    nt_path_to_dos_path, placeholder_path,
};
use super::{is_synthetic_path, start_ts_compatible, ResolvedIdentity};

struct TrackedProcess {
    path: String,
    /// Empty only for a stop whose start has not arrived (see
    /// [`TrackedProcesses::stopped_at`]): such an entry names nobody.
    name: String,
    /// Unconverted NT device path, kept while the drive map does not know the
    /// volume. Retried on every resolve so a transient map gap heals without
    /// ever publishing the NT string as its own application identity.
    raw_nt: Option<String>,
    /// Process creation timestamp, in Unix epoch milliseconds, or zero when the
    /// lifecycle event did not carry one.
    start_ts: u64,
    stopped_at: Option<Instant>,
    stop_ts: u64,
}

/// A tracked process identity together with the lifecycle state that made it
/// available. Active entries need a fresh live lookup when the flow has no
/// creation timestamp; stopped entries are the bounded post-exit grace path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct TrackedIdentity {
    pub(super) identity: ResolvedIdentity,
    pub(super) stopped: bool,
    /// When the process exited, in Unix epoch milliseconds. Zero while it
    /// runs, or when its stop event carried no time.
    pub(super) stop_ts: u64,
}

/// What the lifecycle map knows about a PID.
#[derive(Debug, Eq, PartialEq)]
pub(super) enum TrackedLookup {
    Found(TrackedIdentity),
    /// The entry is another process with this PID than the one asked about.
    /// It was dropped if it is the earlier of the two.
    Recycled,
    /// No entry, or a stopped one past its retention.
    Missing,
}

/// Process lifecycle evidence by PID, kept for a bounded time after exit.
pub(super) struct TrackedProcesses {
    state: Mutex<TrackedState>,
}

#[derive(Default)]
struct TrackedState {
    entries: HashMap<u32, TrackedProcess>,
    stops_since_sweep: i32,
}

impl TrackedProcesses {
    pub(super) fn new() -> Self {
        Self {
            state: Mutex::new(TrackedState::default()),
        }
    }

    /// Records a process start. Returns whether the PID's entry was replaced,
    /// which makes any identity cached for the PID stale.
    pub(super) fn started(
        &self,
        pid: u32,
        nt_or_dos_path: &str,
        image_file_name: &str,
        start_ts: u64,
    ) -> bool {
        if pid == 0 {
            return false;
        }
        // Convert before locking: on a device-map miss this queries every drive
        // letter, which no other lifecycle event should wait behind.
        let converted = nt_path_to_dos_path(nt_or_dos_path);
        let mut state = self.state.lock();

        let (mut stopped_at, mut stop_ts) = (None, 0);
        if let Some(existing) = state.entries.get(&pid) {
            // Evidence without a creation time cannot supersede a verified
            // generation, including its stopped state, on a reused PID.
            if existing.start_ts > 0 && (start_ts == 0 || existing.start_ts > start_ts) {
                return false;
            }
            if start_ts > 0
                && existing.start_ts == start_ts
                && !has_path_separators(nt_or_dos_path)
                && (has_path_separators(&existing.path) || existing.raw_nt.is_some())
            {
                return false;
            }
            if start_ts > 0
                && existing.start_ts == start_ts
                && !is_synthetic_path(&existing.path)
                && is_nt_device_path(nt_or_dos_path)
                && is_nt_device_path(&converted)
            {
                return false;
            }
            // The same generation keeps its stop state, and so does an unknown
            // one whose stop came after this process started. A stop that
            // arrived before any start is such an unknown one: a PID belongs
            // to one process at a time, so a process that had started by the
            // stop is the one that stopped.
            if start_ts > 0
                && (existing.start_ts == start_ts
                    || (existing.start_ts == 0
                        && existing.stop_ts > 0
                        && start_ts <= existing.stop_ts))
            {
                (stopped_at, stop_ts) = (existing.stopped_at, existing.stop_ts);
            }
        }

        let mut path = converted;
        if (path.is_empty() || !has_path_separators(&path)) && has_path_separators(image_file_name)
        {
            image_file_name.clone_into(&mut path);
        }

        let mut name = executable_name(&path);
        if name.is_empty() {
            image_file_name.clone_into(&mut name);
        }
        if name.is_empty() {
            return true;
        }
        name = normalize_process_name(&name);
        // An NT device path the map cannot convert yet must not be stored
        // verbatim: the DOS spelling arriving later would fork a second
        // application row for one file. Keep the name-keyed placeholder and
        // the raw NT string, and retry the conversion on every resolve.
        let mut raw_nt = None;
        if path.is_empty() {
            placeholder_path().clone_into(&mut path);
        } else if is_nt_device_path(&path) {
            raw_nt = Some(path.clone());
            placeholder_path().clone_into(&mut path);
        }

        state.entries.insert(
            pid,
            TrackedProcess {
                path,
                name,
                raw_nt,
                start_ts,
                stopped_at,
                stop_ts,
            },
        );

        if state.entries.len() >= PROCESS_SWEEP_WHEN_COUNT_EXCEEDS as usize {
            state.sweep();
        }
        true
    }

    #[cfg(test)]
    pub(super) fn stopped(&self, pid: u32) {
        let now = time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000;
        self.stopped_at(pid, u64::try_from(now).unwrap_or(0));
    }

    /// Records a process exit, which starts its retention period.
    ///
    /// The stop of a process never heard of is kept too, for as long as any
    /// other stop. Its start can still arrive, from a source that runs behind
    /// the one that reported the exit, and [`Self::started`] then joins the
    /// two. Until it does the entry names nobody and [`Self::resolve`] does
    /// not find it.
    pub(super) fn stopped_at(&self, pid: u32, stop_ts: u64) {
        if pid == 0 {
            return;
        }
        let mut state = self.state.lock();
        if let Some(entry) = state.entries.get_mut(&pid) {
            if entry.stopped_at.is_none() {
                entry.stopped_at = Some(Instant::now());
                entry.stop_ts = stop_ts;
            }
        } else if stop_ts > 0 {
            // Without its time a stop cannot be told from an earlier
            // process's, so only a timed one is worth keeping.
            state.entries.insert(
                pid,
                TrackedProcess {
                    path: String::new(),
                    name: String::new(),
                    raw_nt: None,
                    start_ts: 0,
                    stopped_at: Some(Instant::now()),
                    stop_ts,
                },
            );
        }

        state.stops_since_sweep += 1;
        if state.stops_since_sweep >= PROCESS_SWEEP_EVERY_N_STOPS {
            state.stops_since_sweep = 0;
            state.sweep();
        }
    }

    /// Looks a PID up. An entry is found while the process is alive or within
    /// its post-exit retention, and only when its creation time agrees with
    /// `expected_start_ts`.
    pub(super) fn resolve(&self, pid: u32, expected_start_ts: Option<u64>) -> TrackedLookup {
        let mut state = self.state.lock();
        let Some(entry) = state
            .entries
            .get_mut(&pid)
            .filter(|entry| !entry.name.is_empty())
        else {
            return TrackedLookup::Missing;
        };
        if !start_ts_compatible(entry.start_ts, expected_start_ts) {
            // The entry and the question are about two processes with this PID.
            // An entry older than the process asked about is out of date: a
            // lifecycle event was lost, and it must not attribute the new
            // process, so it goes. An entry newer than the process asked about
            // is the PID's current one. The question is the late one, from a
            // delayed flow of the previous process, and takes nothing with it.
            if expected_start_ts.is_some_and(|expected| expected > entry.start_ts) {
                state.entries.remove(&pid);
            }
            return TrackedLookup::Recycled;
        }

        // A previously unconvertible device path may map now (the device map
        // refreshes independently of lifecycle events). Heal in place so the
        // next sighting reports the real path instead of forking an identity.
        if let Some(raw) = &entry.raw_nt {
            let converted = nt_path_to_dos_path(raw);
            if !is_nt_device_path(&converted) {
                entry.path = converted;
                entry.raw_nt = None;
            }
        }

        let retention = Duration::from_millis(PROCESS_STOP_RETENTION_MS);
        if entry
            .stopped_at
            .is_some_and(|stopped_at| stopped_at.elapsed() > retention)
        {
            return TrackedLookup::Missing;
        }
        TrackedLookup::Found(TrackedIdentity {
            identity: ResolvedIdentity {
                path: entry.path.clone(),
                name: entry.name.clone(),
                start_ts: entry.start_ts,
            },
            stopped: entry.stopped_at.is_some(),
            stop_ts: entry.stop_ts,
        })
    }
}

impl TrackedState {
    fn sweep(&mut self) {
        let retention = Duration::from_millis(PROCESS_STOP_RETENTION_MS);
        self.entries.retain(|_, entry| {
            entry
                .stopped_at
                .is_none_or(|stopped_at| stopped_at.elapsed() <= retention)
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    impl TrackedProcesses {
        fn identity(&self, pid: u32, expected_start_ts: Option<u64>) -> Option<ResolvedIdentity> {
            match self.resolve(pid, expected_start_ts) {
                TrackedLookup::Found(tracked) => Some(tracked.identity),
                TrackedLookup::Recycled | TrackedLookup::Missing => None,
            }
        }

        fn stopped_instant(&self, pid: u32) -> Option<Instant> {
            self.state
                .lock()
                .entries
                .get(&pid)
                .expect("entry")
                .stopped_at
        }

        fn raw_nt(&self, pid: u32) -> Option<String> {
            self.state
                .lock()
                .entries
                .get(&pid)
                .expect("entry")
                .raw_nt
                .clone()
        }
    }

    #[test]
    fn same_instance_basename_keeps_captured_path_and_stop_state() {
        let tracked = TrackedProcesses::new();
        tracked.started(910_002, r"C:\apps\quick.exe", "quick.exe", 10_000);
        tracked.stopped(910_002);
        tracked.started(910_002, "quick.exe", "quick.exe", 10_000);
        let identity = tracked.identity(910_002, Some(10_000)).expect("identity");
        assert_eq!(identity.path, r"C:\apps\quick.exe");
        assert!(tracked.stopped_instant(910_002).is_some());
    }

    #[test]
    fn retains_stopped_pid_within_grace_window() {
        let tracked = TrackedProcesses::new();
        tracked.started(42_001, r"C:\Apps\tool.exe", "tool.exe", 1_000);
        tracked.stopped(42_001);
        let identity = tracked.identity(42_001, None).expect("tracked");
        assert_eq!(identity.path, r"C:\Apps\tool.exe");
        assert_eq!(identity.name, "tool.exe");
        assert_eq!(identity.start_ts, 1_000);
    }

    #[test]
    fn zero_timestamp_event_cannot_erase_verified_generation_or_stop_state() {
        let tracked = TrackedProcesses::new();
        tracked.started(910_003, r"C:\apps\quick.exe", "quick.exe", 10_000);
        tracked.stopped(910_003);
        assert!(!tracked.started(910_003, "quick.exe", "quick.exe", 0));
        let identity = tracked.identity(910_003, Some(10_000)).expect("identity");
        assert_eq!(identity.path, r"C:\apps\quick.exe");
        assert_eq!(identity.start_ts, 10_000);
        assert!(tracked.stopped_instant(910_003).is_some());
    }

    #[test]
    fn delayed_known_start_does_not_revive_a_stopped_unknown_generation() {
        let tracked = TrackedProcesses::new();
        tracked.started(917_001, "quick.exe", "quick.exe", 0);
        tracked.stopped(917_001);
        let stopped_at = tracked.stopped_instant(917_001);
        tracked.started(917_001, r"C:\apps\quick.exe", "quick.exe", 20);
        assert_eq!(
            tracked.identity(917_001, Some(20)).expect("in grace").path,
            r"C:\apps\quick.exe"
        );
        assert_eq!(tracked.stopped_instant(917_001), stopped_at);
    }

    #[test]
    fn a_stop_before_its_start_names_nobody_until_the_start_joins_it() {
        let tracked = TrackedProcesses::new();
        tracked.stopped_at(917_002, 12_000);
        assert_eq!(tracked.resolve(917_002, None), TrackedLookup::Missing);
        let stopped_at = tracked.stopped_instant(917_002);
        assert!(stopped_at.is_some(), "the stop is kept");

        tracked.started(917_002, r"C:\apps\quick.exe", "quick.exe", 10_000);
        let TrackedLookup::Found(found) = tracked.resolve(917_002, Some(10_000)) else {
            panic!("the start names the process");
        };
        assert_eq!(found.identity.path, r"C:\apps\quick.exe");
        assert!(found.stopped);
        assert_eq!(found.stop_ts, 12_000);
        assert_eq!(
            tracked.stopped_instant(917_002),
            stopped_at,
            "retention runs from the stop"
        );
    }

    #[test]
    fn an_early_stop_is_not_joined_to_a_later_or_undated_process() {
        for start_ts in [12_001, 0] {
            let tracked = TrackedProcesses::new();
            tracked.stopped_at(917_003, 12_000);
            tracked.started(917_003, r"C:\apps\quick.exe", "quick.exe", start_ts);
            assert_eq!(
                tracked.stopped_instant(917_003),
                None,
                "a process created at {start_ts} is not known to have stopped"
            );
        }
        // A stop that carries no time cannot be placed, so it is not kept.
        let tracked = TrackedProcesses::new();
        tracked.stopped_at(917_003, 0);
        tracked.started(917_003, r"C:\apps\quick.exe", "quick.exe", 10_000);
        assert_eq!(tracked.stopped_instant(917_003), None);
    }

    #[test]
    fn basename_preserves_unmapped_nt_evidence_and_dos_path_keeps_quality() {
        let tracked = TrackedProcesses::new();
        let raw = r"\Device\AntiwireBogusVolume\dir\quick.exe";
        tracked.started(910_004, raw, "quick.exe", 10_000);
        tracked.started(910_004, "quick.exe", "quick.exe", 10_000);
        assert_eq!(tracked.raw_nt(910_004).as_deref(), Some(raw));
        tracked.started(910_004, r"C:\apps\quick.exe", "quick.exe", 10_000);
        tracked.started(910_004, raw, "quick.exe", 10_000);
        assert_eq!(
            tracked
                .identity(910_004, Some(10_000))
                .expect("identity")
                .path,
            r"C:\apps\quick.exe"
        );
    }

    #[test]
    fn start_replaces_reused_pid() {
        let tracked = TrackedProcesses::new();
        tracked.started(42_002, r"C:\Apps\first.exe", "first.exe", 1_000);
        tracked.stopped(42_002);
        assert!(tracked.started(42_002, r"C:\Apps\second.exe", "second.exe", 2_000));
        let identity = tracked.identity(42_002, None).expect("tracked");
        assert_eq!(identity.path, r"C:\Apps\second.exe");
        assert_eq!(identity.name, "second.exe");
    }

    #[test]
    fn mismatched_start_ts_rejects_a_recycled_pid() {
        let tracked = TrackedProcesses::new();
        tracked.started(42_005, r"C:\Apps\old.exe", "old.exe", 1_000);

        // A flow claiming a newer creation time proves the PID was recycled.
        assert_eq!(
            tracked.resolve(42_005, Some(9_000)),
            TrackedLookup::Recycled
        );
        // The stale entry is dropped rather than left to attribute the next flow.
        assert_eq!(tracked.resolve(42_005, None), TrackedLookup::Missing);
    }

    /// The regression this guards: any mismatch dropped the entry, so a lookup
    /// for the PID's previous process erased the one that has it now.
    #[test]
    fn a_lookup_for_an_earlier_process_keeps_the_current_one() {
        let tracked = TrackedProcesses::new();
        tracked.started(42_008, r"C:\Apps\current.exe", "current.exe", 9_000);

        assert_eq!(
            tracked.resolve(42_008, Some(1_000)),
            TrackedLookup::Recycled
        );
        let identity = tracked.identity(42_008, Some(9_000)).expect("kept");
        assert_eq!(identity.path, r"C:\Apps\current.exe");
    }

    #[test]
    fn unknown_start_ts_on_either_side_stays_trusted() {
        let tracked = TrackedProcesses::new();
        tracked.started(42_006, r"C:\Apps\tool.exe", "tool.exe", 1_000);
        assert!(tracked.identity(42_006, Some(1_000)).is_some());
        assert!(tracked.identity(42_006, None).is_some());

        let unknown = TrackedProcesses::new();
        unknown.started(42_007, r"C:\Apps\tool.exe", "tool.exe", 0);
        assert!(unknown.identity(42_007, Some(5_000)).is_some());
    }

    #[test]
    fn bare_image_name_is_stored_without_path_separators() {
        let tracked = TrackedProcesses::new();
        tracked.started(42_003, "brave.exe", "brave.exe", 0);
        let identity = tracked.identity(42_003, None).expect("tracked");
        assert_eq!(identity.path, "brave.exe");
        assert_eq!(identity.name, "brave.exe");
        assert!(!has_path_separators(&identity.path));
    }

    #[test]
    fn unmapped_nt_path_stays_name_keyed_instead_of_forking() {
        let tracked = TrackedProcesses::new();
        // `\Device\...` that the drive map cannot convert must never be
        // stored verbatim: the DOS spelling arriving later would fork a
        // second application row for one file.
        tracked.started(
            42_008,
            r"\Device\AntiwireBogusVolume\dir\tool.exe",
            "tool.exe",
            1_000,
        );
        let identity = tracked.identity(42_008, None).expect("tracked");
        assert_eq!(identity.path, placeholder_path());
        assert_eq!(identity.name, "tool.exe");
        assert_eq!(identity.start_ts, 1_000);
    }

    #[test]
    fn full_path_is_tracked() {
        let tracked = TrackedProcesses::new();
        tracked.started(42_004, r"C:\Apps\tool.exe", "tool.exe", 0);
        let identity = tracked.identity(42_004, None).expect("tracked");
        assert_eq!(identity.path, r"C:\Apps\tool.exe");
        assert_eq!(identity.name, "tool.exe");
    }
}
