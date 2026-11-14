//! Resolves a PID and optional netmet metadata into an executable path and process name.

mod cache;
mod path;
mod stats;
mod tracked;

#[cfg(not(windows))]
mod stub;

#[cfg(windows)]
mod hosted;

#[cfg(windows)]
mod windows;

use moka::sync::Cache;

use crate::sanitize;
use path::{
    executable_name, has_path_separators, is_basename_only, is_nt_device_path,
    is_trusted_process_path, normalize_process_name, nt_path_to_dos_path, placeholder_path,
};
use stats::{ResolutionCounters, ResolutionFailure};
use tracked::{TrackedIdentity, TrackedLookup, TrackedProcesses};

#[cfg(any(windows, test))]
pub(crate) use path::is_system_host_binary;
pub(crate) use path::name_without_stray_suffix;
pub use path::{is_recoverable_placeholder, is_synthetic_path, is_unknown_placeholder};
pub(crate) use stats::ResolutionStats;

/// A PID's resolved executable identity.
///
/// `start_ts` (Unix epoch milliseconds, zero when unknown) is what makes PID
/// reuse detectable: a lifecycle event that was lost can no longer let a
/// recycled PID inherit the previous process's cached identity when the later
/// flow metadata carries the new process's creation time.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResolvedIdentity {
    pub path: String,
    pub name: String,
    pub start_ts: u64,
}

/// Creation timestamps compared across sources are allowed one second of skew:
/// `sysinfo` reports whole seconds while ETW reports milliseconds.
const START_TS_TOLERANCE_MS: u64 = 1_000;

/// Display name of every unknown identity: no owner, exited, or access denied.
pub(crate) use antiwire_policy::UNKNOWN_APP_NAME;

/// Returns true when a stored creation timestamp can describe the process the
/// caller is asking about.
///
/// Zero on either side means unknown and is never treated as a mismatch, so a
/// backend that cannot report a creation time is no worse off than before.
/// This is a compatibility predicate for stored lifecycle evidence; the
/// resolver still performs a live lookup before trusting an active identity
/// when the flow carries no creation time.
pub(crate) fn start_ts_compatible(stored: u64, expected: Option<u64>) -> bool {
    match expected {
        Some(expected) => {
            stored == 0 || expected == 0 || stored.abs_diff(expected) < START_TS_TOLERANCE_MS
        }
        None => true,
    }
}

/// Returns true when a process created at `start_ts` started after `at`, both
/// Unix milliseconds, allowing the skew [`start_ts_compatible`] allows. Such a
/// process is a later holder of a reused PID, not the one that was running at
/// `at`. Zero on either side means unknown and never counts as later.
pub(crate) fn started_after(start_ts: u64, at: u64) -> bool {
    start_ts != 0 && at != 0 && start_ts > at.saturating_add(START_TS_TOLERANCE_MS)
}

/// Everything one resolver knows about processes: lifecycle evidence from
/// ETW, the short-lived cache of live lookups, the labels given to service
/// and DLL hosts, and counters for how resolutions ended.
///
/// Each value is independent. Two resolvers never share evidence, so a test
/// can own one without serialising against every other test.
pub(crate) struct ProcessIdentities {
    tracked: TrackedProcesses,
    /// Identities with a real path, by PID, from any source. Only valid while
    /// the PID's creation timestamp matches.
    cache: Cache<u32, ResolvedIdentity>,
    #[cfg(windows)]
    hosted: hosted::HostedIdentities,
    stats: ResolutionCounters,
}

impl Default for ProcessIdentities {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcessIdentities {
    pub(crate) fn new() -> Self {
        Self {
            tracked: TrackedProcesses::new(),
            cache: cache::identity_cache(),
            #[cfg(windows)]
            hosted: hosted::HostedIdentities::new(),
            stats: ResolutionCounters::default(),
        }
    }

    /// Records a process start from kernel ETW or netmetrics.
    pub(crate) fn process_started(&self, pid: u32, executable: &str, name: &str, start_ts: u64) {
        if self.tracked.started(pid, executable, name, start_ts) {
            self.forget(pid);
        }
    }

    /// Records a process exit from kernel ETW or netmetrics.
    pub(crate) fn process_stopped_at(&self, pid: u32, stop_ts: u64) {
        self.tracked.stopped_at(pid, stop_ts);
        if pid != 0 {
            self.forget(pid);
        }
    }

    #[cfg(test)]
    pub(crate) fn process_stopped(&self, pid: u32) {
        self.tracked.stopped(pid);
        if pid != 0 {
            self.forget(pid);
        }
    }

    /// Seeds lifecycle evidence from processes already running at daemon start
    /// (parity with ETW `ProcessDCStart` rundown).
    ///
    /// This warms the lifecycle map only; the live lookup cache fills lazily on
    /// each PID's first resolution.
    pub(crate) fn bootstrap_running_processes(&self) -> BootstrapStats {
        let seed = |pid: u32, identity: &ResolvedIdentity| {
            self.process_started(pid, &identity.path, &identity.name, identity.start_ts);
        };
        #[cfg(windows)]
        let stats = windows::running_processes(seed);
        #[cfg(not(windows))]
        let stats = stub::running_processes(seed);
        stats
    }

    /// The executable `pid` was running at `at_ms`, in Unix epoch
    /// milliseconds, or `None` when that cannot be established.
    ///
    /// [`Self::resolve`] answers for a connection as it is observed. This
    /// answers for a moment in the past, which is what evidence that arrives
    /// late needs: a DNS hint, or the lifecycle events of a process that had
    /// exited before its connection was looked at.
    ///
    /// Two processes can be vouched for. One that is running now and had
    /// started by then, because a PID belongs to one process at a time. And
    /// one that has since exited, when its start and stop events bracket the
    /// moment. A process last known running that can no longer be found is
    /// not: it may have exited before `at_ms` and another taken its PID, and
    /// its stop event, when it arrives, will say.
    ///
    /// This counts nothing towards [`Self::resolution_stats`], which describe
    /// attributing connections, and discards no cached identity.
    pub(crate) fn identity_at(&self, pid: u32, at_ms: u64) -> Option<ResolvedIdentity> {
        if pid <= 4 || at_ms == 0 {
            return None;
        }
        let started_by_then = |start_ts: u64| start_ts != 0 && !started_after(start_ts, at_ms);
        #[cfg(windows)]
        let live = windows::live_lookup(pid);
        #[cfg(not(windows))]
        let live = stub::live_lookup(pid);
        if let Ok(mut identity) = live {
            if started_by_then(identity.start_ts) {
                if identity.name.is_empty() {
                    identity.name = normalize_process_name(&executable_name(&identity.path));
                }
                return Some(self.finalize(pid, identity));
            }
        }
        let TrackedLookup::Found(tracked) = self.tracked.resolve(pid, None) else {
            return None;
        };
        let identity = tracked.identity;
        let bracketed = tracked.stopped
            && tracked.stop_ts != 0
            && tracked.stop_ts.saturating_add(START_TS_TOLERANCE_MS) >= at_ms
            && started_by_then(identity.start_ts)
            && has_path_separators(&identity.path)
            && !is_synthetic_path(&identity.path);
        bracketed.then(|| ResolvedIdentity {
            path: sanitize::trimmed(&identity.path, sanitize::MAX_PATH_CHARS),
            name: sanitize::trimmed(&identity.name, sanitize::MAX_NAME_CHARS),
            start_ts: identity.start_ts,
        })
    }

    /// Cumulative counters for how resolutions ended.
    pub(crate) fn resolution_stats(&self) -> ResolutionStats {
        self.stats.snapshot()
    }

    /// Resolves a process into an executable identity, using netmet metadata
    /// when trustworthy and falling back to lifecycle evidence or a cached live
    /// lookup when needed.
    ///
    /// `meta_start_ts` is `FlowMeta.process.start_ts` when the event carried one.
    /// It is validated against any cached or tracked identity so a recycled PID
    /// cannot inherit the previous process's identity after a lost lifecycle
    /// event.
    ///
    /// A successful live lookup is validated the same way: without that check a
    /// flow for a dead instance would adopt the recycled PID's new occupant.
    /// Socket and packet observation times are never acceptable substitutes for
    /// a process creation timestamp — an unknown creation time stays unknown
    /// (zero) and is never treated as a mismatch.
    pub(crate) fn resolve(
        &self,
        pid: u32,
        meta_path: Option<&str>,
        meta_name: Option<&str>,
        meta_start_ts: Option<u64>,
    ) -> ResolvedIdentity {
        self.stats.record_attempt();
        let expected_start_ts = meta_start_ts.filter(|timestamp| *timestamp > 0);

        if let Some(path) = meta_path.filter(|value| !value.is_empty()) {
            if is_basename_only(path) {
                // The backend supplied a name without a location. Attribution may
                // still succeed below; record that the image source came up short.
                self.stats
                    .record_failure(ResolutionFailure::BasenameOnlyImage);
            } else if is_trusted_process_path(path) {
                let dos_path = nt_path_to_dos_path(path);
                if is_nt_device_path(&dos_path) {
                    // The drive map does not know this volume (yet). A verbatim
                    // NT string would fork a second application row for one file
                    // the moment the DOS spelling arrives, so fall through to the
                    // tracked/live sources and retry the conversion there.
                    self.stats
                        .record_failure(ResolutionFailure::PathConversionFailed);
                } else {
                    let name = meta_name.filter(|value| !value.is_empty()).map_or_else(
                        || normalize_process_name(&executable_name(&dos_path)),
                        normalize_process_name,
                    );
                    let identity = self.finalize(
                        pid,
                        ResolvedIdentity {
                            path: dos_path,
                            name,
                            start_ts: expected_start_ts.unwrap_or(0),
                        },
                    );
                    self.stats.record_authoritative_hit();
                    return identity;
                }
            }
        }

        if pid == 0 {
            self.stats.record_unknown_result();
            return ResolvedIdentity {
                path: String::new(),
                name: String::new(),
                start_ts: 0,
            };
        }
        if pid == 4 {
            // The kernel itself: a genuine identity, not a resolution failure.
            return ResolvedIdentity {
                path: "System".to_owned(),
                name: "system".to_owned(),
                start_ts: 0,
            };
        }

        let (cached, cache_requires_fresh) = self.cached_identity(pid, expected_start_ts);
        if let Some(cached) = cached {
            self.stats.record_authoritative_hit();
            return cached;
        }

        let (tracked_identity, tracked_for_fallback) =
            self.tracked_identity(pid, expected_start_ts, cache_requires_fresh);
        if let Some(identity) = tracked_identity {
            self.stats.record_authoritative_hit();
            return identity;
        }

        // An active entry has no proof that the PID still belongs to the same
        // process when the flow carries no creation timestamp. It may still
        // provide the best process name if the live lookup fails, but
        // `tracked_fallback` strips its path. A stopped entry may retain its
        // real path during the bounded post-exit grace period.
        #[cfg(windows)]
        let live_result = windows::live_lookup(pid);
        #[cfg(not(windows))]
        let live_result = stub::live_lookup(pid);

        let mut identity = match live_result {
            Ok(identity) => {
                if !live_identity_matches_expected(&identity, expected_start_ts) {
                    // The PID was recycled between the flow's observation and this
                    // lookup: the live process is a different instance, so its
                    // identity must not attribute the flow.
                    self.stats
                        .record_failure(ResolutionFailure::StartTsMismatch);
                    self.forget(pid);
                    if let Some(tracked) = tracked_for_fallback.filter(|tracked| tracked.stopped) {
                        return self.tracked_fallback(pid, tracked);
                    }
                    self.stats.record_unknown_result();
                    return exited_unknown();
                }
                identity
            }
            Err(err) => {
                return self.failed_lookup(
                    pid,
                    meta_path,
                    meta_name,
                    expected_start_ts,
                    tracked_for_fallback,
                    err,
                );
            }
        };

        if identity.name.is_empty() {
            identity.name = normalize_process_name(&executable_name(&identity.path));
        }

        let identity = self.finalize(pid, identity);
        self.stats.record_authoritative_hit();
        identity
    }

    /// Returns a cache hit only when a known flow creation time can validate a
    /// known cached creation time. Any other cache entry is invalidated before
    /// the caller performs a fresh live lookup.
    fn cached_identity(
        &self,
        pid: u32,
        expected_start_ts: Option<u64>,
    ) -> (Option<ResolvedIdentity>, bool) {
        let Some(cached) = self.cache.get(&pid) else {
            return (None, false);
        };
        let requires_fresh = expected_start_ts.is_none() || cached.start_ts == 0;
        if !requires_fresh {
            if let Some(cached) = self.trusted_cache_hit(pid, cached, expected_start_ts) {
                return (Some(cached), false);
            }
        }
        self.cache.invalidate(&pid);
        (None, requires_fresh)
    }

    fn trusted_cache_hit(
        &self,
        pid: u32,
        cached: ResolvedIdentity,
        expected_start_ts: Option<u64>,
    ) -> Option<ResolvedIdentity> {
        if !start_ts_compatible(cached.start_ts, expected_start_ts) {
            self.stats
                .record_failure(ResolutionFailure::StartTsMismatch);
            self.cache.invalidate(&pid);
            return None;
        }
        // Synthetic results are never cached (see `finalize`), but an entry
        // written before that policy must not serve a placeholder as authoritative.
        if is_synthetic_path(&cached.path) {
            self.cache.invalidate(&pid);
            return None;
        }
        has_path_separators(&cached.path).then_some(cached)
    }

    /// Resolves lifecycle evidence before the live lookup. Known active evidence
    /// can serve a matching known generation; otherwise it remains only a guarded
    /// fallback, preserving stopped-process grace without trusting an active path.
    fn tracked_identity(
        &self,
        pid: u32,
        expected_start_ts: Option<u64>,
        cache_requires_fresh: bool,
    ) -> (Option<ResolvedIdentity>, Option<TrackedIdentity>) {
        let tracked = match self.tracked.resolve(pid, expected_start_ts) {
            TrackedLookup::Found(tracked) => tracked,
            lookup => {
                if lookup == TrackedLookup::Recycled {
                    self.stats
                        .record_failure(ResolutionFailure::StartTsMismatch);
                }
                self.stats
                    .record_failure(ResolutionFailure::MissingLifecycleEvent);
                return (None, None);
            }
        };
        let can_use_without_live = expected_start_ts.is_some() && !cache_requires_fresh;
        let identity = (can_use_without_live
            && tracked.identity.start_ts > 0
            && has_path_separators(&tracked.identity.path)
            && !is_synthetic_path(&tracked.identity.path))
        .then(|| self.finalize(pid, tracked.identity.clone()));
        let fallback =
            (expected_start_ts.is_none() || tracked.identity.start_ts > 0).then_some(tracked);
        (identity, fallback)
    }

    fn tracked_fallback(&self, pid: u32, tracked: TrackedIdentity) -> ResolvedIdentity {
        let preserve_path = tracked.stopped
            && has_path_separators(&tracked.identity.path)
            && !is_synthetic_path(&tracked.identity.path);
        let path = if preserve_path {
            tracked.identity.path.clone()
        } else {
            placeholder_path().to_owned()
        };
        let identity = self.finalize(
            pid,
            ResolvedIdentity {
                path,
                ..tracked.identity
            },
        );
        if preserve_path {
            self.stats.record_authoritative_hit();
        } else {
            self.stats.record_placeholder_fallback();
        }
        identity
    }

    /// Retains the best observed name when the live process query fails.
    fn failed_lookup(
        &self,
        pid: u32,
        meta_path: Option<&str>,
        meta_name: Option<&str>,
        expected_start_ts: Option<u64>,
        tracked: Option<TrackedIdentity>,
        err: ProcessLookupError,
    ) -> ResolvedIdentity {
        self.stats.record_failure(match err {
            ProcessLookupError::AccessDenied => ResolutionFailure::AccessDenied,
            ProcessLookupError::NotFound => ResolutionFailure::ExitedProcess,
        });
        if let Some(tracked) = tracked {
            return self.tracked_fallback(pid, tracked);
        }
        if let Some((path, name)) = fallback_from_basename(meta_path, meta_name)
            .or_else(|| fallback_from_unmapped_nt(meta_path, meta_name))
        {
            let identity = self.finalize(
                pid,
                ResolvedIdentity {
                    path,
                    name,
                    start_ts: expected_start_ts.unwrap_or(0),
                },
            );
            self.stats.record_placeholder_fallback();
            return identity;
        }
        self.stats.record_unknown_result();
        match err {
            ProcessLookupError::AccessDenied => access_denied_unknown(),
            ProcessLookupError::NotFound => exited_unknown(),
        }
    }

    /// Sanitizes, disambiguates, and caches a resolved identity.
    fn finalize(&self, pid: u32, identity: ResolvedIdentity) -> ResolvedIdentity {
        let ResolvedIdentity {
            path,
            name,
            start_ts,
        } = identity;
        let identity = ResolvedIdentity {
            path: sanitize::trimmed(&path, sanitize::MAX_PATH_CHARS),
            name: sanitize::trimmed(&name, sanitize::MAX_NAME_CHARS),
            start_ts,
        };
        #[cfg(windows)]
        let identity = self.hosted.disambiguate(pid, identity);
        // Only real paths are cached. A cached placeholder would keep serving the
        // fallback after the path becomes resolvable, permanently hiding the
        // recovery the retry machinery exists to perform.
        if pid > 4 && !identity.path.is_empty() && !is_synthetic_path(&identity.path) {
            self.cache.insert(pid, identity.clone());
        }
        identity
    }

    /// Drops every cached identity for a PID that stopped or was reused.
    fn forget(&self, pid: u32) {
        self.cache.invalidate(&pid);
        #[cfg(windows)]
        self.hosted.forget(pid);
    }

    /// Seeds the identity cache with a fully-formed identity.
    ///
    /// Production fills this cache through `finalize` after host
    /// disambiguation; tests use this to pin the orchestration that consumes a
    /// verified identity without depending on a live service host.
    #[cfg(test)]
    pub(crate) fn seed_cache(&self, pid: u32, path: &str, name: &str, start_ts: u64) {
        self.cache.insert(
            pid,
            ResolvedIdentity {
                path: path.to_owned(),
                name: name.to_owned(),
                start_ts,
            },
        );
    }
}

/// A live lookup with a known expected creation time must also report a known
/// creation time. Treating a zero live timestamp as compatible would let a
/// failed timestamp query silently adopt a recycled PID's current image.
fn live_identity_matches_expected(
    identity: &ResolvedIdentity,
    expected_start_ts: Option<u64>,
) -> bool {
    match expected_start_ts {
        Some(expected) => {
            identity.start_ts > 0 && start_ts_compatible(identity.start_ts, Some(expected))
        }
        None => true,
    }
}

fn fallback_from_basename(
    meta_path: Option<&str>,
    meta_name: Option<&str>,
) -> Option<(String, String)> {
    let basename = meta_path.filter(|value| is_basename_only(value))?;
    let name = meta_name
        .filter(|value| !value.is_empty())
        .map_or_else(|| normalize_process_name(basename), normalize_process_name);
    if name.is_empty() {
        return None;
    }
    Some((placeholder_path().to_owned(), name))
}

/// Name-keyed fallback for an NT device path the drive map cannot convert.
///
/// The file is real but its DOS spelling is unknown right now; reporting the
/// verbatim NT string would fork a second application identity the moment the
/// DOS spelling arrives. The placeholder joins the application's existing row
/// by name instead, and the conversion is retried while the process is alive.
fn fallback_from_unmapped_nt(
    meta_path: Option<&str>,
    meta_name: Option<&str>,
) -> Option<(String, String)> {
    let nt_path = meta_path.filter(|value| is_nt_device_path(value))?;
    let name = meta_name.filter(|value| !value.is_empty()).map_or_else(
        || normalize_process_name(&executable_name(nt_path)),
        normalize_process_name,
    );
    if name.is_empty() {
        return None;
    }
    Some((placeholder_path().to_owned(), name))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessLookupError {
    NotFound,
    /// Only the Windows resolver can be refused access to a live process.
    #[cfg_attr(not(windows), allow(dead_code))]
    AccessDenied,
}

fn access_denied_unknown() -> ResolvedIdentity {
    ResolvedIdentity {
        path: "Unknown (Access Denied)".to_owned(),
        name: UNKNOWN_APP_NAME.to_owned(),
        start_ts: 0,
    }
}

fn exited_unknown() -> ResolvedIdentity {
    ResolvedIdentity {
        path: "Unknown (Exited)".to_owned(),
        name: UNKNOWN_APP_NAME.to_owned(),
        start_ts: 0,
    }
}

/// Outcome of seeding lifecycle evidence from already-running processes.
///
/// Logged at startup: `seeded < enumerated` is expected (protected and
/// exited processes cannot seed), but `seeded == 0` with a large `enumerated`
/// means rundown capture is broken and every early flow will resolve cold.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BootstrapStats {
    /// Processes enumerated by the snapshot.
    pub enumerated: usize,
    /// Processes that produced a usable tracked identity.
    pub seeded: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    const CURL_PATH: &str = if cfg!(windows) {
        r"C:\Windows\System32\curl.exe"
    } else {
        "/usr/bin/curl"
    };

    /// A process that has exited is vouched for only between its start and
    /// its stop: before the stop event arrives, nothing says it was still
    /// running at the moment asked about.
    #[test]
    fn a_past_moment_is_answered_by_a_process_whose_start_and_stop_bracket_it() {
        let processes = ProcessIdentities::new();
        let pid = 918_001;
        processes.process_started(pid, CURL_PATH, "curl.exe", 10_000);
        assert_eq!(
            processes.identity_at(pid, 11_000),
            None,
            "last seen running and now gone: it may have exited before then"
        );

        processes.process_stopped_at(pid, 12_000);
        let identity = processes.identity_at(pid, 11_000).expect("bracketed");
        assert_eq!(
            (identity.path.as_str(), identity.start_ts),
            (CURL_PATH, 10_000)
        );
        assert!(
            processes.identity_at(pid, 12_500).is_some(),
            "within the clock skew allowed after its stop"
        );
        assert_eq!(processes.identity_at(pid, 14_000), None, "after it exited");
        assert_eq!(processes.identity_at(pid, 8_000), None, "before it started");
        assert_eq!(
            processes.identity_at(pid, 0),
            None,
            "no moment to answer for"
        );
        assert_eq!(
            processes.identity_at(918_002, 11_000),
            None,
            "never heard of"
        );
        assert_eq!(
            processes.resolution_stats().attempts,
            0,
            "these are not connection attributions"
        );
    }

    #[test]
    fn a_past_moment_is_answered_by_a_running_process_that_had_started_by_then() {
        let processes = ProcessIdentities::new();
        let pid = std::process::id();
        let now_ms =
            u64::try_from(time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000)
                .expect("after the epoch");
        let identity = processes.identity_at(pid, now_ms).expect("this process");
        assert!(has_path_separators(&identity.path));
        assert!(identity.start_ts > 0 && identity.start_ts <= now_ms);
        assert_eq!(
            processes.identity_at(pid, identity.start_ts - 60_000),
            None,
            "it had not started then, so another process had the PID if any did"
        );
    }

    #[test]
    fn started_after_allows_the_creation_time_skew() {
        assert!(started_after(2_001, 1_000));
        assert!(!started_after(2_000, 1_000));
        assert!(!started_after(500, 1_000));
        assert!(!started_after(0, 1_000), "unknown creation time");
        assert!(!started_after(2_001, 0), "unknown open time");
    }

    fn live_lookup(pid: u32) -> Result<ResolvedIdentity, ProcessLookupError> {
        #[cfg(windows)]
        let live = windows::live_lookup(pid);
        #[cfg(not(windows))]
        let live = stub::live_lookup(pid);
        live
    }

    /// Resolves through `identities` and keeps only the path and name.
    fn resolve(
        identities: &ProcessIdentities,
        pid: u32,
        meta_path: Option<&str>,
        meta_name: Option<&str>,
        meta_start_ts: Option<u64>,
    ) -> (String, String) {
        let identity = identities.resolve(pid, meta_path, meta_name, meta_start_ts);
        (identity.path, identity.name)
    }

    #[test]
    fn tracked_placeholder_allows_live_path_recovery() {
        let identities = ProcessIdentities::new();
        let pid = std::process::id();
        let live = live_lookup(pid).expect("own process");
        identities.process_started(
            pid,
            r"\Device\AntiwireBogusVolume\tool.exe",
            "tool.exe",
            live.start_ts,
        );
        let (path, _) = resolve(&identities, pid, None, None, Some(live.start_ts));
        assert_eq!(path, live.path);
    }

    #[test]
    fn unknown_creation_time_full_path_resolves_after_exit() {
        let identities = ProcessIdentities::new();
        let pid = 4_000_042;
        identities.process_started(pid, r"C:\Apps\retained.exe", "retained.exe", 0);
        identities.process_stopped(pid);
        let (path, name) = resolve(&identities, pid, None, None, None);
        assert_eq!(path, r"C:\Apps\retained.exe");
        assert_eq!(name, "retained.exe");
        let (path, name) = resolve(&identities, pid, None, None, Some(0));
        assert_eq!(path, r"C:\Apps\retained.exe");
        assert_eq!(name, "retained.exe");
    }

    #[test]
    fn sentinel_pid_zero_returns_empty() {
        let (path, name) = resolve(&ProcessIdentities::new(), 0, None, None, None);
        assert_eq!(path, "");
        assert_eq!(name, "");
    }

    #[test]
    fn sentinel_pid_four_returns_system() {
        let (path, name) = resolve(&ProcessIdentities::new(), 4, None, None, None);
        assert_eq!(path, "System");
        assert_eq!(name, "system");
    }

    #[test]
    fn prefers_full_flow_meta_path() {
        let (path, name) = resolve(
            &ProcessIdentities::new(),
            0,
            Some(CURL_PATH),
            Some("curl.exe"),
            None,
        );
        assert_eq!(path, CURL_PATH);
        assert_eq!(name, "curl.exe");
    }

    #[test]
    fn untrusted_meta_path_is_ignored() {
        let identities = ProcessIdentities::new();
        // Relative names and control characters are not executable identities.
        let (path, name) = resolve(
            &identities,
            0,
            Some("..\\forged.exe"),
            Some("forged.exe"),
            None,
        );
        assert_eq!(path, "");
        assert_eq!(name, "");

        let (path, name) = resolve(
            &identities,
            0,
            Some("C:\\forged\n.exe"),
            Some("forged.exe"),
            None,
        );
        assert_eq!(path, "");
        assert_eq!(name, "");
    }

    #[test]
    fn meta_name_is_sanitized_before_it_is_reported() {
        let (path, name) = resolve(
            &ProcessIdentities::new(),
            0,
            Some(CURL_PATH),
            Some("curl.exe\nINFO forged"),
            None,
        );
        assert_eq!(path, CURL_PATH);
        assert!(!name.contains('\n'));
        assert!(name.starts_with("curl.exe"));
    }

    #[test]
    fn basename_metadata_does_not_short_circuit_live_lookup() {
        let (path, name) = resolve(
            &ProcessIdentities::new(),
            0,
            Some("svchost.exe"),
            Some("svchost.exe"),
            None,
        );
        assert_eq!(path, "");
        assert_eq!(name, "");
    }

    #[test]
    fn stale_bare_name_cache_entry_is_not_trusted() {
        let pid = 42_101;
        let cache = cache::build_cache(4, Duration::from_secs(60));
        cache.insert(
            pid,
            ResolvedIdentity {
                path: "brave.exe".to_owned(),
                name: "brave.exe".to_owned(),
                start_ts: 0,
            },
        );
        let cached = cache.get(&pid).expect("cached");
        assert!(!has_path_separators(&cached.path));
        assert_eq!(cached.name, "brave.exe");
        assert!(has_path_separators(&cached.path)
            .then_some(cached)
            .is_none());
    }

    #[test]
    fn start_timestamp_comparison_detects_reuse() {
        assert!(start_ts_compatible(1_000, Some(1_000)));
        assert!(start_ts_compatible(1_000, Some(1_500)));
        assert!(!start_ts_compatible(1_000, Some(5_000)));
        assert!(start_ts_compatible(1_000, None));
        assert!(start_ts_compatible(0, Some(5_000)));
    }

    #[test]
    fn live_identity_with_unknown_creation_is_not_valid_for_known_generation() {
        let unknown = ResolvedIdentity {
            path: r"C:\Apps\unknown.exe".to_owned(),
            name: "unknown.exe".to_owned(),
            start_ts: 0,
        };
        let known = ResolvedIdentity {
            start_ts: 5_000,
            ..unknown.clone()
        };

        assert!(!live_identity_matches_expected(&unknown, Some(5_000)));
        assert!(live_identity_matches_expected(&unknown, None));
        assert!(live_identity_matches_expected(&known, Some(5_000)));
        assert!(!live_identity_matches_expected(&known, Some(6_500)));
    }

    #[test]
    fn unknown_creation_does_not_trust_an_active_cached_identity() {
        let identities = ProcessIdentities::new();
        let pid = 915_101;
        identities.seed_cache(
            pid,
            r"C:\PreviousGeneration\cached.exe",
            "cached.exe",
            10_000,
        );

        let missing = identities.resolve(pid, None, None, None);
        assert_eq!(missing.path, exited_unknown().path);
        let zero = identities.resolve(pid, None, None, Some(0));
        assert_eq!(zero.path, exited_unknown().path);
        let known = identities.resolve(pid, None, None, Some(20_000));
        assert_eq!(known.path, exited_unknown().path);
    }

    #[test]
    fn unknown_creation_does_not_trust_an_active_tracked_identity() {
        let identities = ProcessIdentities::new();
        let pid = 915_102;
        identities.process_started(
            pid,
            r"C:\PreviousGeneration\tracked.exe",
            "tracked.exe",
            10_000,
        );

        let missing = identities.resolve(pid, None, None, None);
        assert_eq!(missing.path, placeholder_path());
        assert_eq!(missing.name, "tracked.exe");
        let zero = identities.resolve(pid, None, None, Some(0));
        assert_eq!(zero.path, placeholder_path());
        assert_eq!(zero.name, "tracked.exe");
        let known = identities.resolve(pid, None, None, Some(20_000));
        assert_eq!(known.path, exited_unknown().path);
    }

    #[test]
    fn stopped_known_generation_survives_an_unknown_cache_after_live_failure() {
        let identities = ProcessIdentities::new();
        let pid = 915_103;
        identities.process_started(
            pid,
            r"C:\PreviousGeneration\stopped.exe",
            "stopped.exe",
            10_000,
        );
        identities.process_stopped(pid);
        identities.seed_cache(pid, r"C:\UnverifiedGeneration\stale.exe", "stale.exe", 0);

        let resolved = identities.resolve(pid, None, None, Some(10_000));
        assert_eq!(resolved.path, r"C:\PreviousGeneration\stopped.exe");
        assert_eq!(resolved.name, "stopped.exe");
    }

    /// A successful live lookup must still prove it belongs to the same
    /// process instance: without this check a flow for a dead instance would
    /// adopt the recycled PID's new occupant.
    #[test]
    fn live_lookup_result_is_validated_against_the_expected_creation_time() {
        let identities = ProcessIdentities::new();
        let pid = std::process::id();
        // The test binary's own creation time through the same live path
        // production uses; both backends report non-zero for a live process.
        let live = live_lookup(pid).expect("own process resolves");
        assert!(live.start_ts > 0);

        // Same instance: the live identity applies.
        let (path, _) = resolve(&identities, pid, None, None, Some(live.start_ts));
        assert_eq!(path, live.path);

        // Recycled PID with a newer creation time: the live process is a
        // different instance and must not attribute the flow.
        let (path, name) = resolve(
            &identities,
            pid,
            None,
            None,
            Some(live.start_ts.saturating_add(60_000)),
        );
        assert_ne!(path, live.path);
        assert_ne!(name, live.name);

        // Missing creation metadata must refresh a cached identity against the
        // current process rather than allowing a previous generation to win.
        identities.forget(pid);
        identities.seed_cache(
            pid,
            r"C:\PreviousGeneration\cached.exe",
            "cached.exe",
            live.start_ts.saturating_sub(60_000),
        );
        let (path, name) = resolve(&identities, pid, None, None, None);
        assert_eq!(path, live.path);
        assert_eq!(name, live.name);
        let (path, name) = resolve(&identities, pid, None, None, Some(0));
        assert_eq!(path, live.path);
        assert_eq!(name, live.name);

        // The same control applies to an active lifecycle entry: with no flow
        // creation time, a stale tracked path must not shadow the live PID.
        identities.forget(pid);
        identities.process_started(
            pid,
            r"C:\PreviousGeneration\tracked.exe",
            "tracked.exe",
            live.start_ts.saturating_add(60_000),
        );
        let (path, name) = resolve(&identities, pid, None, None, None);
        assert_eq!(path, live.path);
        assert_eq!(name, live.name);
        let (path, name) = resolve(&identities, pid, None, None, Some(0));
        assert_eq!(path, live.path);
        assert_eq!(name, live.name);
    }

    #[test]
    fn unmapped_nt_meta_stays_name_keyed_instead_of_forking() {
        let identities = ProcessIdentities::new();
        let pid = 430_001;
        let (path, name) = resolve(
            &identities,
            pid,
            Some(r"\Device\AntiwireBogusVolume\dir\tool.exe"),
            Some("tool.exe"),
            None,
        );
        assert_eq!(path, placeholder_path());
        assert_eq!(name, "tool.exe");
        // ... and the fallback never caches, so a later conversion still heals.
        assert!(identities.cache.get(&pid).is_none());
    }

    #[test]
    fn placeholder_results_are_not_cached() {
        let identities = ProcessIdentities::new();
        let pid = 431_001;
        let (path, _) = resolve(
            &identities,
            pid,
            Some("ghost-tool.exe"),
            Some("ghost-tool.exe"),
            None,
        );
        assert_eq!(path, placeholder_path());
        assert!(
            identities.cache.get(&pid).is_none(),
            "a cached placeholder would hide the recovery a later sighting enables"
        );
    }

    #[test]
    fn named_placeholder_retains_the_live_lookup_failure_reason() {
        for (error, failure) in [
            (
                ProcessLookupError::AccessDenied,
                ResolutionFailure::AccessDenied,
            ),
            (
                ProcessLookupError::NotFound,
                ResolutionFailure::ExitedProcess,
            ),
        ] {
            let identities = ProcessIdentities::new();
            let identity = identities.failed_lookup(
                915_001,
                Some("ghost.exe"),
                Some("ghost.exe"),
                Some(1_000),
                None,
                error,
            );
            assert_eq!(identity.path, placeholder_path());

            let expected = ResolutionCounters::default();
            expected.record_placeholder_fallback();
            expected.record_failure(failure);
            assert_eq!(identities.resolution_stats(), expected.snapshot());
        }
    }

    #[test]
    fn a_recycled_lifecycle_entry_is_counted_as_a_mismatch() {
        let identities = ProcessIdentities::new();
        identities.process_started(42_009, r"C:\Apps\old.exe", "old.exe", 1_000);
        let (identity, fallback) = identities.tracked_identity(42_009, Some(9_000), false);
        assert_eq!((identity, fallback), (None, None));

        let stats = identities.resolution_stats();
        assert_eq!(
            stats.start_ts_mismatch, 1,
            "a recycled PID must be measurable, not just dropped"
        );
        assert_eq!(stats.missing_lifecycle_event, 1);
    }

    /// A lost lifecycle event must not let a recycled PID reuse the previous
    /// process's cached identity once a later event reports the new creation time.
    #[test]
    fn recycled_pid_with_a_new_start_ts_does_not_inherit_the_cached_identity() {
        let identities = ProcessIdentities::new();
        let pid = 424_242;
        let old_path = if cfg!(windows) {
            r"C:\apps\old.exe"
        } else {
            "/tmp/old.exe"
        };
        let (path, _) = resolve(
            &identities,
            pid,
            Some(old_path),
            Some("old.exe"),
            Some(1_000),
        );
        assert_eq!(path, old_path);

        // Same creation time: the cache still applies.
        let (path, _) = resolve(&identities, pid, None, None, Some(1_000));
        assert_eq!(path, old_path);

        // Newer creation time: the PID was recycled, so the stale entry is
        // evicted and the bogus PID resolves as unknown instead.
        let (path, name) = resolve(&identities, pid, None, None, Some(9_000));
        assert_ne!(path, old_path);
        assert_ne!(name, "old.exe");
    }

    /// Processes already running at daemon start must be seeded into the tracked
    /// map so their flows can be attributed before any lifecycle event arrives.
    #[test]
    fn bootstrap_seeds_the_current_process() {
        let identities = ProcessIdentities::new();
        let stats = identities.bootstrap_running_processes();
        assert!(stats.seeded > 0);

        let pid = std::process::id();
        let TrackedLookup::Found(tracked) = identities.tracked.resolve(pid, None) else {
            panic!("the current process must be seeded");
        };
        assert_ne!(tracked.identity.path, "");
    }

    /// Each value keeps its own evidence, which is what lets tests run in
    /// parallel without serialising on shared process state.
    #[test]
    fn identities_do_not_share_evidence() {
        let first = ProcessIdentities::new();
        let second = ProcessIdentities::new();
        first.process_started(915_200, r"C:\Apps\first.exe", "first.exe", 1_000);
        first.process_stopped(915_200);

        assert_eq!(
            resolve(&first, 915_200, None, None, None).0,
            r"C:\Apps\first.exe"
        );
        assert_ne!(
            resolve(&second, 915_200, None, None, None).0,
            r"C:\Apps\first.exe"
        );
    }
}

#[cfg(windows)]
#[cfg(test)]
mod live_tests {
    use super::ProcessIdentities;

    fn resolve(identities: &ProcessIdentities, pid: u32) -> (String, String) {
        let identity = identities.resolve(pid, None, None, None);
        (identity.path, identity.name)
    }

    #[test]
    #[ignore = "requires live Windows process access"]
    fn resolves_own_process_with_real_path() {
        let pid = std::process::id();
        let (path, name) = resolve(&ProcessIdentities::new(), pid);
        assert_ne!(name, crate::process_resolver::UNKNOWN_APP_NAME);
        assert!(name
            .rsplit_once('.')
            .is_some_and(|(_, extension)| extension.eq_ignore_ascii_case("exe")));
        assert!(
            std::path::Path::new(&path).exists(),
            "expected a real executable path, got '{path}'"
        );
    }
    #[test]
    #[ignore = "requires live Windows process access"]
    fn disambiguates_running_svchost_instance() {
        use sysinfo::{ProcessRefreshKind, RefreshKind, System};

        let mut system = System::new_with_specifics(
            RefreshKind::nothing().with_processes(ProcessRefreshKind::everything()),
        );
        system.refresh_all();

        let pid = system
            .processes()
            .iter()
            .find(|(_, process)| {
                process
                    .name()
                    .to_string_lossy()
                    .eq_ignore_ascii_case("svchost.exe")
            })
            .map(|(pid, _)| pid.as_u32());
        let Some(pid) = pid else {
            return;
        };

        let (path, name) = resolve(&ProcessIdentities::new(), pid);
        assert_ne!(path, "");
        assert!(
            name.contains("(svchost.exe)") || name.eq_ignore_ascii_case("svchost.exe"),
            "unexpected svchost attribution: path={path}, name={name}"
        );
    }

    #[test]
    #[ignore = "requires live Windows process access"]
    fn disambiguates_running_rundll32_instance() {
        use sysinfo::{ProcessRefreshKind, RefreshKind, System};

        let mut system = System::new_with_specifics(
            RefreshKind::nothing().with_processes(ProcessRefreshKind::everything()),
        );
        system.refresh_all();

        let pid = system
            .processes()
            .iter()
            .find(|(_, process)| {
                process
                    .name()
                    .to_string_lossy()
                    .eq_ignore_ascii_case("rundll32.exe")
            })
            .map(|(pid, _)| pid.as_u32());
        let Some(pid) = pid else {
            return;
        };

        let (path, name) = resolve(&ProcessIdentities::new(), pid);
        assert_ne!(path, "");
        assert!(
            name.contains("(rundll32.exe)") || name.eq_ignore_ascii_case("rundll32.exe"),
            "unexpected rundll32 attribution: path={path}, name={name}"
        );
    }

    #[test]
    #[ignore = "requires live Windows process access"]
    fn resolve_returns_stable_cached_result_for_current_process() {
        let identities = ProcessIdentities::new();
        let pid = std::process::id();
        let first = resolve(&identities, pid);
        let second = resolve(&identities, pid);
        assert_ne!(first.1, "");
        assert!(first
            .1
            .rsplit_once('.')
            .is_some_and(|(_, extension)| extension.eq_ignore_ascii_case("exe")));
        assert_eq!(first.0, second.0);
        assert_eq!(first.1, second.1);
    }
}
