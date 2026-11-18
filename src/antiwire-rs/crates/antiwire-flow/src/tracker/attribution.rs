//! Socket and identity attribution for active flows: retries, closed-identity recovery, and the attribution predicates.

use super::closed_identity::Candidate;
use super::persistence::{conn_id_to_i64, pid_to_i32};
use super::FlowTracker;
use super::{
    ActiveFlow, AttributionLookup, AttributionVersion, IDENTITY_RETRY_BACKOFF,
    MAX_IDENTITY_LOOKUP_ATTEMPTS, MAX_SOCKET_LOOKUP_ATTEMPTS, SOCKET_LOOKUP_BACKOFF,
};
use crate::app_resolver::ResolvedApplication;
use crate::process_resolver;
use crate::processor::FlowProcessor;
use crate::store::FlowStore;
use crate::system_services;
use antiwire_store::ConnectionLogAttribution;
use antiwire_tuning::UNKNOWN_SOCKET_ATTRIBUTION_DELAY;
use netmetrics::owner_cache::{CachedSnapshot, Wait};
use netmetrics::SocketOwnerCache;
use netmetrics_core::{
    CookieSource, FlowKey, FlowMeta, ProcessIdentity, Protocol, SocketCookie, SocketOwnerSnapshot,
};
use std::cell::OnceCell;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};
use time::OffsetDateTime;

impl<S: FlowStore> FlowTracker<S> {
    pub(super) fn refresh_active_flows_for_pid(&self, pid: u32, start_ts: u64) {
        if pid == 0 {
            return;
        }
        let keys = {
            let mut active = self.active.lock();
            let mut keys = Vec::new();
            for (key, flow) in active.iter_mut() {
                if flow.pid != pid {
                    continue;
                }
                // A process created after the flow opened took the PID over
                // from the flow's own. Its start says nothing of this flow,
                // and must not date it: the flow's real process, named later,
                // would then be turned away as a different one.
                if process_resolver::started_after(start_ts, flow.open_ts) {
                    continue;
                }
                if flow.process_start_ts.is_none() && start_ts > 0 {
                    flow.process_start_ts = Some(start_ts);
                } else if start_ts > 0
                    && !process_resolver::start_ts_compatible(
                        flow.process_start_ts.unwrap_or(0),
                        Some(start_ts),
                    )
                {
                    // The PID was recycled: this lifecycle event belongs to a new
                    // instance, so it must not refresh a flow owned by the old one.
                    continue;
                }
                // New lifecycle evidence bypasses the retry backoff below.
                keys.push(*key);
            }
            keys
        };
        for key in keys {
            self.refresh_active_attribution(&key, true, None);
        }
    }

    /// Snapshot attribution, perform process/SCM/store work off the map lock,
    /// then merge only identity state into the same connection generation.
    pub(super) fn refresh_active_attribution(
        &self,
        key: &FlowKey,
        force: bool,
        socket_tables: Option<&SocketTables>,
    ) {
        let mut force = force;
        let mut tables = socket_tables;
        while self.refresh_active_attribution_once(key, force, tables) {
            force = true;
            tables = None;
        }
    }

    /// Returns whether lifecycle evidence requested another forced identity pass.
    fn refresh_active_attribution_once(
        &self,
        key: &FlowKey,
        force: bool,
        socket_tables: Option<&SocketTables>,
    ) -> bool {
        let (version, mut candidate) = {
            let mut active = self.active.lock();
            let Some(flow) = active.get_mut(key) else {
                return false;
            };
            if flow.attribution_lookup != AttributionLookup::Idle {
                if force {
                    flow.attribution_lookup = AttributionLookup::RefreshPending;
                }
                return false;
            }
            let port_hint = flow.pid == 0
                && needs_socket_attribution(flow)
                && self.cached_owner_pid(flow, key).is_some();
            let socket_due = socket_tables.is_some()
                && needs_socket_attribution(flow)
                && (force || should_retry_socket_lookup(flow));
            if !port_hint && !socket_due && !identity_retry_due(flow, force) {
                return false;
            }
            let version = AttributionVersion::capture(flow);
            let mut candidate = flow.clone();
            // A speculative result is only a recovery after the guarded merge.
            candidate.attribution_lookup = AttributionLookup::Running;
            flow.attribution_lookup = AttributionLookup::Running;
            (version, candidate)
        };
        if let Some(tables) = socket_tables {
            let snapshot = self.socket_table(tables, key.protocol);
            self.maybe_attempt_socket_attribution(&mut candidate, key, snapshot, force);
        } else {
            self.maybe_attempt_port_cache_attribution(&mut candidate, key);
            self.try_refresh_attribution(&mut candidate, key, force);
        }
        self.normalize_active_flow(&mut candidate);
        touch_unknown_state(&mut candidate);
        let mut active = self.active.lock();
        let Some(flow) = active
            .get_mut(key)
            .filter(|flow| flow.conn_id == version.conn_id)
        else {
            return false;
        };
        let refresh_again = flow.attribution_lookup == AttributionLookup::RefreshPending;
        flow.attribution_lookup = AttributionLookup::Idle;
        if !version.matches(flow) {
            return refresh_again;
        }
        let recovered = (candidate.app_id != version.app_id
            || candidate.app_path != version.app_path
            || candidate.app_name != version.app_name)
            && (identity_upgrade_acceptable(
                process_resolver::is_recoverable_placeholder(&version.app_path),
                &candidate.app_path,
                &candidate.app_name,
            ) || system_services::is_system_identity(&candidate.app_path, &candidate.app_name));
        flow.app_id = candidate.app_id;
        flow.app_path = candidate.app_path;
        flow.app_name = candidate.app_name;
        flow.pid = candidate.pid;
        flow.process_start_ts = candidate.process_start_ts;
        flow.unknown_since = candidate.unknown_since;
        flow.unknown_socket_lookup_done = candidate.unknown_socket_lookup_done;
        flow.socket_lookup_attempts = candidate.socket_lookup_attempts;
        flow.next_socket_lookup = candidate.next_socket_lookup;
        flow.identity_lookup_attempts = candidate.identity_lookup_attempts;
        flow.next_identity_retry = candidate.next_identity_retry;
        if recovered {
            self.record_identity_recovery(flow.opened_at);
        }
        refresh_again
    }

    /// Recovers closed connections of the exact process `info` reports: the
    /// same PID and creation time.
    ///
    /// A report with a path names a connection or completes a named one. A
    /// report with only a name, which is all that is left of a process gone
    /// before it could be asked, still names a connection that had none.
    pub(super) fn recover_closed_identities(&self, info: &netmetrics_core::ProcessInfo) {
        if info.identity.start_ts == 0 || !info.identity.is_usable() {
            return;
        }
        let Some(processor) = &self.processor else {
            return;
        };
        let has_path = info.identity.executable.contains(['\\', '/']);
        let candidates = self.closed_identities.lock().take_for(
            info.pid,
            info.identity.start_ts,
            Instant::now(),
        );
        for candidate in candidates {
            if evidence_adds_nothing(&candidate, has_path) {
                self.closed_identities
                    .lock()
                    .restore(candidate, Instant::now());
                continue;
            }
            self.recover_closed(processor, candidate, info.pid, &info.identity);
        }
    }

    /// Recovers closed connections of `pid` that never learned which process
    /// had it, now that more is known of the processes that did.
    ///
    /// A process can open a connection and exit before its start event has
    /// been delivered. Its connection is then looked at with nothing known of
    /// the PID and no process left to ask, and closes unattributed. The start
    /// and stop events that follow say which process had the PID when the
    /// connection opened. A connection they do not place is kept for later.
    pub(super) fn recover_closed_unstarted(&self, pid: u32) {
        let Some(processor) = &self.processor else {
            return;
        };
        let candidates = self
            .closed_identities
            .lock()
            .take_unstarted(pid, Instant::now());
        for candidate in candidates {
            let Some(identity) = processor
                .processes()
                .identity_at(pid, candidate.flow.open_ts)
            else {
                self.closed_identities
                    .lock()
                    .restore(candidate, Instant::now());
                continue;
            };
            let has_path = !process_resolver::is_synthetic_path(&identity.path);
            if evidence_adds_nothing(&candidate, has_path) {
                self.closed_identities
                    .lock()
                    .restore(candidate, Instant::now());
                continue;
            }
            let process = ProcessIdentity {
                // The placeholder stands for a path nobody reported. It is not
                // an executable, so the resolver is not handed it as one.
                executable: if has_path {
                    identity.path
                } else {
                    String::new()
                },
                name: identity.name,
                start_ts: identity.start_ts,
            };
            self.recover_closed(processor, candidate, pid, &process);
        }
    }

    /// Re-attributes the closed connection `candidate` to `process`, which
    /// had `pid` when it was open, or keeps it for later if that fails.
    ///
    /// A connection with no name takes a name without a path. It is then kept
    /// as any connection closed under such a name is, for the path the same
    /// process may still report.
    fn recover_closed(
        &self,
        processor: &FlowProcessor,
        mut candidate: Candidate,
        pid: u32,
        process: &ProcessIdentity,
    ) {
        let named = process_resolver::is_recoverable_placeholder(&candidate.flow.app_path);
        self.identity_recovery_attempts
            .fetch_add(1, Ordering::Relaxed);
        let resolved = processor.resolve_flow_app(
            &candidate.key,
            &FlowMeta {
                pid,
                process: Some(process.clone()),
                open_ts: candidate.flow.open_ts,
                cookie: candidate.flow.cookie,
                if_index: None,
            },
        );
        if resolved.start_ts != process.start_ts
            || resolved.app_id <= 0
            || (!identity_upgrade_acceptable(named, &resolved.app_path, &resolved.app_name)
                && !system_services::is_system_identity(&resolved.app_path, &resolved.app_name))
        {
            self.closed_identities
                .lock()
                .restore(candidate, Instant::now());
            return;
        }
        let mut flow = candidate.flow.clone();
        let attribution = ConnectionLogAttribution {
            from_app_id: flow.app_id,
            to_app_id: resolved.app_id,
            protocol: flow.protocol.clone(),
            src_ip: flow.src_ip.clone(),
            dst_ip: flow.dst_ip.clone(),
            dst_port: flow.dst_port,
            conn_id: conn_id_to_i64(flow.conn_id),
            conn_pid: pid_to_i32(flow.open_pid),
            conn_start: flow.opened_at,
        };
        let _flush = self.flush_gate.lock();
        if !self.queue_attribution(attribution) {
            self.closed_identities
                .lock()
                .restore(candidate, Instant::now());
            return;
        }
        for log in self.pending.lock().iter_mut().filter(|log| {
            log.conn_id == conn_id_to_i64(flow.conn_id)
                && log.conn_pid == pid_to_i32(flow.open_pid)
                && log.timestamp == flow.opened_at
        }) {
            log.app_id = resolved.app_id;
            log.app_path.clone_from(&resolved.app_path);
        }
        flow.app_id = resolved.app_id;
        flow.app_path = resolved.app_path;
        flow.app_name = resolved.app_name;
        self.record_closed_bytes(&flow);
        self.record_identity_recovery(flow.opened_at);
        if process_resolver::is_recoverable_placeholder(&flow.app_path) {
            flow.process_start_ts = Some(process.start_ts);
            candidate.flow = flow;
            self.closed_identities
                .lock()
                .restore(candidate, Instant::now());
        }
    }

    /// Re-resolves a recoverable flow's identity: unknown rows and the
    /// path placeholder both retry while the flow is alive.
    ///
    /// `force` bypasses the bounded backoff for new evidence (lifecycle
    /// events, close-time resolution). Periodic ticks pass `false`.
    pub(super) fn try_refresh_attribution(
        &self,
        flow: &mut ActiveFlow,
        key: &FlowKey,
        force: bool,
    ) {
        if !identity_retry_due(flow, force) {
            return;
        }
        let placeholder = process_resolver::is_recoverable_placeholder(&flow.app_path);
        if !force {
            flow.identity_lookup_attempts += 1;
            flow.next_identity_retry = Instant::now().checked_add(
                IDENTITY_RETRY_BACKOFF.delay(u32::from(flow.identity_lookup_attempts)),
            );
        }
        let Some(processor) = &self.processor else {
            return;
        };
        self.identity_recovery_attempts
            .fetch_add(1, Ordering::Relaxed);
        // An empty path with a creation timestamp lets the resolver validate
        // any cached or tracked identity for this PID without short-circuiting
        // to a path that was never observed for this flow.
        let meta = FlowMeta {
            pid: flow.pid,
            process: flow.process_start_ts.map(|start_ts| ProcessIdentity {
                executable: String::new(),
                name: String::new(),
                start_ts,
            }),
            open_ts: flow.open_ts,
            cookie: flow.cookie,
            if_index: None,
        };
        let ResolvedApplication {
            app_id,
            app_path,
            app_name,
            start_ts,
        } = processor.resolve_flow_app(key, &meta);
        if placeholder
            && (start_ts == 0
                || !process_resolver::start_ts_compatible(start_ts, flow.process_start_ts))
        {
            // A real path without its own creation time cannot establish that
            // the lookup still describes the flow's original process instance.
            return;
        }
        if !identity_upgrade_acceptable(placeholder, &app_path, &app_name)
            && !system_services::is_system_identity(&app_path, &app_name)
        {
            return;
        }
        flow.app_id = app_id;
        flow.app_path = app_path;
        flow.app_name = app_name;
        if flow.process_start_ts.is_none() && start_ts > 0 {
            flow.process_start_ts = Some(start_ts);
        }
        flow.identity_lookup_attempts = 0;
        flow.next_identity_retry = None;
        if flow.attribution_lookup == AttributionLookup::Idle {
            self.record_identity_recovery(flow.opened_at);
        }
        touch_unknown_state(flow);
    }

    fn record_identity_recovery(&self, opened_at: OffsetDateTime) {
        self.identity_recoveries.fetch_add(1, Ordering::Relaxed);
        let latency_ms = u64::try_from(
            (OffsetDateTime::now_utc() - opened_at)
                .whole_milliseconds()
                .max(0),
        )
        .unwrap_or(u64::MAX);
        self.identity_recovery_latency_ms
            .fetch_add(latency_ms, Ordering::Relaxed);
    }

    pub(super) fn maybe_attempt_socket_attribution(
        &self,
        flow: &mut ActiveFlow,
        key: &FlowKey,
        snapshot: &SocketOwnerSnapshot,
        force: bool,
    ) {
        if !needs_socket_attribution(flow) {
            return;
        }
        if flow.unknown_socket_lookup_done && !force {
            return;
        }

        self.maybe_attempt_port_cache_attribution(flow, key);
        if !needs_socket_attribution(flow) {
            return;
        }

        if !force {
            if !should_retry_socket_lookup(flow) {
                return;
            }
            flow.socket_lookup_attempts += 1;
            flow.next_socket_lookup = Instant::now()
                .checked_add(SOCKET_LOOKUP_BACKOFF.delay(u32::from(flow.socket_lookup_attempts)));
        }

        if let Some(pid) = snapshot.lookup_owner_pid(key) {
            // A payload or WinDivert pid already on the flow stays. The socket
            // table is only allowed to fill a missing owner, and a matching
            // hit must not wipe the creation time used to detect pid reuse.
            if flow.pid != 0 && flow.pid != pid {
                return;
            }
            let changed = flow.pid != pid;
            if changed {
                flow.pid = pid;
                flow.process_start_ts = None;
            }
            self.port_pid_cache.lock().remember(key, pid);
            // A (possibly new) owner is fresh evidence: resolve past the
            // backoff so one slow lookup cannot strand the flow as unknown.
            // Repeated failures stay bounded by the socket-attempt budget.
            self.try_refresh_attribution(flow, key, changed);
            Self::mark_lookup_resolved(flow);
        }
    }

    /// Owner already known without a socket table scan: the port cache, then
    /// the owner the FLOW listener recorded for the flow's local endpoint.
    fn cached_owner_pid(&self, flow: &ActiveFlow, key: &FlowKey) -> Option<u32> {
        // Release the cache lock before falling back to the endpoint-owner table.
        let cached = self.port_pid_cache.lock().lookup(key);
        cached.or_else(|| recorded_owner_pid(flow, key))
    }

    /// Fills a missing owner from [`Self::cached_owner_pid`], so a flow it
    /// answers needs no socket table capture.
    pub(super) fn maybe_attempt_port_cache_attribution(
        &self,
        flow: &mut ActiveFlow,
        key: &FlowKey,
    ) {
        if flow.pid != 0 || !needs_socket_attribution(flow) {
            return;
        }
        let pid = self.cached_owner_pid(flow, key);
        if let Some(pid) = pid {
            flow.pid = pid;
            flow.process_start_ts = None;
            // First owner for this flow: fresh evidence, resolve past the backoff.
            self.try_refresh_attribution(flow, key, true);
            Self::mark_lookup_resolved(flow);
        }
    }

    pub(super) fn mark_lookup_resolved(flow: &mut ActiveFlow) {
        if !needs_socket_attribution(flow) {
            flow.unknown_socket_lookup_done = true;
            touch_unknown_state(flow);
        }
    }

    /// `protocol`'s socket owners from `tables`, read on first use.
    ///
    /// Callers gate this behind [`needs_socket_attribution`]: a read can scan the
    /// host's entire socket table (or every `/proc` FD on Linux), so it must never
    /// run for an already-attributed flow.
    #[cfg_attr(
        not(test),
        expect(
            clippy::unused_self,
            reason = "the receiver carries the test-only capture counter"
        )
    )]
    pub(super) fn socket_table<'t>(
        &self,
        tables: &'t SocketTables,
        protocol: Protocol,
    ) -> &'t SocketOwnerSnapshot {
        tables.get(protocol, || {
            #[cfg(test)]
            self.socket_snapshot_calls.fetch_add(1, Ordering::Relaxed);
        })
    }

    /// Maps empty unattributed flows to the canonical `Unknown (No Owner)` application row.
    pub(super) fn normalize_unattributed(
        &self,
        app_id: i32,
        app_path: String,
        app_name: String,
    ) -> (i32, String, String) {
        if app_path.is_empty() && app_id == 0 {
            if let Some(processor) = &self.processor {
                return processor.unknown_no_owner();
            }
        }
        (app_id, app_path, app_name)
    }

    pub(super) fn normalize_active_flow(&self, flow: &mut ActiveFlow) {
        if flow.app_path.is_empty() && flow.app_id == 0 {
            let (app_id, app_path, app_name) =
                self.normalize_unattributed(0, String::new(), String::new());
            flow.app_id = app_id;
            flow.app_path = app_path;
            flow.app_name = app_name;
        }
    }
}

/// The kind of owner a closed connection ended with, as an index into the
/// tracker's closed-owner counts: an application with a real executable path,
/// `System`, a process known by name only, no owner, a process that had
/// exited, and any other unknown.
pub(super) fn closed_owner_kind(app_path: &str, app_name: &str) -> usize {
    if system_services::is_system_identity(app_path, app_name) {
        1
    } else if app_path.is_empty() || app_path.eq_ignore_ascii_case("Unknown (No Owner)") {
        3
    } else if app_path.eq_ignore_ascii_case("Unknown (Exited)") {
        4
    } else if process_resolver::is_unknown_placeholder(app_path) {
        5
    } else if process_resolver::is_synthetic_path(app_path) {
        2
    } else {
        0
    }
}

pub(super) fn is_unknown_attribution(flow: &ActiveFlow) -> bool {
    flow.app_name
        .eq_ignore_ascii_case(process_resolver::UNKNOWN_APP_NAME)
        || flow.app_path.eq_ignore_ascii_case("Unknown (Exited)")
}

/// Returns true when a flow's identity may still improve while it is alive:
/// unknown rows plus the path placeholder.
///
/// `System` and the `Unknown (...)` placeholders are terminal identities, not
/// recovery candidates: the former is genuine, the latter carry no name to
/// recover toward.
fn needs_identity_recovery(flow: &ActiveFlow) -> bool {
    is_unknown_attribution(flow) || process_resolver::is_recoverable_placeholder(&flow.app_path)
}

fn identity_retry_due(flow: &ActiveFlow, force: bool) -> bool {
    needs_identity_recovery(flow)
        && flow.pid > 0
        && (!process_resolver::is_recoverable_placeholder(&flow.app_path)
            || flow.process_start_ts.is_some())
        && (force
            || (flow.identity_lookup_attempts < MAX_IDENTITY_LOOKUP_ATTEMPTS
                && flow
                    .next_identity_retry
                    .is_none_or(|next| Instant::now() >= next)))
}

/// Acceptance rule for an identity refresh result.
///
/// Unknown rows take any named identity (legacy behavior). A placeholder
/// already carries a real name, so only an authoritative real path may
/// replace it — a fallback or unknown result is never an upgrade.
pub(super) fn identity_upgrade_acceptable(
    placeholder: bool,
    app_path: &str,
    app_name: &str,
) -> bool {
    if app_path.is_empty() || app_name.eq_ignore_ascii_case(process_resolver::UNKNOWN_APP_NAME) {
        return false;
    }
    if placeholder && process_resolver::is_synthetic_path(app_path) {
        return false;
    }
    true
}

/// Whether evidence of a process has nothing to give `candidate`: it carries
/// no path, and the connection closed under a name already, which only a path
/// improves on.
fn evidence_adds_nothing(candidate: &Candidate, has_path: bool) -> bool {
    !has_path && process_resolver::is_recoverable_placeholder(&candidate.flow.app_path)
}

/// Returns the observed process creation timestamp, when the backend supplied one.
fn observed_process_start_ts(meta: &FlowMeta) -> Option<u64> {
    meta.process
        .as_ref()
        .map(|process| process.start_ts)
        .filter(|start_ts| *start_ts > 0)
}

/// Creation timestamp attributable to a process instance: ownerless metadata
/// carries none. A PID-less event must neither prove continuity (adopting a
/// foreign identity) nor poison it (blocking a later real owner with a bogus
/// timestamp that matches nothing observable).
pub(super) fn attributable_process_start_ts(meta: &FlowMeta) -> Option<u64> {
    if system_services::has_owner_evidence(meta) {
        observed_process_start_ts(meta)
    } else {
        None
    }
}

/// How long a pass waits for a socket-table scan another caller is running
/// before it scans on its own. A scan takes well under a millisecond.
const SOCKET_TABLE_WAIT: Duration = Duration::from_secs(1);

/// Socket-table snapshots for one attribution pass, taken from the shared
/// [`SocketOwnerCache`] on first use, one protocol at a time.
///
/// `since` is the earliest scan the pass can use: one that started after the
/// sockets it looks for were known to be open, so the scan saw them unless
/// they had closed. Any scan since then is as good as a new one, so passes
/// share scans with each other and with DNS attribution.
pub(super) struct SocketTables {
    since: Instant,
    tcp: OnceCell<Table>,
    udp: OnceCell<Table>,
}

enum Table {
    Cached(Arc<CachedSnapshot>),
    /// Scanned directly because the cache could not answer in time.
    Scanned(SocketOwnerSnapshot),
}

impl SocketTables {
    /// Tables from scans that started at or after `since`.
    pub(super) fn since(since: Instant) -> Self {
        Self {
            since,
            tcp: OnceCell::new(),
            udp: OnceCell::new(),
        }
    }

    /// Tables for a flow last seen at `last_seen`: a scan after it saw the
    /// flow's socket if it was still open.
    pub(super) fn after(last_seen: OffsetDateTime) -> Self {
        Self::since(instant_at(
            last_seen,
            OffsetDateTime::now_utc(),
            Instant::now(),
        ))
    }

    /// `protocol`'s owners, read on first use, when `on_read` is called.
    fn get(&self, protocol: Protocol, on_read: impl FnOnce()) -> &SocketOwnerSnapshot {
        let cell = match protocol {
            Protocol::Tcp => &self.tcp,
            Protocol::Udp => &self.udp,
        };
        let table = cell.get_or_init(|| {
            on_read();
            let wait = Instant::now()
                .checked_add(SOCKET_TABLE_WAIT)
                .map_or(Wait::Never, Wait::Until);
            match SocketOwnerCache::shared().snapshot_since(protocol, self.since, wait) {
                Ok(snapshot) => Table::Cached(snapshot),
                Err(_) => Table::Scanned(netmetrics::socket_owner_snapshot_for(protocol)),
            }
        });
        match table {
            Table::Cached(snapshot) => snapshot.owners(),
            Table::Scanned(owners) => owners,
        }
    }
}

/// The monotonic instant the wall-clock `at` names, or `now` for a time the
/// monotonic clock cannot reach back to.
fn instant_at(at: OffsetDateTime, now_utc: OffsetDateTime, now: Instant) -> Instant {
    let ago = Duration::try_from(now_utc - at).unwrap_or(Duration::ZERO);
    now.checked_sub(ago).unwrap_or(now)
}

/// Margin past `last_seen` for the recorded-owner lookup. `last_seen` comes
/// from the wall clock and the FLOW record's time from the kernel's, so a flow
/// seen only at its start could otherwise look older than its own record.
const RECORDED_OWNER_SLACK: Duration = Duration::from_millis(50);

/// Owner the FLOW listener recorded for `key`'s local endpoint while the flow
/// was last seen. Exact after the socket has closed, which a socket table
/// scan cannot be. Never waits; `None` without a listener or a record.
fn recorded_owner_pid(flow: &ActiveFlow, key: &FlowKey) -> Option<u32> {
    let at = recorded_lookup_instant(flow.last_seen, OffsetDateTime::now_utc(), Instant::now());
    let endpoint = netmetrics_core::LocalEndpoint {
        address: key.local_addr,
        port: key.local_port,
    };
    match netmetrics::endpoint_owner::owner_at(key.protocol, endpoint, at, Duration::ZERO) {
        netmetrics::endpoint_owner::EndpointOwner::Resolved(pid) => Some(pid),
        _ => None,
    }
}

/// The monotonic instant `last_seen` names, plus [`RECORDED_OWNER_SLACK`].
fn recorded_lookup_instant(
    last_seen: OffsetDateTime,
    now_utc: OffsetDateTime,
    now: Instant,
) -> Instant {
    instant_at(last_seen, now_utc, now)
        .checked_add(RECORDED_OWNER_SLACK)
        .unwrap_or(now)
}

pub(super) fn needs_socket_attribution(flow: &ActiveFlow) -> bool {
    is_unknown_attribution(flow)
        || (flow.pid == 0
            && flow.app_id == 0
            // A folded System identity whose store id is still pending (the
            // sighting write failed transiently) already has its owner: the id
            // is retried at flush time, so no socket work is needed.
            && !system_services::is_system_identity(&flow.app_path, &flow.app_name))
}

pub(super) fn should_retry_socket_lookup(flow: &ActiveFlow) -> bool {
    needs_socket_attribution(flow)
        && !flow.unknown_socket_lookup_done
        && flow.socket_lookup_attempts < MAX_SOCKET_LOOKUP_ATTEMPTS
        && flow
            .next_socket_lookup
            .is_none_or(|next| Instant::now() >= next)
        && flow
            .unknown_since
            .is_some_and(|since| since.elapsed() >= UNKNOWN_SOCKET_ATTRIBUTION_DELAY)
}

/// Mirrors [`netmetrics_core::FlowTable`]'s cookie-source upgrade rule.
///
/// A cookie only compares against one from the same source, so a coarse `LinuxInode`
/// cookie has to yield to the boot-unique `LinuxSockCookie` when one arrives. Without the
/// upgrade the stored source never changes and a recycled tuple goes undetected.
pub(super) fn should_upgrade_cookie(
    stored: Option<SocketCookie>,
    incoming: Option<SocketCookie>,
) -> bool {
    match (stored, incoming) {
        (None, Some(_)) => true,
        (Some(stored), Some(incoming)) => {
            stored.source == CookieSource::LinuxInode
                && incoming.source == CookieSource::LinuxSockCookie
        }
        _ => false,
    }
}

pub(super) fn touch_unknown_state(flow: &mut ActiveFlow) {
    if needs_socket_attribution(flow) {
        flow.unknown_since.get_or_insert(Instant::now());
    } else {
        flow.unknown_since = None;
        flow.unknown_socket_lookup_done = false;
        flow.socket_lookup_attempts = 0;
        flow.next_socket_lookup = None;
    }
}

/// Stable key for counting applications; `None` for flows without a real owner.
pub(super) fn application_identity(path: &str, name: &str) -> Option<String> {
    let path = path.trim();
    if path.is_empty()
        || process_resolver::is_synthetic_path(path)
        || name.eq_ignore_ascii_case(process_resolver::UNKNOWN_APP_NAME)
    {
        return None;
    }
    // Windows paths are case-insensitive; elsewhere case distinguishes files.
    Some(if cfg!(windows) {
        path.to_ascii_lowercase()
    } else {
        path.to_owned()
    })
}

#[cfg(test)]
mod recorded_owner_tests {
    use super::*;

    #[test]
    fn the_lookup_instant_is_last_seen_on_the_monotonic_clock_plus_slack() {
        let now = Instant::now();
        let now_utc = OffsetDateTime::now_utc();
        let at = recorded_lookup_instant(now_utc - time::Duration::seconds(2), now_utc, now);
        assert_eq!(
            now.checked_sub(Duration::from_secs(2))
                .and_then(|seen| seen.checked_add(RECORDED_OWNER_SLACK)),
            Some(at)
        );
        let future = recorded_lookup_instant(now_utc + time::Duration::seconds(1), now_utc, now);
        assert_eq!(
            future,
            now + RECORDED_OWNER_SLACK,
            "a future last_seen is now"
        );
    }

    #[test]
    fn a_wall_clock_time_maps_to_the_monotonic_instant_it_names() {
        let now = Instant::now();
        let now_utc = OffsetDateTime::now_utc();
        assert_eq!(
            Some(instant_at(
                now_utc - time::Duration::seconds(3),
                now_utc,
                now
            )),
            now.checked_sub(Duration::from_secs(3))
        );
        assert_eq!(
            instant_at(now_utc + time::Duration::seconds(3), now_utc, now),
            now,
            "a future time is now"
        );
        assert_eq!(
            instant_at(OffsetDateTime::UNIX_EPOCH, now_utc, now),
            now.checked_sub(Duration::try_from(now_utc - OffsetDateTime::UNIX_EPOCH).unwrap())
                .unwrap_or(now),
            "a time before the monotonic clock's origin is now"
        );
    }
}
