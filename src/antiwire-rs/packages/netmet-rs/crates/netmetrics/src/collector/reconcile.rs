use super::{InterfaceLookup, SharedStats, request_interface};
use crate::config::CollectorConfig;
use netmetrics_core::unix_now_ms;
use netmetrics_core::{
    DegradeReason, DnsResolutionAttribution, FlowEvent, FlowKey, FlowTable, IngressCoalescer,
    ProcessTable, SocketCookie, StopOutcome, UpsertOutcome,
};
use netmetrics_sys::BackendEvent;
use std::collections::HashSet;
use std::sync::atomic::Ordering;
use std::time::Instant;

pub(super) const MAX_DNS_TTL_MS: u64 = 60 * 60 * 1_000;

/// Snapshot-only fallbacks the collector has published that no [`FlowEvent::Restored`] has
/// ended yet, by source.
///
/// A backend reports [`BackendEvent::Restored`] every time its native source starts, since a
/// run the collector restarted cannot know what an earlier run reported. The collector
/// outlives its backend runs, so it decides: a `Restored` is published only when it ends a
/// fallback consumers were told about. One entry per fallback source name, and backends fix
/// those names in their code.
#[derive(Debug, Default)]
pub(super) struct OpenFallbacks(HashSet<String>);

impl OpenFallbacks {
    /// Whether to publish `event`, recording the fallback it starts or ends.
    pub(super) fn admit(&mut self, event: &BackendEvent) -> bool {
        match event {
            BackendEvent::Degraded(DegradeReason::SnapshotOnly { source }) => {
                self.0.insert(source.clone());
                true
            }
            BackendEvent::Restored { source } => self.0.remove(source),
            _ => true,
        }
    }
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(super) fn process_backend_event(
    event: BackendEvent,
    config: &CollectorConfig,
    flow_table: &mut FlowTable,
    process_table: &mut ProcessTable,
    coalescer: &mut IngressCoalescer,
    stats: &SharedStats,
    batch: &mut Vec<FlowEvent>,
    interface_lookup: Option<&InterfaceLookup>,
) {
    match event {
        BackendEvent::Opened {
            key,
            pid,
            cookie,
            timestamp,
            if_index,
        } => {
            if config.ignore_loopback && key.is_loopback() {
                return;
            }
            // A connection that is established on the addresses of a finishing flow is a
            // new one: the finishing flow's close was not seen.
            if flow_table.is_finishing(&key) {
                close_displaced(flow_table.close(&key, timestamp), coalescer, batch);
            }
            let process = process_table.resolve(pid, timestamp);
            let outcome = flow_table.open(key, pid, process, cookie, timestamp);
            let interface_changed =
                remember_native_interface(flow_table, interface_lookup, &outcome, if_index);
            publish_upsert(flow_table, outcome, interface_changed, coalescer, batch);
        }
        BackendEvent::CookieResolved {
            key,
            pid,
            cookie,
            timestamp,
        } => {
            if config.ignore_loopback && key.is_loopback() {
                return;
            }
            apply_cookie(
                flow_table,
                key,
                pid,
                cookie,
                timestamp,
                coalescer,
                batch,
                interface_lookup,
            );
        }
        BackendEvent::Closed {
            key,
            timestamp,
            pid,
        } => {
            if pid > 0 {
                let process = process_table.resolve(pid, timestamp);
                flow_table.adopt_pid_if_present(key, pid, process);
            }
            close_displaced(flow_table.close(&key, timestamp), coalescer, batch);
        }
        BackendEvent::Finishing { key, timestamp } => {
            if let Some(key) = flow_table.finish(&key, timestamp) {
                batch.push(FlowEvent::Finishing(key));
            }
        }
        BackendEvent::LocalEndpointClosed {
            protocol,
            local_addr,
            local_port,
            cookie,
            timestamp,
        } => {
            for record in
                flow_table.close_local_endpoint(protocol, local_addr, local_port, timestamp, cookie)
            {
                close_displaced(Some(record), coalescer, batch);
            }
        }
        BackendEvent::Bytes {
            key,
            pid,
            delta,
            timestamp,
            if_index,
            cookie,
        } => {
            if delta.is_zero() || (config.ignore_loopback && key.is_loopback()) {
                return;
            }
            let process = process_table.resolve_ref(pid, timestamp);
            let outcome =
                flow_table.add_attributed_bytes_ref(key, pid, process, delta, timestamp, cookie);
            let interface_changed =
                remember_native_interface(flow_table, interface_lookup, &outcome, if_index);
            let resolved = outcome.key;
            publish_upsert(flow_table, outcome, interface_changed, coalescer, batch);
            if let Some((key, delta)) = coalescer.push(resolved, delta, Instant::now()) {
                batch.push(FlowEvent::Bytes(key, delta));
            }
        }
        BackendEvent::InterfaceHint {
            key,
            if_index,
            bound,
            generation,
        } => {
            if flow_table.remember_interface_if_generation(key, if_index, generation, bound)
                && let Some(record) = flow_table.get(&key)
            {
                batch.push(FlowEvent::Opened(key, record.meta));
            }
        }
        BackendEvent::ProcessStarted(process) => {
            let Some(process) = select_process_start(process_table, &process, unix_now_ms()) else {
                return;
            };
            flow_table.update_process(process.pid, &process.identity);
            batch.push(FlowEvent::ProcessStarted(process));
        }
        BackendEvent::ProcessStopped {
            pid,
            timestamp,
            identity,
        } => {
            // A stale stop belongs to an earlier process with this PID. The
            // tracked one is still running, so consumers must not hear of it.
            if process_table.stopped_with_identity(pid, timestamp, identity) != StopOutcome::Stale {
                batch.push(FlowEvent::ProcessStopped {
                    pid,
                    stop_ts: timestamp,
                });
            }
        }
        BackendEvent::DnsResolved {
            pid,
            query,
            answers,
            ttl_ms,
            timestamp,
        } => {
            if !config.dns_hints {
                return;
            }
            let Some(ttl_ms) = effective_dns_ttl(ttl_ms, config.dns_ttl_ms) else {
                return;
            };
            batch.push(FlowEvent::DnsResolvedWithMetadata {
                attribution: if pid > 0 {
                    DnsResolutionAttribution::Process(pid)
                } else {
                    DnsResolutionAttribution::Shared
                },
                query: netmetrics_core::normalize_dns_name(&query),
                answers: answers.iter().map(ToString::to_string).collect(),
                ttl_ms,
                observed_at: timestamp,
            });
        }
        BackendEvent::DnsQuery(query) => {
            batch.push(FlowEvent::DnsQuery(query));
        }
        BackendEvent::Interface(sample) => batch.push(FlowEvent::Interface(sample)),
        BackendEvent::Degraded(reason) => batch.push(FlowEvent::Degraded { reason }),
        BackendEvent::Restored { source } => batch.push(FlowEvent::Restored { source }),
    }
    stats
        .flow_evicted
        .store(flow_table.stats().evicted, Ordering::Relaxed);
}

fn select_process_start(
    table: &mut ProcessTable,
    process: &netmetrics_core::ProcessInfo,
    now: u64,
) -> Option<netmetrics_core::ProcessInfo> {
    table.started(process.clone());
    let identity = table.resolve_ref(process.pid, now)?;
    // An ignored event for an older or unverified generation must not be
    // republished using the current occupant of this PID.
    if identity.start_ts != process.identity.start_ts {
        return None;
    }
    Some(netmetrics_core::ProcessInfo {
        pid: process.pid,
        identity: identity.clone(),
    })
}

pub(super) fn effective_dns_ttl(observed: u64, default_ttl_ms: u64) -> Option<u64> {
    let ttl_ms = if observed == 0 {
        default_ttl_ms
    } else {
        observed
    }
    .min(MAX_DNS_TTL_MS);
    (ttl_ms != 0).then_some(ttl_ms)
}

/// Drains rows the upsert displaced, then republishes the flow when its identity changed.
/// Applies an interface index a native event carried, or asks for one when a new
/// flow arrived without it. Returns true when the flow's metadata changed.
fn remember_native_interface(
    flow_table: &mut FlowTable,
    interface_lookup: Option<&InterfaceLookup>,
    outcome: &UpsertOutcome,
    if_index: Option<u32>,
) -> bool {
    if let Some(if_index) = if_index {
        return flow_table.remember_interface(outcome.key, if_index);
    }
    if outcome.inserted {
        request_interface(interface_lookup, outcome.key, outcome.identity_generation);
    }
    false
}

/// Publishes the flow when the upsert, or enrichment applied with it
/// (`metadata_changed`), changed what consumers were told.
fn publish_upsert(
    flow_table: &FlowTable,
    outcome: UpsertOutcome,
    metadata_changed: bool,
    coalescer: &mut IngressCoalescer,
    batch: &mut Vec<FlowEvent>,
) {
    close_displaced(outcome.evicted, coalescer, batch);
    // A superseded row must close before the replacement opens, so consumers see a clean
    // boundary between the two sockets rather than an overlap.
    close_displaced(outcome.superseded, coalescer, batch);
    if !(outcome.inserted
        || outcome.attribution_changed
        || outcome.cookie_learned
        || metadata_changed)
    {
        return;
    }
    if let Some(record) = flow_table.get(&outcome.key) {
        batch.push(FlowEvent::Opened(outcome.key, record.meta));
    }
}

/// Applies a side-channel cookie to an already-tracked flow.
///
/// Enrichment only: an untracked key is ignored rather than opened, so a source that
/// enumerates every socket on the machine cannot invent flows the lifecycle source never
/// reported.
#[allow(clippy::too_many_arguments)]
fn apply_cookie(
    flow_table: &mut FlowTable,
    key: FlowKey,
    pid: u32,
    cookie: SocketCookie,
    timestamp: u64,
    coalescer: &mut IngressCoalescer,
    batch: &mut Vec<FlowEvent>,
    interface_lookup: Option<&InterfaceLookup>,
) {
    if let Some(outcome) = flow_table.learn_cookie(key, pid, cookie, timestamp) {
        if outcome.inserted {
            request_interface(interface_lookup, outcome.key, outcome.identity_generation);
        }
        publish_upsert(flow_table, outcome, false, coalescer, batch);
    }
}

/// Closes a row the flow table dropped, draining any bytes still pending for it.
///
/// Used for every close, a capacity eviction and a cookie supersession included; in each
/// case the coalescer must be drained first or the row's final bytes are lost.
fn close_displaced(
    displaced: Option<netmetrics_core::FlowRecord>,
    coalescer: &mut IngressCoalescer,
    batch: &mut Vec<FlowEvent>,
) {
    if let Some(record) = displaced {
        if let Some(delta) = coalescer.take(&record.key) {
            batch.push(FlowEvent::Bytes(record.key, delta));
        }
        batch.push(FlowEvent::Closed(record.key, record.meta));
    }
}

#[cfg(test)]
mod process_start_tests {
    use super::*;
    use netmetrics_core::{ProcessIdentity, ProcessInfo};

    fn process(path: &str, start_ts: u64) -> ProcessInfo {
        ProcessInfo {
            pid: 42,
            identity: ProcessIdentity {
                executable: path.into(),
                name: "quick".into(),
                start_ts,
            },
        }
    }

    #[test]
    fn stale_start_is_not_republished_as_the_current_generation() {
        let mut table = ProcessTable::new(100, 4);
        select_process_start(&mut table, &process("/bin/current", 20), 21).expect("current");
        assert!(select_process_start(&mut table, &process("/bin/old", 10), 22).is_none());
        assert!(select_process_start(&mut table, &process("quick", 0), 22).is_none());
        assert_eq!(table.resolve(42, 22).unwrap().executable, "/bin/current");
    }

    #[test]
    fn enrichment_preserves_the_path_and_obeys_post_exit_retention() {
        let mut table = ProcessTable::new(100, 4);
        select_process_start(&mut table, &process("/bin/current", 20), 21).expect("current");
        table.stopped(42, 30);
        let selected =
            select_process_start(&mut table, &process("quick", 20), 50).expect("in grace");
        assert_eq!(selected.identity.executable, "/bin/current");
        assert!(select_process_start(&mut table, &process("/bin/current", 20), 131).is_none());
    }
}
