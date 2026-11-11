//! DNS-Client tracing, caller recovery, and DNS answer decoding.

use super::dns_flush::DnsFlusher;
use super::session::{
    ProcessingWorker, RunningTrace, SessionOwners, TraceStartError, classify_trace_error,
    etw_trace_properties, failed_start_may_own_session, report_decode_error_once,
    start_clearing_stale_session, stop_stale_session,
};
use crate::filetime::filetime_to_unix_ms;
use ferrisetw::EventRecord;
use ferrisetw::parser::Parser;
use ferrisetw::provider::{EventFilter, Provider};
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::UserTrace;
use netmetrics_core::{
    DnsCallerIdentity, DnsCallerObservation, DnsCallerRecovery, DnsCallerRecoveryStats,
    DnsCorrelationId, DnsEventKind, DnsQueryEvent, parse_dns_result_addresses_with_ttl,
    unix_now_ms,
};
use netmetrics_sys::{BackendConfig, BackendError, BackendEvent, EventSink};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

const DNS_CLIENT_GUID: &str = "1c95126e-7eea-49a9-a3fe-a378b03ddb4d";

/// DNS-Client event ids worth decoding.
///
/// `3006`/`3008`/`3018`/`3020` are the request/completion pair used for
/// resolution recovery. The outcome, error, NETBIOS, and resolver-operation
/// events additionally carry `ClientPID` (and often `QueryBlob`), so they feed
/// caller correlation even when the query's request/completion pair was missed
/// or its schema carried no caller. Names come from `QueryName` or `Name`.
pub(super) const DNS_CLIENT_EVENT_IDS: [u16; 25] = [
    1013, // name resolution timed out (no servers)
    1014, // name resolution timed out (no servers, System channel)
    1015, // name resolution timed out (single server)
    1016, // name not found (NXDOMAIN)
    1017, // authoritative NODATA
    1018, // link-local answer
    1022, // no LLMNR/NetBIOS fallback
    1024, // response transaction id mismatch
    1025, // response from an unconfigured server
    1026, // response question mismatch
    1027, // resolution failed: no server reachable
    1028, // effective policy matched
    3006, // query called (request)
    3008, // query completed (completion)
    3009, // network query initiated
    3010, // query sent to server
    3011, // response received
    3012, // NETBIOS query initiated
    3013, // NETBIOS query completed
    3014, // NETBIOS query pending
    3016, // cache lookup called
    3018, // cache lookup returned (completion)
    3019, // query wire called
    3020, // query response returned (completion)
    3023, // initiating resolver operation
];

static DNS_CALLER_RECOVERED: AtomicU64 = AtomicU64::new(0);
static DNS_CALLER_AMBIGUOUS: AtomicU64 = AtomicU64::new(0);
static DNS_CALLER_UNMATCHED: AtomicU64 = AtomicU64::new(0);
static DNS_CALLER_EXPIRATIONS: AtomicU64 = AtomicU64::new(0);
static DNS_CALLER_EVICTIONS: AtomicU64 = AtomicU64::new(0);
static DNS_CALLER_RETAINED: AtomicU64 = AtomicU64::new(0);

/// Cumulative DNS answer-caller recovery counters for the current trace.
#[must_use]
pub fn dns_caller_recovery_stats() -> DnsCallerRecoveryStats {
    DnsCallerRecoveryStats {
        recovered: DNS_CALLER_RECOVERED.load(Ordering::Relaxed),
        ambiguous: DNS_CALLER_AMBIGUOUS.load(Ordering::Relaxed),
        unmatched_completions: DNS_CALLER_UNMATCHED.load(Ordering::Relaxed),
        expirations: DNS_CALLER_EXPIRATIONS.load(Ordering::Relaxed),
        capacity_evictions: DNS_CALLER_EVICTIONS.load(Ordering::Relaxed),
        retained: DNS_CALLER_RETAINED.load(Ordering::Relaxed),
    }
}

/// Clears the recovery counters so a new trace starts from zero.
fn reset_dns_caller_stats() {
    DNS_CALLER_RECOVERED.store(0, Ordering::Relaxed);
    DNS_CALLER_AMBIGUOUS.store(0, Ordering::Relaxed);
    DNS_CALLER_UNMATCHED.store(0, Ordering::Relaxed);
    DNS_CALLER_EXPIRATIONS.store(0, Ordering::Relaxed);
    DNS_CALLER_EVICTIONS.store(0, Ordering::Relaxed);
    DNS_CALLER_RETAINED.store(0, Ordering::Relaxed);
}

fn sync_dns_caller_stats(recovery: &DnsCallerRecovery) {
    let stats = recovery.stats();
    DNS_CALLER_RECOVERED.store(stats.recovered, Ordering::Relaxed);
    DNS_CALLER_AMBIGUOUS.store(stats.ambiguous, Ordering::Relaxed);
    DNS_CALLER_UNMATCHED.store(stats.unmatched_completions, Ordering::Relaxed);
    DNS_CALLER_EXPIRATIONS.store(stats.expirations, Ordering::Relaxed);
    DNS_CALLER_EVICTIONS.store(stats.capacity_evictions, Ordering::Relaxed);
    DNS_CALLER_RETAINED.store(stats.retained, Ordering::Relaxed);
}

/// A running DNS-Client trace and the thread that flushes it on request.
pub(super) struct DnsTrace {
    // Declared first so it stops flushing before the session it names is stopped.
    flusher: Option<DnsFlusher>,
    trace: RunningTrace<UserTrace>,
}

impl DnsTrace {
    pub(super) fn processing_result(&self) -> Option<Result<(), String>> {
        self.trace.processing_result()
    }

    pub(super) fn stop(self) -> Result<(), String> {
        let Self { flusher, trace } = self;
        drop(flusher);
        trace.stop()
    }
}

/// Starts the DNS-Client trace, clearing a stale session of the same name first.
///
/// Shares the kernel session's failure mode: the name outlives the process that registered it.
pub(super) fn start_dns_trace(
    config: &BackendConfig,
    name: &str,
    owners: &SessionOwners,
    sink: &EventSink,
) -> Result<DnsTrace, BackendError> {
    let trace =
        start_clearing_stale_session(owners, name, || build_dns_trace(config, name, owners, sink))
            .map_err(|detail| classify_trace_error("DNS-Client ETW", &detail))?;
    Ok(DnsTrace {
        flusher: DnsFlusher::start(name),
        trace,
    })
}

fn build_dns_trace(
    config: &BackendConfig,
    name: &str,
    owners: &SessionOwners,
    sink: &EventSink,
) -> Result<RunningTrace<UserTrace>, TraceStartError> {
    let decode_errors = Arc::new(AtomicU64::new(0));
    let callback_errors = Arc::clone(&decode_errors);
    let sink = sink.clone();
    reset_dns_caller_stats();
    let mut recovery = DnsCallerRecovery::default();
    let callback = move |record: &EventRecord, locator: &SchemaLocator| match decode_dns_events(
        record,
        locator,
        &mut recovery,
    ) {
        Ok(events) => {
            for event in events {
                sink.emit(event);
            }
        }
        Err(()) => report_decode_error_once(&sink, &callback_errors, "windows-dns-client"),
    };
    let provider = Provider::by_guid(DNS_CLIENT_GUID)
        .add_filter(EventFilter::ByEventIds(DNS_CLIENT_EVENT_IDS.to_vec()))
        .add_callback(callback)
        .build();
    let started = UserTrace::new()
        .named(name.to_owned())
        .set_trace_properties(etw_trace_properties((config.buffer_mb / 4).max(1)))
        .enable(provider)
        .start();
    let (trace, handle) = match started {
        Ok(started) => started,
        Err(error) => {
            if failed_start_may_own_session(&error) {
                let _ = stop_stale_session(owners, name);
            }
            return Err(TraceStartError::Native(error));
        }
    };
    match ProcessingWorker::spawn::<UserTrace>(handle, "netmetrics-etw-dns") {
        Ok(worker) => Ok(RunningTrace::new(trace, worker)),
        Err(detail) => {
            let _ = trace.stop();
            Err(TraceStartError::Worker(detail))
        }
    }
}

/// Decodes one DNS-Client event and offers it to the caller-recovery cache.
///
/// Schema roles (see [`DnsCallerRecovery`] for the matching rules):
/// * 3006 is the query request; 3008/3018/3020 are completions that carry
///   answers. `ClientPID` is read whenever the schema exposes it, and only the
///   3008 version 0 header-PID fallback that [`classify_dns_caller`] already
///   treats as the caller is header-derived.
/// * The outcome, error, NETBIOS, and resolver-operation ids in
///   [`DNS_CLIENT_EVENT_IDS`] carry `ClientPID` (and often `QueryBlob`) without
///   answers. They are emitted as caller evidence only, so a blocked query can
///   still be attributed from the event that reported its failure.
/// * Every event may carry `ActivityId` and `QueryBlob`.
#[allow(clippy::too_many_lines)]
fn decode_dns_events(
    record: &EventRecord,
    locator: &SchemaLocator,
    recovery: &mut DnsCallerRecovery,
) -> Result<Vec<BackendEvent>, ()> {
    let event_id = record.event_id();
    if !DNS_CLIENT_EVENT_IDS.contains(&event_id) {
        return Ok(Vec::new());
    }
    let schema = locator.event_schema(record).map_err(|_| ())?;
    let parser = Parser::create(record, &schema);
    let query = parser
        .try_parse::<String>("QueryName")
        .or_else(|_| parser.try_parse::<String>("Name"))
        .map_err(|_| ())?;

    if query.trim().is_empty() {
        return Ok(Vec::new());
    }

    let query_type = parser
        .try_parse::<u32>("QueryType")
        .ok()
        .and_then(|t| u16::try_from(t).ok())
        .unwrap_or(1);

    let status = parser
        .try_parse::<u32>("QueryStatus")
        .or_else(|_| parser.try_parse::<u32>("Status"))
        .or_else(|_| parser.try_parse::<u32>("ResponseStatus"))
        .unwrap_or(0);

    let client_pid = parser
        .try_parse::<u32>("ClientPID")
        .ok()
        .filter(|pid| *pid > 0);

    let caller = classify_dns_caller(event_id, record.version(), record.process_id(), client_pid);

    let activity_guid = record.activity_id();
    let activity_id = if activity_guid.to_u128() != 0 {
        Some(activity_guid.to_u128().to_le_bytes())
    } else {
        None
    };

    let query_blob = parser
        .try_parse::<u64>("QueryBlob")
        .or_else(|_| parser.try_parse::<u32>("QueryBlob").map(u64::from))
        .ok();

    let timestamp = u64::try_from(record.raw_timestamp())
        .ok()
        .and_then(filetime_to_unix_ms)
        .unwrap_or_else(unix_now_ms);

    let correlation = DnsCorrelationId {
        activity_id,
        query_blob,
    };
    let query_event = DnsQueryEvent {
        event_id: Some(event_id),
        event_version: Some(record.version()),
        name: query.clone(),
        query_type,
        status,
        caller,
        correlation,
        timestamp,
    };

    let mut events = vec![BackendEvent::DnsQuery(query_event)];

    // Only the completion schemas carry answers.
    if !matches!(event_id, 3008 | 3018 | 3020) {
        let Some(kind) = dns_event_kind(event_id) else {
            return Ok(events);
        };
        emit_dns_recovery(
            recovery,
            kind,
            event_id,
            record.version(),
            query,
            query_type,
            status,
            caller,
            correlation,
            Vec::new(),
            None,
            timestamp,
            &mut events,
        );
        return Ok(events);
    }

    let results = parser
        .try_parse::<String>("QueryResults")
        .or_else(|_| parser.try_parse::<String>("Address"))
        .unwrap_or_default();
    let (answers, parsed_ttl_ms) = parse_dns_result_addresses_with_ttl(&results);
    if answers.is_empty() {
        return Ok(events);
    }
    let observed_ttl_ms = parser
        .try_parse::<u32>("QueryTtl")
        .or_else(|_| parser.try_parse::<u32>("TTL"))
        .ok()
        .map(|seconds| u64::from(seconds).saturating_mul(1_000))
        .or(parsed_ttl_ms);
    if observed_ttl_ms == Some(0) {
        return Ok(events);
    }

    emit_dns_recovery(
        recovery,
        DnsEventKind::Completion,
        event_id,
        record.version(),
        query,
        query_type,
        status,
        caller,
        correlation,
        answers,
        observed_ttl_ms,
        timestamp,
        &mut events,
    );
    Ok(events)
}

/// Returns the recovery role for a DNS-Client event identifier.
fn dns_event_kind(event_id: u16) -> Option<DnsEventKind> {
    match event_id {
        3006 => Some(DnsEventKind::Request),
        3008 | 3018 | 3020 => Some(DnsEventKind::Completion),
        _ => None,
    }
}

#[allow(clippy::too_many_arguments)]
fn emit_dns_recovery(
    recovery: &mut DnsCallerRecovery,
    kind: DnsEventKind,
    event_id: u16,
    event_version: u8,
    name: String,
    query_type: u16,
    status: u32,
    caller: DnsCallerIdentity,
    correlation: DnsCorrelationId,
    answers: Vec<IpAddr>,
    ttl_ms: Option<u64>,
    timestamp: u64,
    events: &mut Vec<BackendEvent>,
) {
    let observation = DnsCallerObservation {
        kind,
        event_id,
        event_version,
        name,
        query_type,
        status,
        caller,
        correlation,
        answers,
        ttl_ms,
        timestamp,
    };
    for resolution in recovery.observe(observation) {
        events.push(BackendEvent::DnsResolved {
            pid: resolution.pid,
            query: resolution.query,
            answers: resolution.answers,
            ttl_ms: resolution.ttl_ms,
            timestamp: resolution.observed_at,
        });
    }
    sync_dns_caller_stats(recovery);
}

pub(super) fn classify_dns_caller(
    event_id: u16,
    event_version: u8,
    header_pid: u32,
    client_pid: Option<u32>,
) -> DnsCallerIdentity {
    let logging_pid = (header_pid > 0).then_some(header_pid);
    let requesting_pid = client_pid.or_else(|| {
        // EVENT_HEADER::ProcessId identifies the process that generated the event; it does not
        // define that process's DNS role. Event 3008 v0 is the one header-only schema currently
        // validated as caller-owned (and is interpreted that way by osquery). Keep every other
        // header-only event unattributed until its ID/version semantics are verified.
        // Sources:
        // https://learn.microsoft.com/windows/win32/api/evntcons/ns-evntcons-event_header
        // https://github.com/osquery/osquery/blob/master/osquery/events/windows/etw/etw_publisher_dns.cpp#L62
        (event_id == 3008 && event_version == 0).then_some(header_pid)
    });
    DnsCallerIdentity {
        logging_pid,
        requesting_pid: requesting_pid.filter(|pid| *pid > 0),
        resolver_pid: None,
    }
}

#[cfg(test)]
pub(super) fn split_dns_answers(results: &str) -> Vec<String> {
    netmetrics_core::parse_dns_result_text(results).0
}
