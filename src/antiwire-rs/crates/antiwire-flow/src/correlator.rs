//! Correlates DNS-layer block signals with ETW DNS-Client queries.
//!
//! Windows applications pass DNS queries to the DNS Client service (`Dnscache`),
//! which dispatches queries over UDP. As a result, socket-level attribution identifies
//! `Dnscache` (or a helper svchost), while ETW `Microsoft-Windows-DNS-Client` events
//! capture the true `requesting_pid` (`ClientPID`).
//!
//! This module provides a bounded, thread-safe correlator that matches blocked domains
//! and resolver socket owners back to the original caller.

use std::collections::VecDeque;

use netmetrics_core::DnsQueryEvent;
use parking_lot::Mutex;
use time::OffsetDateTime;

const DEFAULT_CAPACITY: usize = 4096;
const DEFAULT_CORRELATION_WINDOW_MS: u64 = 5000;
const CLOCK_SKEW_TOLERANCE_MS: u64 = 1000;
/// The nearest recorded request must be this close to the blocked query for a
/// multi-caller tie-break to be trusted: a block is emitted as the query
/// reaches the local resolver, so its causing request is nearly simultaneous.
const CLOSEST_MATCH_WINDOW_MS: u64 = 1_500;
/// The nearest caller must beat the next distinct caller by this margin.
/// Near-simultaneous callers stay ambiguous rather than being guessed.
const CLOSEST_MATCH_MARGIN_MS: u64 = 750;

#[derive(Clone, Debug)]
struct QueryEntry {
    normalized_name: String,
    logging_pid: Option<u32>,
    requesting_pid: Option<u32>,
    resolver_pid: Option<u32>,
    /// ETW `ActivityId`: stable across the request/response events of one query.
    activity_id: Option<[u8; 16]>,
    /// Payload query identifier (e.g. `QueryBlob`) for the same transaction.
    query_blob: Option<u64>,
    timestamp_ms: u64,
}

/// Identifies the ETW transaction a query event belongs to.
///
/// Events that share a correlation identity describe one DNS query. Treating
/// them as one candidate prevents a request/response pair emitted with
/// different caller roles from looking like two different callers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CorrelationKey {
    /// ETW `ActivityId`, shared by every event of one activity.
    Activity([u8; 16]),
    /// Payload query identifier, used when no `ActivityId` was available.
    Query(u64),
}

impl QueryEntry {
    /// Returns the transaction key when the event carried a correlation id.
    ///
    /// `ActivityId` is preferred over `QueryBlob` because it is the identifier
    /// ETW guarantees to be stable across a query's request and response
    /// events. Backends that supply no ids keep every event as its own
    /// candidate, preserving the window-based ambiguity behaviour for them.
    fn correlation_key(&self) -> Option<CorrelationKey> {
        if let Some(activity_id) = self.activity_id {
            Some(CorrelationKey::Activity(activity_id))
        } else {
            self.query_blob.map(CorrelationKey::Query)
        }
    }
}

/// One DNS transaction's caller evidence, after folding the request/response
/// events that share a correlation id.
#[derive(Clone, Debug)]
struct MergedQuery {
    /// Transaction this evidence belongs to, or `None` for an uncorrelated event.
    key: Option<CorrelationKey>,
    resolver_pid: Option<u32>,
    logging_pid: Option<u32>,
    /// Requesting PID stated explicitly by the event schema (`ClientPID`).
    explicit_requesting_pid: Option<u32>,
    /// Requesting PID that merely repeats the event's logging PID.
    fallback_requesting_pid: Option<u32>,
    /// Smallest distance between any event of this transaction and the target.
    nearest_ms: Option<u64>,
}

impl MergedQuery {
    fn new(key: Option<CorrelationKey>, entry: &QueryEntry, target_ms: u64) -> Self {
        let mut merged = Self {
            key,
            resolver_pid: None,
            logging_pid: None,
            explicit_requesting_pid: None,
            fallback_requesting_pid: None,
            nearest_ms: None,
        };
        merged.merge(entry, target_ms);
        merged
    }

    /// Folds another event of the same transaction into this one.
    ///
    /// The first observed value of each field wins, so callers that iterate
    /// newest-first keep the freshest evidence for every field.
    fn merge(&mut self, entry: &QueryEntry, target_ms: u64) {
        self.resolver_pid = self.resolver_pid.or(entry.resolver_pid);
        self.logging_pid = self.logging_pid.or(entry.logging_pid);
        if let Some(pid) = entry.requesting_pid {
            if entry.logging_pid == Some(pid) {
                self.fallback_requesting_pid.get_or_insert(pid);
            } else {
                self.explicit_requesting_pid.get_or_insert(pid);
            }
        }
        let diff = entry.timestamp_ms.abs_diff(target_ms);
        self.nearest_ms = Some(self.nearest_ms.map_or(diff, |current| current.min(diff)));
    }

    /// The caller, preferring an explicit `ClientPID` over a header-derived PID.
    fn requesting_pid(&self) -> Option<u32> {
        self.explicit_requesting_pid
            .or(self.fallback_requesting_pid)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct DnsCorrelationResult {
    /// The original application PID that initiated the DNS resolution.
    pub requesting_pid: Option<u32>,
    /// The DNS client resolver PID (e.g. Dnscache svchost.exe), if any.
    pub resolver_pid: Option<u32>,
    /// True when multiple distinct requesting processes queried the same domain in the time window.
    pub ambiguous: bool,
    /// Strength and provenance of the caller attribution.
    pub status: DnsAttributionStatus,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum DnsAttributionStatus {
    /// Resolver/socket evidence exists, but the requesting application is unknown.
    #[default]
    Unattributed,
    /// Caller and resolver evidence agree for the same query.
    Correlated,
    /// Caller identity was inferred only from domain/time proximity.
    Inferred,
    /// Multiple callers remain possible.
    Ambiguous,
}

pub struct DnsQueryCorrelator {
    entries: Mutex<VecDeque<QueryEntry>>,
    capacity: usize,
    window_ms: u64,
}

impl Default for DnsQueryCorrelator {
    fn default() -> Self {
        Self::new(DEFAULT_CAPACITY, DEFAULT_CORRELATION_WINDOW_MS)
    }
}

impl DnsQueryCorrelator {
    #[must_use]
    pub(crate) fn new(capacity: usize, window_ms: u64) -> Self {
        Self {
            entries: Mutex::new(VecDeque::with_capacity(capacity.min(DEFAULT_CAPACITY))),
            capacity: capacity.max(16),
            window_ms: window_ms.max(500),
        }
    }

    /// Records an ETW DNS-Client query event into the correlation buffer.
    pub(crate) fn record_query(&self, event: &DnsQueryEvent) {
        let normalized = normalize_domain(&event.name);
        if normalized.is_empty() {
            return;
        }

        let entry = QueryEntry {
            normalized_name: normalized,
            logging_pid: event.caller.logging_pid,
            requesting_pid: event.caller.requesting_pid,
            resolver_pid: event.caller.resolver_pid,
            activity_id: event.correlation.activity_id,
            query_blob: event.correlation.query_blob,
            timestamp_ms: event.timestamp,
        };

        let mut lock = self.entries.lock();
        if lock.len() >= self.capacity {
            lock.pop_front();
        }
        // Kept in timestamp order so a correlation can search to its window.
        // Events arrive almost in order, so this is nearly always the back.
        let at = lock.partition_point(|queued| queued.timestamp_ms <= entry.timestamp_ms);
        lock.insert(at, entry);
    }

    /// Correlates a blocked DNS domain and socket-owner PID with recorded ETW queries.
    pub(crate) fn correlate(
        &self,
        domain: &str,
        socket_pid: u32,
        event_time: Option<OffsetDateTime>,
    ) -> DnsCorrelationResult {
        let normalized = normalize_domain(domain);
        if normalized.is_empty() {
            return DnsCorrelationResult {
                requesting_pid: None,
                resolver_pid: (socket_pid > 0).then_some(socket_pid),
                ambiguous: false,
                status: DnsAttributionStatus::Unattributed,
            };
        }

        let target_ms = event_time.map_or_else(
            || unix_timestamp_ms(OffsetDateTime::now_utc()),
            unix_timestamp_ms,
        );

        let lock = self.entries.lock();

        // Fold events that share a correlation identity into one transaction, so
        // a request/response pair reported through different caller roles cannot
        // look like two callers. Events without an id stay independent.
        let earliest = target_ms.saturating_sub(self.window_ms);
        let latest = target_ms.saturating_add(self.window_ms.max(CLOCK_SKEW_TOLERANCE_MS));
        let start = lock.partition_point(|entry| entry.timestamp_ms < earliest);
        let end = lock.partition_point(|entry| entry.timestamp_ms <= latest);
        let mut merged: Vec<MergedQuery> = Vec::new();
        for entry in lock.range(start..end).rev() {
            if !entry_matches(entry, &normalized, target_ms, self.window_ms) {
                continue;
            }
            match entry.correlation_key() {
                Some(key) => {
                    if let Some(existing) = merged.iter_mut().find(|query| query.key == Some(key)) {
                        existing.merge(entry, target_ms);
                    } else {
                        merged.push(MergedQuery::new(Some(key), entry, target_ms));
                    }
                }
                None => merged.push(MergedQuery::new(None, entry, target_ms)),
            }
        }

        if socket_pid == 0 {
            return resolve_caller_only(&merged);
        }

        let mut resolvers = Tally::default();
        let mut direct = Tally::default();
        let mut logging = Tally::default();
        for query in &merged {
            // 1. Prefer roles the event schema states explicitly.
            if query.resolver_pid == Some(socket_pid) {
                resolvers.observe(query);
            }
            // 2. Direct caller match (the socket owner itself is the requesting process).
            if query.requesting_pid() == Some(socket_pid) {
                direct.observe(query);
            }
            // 3. A neutral logging PID can be assigned the resolver role only after
            //    independent socket ownership agrees, and only when the schema
            //    identified a different caller.
            if query.logging_pid == Some(socket_pid)
                && query.requesting_pid().is_some()
                && query.requesting_pid() != Some(socket_pid)
            {
                logging.observe(query);
            }
        }

        // A resolver match that names no caller says only that the socket owner
        // resolved the name, so a direct or logging match can still name one.
        if resolvers.has_requester() {
            return resolvers.resolve(Some(socket_pid), DnsAttributionStatus::Correlated);
        }
        if !direct.is_empty() {
            return direct.resolve(None, DnsAttributionStatus::Correlated);
        }
        if !logging.is_empty() {
            return logging.resolve(Some(socket_pid), DnsAttributionStatus::Correlated);
        }

        // A known socket owner is stronger ownership evidence than domain/time
        // proximity, but no query in the window matched it.
        DnsCorrelationResult {
            requesting_pid: None,
            resolver_pid: Some(socket_pid),
            ambiguous: false,
            status: DnsAttributionStatus::Unattributed,
        }
    }
}

/// Resolves the caller from recorded queries alone, without a socket owner.
///
/// Exactly one distinct caller is always trusted. Multiple callers are only
/// collapsed when one request is clearly nearest the block; otherwise the
/// evidence stays ambiguous.
fn resolve_caller_only(merged: &[MergedQuery]) -> DnsCorrelationResult {
    let mut first_resolver_pid = None;
    let mut per_pid: Vec<(u32, u64)> = Vec::new();
    for query in merged {
        if first_resolver_pid.is_none() {
            first_resolver_pid = query.resolver_pid;
        }
        let (Some(pid), Some(diff)) = (query.requesting_pid(), query.nearest_ms) else {
            continue;
        };
        match per_pid.iter_mut().find(|(existing, _)| *existing == pid) {
            Some((_, best)) => *best = (*best).min(diff),
            None => per_pid.push((pid, diff)),
        }
    }

    if per_pid.is_empty() {
        return DnsCorrelationResult {
            requesting_pid: None,
            resolver_pid: first_resolver_pid,
            ambiguous: false,
            status: DnsAttributionStatus::Unattributed,
        };
    }
    per_pid.sort_unstable_by_key(|(_, diff)| *diff);
    if per_pid.len() == 1 {
        return DnsCorrelationResult {
            requesting_pid: Some(per_pid[0].0),
            resolver_pid: first_resolver_pid,
            ambiguous: false,
            status: DnsAttributionStatus::Inferred,
        };
    }

    let (nearest_pid, nearest_diff) = per_pid[0];
    let runner_up_diff = per_pid[1].1;
    if nearest_diff <= CLOSEST_MATCH_WINDOW_MS
        && runner_up_diff.saturating_sub(nearest_diff) >= CLOSEST_MATCH_MARGIN_MS
    {
        DnsCorrelationResult {
            requesting_pid: Some(nearest_pid),
            resolver_pid: first_resolver_pid,
            ambiguous: false,
            status: DnsAttributionStatus::Inferred,
        }
    } else {
        DnsCorrelationResult {
            requesting_pid: None,
            resolver_pid: first_resolver_pid,
            ambiguous: true,
            status: DnsAttributionStatus::Ambiguous,
        }
    }
}

/// Whether a recorded query matches the target domain inside the correlation window.
fn entry_matches(entry: &QueryEntry, normalized: &str, target_ms: u64, window_ms: u64) -> bool {
    if entry.normalized_name != normalized {
        return false;
    }
    let diff = entry.timestamp_ms.abs_diff(target_ms);
    diff <= window_ms || (entry.timestamp_ms > target_ms && diff <= CLOCK_SKEW_TOLERANCE_MS)
}

/// Accumulator for one candidate bucket.
///
/// Only three outcomes matter: no requesting PID, exactly one, or more than
/// one (which is always ambiguous). Tracking the second distinct PID is enough,
/// so a `Vec` + `contains` dedup is unnecessary. Inputs are already folded per
/// ETW transaction by [`MergedQuery`].
#[derive(Default)]
struct Tally {
    count: usize,
    first_requesting_pid: Option<u32>,
    distinct_requesting_pids: u8,
    first_resolver_pid: Option<u32>,
}

impl Tally {
    fn observe(&mut self, query: &MergedQuery) {
        self.count += 1;
        if let Some(pid) = query.requesting_pid() {
            match self.first_requesting_pid {
                None => {
                    self.first_requesting_pid = Some(pid);
                    self.distinct_requesting_pids = 1;
                }
                Some(first) if first == pid => {}
                Some(_) => self.distinct_requesting_pids = 2,
            }
        }
        if self.first_resolver_pid.is_none() {
            self.first_resolver_pid = query.resolver_pid;
        }
    }

    fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Whether any observed query named its requesting process.
    fn has_requester(&self) -> bool {
        self.distinct_requesting_pids > 0
    }

    fn resolve(
        self,
        resolver_pid: Option<u32>,
        matched_status: DnsAttributionStatus,
    ) -> DnsCorrelationResult {
        let resolver_pid = resolver_pid.or(self.first_resolver_pid);
        match self.distinct_requesting_pids {
            0 => DnsCorrelationResult {
                requesting_pid: None,
                resolver_pid,
                ambiguous: false,
                status: DnsAttributionStatus::Unattributed,
            },
            1 => DnsCorrelationResult {
                requesting_pid: self.first_requesting_pid,
                resolver_pid,
                ambiguous: false,
                status: matched_status,
            },
            // Multiple applications requested the same name in the same window;
            // keep ambiguous ownership explicit to prevent incorrect attribution.
            _ => DnsCorrelationResult {
                requesting_pid: None,
                resolver_pid,
                ambiguous: true,
                status: DnsAttributionStatus::Ambiguous,
            },
        }
    }
}

fn unix_timestamp_ms(timestamp: OffsetDateTime) -> u64 {
    u64::try_from(timestamp.unix_timestamp_nanos() / 1_000_000).unwrap_or(0)
}

fn normalize_domain(domain: &str) -> String {
    domain.trim_end_matches('.').to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use netmetrics_core::{DnsCallerIdentity, DnsCorrelationId};

    #[test]
    fn single_query_correlates_to_requesting_pid() {
        let correlator = DnsQueryCorrelator::default();
        let now_ms = 1_000_000;

        correlator.record_query(&DnsQueryEvent {
            event_id: None,
            event_version: None,
            name: "malicious.example.com".to_owned(),
            query_type: 1,
            status: 0,
            caller: DnsCallerIdentity {
                logging_pid: None,
                requesting_pid: Some(4242),
                resolver_pid: Some(1000), // Dnscache
            },
            correlation: DnsCorrelationId::default(),
            timestamp: now_ms,
        });

        // Query arrives from socket owned by Dnscache (pid 1000)
        let result = correlator.correlate(
            "malicious.example.com.",
            1000,
            Some(
                OffsetDateTime::from_unix_timestamp_nanos(i128::from(now_ms) * 1_000_000).unwrap(),
            ),
        );

        assert_eq!(result.requesting_pid, Some(4242));
        assert_eq!(result.resolver_pid, Some(1000));
        assert!(!result.ambiguous);
    }

    #[test]
    fn resolver_pid_disambiguates_multiple_requests() {
        let correlator = DnsQueryCorrelator::default();
        let now_ms = 1_000_000;

        // Query 1: from PID 4242 via resolver PID 1000
        correlator.record_query(&DnsQueryEvent {
            event_id: None,
            event_version: None,
            name: "example.com".to_owned(),
            query_type: 1,
            status: 0,
            caller: DnsCallerIdentity {
                logging_pid: None,
                requesting_pid: Some(4242),
                resolver_pid: Some(1000),
            },
            correlation: DnsCorrelationId::default(),
            timestamp: now_ms,
        });

        // Query 2: from PID 9999 via resolver PID 2000
        correlator.record_query(&DnsQueryEvent {
            event_id: None,
            event_version: None,
            name: "example.com".to_owned(),
            query_type: 1,
            status: 0,
            caller: DnsCallerIdentity {
                logging_pid: None,
                requesting_pid: Some(9999),
                resolver_pid: Some(2000),
            },
            correlation: DnsCorrelationId::default(),
            timestamp: now_ms,
        });

        // Correlate with socket owner 1000
        let result = correlator.correlate(
            "example.com",
            1000,
            Some(
                OffsetDateTime::from_unix_timestamp_nanos(i128::from(now_ms) * 1_000_000).unwrap(),
            ),
        );

        assert_eq!(result.requesting_pid, Some(4242));
        assert_eq!(result.resolver_pid, Some(1000));
        assert!(!result.ambiguous);
    }

    #[test]
    fn socket_owner_can_confirm_matching_logging_process_without_relabeling_event() {
        let correlator = DnsQueryCorrelator::default();
        let now_ms = 1_000_000;

        correlator.record_query(&DnsQueryEvent {
            event_id: Some(3018),
            event_version: Some(2),
            name: "example.com".to_owned(),
            query_type: 1,
            status: 0,
            caller: DnsCallerIdentity {
                logging_pid: Some(1000),
                requesting_pid: Some(4242),
                resolver_pid: None,
            },
            correlation: DnsCorrelationId::default(),
            timestamp: now_ms,
        });

        let result = correlator.correlate(
            "example.com",
            1000,
            Some(
                OffsetDateTime::from_unix_timestamp_nanos(i128::from(now_ms) * 1_000_000).unwrap(),
            ),
        );

        assert_eq!(result.requesting_pid, Some(4242));
        assert_eq!(result.resolver_pid, Some(1000));
        assert_eq!(result.status, DnsAttributionStatus::Correlated);
    }

    #[test]
    fn caller_owned_logging_process_is_not_recast_as_resolver() {
        let correlator = DnsQueryCorrelator::default();
        let now_ms = 1_000_000;

        correlator.record_query(&DnsQueryEvent {
            event_id: Some(3008),
            event_version: Some(0),
            name: "example.com".to_owned(),
            query_type: 1,
            status: 0,
            caller: DnsCallerIdentity {
                logging_pid: Some(4242),
                requesting_pid: Some(4242),
                resolver_pid: None,
            },
            correlation: DnsCorrelationId::default(),
            timestamp: now_ms,
        });

        let result = correlator.correlate(
            "example.com",
            4242,
            Some(
                OffsetDateTime::from_unix_timestamp_nanos(i128::from(now_ms) * 1_000_000).unwrap(),
            ),
        );

        assert_eq!(result.requesting_pid, Some(4242));
        assert_eq!(result.resolver_pid, None);
    }

    #[test]
    fn ambiguous_query_without_resolver_match_is_marked_ambiguous() {
        let correlator = DnsQueryCorrelator::default();
        let now_ms = 1_000_000;

        // Two queries for same domain with different requesting PIDs under same resolver
        correlator.record_query(&DnsQueryEvent {
            event_id: None,
            event_version: None,
            name: "shared.example".to_owned(),
            query_type: 1,
            status: 0,
            caller: DnsCallerIdentity {
                logging_pid: None,
                requesting_pid: Some(1111),
                resolver_pid: Some(1000),
            },
            correlation: DnsCorrelationId::default(),
            timestamp: now_ms,
        });
        correlator.record_query(&DnsQueryEvent {
            event_id: None,
            event_version: None,
            name: "shared.example".to_owned(),
            query_type: 1,
            status: 0,
            caller: DnsCallerIdentity {
                logging_pid: None,
                requesting_pid: Some(2222),
                resolver_pid: Some(1000),
            },
            correlation: DnsCorrelationId::default(),
            timestamp: now_ms,
        });

        let result = correlator.correlate(
            "shared.example",
            1000,
            Some(
                OffsetDateTime::from_unix_timestamp_nanos(i128::from(now_ms) * 1_000_000).unwrap(),
            ),
        );

        assert!(result.ambiguous);
        assert_eq!(result.requesting_pid, None);
        assert_eq!(result.resolver_pid, Some(1000));
    }

    #[test]
    fn expired_queries_are_not_correlated() {
        let correlator = DnsQueryCorrelator::new(100, 2000);
        let now_ms = 1_000_000;

        correlator.record_query(&DnsQueryEvent {
            event_id: None,
            event_version: None,
            name: "old.example".to_owned(),
            query_type: 1,
            status: 0,
            caller: DnsCallerIdentity {
                logging_pid: None,
                requesting_pid: Some(4242),
                resolver_pid: Some(1000),
            },
            correlation: DnsCorrelationId::default(),
            timestamp: now_ms,
        });

        // Block event happens 10 seconds later
        let result = correlator.correlate(
            "old.example",
            1000,
            Some(
                OffsetDateTime::from_unix_timestamp_nanos(i128::from(now_ms + 10_000) * 1_000_000)
                    .unwrap(),
            ),
        );

        assert_eq!(result.requesting_pid, None);
        assert_eq!(result.resolver_pid, Some(1000));
        assert_eq!(result.status, DnsAttributionStatus::Unattributed);
        assert!(!result.ambiguous);
    }

    /// A socket owner that matches no recorded query must not be replaced by an
    /// unrelated query's requesting PID: only the resolver evidence survives.
    #[test]
    fn unrelated_resolver_does_not_replace_a_known_socket_owner() {
        let correlator = DnsQueryCorrelator::default();
        correlator.record_query(&DnsQueryEvent {
            event_id: None,
            event_version: None,
            name: "shared.example".to_owned(),
            query_type: 1,
            status: 0,
            caller: DnsCallerIdentity {
                logging_pid: None,
                requesting_pid: Some(4242),
                resolver_pid: Some(1000),
            },
            correlation: DnsCorrelationId::default(),
            timestamp: 1_000_000,
        });

        let result = correlator.correlate(
            "shared.example",
            2000,
            Some(OffsetDateTime::from_unix_timestamp(1000).unwrap()),
        );

        assert_eq!(result.requesting_pid, None);
        assert_eq!(result.resolver_pid, Some(2000));
        assert_eq!(result.status, DnsAttributionStatus::Unattributed);
    }

    /// With no matching query at all, the socket owner is still surfaced as the
    /// resolver even though no caller can be attributed.
    #[test]
    fn socket_owner_without_caller_evidence_remains_resolver_only() {
        let correlator = DnsQueryCorrelator::default();

        let result = correlator.correlate(
            "uncorrelated.example",
            1000,
            Some(OffsetDateTime::from_unix_timestamp(1000).unwrap()),
        );

        assert_eq!(result.requesting_pid, None);
        assert_eq!(result.resolver_pid, Some(1000));
        assert_eq!(result.status, DnsAttributionStatus::Unattributed);
    }

    /// A block is emitted as its query arrives, so the clearly nearest request
    /// is the one that caused it even when older callers are still in the window.
    #[test]
    fn nearest_request_disambiguates_multiple_callers() {
        let correlator = DnsQueryCorrelator::default();
        let target_ms = 1_000_000;
        correlator.record_query(&query_event(
            "popular.example",
            None,
            Some(1111),
            None,
            DnsCorrelationId::default(),
            target_ms - 40,
        ));
        correlator.record_query(&query_event(
            "popular.example",
            None,
            Some(2222),
            None,
            DnsCorrelationId::default(),
            target_ms - 3_000,
        ));

        let result = correlator.correlate(
            "popular.example",
            0,
            Some(
                OffsetDateTime::from_unix_timestamp_nanos(i128::from(target_ms) * 1_000_000)
                    .unwrap(),
            ),
        );

        assert_eq!(result.requesting_pid, Some(1111));
        assert_eq!(result.status, DnsAttributionStatus::Inferred);
        assert!(!result.ambiguous);
    }

    /// Two callers that close in time are indistinguishable and must stay
    /// ambiguous rather than being guessed at.
    #[test]
    fn near_simultaneous_callers_stay_ambiguous() {
        let correlator = DnsQueryCorrelator::default();
        let target_ms = 1_000_000;
        for (pid, offset) in [(1111_u32, 100_u64), (2222, 300)] {
            correlator.record_query(&query_event(
                "simultaneous.example",
                None,
                Some(pid),
                None,
                DnsCorrelationId::default(),
                target_ms - offset,
            ));
        }

        let result = correlator.correlate(
            "simultaneous.example",
            0,
            Some(
                OffsetDateTime::from_unix_timestamp_nanos(i128::from(target_ms) * 1_000_000)
                    .unwrap(),
            ),
        );

        assert_eq!(result.requesting_pid, None);
        assert!(result.ambiguous);
        assert_eq!(result.status, DnsAttributionStatus::Ambiguous);
    }

    /// A nearest caller outside the tight window cannot explain an immediate
    /// block, so the time gap does not become an attribution.
    #[test]
    fn distant_nearest_caller_does_not_disambiguate() {
        let correlator = DnsQueryCorrelator::default();
        let target_ms = 1_000_000;
        for (pid, offset) in [(1111_u32, 4_000_u64), (2222, 4_900)] {
            correlator.record_query(&query_event(
                "stale.example",
                None,
                Some(pid),
                None,
                DnsCorrelationId::default(),
                target_ms - offset,
            ));
        }

        let result = correlator.correlate(
            "stale.example",
            0,
            Some(
                OffsetDateTime::from_unix_timestamp_nanos(i128::from(target_ms) * 1_000_000)
                    .unwrap(),
            ),
        );

        assert_eq!(result.requesting_pid, None);
        assert!(result.ambiguous);
    }

    fn query_event(
        name: &str,
        logging_pid: Option<u32>,
        requesting_pid: Option<u32>,
        resolver_pid: Option<u32>,
        correlation: DnsCorrelationId,
        timestamp: u64,
    ) -> DnsQueryEvent {
        DnsQueryEvent {
            event_id: None,
            event_version: None,
            name: name.to_owned(),
            query_type: 1,
            status: 0,
            caller: DnsCallerIdentity {
                logging_pid,
                requesting_pid,
                resolver_pid,
            },
            correlation,
            timestamp,
        }
    }

    /// A request/response pair sharing an `ActivityId` describes one query. The
    /// response's header-derived PID must not turn the transaction's explicit
    /// `ClientPID` into a second caller.
    #[test]
    fn request_and_response_of_one_activity_resolve_to_the_explicit_caller() {
        let correlator = DnsQueryCorrelator::default();
        let activity_id = [7_u8; 16];
        let now_ms = 1_000_000;
        let correlation = DnsCorrelationId {
            activity_id: Some(activity_id),
            query_blob: Some(1),
        };

        // Query event: Dnscache logs it, but the ClientPID is the application.
        correlator.record_query(&query_event(
            "role.example",
            Some(1000),
            Some(4242),
            None,
            correlation,
            now_ms,
        ));
        // Response event for the same activity: the header PID is Dnscache.
        correlator.record_query(&query_event(
            "role.example",
            Some(1000),
            Some(1000),
            None,
            correlation,
            now_ms,
        ));

        let result = correlator.correlate(
            "role.example",
            1000,
            Some(
                OffsetDateTime::from_unix_timestamp_nanos(i128::from(now_ms) * 1_000_000).unwrap(),
            ),
        );

        assert_eq!(result.requesting_pid, Some(4242));
        assert_eq!(result.resolver_pid, Some(1000));
        assert_eq!(result.status, DnsAttributionStatus::Correlated);
    }

    /// Queries in different activities really are different transactions, so
    /// distinct callers still surface as ambiguous.
    #[test]
    fn distinct_activities_with_distinct_callers_remain_ambiguous() {
        let correlator = DnsQueryCorrelator::default();
        let now_ms = 1_000_000;

        for (activity, requesting_pid) in [([1_u8; 16], 1111_u32), ([2_u8; 16], 2222_u32)] {
            correlator.record_query(&query_event(
                "multi.example",
                None,
                Some(requesting_pid),
                Some(1000),
                DnsCorrelationId {
                    activity_id: Some(activity),
                    query_blob: None,
                },
                now_ms,
            ));
        }

        let result = correlator.correlate(
            "multi.example",
            1000,
            Some(
                OffsetDateTime::from_unix_timestamp_nanos(i128::from(now_ms) * 1_000_000).unwrap(),
            ),
        );

        assert!(result.ambiguous);
        assert_eq!(result.requesting_pid, None);
        assert_eq!(result.status, DnsAttributionStatus::Ambiguous);
    }

    /// Events are searched by time, so the window's edges must hold however
    /// the events arrived.
    #[test]
    fn only_events_inside_the_window_count_whatever_order_they_arrive_in() {
        let correlator = DnsQueryCorrelator::default();
        let target_ms = 1_000_000;
        let window = DEFAULT_CORRELATION_WINDOW_MS;
        for (pid, timestamp) in [
            (3333, target_ms + window.max(CLOCK_SKEW_TOLERANCE_MS) + 1),
            (1111, target_ms - window),
            (2222, target_ms - window - 1),
        ] {
            correlator.record_query(&query_event(
                "edge.example",
                None,
                Some(pid),
                None,
                DnsCorrelationId::default(),
                timestamp,
            ));
        }
        let timestamps: Vec<_> = correlator
            .entries
            .lock()
            .iter()
            .map(|entry| entry.timestamp_ms)
            .collect();
        assert!(timestamps.is_sorted());

        let result = correlator.correlate(
            "edge.example",
            0,
            Some(
                OffsetDateTime::from_unix_timestamp_nanos(i128::from(target_ms) * 1_000_000)
                    .unwrap(),
            ),
        );

        assert_eq!(result.requesting_pid, Some(1111));
        assert!(!result.ambiguous);
    }

    /// A resolver match that names no caller used to end the search, so a
    /// query the socket owner made itself was never considered.
    #[test]
    fn a_callerless_resolver_match_does_not_hide_a_direct_caller() {
        let correlator = DnsQueryCorrelator::default();
        let now_ms = 1_000_000;
        correlator.record_query(&query_event(
            "direct.example",
            None,
            None,
            Some(3000),
            DnsCorrelationId::default(),
            now_ms,
        ));
        correlator.record_query(&query_event(
            "direct.example",
            None,
            Some(3000),
            None,
            DnsCorrelationId::default(),
            now_ms,
        ));

        let result = correlator.correlate(
            "direct.example",
            3000,
            Some(
                OffsetDateTime::from_unix_timestamp_nanos(i128::from(now_ms) * 1_000_000).unwrap(),
            ),
        );

        assert_eq!(result.requesting_pid, Some(3000));
        assert_eq!(result.status, DnsAttributionStatus::Correlated);
    }
}
