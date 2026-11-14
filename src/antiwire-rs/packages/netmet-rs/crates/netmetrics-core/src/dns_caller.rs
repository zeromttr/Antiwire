//! Recovers DNS answer callers from a matching query request.
//!
//! Windows DNS-Client ETW splits one lookup across several events. The
//! `Microsoft-Windows-DNS-Client` schemas observed by this backend are:
//!
//! | Event | Role | Caller evidence | Correlation |
//! |-------|------|-----------------|-------------|
//! | 3006 | request: "DNS query is called" | `ClientPID` payload | `ActivityId`, `QueryBlob` |
//! | 3008 | completion: "DNS query is completed" | `ClientPID` when present, otherwise the header PID on version 0 | `ActivityId`, `QueryBlob` |
//! | 3018 | completion: cache lookup returned | `ClientPID` when present | `ActivityId`, `QueryBlob` |
//! | 3020 | completion: wire response returned | `ClientPID` when present | `ActivityId`, `QueryBlob` |
//!
//! A completion often carries the answer but no caller, while the request that
//! preceded it named the requesting process. This module owns a bounded
//! transaction cache that folds those events together so a missing completion
//! caller can be recovered from an unambiguous request. Evidence is matched by
//! `ActivityId` first and by query identifier second, never by domain and time
//! proximity alone, and contradictory authoritative callers stay shared.

use std::collections::VecDeque;
use std::net::IpAddr;

use crate::{DnsCallerIdentity, DnsCorrelationId, normalize_dns_name};

/// How long an unmatched transaction stays eligible for delayed recovery.
const RETENTION_MS: u64 = 10_000;
/// Time window allowed for a query-identifier (not activity) match.
const MATCH_WINDOW_MS: u64 = 2_000;
/// Hard upper bound on retained transactions.
const MAX_CAPACITY: usize = 8_192;

/// Which side of a DNS transaction an event represents.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsEventKind {
    /// Query initiated; normally carries the requesting caller.
    Request,
    /// Query completed; normally carries the answers.
    Completion,
}

/// One decoded DNS-Client event offered to [`DnsCallerRecovery`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsCallerObservation {
    /// Request or completion.
    pub kind: DnsEventKind,
    /// Native source event identifier.
    pub event_id: u16,
    /// Native source schema version.
    pub event_version: u8,
    /// Query name, normalized by the recovery cache.
    pub name: String,
    /// DNS query record type.
    pub query_type: u16,
    /// Native status code; non-zero marks a failed response.
    pub status: u32,
    /// Requesting and resolver identity reported by the event.
    pub caller: DnsCallerIdentity,
    /// Activity and query identifiers reported by the event.
    pub correlation: DnsCorrelationId,
    /// Answer addresses, for a completion.
    pub answers: Vec<IpAddr>,
    /// Answer lifetime in milliseconds. `None` leaves the collector default.
    pub ttl_ms: Option<u64>,
    /// Original event timestamp, Unix epoch milliseconds.
    pub timestamp: u64,
}

/// A resolution the DNS path should publish.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsCallerResolution {
    /// Requesting process, or zero for a shared mapping.
    pub pid: u32,
    /// Normalized query name.
    pub query: String,
    /// Answer addresses.
    pub answers: Vec<IpAddr>,
    /// Answer lifetime in milliseconds; zero asks for the configured default.
    pub ttl_ms: u64,
    /// Original answer timestamp, Unix epoch milliseconds.
    pub observed_at: u64,
    /// True when this corrects an earlier shared emission.
    pub upgrade: bool,
}

/// Cumulative recovery diagnostics.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DnsCallerRecoveryStats {
    /// Completions attributed to a request-derived caller.
    pub recovered: u64,
    /// Transactions abandoned because callers contradicted each other.
    pub ambiguous: u64,
    /// Completions published without a process caller.
    pub unmatched_completions: u64,
    /// Retained transactions dropped after their window.
    pub expirations: u64,
    /// Retained transactions dropped to make room.
    pub capacity_evictions: u64,
    /// Transactions currently retained.
    pub retained: u64,
}

/// Bounded request/completion transaction cache.
#[derive(Debug)]
pub struct DnsCallerRecovery {
    records: VecDeque<TxnRecord>,
    capacity: usize,
    retention_ms: u64,
    match_window_ms: u64,
    stats: DnsCallerRecoveryStats,
}

#[derive(Debug)]
struct TxnRecord {
    activity: Option<[u8; 16]>,
    blob: Option<u64>,
    name: String,
    qtype: u16,
    request: Option<CallerEvidence>,
    request_conflict: bool,
    completion: Option<CompletionEvidence>,
    first_seen: u64,
    expires_at: u64,
}

#[derive(Clone, Copy, Debug)]
struct CallerEvidence {
    pid: u32,
    strength: CallerStrength,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CallerStrength {
    /// The schema only exposes a header PID that merely repeats the logger.
    Weak,
    /// An explicit `ClientPID` (or a caller distinct from the logger).
    Strong,
}

#[derive(Debug)]
struct CompletionEvidence {
    answers: Vec<IpAddr>,
    ttl_ms: Option<u64>,
    timestamp: u64,
    caller: Option<CallerEvidence>,
    emitted_shared: bool,
    emitted_process: Option<u32>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Match {
    None,
    One(usize),
    Ambiguous,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Resolution {
    Shared,
    Process(u32),
    Ambiguous,
}

impl Default for DnsCallerRecovery {
    fn default() -> Self {
        Self::new(2_048)
    }
}

impl DnsCallerRecovery {
    /// Creates a cache holding at most `capacity` transactions.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self::with_timings(capacity, RETENTION_MS, MATCH_WINDOW_MS)
    }

    /// Creates a cache with explicit retention and identifier-match windows.
    #[must_use]
    pub fn with_timings(capacity: usize, retention_ms: u64, match_window_ms: u64) -> Self {
        Self {
            records: VecDeque::new(),
            capacity: capacity.clamp(1, MAX_CAPACITY),
            retention_ms,
            match_window_ms,
            stats: DnsCallerRecoveryStats::default(),
        }
    }

    /// Folds one decoded event in and returns any resolutions to publish.
    ///
    /// The returned order is publish order: an immediate shared resolution may
    /// precede a later process-scoped upgrade for the same answers.
    // `observe` owns the decoded event because it is the boundary value built by
    // the platform decoder; every read happens through a borrowed sub-function.
    #[allow(clippy::needless_pass_by_value)]
    pub fn observe(&mut self, observation: DnsCallerObservation) -> Vec<DnsCallerResolution> {
        self.sweep(observation.timestamp);
        let name = normalize_dns_name(&observation.name);
        if name.is_empty() {
            return Vec::new();
        }
        let caller = caller_evidence(&observation.caller);
        match observation.kind {
            DnsEventKind::Request => self.observe_request(&observation, &name, caller),
            DnsEventKind::Completion => self.observe_completion(&observation, &name, caller),
        }
    }

    /// Drops transactions whose retention window has passed.
    pub fn sweep(&mut self, now: u64) -> usize {
        let before = self.records.len();
        self.records.retain(|record| record.expires_at > now);
        let removed = before - self.records.len();
        self.stats.expirations = self
            .stats
            .expirations
            .saturating_add(u64::try_from(removed).unwrap_or(u64::MAX));
        removed
    }

    /// Returns cumulative counters.
    #[must_use]
    pub fn stats(&self) -> DnsCallerRecoveryStats {
        DnsCallerRecoveryStats {
            retained: u64::try_from(self.records.len()).unwrap_or(u64::MAX),
            ..self.stats
        }
    }

    /// Drops every retained transaction without touching the counters.
    pub fn clear(&mut self) {
        self.records.clear();
    }

    fn observe_request(
        &mut self,
        observation: &DnsCallerObservation,
        name: &str,
        caller: Option<CallerEvidence>,
    ) -> Vec<DnsCallerResolution> {
        let activity = observation.correlation.activity_id;
        let blob = observation.correlation.query_blob;
        if activity.is_none() && blob.is_none() {
            return Vec::new();
        }
        // A request without caller evidence cannot improve any completion.
        let Some(caller) = caller else {
            return Vec::new();
        };

        match self.find_match(
            activity,
            blob,
            name,
            observation.query_type,
            observation.timestamp,
        ) {
            Match::Ambiguous => {
                self.stats.ambiguous = self.stats.ambiguous.saturating_add(1);
                Vec::new()
            }
            Match::None => {
                self.push_record(TxnRecord {
                    activity,
                    blob,
                    name: name.to_owned(),
                    qtype: observation.query_type,
                    request: Some(caller),
                    request_conflict: false,
                    completion: None,
                    first_seen: observation.timestamp,
                    expires_at: observation.timestamp.saturating_add(self.retention_ms),
                });
                Vec::new()
            }
            Match::One(index) => {
                let mut out = Vec::new();
                {
                    let record = &mut self.records[index];
                    merge_request_evidence(record, caller);
                    record.activity = record.activity.or(activity);
                    record.blob = record.blob.or(blob);
                    record.expires_at = record
                        .expires_at
                        .max(observation.timestamp.saturating_add(self.retention_ms));
                }
                self.emit_resolution(index, &mut out);
                out
            }
        }
    }

    fn observe_completion(
        &mut self,
        observation: &DnsCallerObservation,
        name: &str,
        caller: Option<CallerEvidence>,
    ) -> Vec<DnsCallerResolution> {
        if observation.status != 0 || observation.answers.is_empty() {
            return Vec::new();
        }
        // An explicit zero lifetime means "do not cache"; a missing lifetime
        // (`None`) asks the collector for its configured default.
        if observation.ttl_ms == Some(0) {
            return Vec::new();
        }

        let activity = observation.correlation.activity_id;
        let blob = observation.correlation.query_blob;
        if activity.is_none() && blob.is_none() {
            return self.emit_uncorrelated(observation, name, caller);
        }

        match self.find_match(
            activity,
            blob,
            name,
            observation.query_type,
            observation.timestamp,
        ) {
            Match::Ambiguous => {
                self.stats.ambiguous = self.stats.ambiguous.saturating_add(1);
                self.emit_uncorrelated(observation, name, caller)
            }
            Match::None => {
                self.push_record(TxnRecord {
                    activity,
                    blob,
                    name: name.to_owned(),
                    qtype: observation.query_type,
                    request: None,
                    request_conflict: false,
                    completion: Some(CompletionEvidence {
                        answers: observation.answers.clone(),
                        ttl_ms: observation.ttl_ms,
                        timestamp: observation.timestamp,
                        caller,
                        emitted_shared: false,
                        emitted_process: None,
                    }),
                    first_seen: observation.timestamp,
                    expires_at: observation.timestamp.saturating_add(self.retention_ms),
                });
                let index = self.records.len() - 1;
                let mut out = Vec::new();
                self.emit_resolution(index, &mut out);
                out
            }
            Match::One(index) => {
                if self.records[index].completion.is_some() {
                    // A second completion is useful only when it is the first
                    // event that names the caller. Anything else is a duplicate.
                    let Some(caller) = caller else {
                        return Vec::new();
                    };
                    {
                        let completion = self.records[index]
                            .completion
                            .as_mut()
                            .expect("completion was present");
                        if completion.caller.is_some() || completion.emitted_process.is_some() {
                            return Vec::new();
                        }
                        completion.caller = Some(caller);
                    }
                    let mut out = Vec::new();
                    self.emit_resolution(index, &mut out);
                    return out;
                }
                {
                    let record = &mut self.records[index];
                    record.activity = record.activity.or(activity);
                    record.blob = record.blob.or(blob);
                    record.completion = Some(CompletionEvidence {
                        answers: observation.answers.clone(),
                        ttl_ms: observation.ttl_ms,
                        timestamp: observation.timestamp,
                        caller,
                        emitted_shared: false,
                        emitted_process: None,
                    });
                    record.expires_at = record
                        .expires_at
                        .max(observation.timestamp.saturating_add(self.retention_ms));
                }
                let mut out = Vec::new();
                self.emit_resolution(index, &mut out);
                out
            }
        }
    }

    fn emit_uncorrelated(
        &mut self,
        observation: &DnsCallerObservation,
        name: &str,
        caller: Option<CallerEvidence>,
    ) -> Vec<DnsCallerResolution> {
        let pid = caller.map_or(0, |evidence| evidence.pid);
        if pid == 0 {
            self.stats.unmatched_completions = self.stats.unmatched_completions.saturating_add(1);
        }
        vec![DnsCallerResolution {
            pid,
            query: name.to_owned(),
            answers: observation.answers.clone(),
            ttl_ms: observation.ttl_ms.unwrap_or(0),
            observed_at: observation.timestamp,
            upgrade: false,
        }]
    }

    fn emit_resolution(&mut self, index: usize, out: &mut Vec<DnsCallerResolution>) {
        let (answer_pid, ambiguous) = match resolution(&self.records[index]) {
            Resolution::Ambiguous => (0, true),
            Resolution::Shared => (0, false),
            Resolution::Process(pid) => (pid, false),
        };
        if ambiguous {
            self.stats.ambiguous = self.stats.ambiguous.saturating_add(1);
        }

        let (query, answers, ttl_ms, observed_at, upgrade, recovered) = {
            let record = &mut self.records[index];
            let Some(completion) = record.completion.as_mut() else {
                return;
            };
            if answer_pid == 0 {
                // Ambiguous and unmatched answers are published as shared. A
                // stronger process emission already made is never downgraded.
                if completion.emitted_shared || completion.emitted_process.is_some() {
                    return;
                }
                completion.emitted_shared = true;
                (
                    record.name.clone(),
                    completion.answers.clone(),
                    completion.ttl_ms.unwrap_or(0),
                    completion.timestamp,
                    false,
                    false,
                )
            } else {
                if completion.emitted_process == Some(answer_pid) {
                    return;
                }
                let upgrade = completion.emitted_process.is_some() || completion.emitted_shared;
                // "Recovered" means the completion itself did not already name
                // this caller; the request supplied it.
                let recovered = completion
                    .caller
                    .is_none_or(|evidence| evidence.pid != answer_pid);
                completion.emitted_process = Some(answer_pid);
                (
                    record.name.clone(),
                    completion.answers.clone(),
                    completion.ttl_ms.unwrap_or(0),
                    completion.timestamp,
                    upgrade,
                    recovered,
                )
            }
        };

        if answer_pid == 0 {
            self.stats.unmatched_completions = self.stats.unmatched_completions.saturating_add(1);
        } else if recovered {
            self.stats.recovered = self.stats.recovered.saturating_add(1);
        }
        out.push(DnsCallerResolution {
            pid: answer_pid,
            query,
            answers,
            ttl_ms,
            observed_at,
            upgrade,
        });
    }

    /// Finds the record this event belongs to.
    ///
    /// `ActivityId` is authoritative. The query identifier is only a fallback
    /// and additionally requires a compatible name/type inside a short window;
    /// a domain/time match alone is never accepted.
    fn find_match(
        &self,
        activity: Option<[u8; 16]>,
        blob: Option<u64>,
        name: &str,
        qtype: u16,
        now: u64,
    ) -> Match {
        if let Some(activity) = activity {
            let mut found = None;
            let mut count = 0_usize;
            for (index, record) in self.records.iter().enumerate() {
                if record.activity == Some(activity) {
                    count += 1;
                    found = Some(index);
                }
            }
            match count {
                0 => {}
                1 => return found.map_or(Match::None, Match::One),
                _ => return Match::Ambiguous,
            }
        }
        if let Some(blob) = blob {
            let mut found = None;
            let mut count = 0_usize;
            for (index, record) in self.records.iter().enumerate() {
                if record.blob == Some(blob)
                    && record.qtype == qtype
                    && record.name == name
                    && now.abs_diff(record.first_seen) <= self.match_window_ms
                {
                    count += 1;
                    found = Some(index);
                }
            }
            match count {
                0 => {}
                1 => return found.map_or(Match::None, Match::One),
                _ => return Match::Ambiguous,
            }
        }
        Match::None
    }

    fn push_record(&mut self, record: TxnRecord) {
        while self.records.len() >= self.capacity {
            self.records.pop_front();
            self.stats.capacity_evictions = self.stats.capacity_evictions.saturating_add(1);
        }
        self.records.push_back(record);
    }
}

fn merge_request_evidence(record: &mut TxnRecord, caller: CallerEvidence) {
    match record.request {
        None => record.request = Some(caller),
        Some(existing) if existing.pid == caller.pid => {
            if caller.strength == CallerStrength::Strong {
                record.request = Some(caller);
            }
        }
        Some(_) => record.request_conflict = true,
    }
}

/// Resolves the strongest unambiguous caller from a record's evidence.
fn resolution(record: &TxnRecord) -> Resolution {
    if record.request_conflict {
        return Resolution::Ambiguous;
    }
    let mut strong: Option<u32> = None;
    let mut weak: Option<u32> = None;
    let mut strong_conflict = false;
    let mut weak_conflict = false;
    for candidate in [
        record.request,
        record.completion.as_ref().and_then(|entry| entry.caller),
    ]
    .into_iter()
    .flatten()
    {
        match candidate.strength {
            CallerStrength::Strong => match strong {
                None => strong = Some(candidate.pid),
                Some(pid) if pid == candidate.pid => {}
                Some(_) => strong_conflict = true,
            },
            CallerStrength::Weak => match weak {
                None => weak = Some(candidate.pid),
                Some(pid) if pid == candidate.pid => {}
                Some(_) => weak_conflict = true,
            },
        }
    }
    if strong_conflict {
        return Resolution::Ambiguous;
    }
    if let Some(pid) = strong {
        return Resolution::Process(pid);
    }
    if weak_conflict {
        return Resolution::Ambiguous;
    }
    if let Some(pid) = weak {
        return Resolution::Process(pid);
    }
    Resolution::Shared
}

fn caller_evidence(caller: &DnsCallerIdentity) -> Option<CallerEvidence> {
    let pid = caller.requesting_pid.filter(|pid| *pid > 0)?;
    let strength = match caller.logging_pid {
        Some(logging) if logging == pid => CallerStrength::Weak,
        _ => CallerStrength::Strong,
    };
    Some(CallerEvidence { pid, strength })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, last))
    }

    fn activity_id(byte: u8) -> Option<[u8; 16]> {
        (byte != 0).then_some([byte; 16])
    }

    fn request(
        name: &str,
        activity: Option<[u8; 16]>,
        blob: Option<u64>,
        client_pid: u32,
        logger_pid: u32,
        timestamp: u64,
    ) -> DnsCallerObservation {
        DnsCallerObservation {
            kind: DnsEventKind::Request,
            event_id: 3006,
            event_version: 0,
            name: name.to_owned(),
            query_type: 1,
            status: 0,
            caller: DnsCallerIdentity {
                logging_pid: Some(logger_pid),
                requesting_pid: Some(client_pid),
                resolver_pid: None,
            },
            correlation: DnsCorrelationId {
                activity_id: activity,
                query_blob: blob,
            },
            answers: Vec::new(),
            ttl_ms: None,
            timestamp,
        }
    }

    fn completion(
        name: &str,
        activity: Option<[u8; 16]>,
        blob: Option<u64>,
        requesting_pid: Option<u32>,
        logger_pid: u32,
        timestamp: u64,
    ) -> DnsCallerObservation {
        DnsCallerObservation {
            kind: DnsEventKind::Completion,
            event_id: 3018,
            event_version: 2,
            name: name.to_owned(),
            query_type: 1,
            status: 0,
            caller: DnsCallerIdentity {
                logging_pid: Some(logger_pid),
                requesting_pid,
                resolver_pid: None,
            },
            correlation: DnsCorrelationId {
                activity_id: activity,
                query_blob: blob,
            },
            answers: vec![ip(1)],
            ttl_ms: Some(30_000),
            timestamp,
        }
    }

    fn pids(resolutions: &[DnsCallerResolution]) -> Vec<u32> {
        resolutions
            .iter()
            .map(|resolution| resolution.pid)
            .collect()
    }

    #[test]
    fn request_supplies_caller_and_completion_supplies_answers() {
        let mut recovery = DnsCallerRecovery::default();
        assert!(
            recovery
                .observe(request(
                    "example.test",
                    activity_id(1),
                    Some(7),
                    4242,
                    1000,
                    10
                ))
                .is_empty()
        );
        let out = recovery.observe(completion(
            "example.test",
            activity_id(1),
            Some(7),
            None,
            1000,
            20,
        ));
        assert_eq!(pids(&out), vec![4242]);
        assert!(!out[0].upgrade);
        assert_eq!(out[0].answers, vec![ip(1)]);
        assert_eq!(out[0].ttl_ms, 30_000);
        assert_eq!(recovery.stats().recovered, 1);
    }

    #[test]
    fn later_completion_supplies_the_caller_the_first_one_missed() {
        let mut recovery = DnsCallerRecovery::default();
        let first = recovery.observe(completion(
            "example.test",
            activity_id(1),
            Some(7),
            None,
            1000,
            10,
        ));
        assert_eq!(pids(&first), vec![0]);
        let second = recovery.observe(completion(
            "example.test",
            activity_id(1),
            Some(7),
            Some(4242),
            1000,
            20,
        ));
        assert_eq!(pids(&second), vec![4242]);
        assert!(second[0].upgrade);
    }

    #[test]
    fn response_before_request_emits_shared_then_upgrade() {
        let mut recovery = DnsCallerRecovery::default();
        let first = recovery.observe(completion(
            "late.test",
            activity_id(2),
            None,
            None,
            1000,
            100,
        ));
        assert_eq!(pids(&first), vec![0]);
        assert!(!first[0].upgrade);

        let second = recovery.observe(request("late.test", activity_id(2), None, 4242, 1000, 150));
        assert_eq!(pids(&second), vec![4242]);
        assert!(second[0].upgrade);
        assert_eq!(
            second[0].observed_at, 100,
            "the upgrade keeps the original answer timestamp"
        );
        assert_eq!(second[0].ttl_ms, 30_000);
        let stats = recovery.stats();
        assert_eq!(stats.recovered, 1);
        assert_eq!(stats.unmatched_completions, 1);
    }

    #[test]
    fn concurrent_identical_names_stay_separate() {
        let mut recovery = DnsCallerRecovery::default();
        recovery.observe(request("same.test", activity_id(10), None, 1111, 1000, 10));
        recovery.observe(request("same.test", activity_id(11), None, 2222, 1000, 10));
        let first = recovery.observe(completion(
            "same.test",
            activity_id(10),
            None,
            None,
            1000,
            20,
        ));
        let second = recovery.observe(completion(
            "same.test",
            activity_id(11),
            None,
            None,
            1000,
            21,
        ));
        assert_eq!(pids(&first), vec![1111]);
        assert_eq!(pids(&second), vec![2222]);
        assert_eq!(recovery.stats().ambiguous, 0);
    }

    #[test]
    fn conflicting_callers_remain_ambiguous() {
        let mut recovery = DnsCallerRecovery::default();
        recovery.observe(request(
            "conflict.test",
            activity_id(20),
            None,
            1111,
            1000,
            10,
        ));
        recovery.observe(request(
            "conflict.test",
            activity_id(20),
            None,
            2222,
            1000,
            11,
        ));
        let out = recovery.observe(completion(
            "conflict.test",
            activity_id(20),
            None,
            None,
            1000,
            20,
        ));
        assert_eq!(pids(&out), vec![0], "ambiguous answers stay shared");
        assert!(recovery.stats().ambiguous >= 1);
    }

    #[test]
    fn query_identifier_fallback_requires_name_type_and_time() {
        let mut recovery = DnsCallerRecovery::default();
        recovery.observe(request("match.test", None, Some(99), 4242, 1000, 10));
        let out = recovery.observe(completion("match.test", None, Some(99), None, 1000, 20));
        assert_eq!(pids(&out), vec![4242]);

        let mut recovery = DnsCallerRecovery::default();
        recovery.observe(request("first.test", None, Some(99), 4242, 1000, 10));
        let out = recovery.observe(completion("second.test", None, Some(99), None, 1000, 20));
        assert_eq!(pids(&out), vec![0], "a different name must not recover");

        let mut recovery = DnsCallerRecovery::default();
        recovery.observe(request("typed.test", None, Some(99), 4242, 1000, 10));
        let mut typed = completion("typed.test", None, Some(99), None, 1000, 20);
        typed.query_type = 28;
        let out = recovery.observe(typed);
        assert_eq!(pids(&out), vec![0], "a different type must not recover");

        let mut recovery = DnsCallerRecovery::with_timings(16, 100, 50);
        recovery.observe(request("expired.test", None, Some(99), 4242, 1000, 0));
        let out = recovery.observe(completion("expired.test", None, Some(99), None, 1000, 500));
        assert_eq!(pids(&out), vec![0], "expired evidence must not recover");
        assert!(recovery.stats().expirations >= 1);
    }

    #[test]
    fn header_fallback_caller_yields_to_an_explicit_request_caller() {
        let mut recovery = DnsCallerRecovery::default();
        let mut weak = completion("fallback.test", activity_id(40), None, Some(1000), 1000, 10);
        weak.event_id = 3008;
        weak.event_version = 0;
        let first = recovery.observe(weak);
        assert_eq!(pids(&first), vec![1000]);

        let second = recovery.observe(request(
            "fallback.test",
            activity_id(40),
            None,
            4242,
            1000,
            20,
        ));
        assert_eq!(pids(&second), vec![4242]);
        assert!(second[0].upgrade);
        assert_eq!(recovery.stats().recovered, 1);
    }

    #[test]
    fn failed_duplicate_and_zero_ttl_completions_create_no_hints() {
        let mut recovery = DnsCallerRecovery::default();
        let mut failed = completion("failed.test", activity_id(30), None, None, 1000, 10);
        failed.status = 2;
        assert!(recovery.observe(failed).is_empty());
        assert!(
            recovery
                .observe(request(
                    "failed.test",
                    activity_id(30),
                    None,
                    4242,
                    1000,
                    20
                ))
                .is_empty()
        );
        assert_eq!(recovery.stats().retained, 1);

        let mut zero = completion("zero.test", activity_id(31), None, None, 1000, 10);
        zero.ttl_ms = Some(0);
        assert!(recovery.observe(zero).is_empty());
        assert_eq!(recovery.stats().retained, 1);

        let mut recovery = DnsCallerRecovery::default();
        recovery.observe(request("dup.test", activity_id(32), None, 4242, 1000, 10));
        let first = recovery.observe(completion(
            "dup.test",
            activity_id(32),
            None,
            None,
            1000,
            20,
        ));
        assert_eq!(pids(&first), vec![4242]);
        let duplicate = recovery.observe(completion(
            "dup.test",
            activity_id(32),
            None,
            None,
            1000,
            30,
        ));
        assert!(
            duplicate.is_empty(),
            "a duplicate completion must not re-emit"
        );
        assert_eq!(recovery.stats().recovered, 1);
    }

    #[test]
    fn contradictory_request_and_response_callers_stay_shared() {
        let mut recovery = DnsCallerRecovery::default();
        recovery.observe(request(
            "contradict.test",
            activity_id(50),
            None,
            1111,
            1000,
            10,
        ));
        // The completion names a different explicit caller for the same activity.
        let out = recovery.observe(completion(
            "contradict.test",
            activity_id(50),
            None,
            Some(2222),
            1000,
            20,
        ));
        assert_eq!(pids(&out), vec![0]);
        assert!(recovery.stats().ambiguous >= 1);
        assert_eq!(recovery.stats().recovered, 0);
    }

    #[test]
    fn capacity_evictions_bound_retention() {
        let mut recovery = DnsCallerRecovery::with_timings(2, 100_000, 2_000);
        for (index, activity_byte) in [1_u8, 2, 3].into_iter().enumerate() {
            let timestamp = u64::try_from(index).unwrap();
            recovery.observe(completion(
                "cap.test",
                activity_id(activity_byte),
                None,
                None,
                1000,
                timestamp,
            ));
        }
        let stats = recovery.stats();
        assert_eq!(stats.retained, 2);
        assert!(stats.capacity_evictions >= 1);
    }
}
