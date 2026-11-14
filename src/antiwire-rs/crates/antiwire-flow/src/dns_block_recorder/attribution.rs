//! Which process a blocked query belongs to: the caller the DNS Client
//! recorded, else the socket owner, judged against when each started.

use netmetrics::Ownership;
use time::OffsetDateTime;

use super::{PendingBlock, PendingOwnership};
use crate::correlator::{DnsAttributionStatus, DnsCorrelationResult, DnsQueryCorrelator};

pub(super) fn attributed_requesting_pid(correlation: DnsCorrelationResult) -> Option<u32> {
    if correlation.ambiguous {
        return None;
    }
    match correlation.status {
        DnsAttributionStatus::Correlated | DnsAttributionStatus::Inferred => {
            correlation.requesting_pid.filter(|pid| *pid > 0)
        }
        DnsAttributionStatus::Unattributed | DnsAttributionStatus::Ambiguous => None,
    }
}

/// Whether a process created at `start_ts` (Unix milliseconds, zero when
/// unknown) started after `event`, allowing the one second of skew the
/// resolver's own creation-time checks allow.
pub(super) fn started_after(start_ts: u64, event: OffsetDateTime) -> bool {
    const SKEW_MS: i128 = 1_000;
    let event_ms = event.unix_timestamp_nanos() / 1_000_000;
    start_ts > 0 && i128::from(start_ts) > event_ms + SKEW_MS
}

/// The process a block is recorded against.
///
/// Caller evidence wins; otherwise the resolved socket owner is the sender of
/// record — the requesting application for a direct query and the system
/// resolver for a mediated one. Zero means no owner could be established.
pub(super) fn attributed_owner_pid(
    correlation: DnsCorrelationResult,
    ownership: PendingOwnership,
) -> u32 {
    attributed_requesting_pid(correlation)
        .or_else(|| {
            let pid = ownership.socket_owner_pid();
            (pid > 0).then_some(pid)
        })
        .unwrap_or(0)
}

pub(super) fn correlate_block(
    correlator: &DnsQueryCorrelator,
    block: &PendingBlock,
) -> DnsCorrelationResult {
    match block.ownership {
        PendingOwnership::Caller(pid) if pid > 0 => DnsCorrelationResult {
            requesting_pid: Some(pid),
            resolver_pid: None,
            ambiguous: false,
            status: DnsAttributionStatus::Correlated,
        },
        PendingOwnership::Caller(_) | PendingOwnership::Socket(Ownership::NotFound) => {
            correlator.correlate(&block.domain, 0, Some(block.timestamp))
        }
        PendingOwnership::Socket(Ownership::Resolved(pid)) => {
            let scoped = correlator.correlate(&block.domain, pid, Some(block.timestamp));
            if attributed_requesting_pid(scoped).is_some() {
                scoped
            } else {
                // The resolved owner is frequently the system resolver, whose
                // identity need not appear in the recorded query. Fall back to
                // caller-only evidence instead of discarding an attributable
                // block; multiple callers stay ambiguous unless one request is
                // clearly nearest (see `resolve_caller_only`).
                let caller_only = correlator.correlate(&block.domain, 0, Some(block.timestamp));
                if attributed_requesting_pid(caller_only).is_some() || caller_only.ambiguous {
                    caller_only
                } else {
                    scoped
                }
            }
        }
        PendingOwnership::Socket(Ownership::Ambiguous) => {
            let mut correlation = correlator.correlate(&block.domain, 0, Some(block.timestamp));
            if correlation.status == DnsAttributionStatus::Unattributed {
                correlation.status = DnsAttributionStatus::Ambiguous;
                correlation.ambiguous = true;
            }
            correlation
        }
    }
}
