//! Native attribution diagnostics.

use netmetrics_core::{
    ClockLag, DnsFlushStats, OwnerDisagreement, OwnerEvidenceStats, TcpPidAttributionSample,
};

/// Takes the flows counted in [`OwnerEvidenceStats::disagree`] since the last
/// call, each with both PIDs and what is needed to tell why they differ. A
/// bounded number are kept between calls.
#[must_use]
pub fn take_owner_disagreements() -> Vec<OwnerDisagreement> {
    #[cfg(all(windows, feature = "windows"))]
    {
        netmetrics_windows::take_owner_disagreements()
    }
    #[cfg(not(all(windows, feature = "windows")))]
    {
        Vec::new()
    }
}

/// Where the owner of each kernel network event came from, and how often an
/// event's own PID and the owner recorded when its flow was established
/// disagreed. Only the Windows backend has both sources; elsewhere every
/// count is zero.
#[must_use]
pub fn owner_evidence_stats() -> OwnerEvidenceStats {
    #[cfg(all(windows, feature = "windows"))]
    {
        netmetrics_windows::owner_evidence_stats()
    }
    #[cfg(not(all(windows, feature = "windows")))]
    {
        OwnerEvidenceStats::default()
    }
}

/// Asks the DNS event source to deliver the events it has logged so far now,
/// instead of on its own timer. Returns at once.
///
/// Call it after answering a DNS query on another process's behalf: the event
/// naming the process that asked is then delivered within tens of
/// milliseconds. Only the Windows DNS-Client trace buffers events this way;
/// elsewhere, and while no trace is running, this does nothing.
pub fn request_dns_event_flush() {
    #[cfg(all(windows, feature = "windows"))]
    netmetrics_windows::request_dns_event_flush();
}

/// Requests made with [`request_dns_event_flush`] and how the flushes went.
#[must_use]
pub fn dns_event_flush_stats() -> DnsFlushStats {
    #[cfg(all(windows, feature = "windows"))]
    {
        netmetrics_windows::dns_event_flush_stats()
    }
    #[cfg(not(all(windows, feature = "windows")))]
    {
        DnsFlushStats::default()
    }
}

/// Returns bounded TCP payload-PID counters partitioned by event ID and version.
#[must_use]
pub fn tcp_pid_attribution_stats() -> Vec<TcpPidAttributionSample> {
    platform_tcp_pid_attribution_stats()
}

#[cfg(all(windows, feature = "windows"))]
fn platform_tcp_pid_attribution_stats() -> Vec<TcpPidAttributionSample> {
    netmetrics_windows::tcp_pid_attribution_stats()
}

#[cfg(not(all(windows, feature = "windows")))]
fn platform_tcp_pid_attribution_stats() -> Vec<TcpPidAttributionSample> {
    Vec::new()
}

/// How far the event source's times run behind the system clock. Only Windows
/// kernel ETW is measured; elsewhere every field is empty.
#[must_use]
pub fn event_clock_lag() -> ClockLag {
    #[cfg(all(windows, feature = "windows"))]
    {
        netmetrics_windows::etw_clock_lag()
    }
    #[cfg(not(all(windows, feature = "windows")))]
    {
        ClockLag::default()
    }
}
