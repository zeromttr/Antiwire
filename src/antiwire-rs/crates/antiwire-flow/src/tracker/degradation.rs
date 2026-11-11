//! Degradation and health reporting for the flow tracker, de-duplicated by reason.

use super::FlowTracker;
use crate::store::FlowStore;
use netmetrics_core::DegradeReason;

impl<S: FlowStore> FlowTracker<S> {
    /// Logs identity telemetry at debug level, so the rate of unresolved
    /// processes can be measured before another recovery source is added.
    pub(super) fn log_identity_telemetry(&self) {
        let recovery = self.identity_recovery_stats();
        let resolution = self
            .processor
            .as_ref()
            .map(|processor| processor.processes().resolution_stats());
        let closed_owners = self.closed_owner_stats();
        let owner_evidence = netmetrics::owner_evidence_stats();
        let system_folds = self
            .processor
            .as_ref()
            .map(|processor| processor.system_attribution_stats());
        tracing::debug!(
            ?recovery,
            ?resolution,
            ?closed_owners,
            ?owner_evidence,
            ?system_folds,
            "flow identity telemetry"
        );
        // Each flow whose two owner sources disagreed, with both processes,
        // so the cause can be read off: the other end of a local connection,
        // a record left by an earlier connection, or a different owner.
        let now_ms = netmetrics_core::unix_now_ms();
        for disagreement in netmetrics::take_owner_disagreements() {
            let event_process = self
                .processor
                .as_ref()
                .and_then(|processor| {
                    processor
                        .processes()
                        .identity_at(disagreement.event_pid, now_ms)
                })
                .map(|identity| identity.path)
                .unwrap_or_default();
            tracing::debug!(
                key = ?disagreement.key,
                loopback = disagreement.key.is_loopback(),
                event_pid = disagreement.event_pid,
                event_process,
                recorded_pid = disagreement.recorded_pid,
                recorded_process = disagreement.recorded_executable,
                reversed = disagreement.reversed,
                record_age_ms = disagreement.record_age_ms,
                opcode = disagreement.opcode,
                events = disagreement.events,
                "flow owner sources disagree"
            );
        }
        // Creation-time checks allow one second of skew between event times and
        // process start times; this shows how much of it clock drift uses up.
        let lag = netmetrics::event_clock_lag();
        if lag.windows > 0 {
            tracing::debug!(
                latest_ms = lag.latest_ms,
                baseline_ms = lag.baseline_ms,
                drift_ms = lag.drift_ms(),
                windows = lag.windows,
                "event clock lag"
            );
        }
        if let Some(processor) = &self.processor {
            let domains = processor.domain_lookup_stats();
            let dns_event_flushes = netmetrics::dns_event_flush_stats();
            tracing::debug!(?domains, ?dns_event_flushes, "connection domain telemetry");
        }
    }

    /// Reports a collector capability loss, once per stable reason category.
    ///
    /// Byte accounting is the capability most often lost. On Windows the kernel ETW session
    /// requires Administrator; without it the collector falls back to IP Helper, which
    /// reports connections but emits no byte events at all. That leaves every sent/received
    /// figure in the UI at zero, and until now nothing said why.
    pub(super) fn on_degraded(&self, reason: &DegradeReason) {
        if !self
            .reported_degradations
            .lock()
            .insert(degradation_key(reason))
        {
            return;
        }
        match reason {
            DegradeReason::PermissionDenied { source } => {
                tracing::warn!(
                    source = %source,
                    "collector source needs elevation; run the daemon as Administrator for byte accounting"
                );
                self.report_byte_accounting_lost(
                    "Traffic volume needs elevated access. Run the Antiwire daemon as \
                     Administrator to record sent and received bytes.",
                );
            }
            DegradeReason::SnapshotOnly { source } => {
                tracing::warn!(
                    source = %source,
                    "collector is snapshot-only: connections are tracked but sent/received byte counts stay at zero"
                );
                self.report_byte_accounting_lost(
                    "The collector is running in snapshot-only mode. Connections are still \
                     tracked, but sent and received byte counts are unavailable.",
                );
            }
            other => tracing::warn!(reason = ?other, "collector degraded"),
        }
    }

    fn report_byte_accounting_lost(&self, detail: &str) {
        if let Some(health) = &self.collector_health {
            health.mark_byte_accounting_lost(detail);
        }
    }

    /// Reports that observed traffic is not reaching the database.
    ///
    /// Deliberately not [`Self::report_byte_accounting_lost`]: that one is permanent by
    /// design, and a store outage is usually transient. Reporting it there would leave
    /// the UI claiming byte accounting was unavailable long after writes recovered.
    pub(super) fn report_store_unavailable(&self, detail: &str) {
        if let Some(health) = &self.collector_health {
            health.mark_store_unavailable(detail);
        }
    }

    pub(super) fn report_store_recovered(&self) {
        if let Some(health) = &self.collector_health {
            health.clear_store_unavailable();
        }
    }
}

/// Returns a stable degradation category for log de-duplication.
///
/// Overflow and capacity reports carry cumulative deltas, so using their full `Debug`
/// representation as a key would make every report appear to be a new reason and would
/// amplify warnings exactly when the system is under load. Keep source/backend identity
/// for actionable diagnostics while intentionally ignoring the changing counters/details.
pub(super) fn degradation_key(reason: &DegradeReason) -> String {
    match reason {
        DegradeReason::PermissionDenied { source } => format!("permission_denied:{source}"),
        DegradeReason::SessionLost { backend, .. } => format!("session_lost:{backend}"),
        DegradeReason::BufferOverflow { .. } => "buffer_overflow".to_owned(),
        DegradeReason::CapacityExceeded { .. } => "capacity_exceeded".to_owned(),
        DegradeReason::SourceUnavailable { source, .. } => {
            format!("source_unavailable:{source}")
        }
        DegradeReason::SnapshotOnly { source } => format!("snapshot_only:{source}"),
        DegradeReason::DecodeError { source } => format!("decode_error:{source}"),
        DegradeReason::UnsupportedPlatform => "unsupported_platform".to_owned(),
    }
}
