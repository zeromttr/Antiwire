//! Folding OS-originated flows into the `System` application, and the
//! impersonation alerts raised when another program uses a system service's
//! wire shape.

use antiwire_events::{Alert, AlertKind, Severity};
use antiwire_tuning::SYSTEM_ATTRIBUTION_ENABLED;
use netmetrics_core::{FlowKey, FlowMeta};

use super::FlowProcessor;
use crate::app_resolver::ResolvedApplication;
use crate::process_resolver;
use crate::sanitize;
use crate::system_services::{
    self, AttributionOutcome, FoldEvidence, Impersonation, OwnerEvidence, SystemAttributionStats,
    SystemService,
};

/// Maximum executable-path characters kept in an impersonation alert. The
/// service, address, and explanatory tail are the security-critical content
/// and must survive the message cap even for maximal paths.
const MAX_ALERT_PATH_CHARS: usize = 512;

/// Upper bound on the fixed (non-path, non-name) characters of an
/// impersonation alert: template text plus the longest service label plus a
/// bracketed IPv6 endpoint.
const MAX_ALERT_FIXED_CHARS: usize = 202;

const _: () = assert!(
    MAX_ALERT_PATH_CHARS + sanitize::MAX_NAME_CHARS + MAX_ALERT_FIXED_CHARS
        <= sanitize::MAX_MESSAGE_CHARS
);

impl FlowProcessor {
    /// System-service attribution totals since this processor was built.
    #[must_use]
    pub fn system_attribution_stats(&self) -> SystemAttributionStats {
        self.system_attributor.stats()
    }

    /// Resolves an application and its process creation time, folding recognized
    /// OS-originated traffic into the canonical `System` identity first.
    ///
    /// Ownerless system-service signatures never trigger identity work: matching by
    /// flow key alone avoids the socket-table, `OpenProcess`, and SCM lookups that
    /// unattributable flows would otherwise burn. A resolvable, non-allowlisted owner
    /// is never replaced; at most an impersonation signal is raised. The daemon's own
    /// PID is always resolved normally.
    pub(crate) fn resolve_flow_app(&self, key: &FlowKey, meta: &FlowMeta) -> ResolvedApplication {
        self.resolve_flow_app_identity_inner(
            SYSTEM_ATTRIBUTION_ENABLED,
            system_services::current(),
            key,
            meta,
        )
    }

    /// Shared implementation so tests can exercise both the enabled and the
    /// audit-only mode, and any OS profile, without rebuilding.
    pub(super) fn resolve_flow_app_identity_inner(
        &self,
        enabled: bool,
        profile: &system_services::SystemProfile,
        key: &FlowKey,
        meta: &FlowMeta,
    ) -> ResolvedApplication {
        if profile.match_signature(key).is_none() {
            return self.resolve_app(meta.pid, meta);
        }
        let note = |outcome| self.system_attributor.note(outcome);
        note(AttributionOutcome::Matched);
        if !enabled {
            // Audit mode: count the match, change nothing.
            note(AttributionOutcome::NoRule);
            return self.resolve_app(meta.pid, meta);
        }
        if meta.pid == 0 && !system_services::has_owner_evidence(meta) {
            // Ownerless fast path: no resolution work at all. A socket cookie
            // without a PID is preserved on the flow for session splitting but
            // cannot attribute: the collector only attaches cookies alongside a
            // resolved owner.
            return if let system_services::SystemVerdict::FoldSystem { .. } =
                profile.classify(key, OwnerEvidence::None)
            {
                note(AttributionOutcome::FoldedOwnerless);
                self.app_resolver.resolved_system_identity(0)
            } else {
                note(AttributionOutcome::NoRule);
                self.resolve_app(meta.pid, meta)
            };
        }
        if meta.pid == std::process::id() {
            // The daemon's own sockets keep daemon attribution, always.
            note(AttributionOutcome::NoRule);
            return self.resolve_app(meta.pid, meta);
        }
        // Peek without store side effects: a verified fold must not mint the
        // service's application row (or its NEW_APP alert) on the way to
        // `System`. Only the non-folding path below records a sighting.
        let process = meta.process.as_ref();
        let process_resolver::ResolvedIdentity {
            path: peek_path,
            name: peek_name,
            start_ts: peek_start_ts,
        } = self.app_resolver.peek_identity(
            meta.pid,
            process.map(|process| process.executable.as_str()),
            process.map(|process| process.name.as_str()),
            process.map(|process| process.start_ts),
        );
        if matches!(
            profile.classify(key, OwnerEvidence::from_identity(&peek_path, &peek_name)),
            system_services::SystemVerdict::FoldSystem {
                evidence: FoldEvidence::VerifiedService,
                ..
            }
        ) {
            note(AttributionOutcome::FoldedVerified);
            return self.app_resolver.resolved_system_identity(peek_start_ts);
        }
        let resolved = self.resolve_app(meta.pid, meta);
        if system_services::is_system_identity(&resolved.app_path, &resolved.app_name) {
            // Already the System identity (e.g. PID 4): nothing to fold and no
            // rule to apply. Counted as matched above, nothing further.
            note(AttributionOutcome::NoRule);
            return resolved;
        }
        let evidence = OwnerEvidence::from_identity(&resolved.app_path, &resolved.app_name);
        match profile.classify(key, evidence) {
            system_services::SystemVerdict::FoldSystem {
                evidence: FoldEvidence::VerifiedService,
                ..
            } => {
                // Reached only when the peek missed but the recorded sighting
                // verified — a process boundary crossed between the two
                // back-to-back resolutions. The row was already minted, so this
                // fold corrects the record without hiding the sighting.
                note(AttributionOutcome::FoldedVerified);
                self.app_resolver
                    .resolved_system_identity(resolved.start_ts)
            }
            system_services::SystemVerdict::KeepOwner {
                service,
                impersonation: Impersonation::Alert,
            } => {
                if self.maybe_publish_impersonation(service, &resolved, key) {
                    note(AttributionOutcome::ImpersonationAlert);
                }
                resolved
            }
            system_services::SystemVerdict::KeepOwner {
                impersonation: Impersonation::Watch,
                ..
            } => {
                note(AttributionOutcome::ImpersonationWatch);
                resolved
            }
            _ => {
                note(AttributionOutcome::NoRule);
                resolved
            }
        }
    }

    #[cfg(test)]
    pub(super) fn resolve_flow_app_inner(
        &self,
        enabled: bool,
        profile: &system_services::SystemProfile,
        key: &FlowKey,
        meta: &FlowMeta,
    ) -> (i32, String, String) {
        self.resolve_flow_app_identity_inner(enabled, profile, key, meta)
            .into_parts()
    }

    /// Publishes one impersonation alert per application and service, returning
    /// whether this call actually published. The record keeps its real
    /// attribution; the alert only makes the misuse visible.
    fn maybe_publish_impersonation(
        &self,
        service: SystemService,
        resolved: &ResolvedApplication,
        key: &FlowKey,
    ) -> bool {
        let app_path = &resolved.app_path;
        let app_name = &resolved.app_name;
        if !self
            .system_attributor
            .claim_impersonation_alert(app_path, app_name, service)
        {
            return false;
        }
        // Trim the path aggressively: the service, address, and explanatory tail
        // are the security-critical content and must survive the message cap.
        let app_name = sanitize::trimmed(app_name, sanitize::MAX_NAME_CHARS);
        let app_path = sanitize::trimmed(app_path, MAX_ALERT_PATH_CHARS);
        // `SocketAddr` brackets an IPv6 address: `[::1]:53`.
        let endpoint = std::net::SocketAddr::new(key.local_addr, key.local_port);
        let message = format!(
            "Program '{app_name}' at '{app_path}' is acting as {service} on {endpoint}. Only operating-system services are expected in this role; the connection keeps its real attribution.",
            service = service.label(),
        );
        self.alerts.publish(Alert::new(
            AlertKind::SystemServiceImpersonation,
            Severity::High,
            "Possible System Service Impersonation",
            message,
        ));
        tracing::warn!(
            service = service.label(),
            app_name = %app_name,
            app_path = %app_path,
            local_addr = %key.local_addr,
            local_port = key.local_port,
            "possible system service impersonation"
        );
        true
    }
}
