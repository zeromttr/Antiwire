//! Alerts raised by the daemon, and the notifications subscribers receive.

/// What an alert reports.
///
/// The name returned by [`AlertKind::as_str`] is what the alerts table stores
/// and what clients receive, so a variant's name must never change.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AlertKind {
    /// An application made its first connection.
    NewApplication,
    /// A known application started running from a different path.
    ApplicationPathChanged,
    /// Traffic was blocked as malicious, by a rule or a blocklist.
    MaliciousFlow,
    /// A program other than the operating system's own took a system service's role.
    SystemServiceImpersonation,
    /// The hosts blocklists synced.
    HostsSync,
    /// Some hosts blocklists could not be synced.
    HostsSyncFailed,
    /// The `GeoIP` database was updated.
    GeoIpSync,
    /// The `GeoIP` database could not be updated.
    GeoIpSyncFailed,
    /// A watched network device appeared.
    NetworkDeviceConnected,
    /// A watched network device disappeared.
    NetworkDeviceDisconnected,
    /// A firewall rule was changed outside Antiwire.
    FirewallRuleDrift,
    /// An application moved but its rules could not follow it.
    ApplicationRulesNotMoved,
    /// Some configured DNS upstreams were invalid and are not used.
    DnsUpstreamSkipped,
    /// The DNS resolver runs, but some lookups bypass it unfiltered.
    DnsEnforcementIncomplete,
    /// A subscriber fell behind and missed notifications.
    NotificationsLagged,
    /// Alerts were raised faster than they could be saved, and some were dropped.
    AlertsDropped,
}

impl AlertKind {
    /// The stable name stored and sent for this kind.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NewApplication => "NEW_APP",
            Self::ApplicationPathChanged => "APP_PATH_CHANGED",
            Self::MaliciousFlow => "MALICIOUS_FLOW",
            Self::SystemServiceImpersonation => "SYSTEM_SERVICE_IMPERSONATION",
            Self::HostsSync => "HOSTS_SYNC",
            Self::HostsSyncFailed => "HOSTS_SYNC_FAIL",
            Self::GeoIpSync => "GEOIP_SYNC",
            Self::GeoIpSyncFailed => "GEOIP_SYNC_FAIL",
            Self::NetworkDeviceConnected => "NETWORK_DEVICE_CONNECTED",
            Self::NetworkDeviceDisconnected => "NETWORK_DEVICE_DISCONNECTED",
            Self::FirewallRuleDrift => "FIREWALL_RULE_DRIFT",
            Self::ApplicationRulesNotMoved => "APP_RULES_NOT_MOVED",
            Self::DnsUpstreamSkipped => "DNS_UPSTREAM_SKIPPED",
            Self::DnsEnforcementIncomplete => "DNS_ENFORCEMENT_INCOMPLETE",
            Self::NotificationsLagged => "NOTIFICATIONS_LAGGED",
            Self::AlertsDropped => "ALERTS_DROPPED",
        }
    }
}

/// How urgent an alert is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    Info,
    Warning,
    High,
    Critical,
}

impl Severity {
    /// The stable name stored and sent for this severity.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Info => "INFO",
            Self::Warning => "WARNING",
            Self::High => "HIGH",
            Self::Critical => "CRITICAL",
        }
    }
}

/// An alert as a producer raises it, before it is saved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Alert {
    pub kind: AlertKind,
    pub severity: Severity,
    pub title: String,
    pub message: String,
    /// Unix seconds when the event happened.
    pub timestamp: u64,
}

impl Alert {
    /// An alert stamped with the current time.
    #[must_use]
    pub fn new(
        kind: AlertKind,
        severity: Severity,
        title: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            severity,
            title: title.into(),
            message: message.into(),
            timestamp: crate::unix_now(),
        }
    }

    /// The same alert, stamped with when the event happened instead of now.
    #[must_use]
    pub fn at(mut self, timestamp: u64) -> Self {
        self.timestamp = timestamp;
        self
    }
}

/// An alert as subscribers receive it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Notification {
    /// Database id, or 0 when the alert could not be saved.
    pub id: u64,
    pub kind: AlertKind,
    pub severity: Severity,
    pub title: String,
    pub message: String,
    /// Unix seconds when the event happened.
    pub timestamp: u64,
}

impl Notification {
    pub(crate) fn from_alert(alert: Alert, id: u64) -> Self {
        Self {
            id,
            kind: alert.kind,
            severity: alert.severity,
            title: alert.title,
            message: alert.message,
            timestamp: alert.timestamp,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_match_what_the_alerts_table_already_holds() {
        // Persisted rows and older clients use these exact strings.
        for (kind, name) in [
            (AlertKind::NewApplication, "NEW_APP"),
            (AlertKind::MaliciousFlow, "MALICIOUS_FLOW"),
            (AlertKind::HostsSyncFailed, "HOSTS_SYNC_FAIL"),
            (AlertKind::GeoIpSyncFailed, "GEOIP_SYNC_FAIL"),
            (AlertKind::ApplicationRulesNotMoved, "APP_RULES_NOT_MOVED"),
        ] {
            assert_eq!(kind.as_str(), name);
        }
        assert_eq!(Severity::Critical.as_str(), "CRITICAL");
    }
}
