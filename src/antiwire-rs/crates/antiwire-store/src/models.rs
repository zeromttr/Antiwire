use antiwire_policy::{RuleDirection, RuleTargetKind, Verdict};
use antiwire_secrets::SecretBytes;
use serde::{Deserialize, Serialize};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use crate::error::{Result, StoreError};

/// Known application executable on this host, identified by `app_path`.
///
/// `app_name` is display metadata refreshed from the most recent sighting; a
/// binary that adopts another application's name is a separate row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Application {
    pub id: i32,
    pub app_path: String,
    #[serde(default)]
    pub app_name: String,
    #[serde(default)]
    pub signature_fingerprint: String,
    pub first_seen: OffsetDateTime,
}

/// One location an application has been observed running from.
#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ApplicationPathHistoryEntry {
    pub(crate) app_path: String,
    pub(crate) first_seen: OffsetDateTime,
    pub(crate) last_seen: OffsetDateTime,
}

/// Result of recording a live sighting of an application.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplicationSighting {
    pub app_id: i32,
    /// A new application row was inserted for this executable path.
    pub is_new_application: bool,
    /// An existing identity's stored location moved to a new path, typically a
    /// version bump inside the same install family.
    pub path_changed: bool,
    /// Another row already carried this name from a different location, so the
    /// new row is a move (or an impersonation) rather than a first sighting.
    /// For an existing identity whose path moved, this is the previous
    /// location of the same row.
    pub previous_path: Option<String>,
}

/// Firewall rule targeting an application path, IP/CIDR, or DNS name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirewallRule {
    pub id: i32,
    pub target_type: RuleTargetKind,
    pub target_value: String,
    #[serde(default = "default_rule_action")]
    pub action: Verdict,
    #[serde(default = "default_rule_direction")]
    pub direction: RuleDirection,
    pub created_at: OffsetDateTime,
}

/// A notification retained in the daemon's alert feed until the user dismisses it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Alert {
    pub id: i64,
    pub alert_type: String,
    pub title: String,
    pub message: String,
    pub timestamp: OffsetDateTime,
    pub severity: String,
}

/// Input for inserting an alert without a database-assigned id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NewAlert {
    pub alert_type: String,
    pub title: String,
    pub message: String,
    pub timestamp: OffsetDateTime,
    pub severity: String,
}

fn default_rule_action() -> Verdict {
    Verdict::Block
}

fn default_rule_direction() -> RuleDirection {
    RuleDirection::Outbound
}

/// Persisted connection / flow log row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectionLog {
    pub id: i32,
    pub timestamp: OffsetDateTime,
    pub app_id: i32,
    /// Executable path this connection ran from, fixed when the row was first
    /// written. Empty for rows the migration could not place and for
    /// unattributed connections; readers fall back to the application's
    /// current path for those.
    #[serde(default)]
    pub app_path: String,
    #[serde(default = "default_protocol")]
    pub protocol: String,
    #[serde(default)]
    pub src_ip: String,
    #[serde(default)]
    pub src_port: i32,
    #[serde(default)]
    pub dst_ip: String,
    #[serde(default)]
    pub dst_port: i32,
    #[serde(default)]
    pub dst_domain: String,
    #[serde(default)]
    pub bytes_sent: i64,
    #[serde(default)]
    pub bytes_received: i64,
    #[serde(default = "default_action_taken")]
    pub action_taken: String,
    pub last_seen: OffsetDateTime,
    #[serde(default)]
    pub country_code: String,
    #[serde(default)]
    pub isp: String,
    /// Newline-separated blocklist ids the connection matched, if any. A row
    /// can carry them while `action_taken` is `ALLOWED`: policy said block, but
    /// bytes were transferred, so the block was not observed to take effect.
    #[serde(default)]
    pub blocklist_names: String,
    /// Tracker-assigned per-connection session id. Together with `conn_pid`
    /// and the connection start (`timestamp`) it identifies the connection a
    /// repeat flush accumulates onto; 0 means legacy/unattributed and never
    /// matches another row.
    #[serde(default)]
    pub conn_id: i64,
    /// Pid observed when the connection opened, pinned for the row's lifetime.
    /// The live pid may resolve after the first persist, so the current pid
    /// must not be used: identity has to stay stable across every flush.
    #[serde(default)]
    pub conn_pid: i32,
    /// When the connection ended. `None` means no close was observed; this does not
    /// establish that a historical connection is live. A closed row never accumulates further flushes.
    #[serde(default)]
    pub closed_at: Option<OffsetDateTime>,
    /// Confirmed open by a tracked-flow write in this store session; never persisted across restart.
    #[serde(default)]
    pub is_active: bool,
}

fn default_protocol() -> String {
    "TCP".to_owned()
}

fn default_action_taken() -> String {
    "ALLOWED".to_owned()
}

/// Daemon configuration persisted as a singleton row (`id = 1`).
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaemonSetting {
    pub id: i32,
    #[serde(default)]
    pub siem_enabled: bool,
    #[serde(default = "default_wazuh_transport")]
    pub wazuh_transport: String,
    #[serde(default)]
    pub wazuh_file_path: String,
    #[serde(default)]
    pub wazuh_manager_host: String,
    #[serde(default = "default_wazuh_port")]
    pub wazuh_manager_port: i32,
    #[serde(default = "default_wazuh_protocol")]
    pub wazuh_protocol: String,
    #[serde(default = "default_true")]
    pub siem_file_enabled: bool,
    #[serde(default)]
    pub siem_syslog_enabled: bool,
    #[serde(default)]
    pub siem_webhook_enabled: bool,
    #[serde(default)]
    pub siem_url: String,
    #[serde(default)]
    pub siem_auth_token: String,
    #[serde(default)]
    pub siem_auth_header: String,
    #[serde(default)]
    pub siem_send_allowed: bool,
    #[serde(default = "default_true")]
    pub siem_send_blocked: bool,
    #[serde(default = "default_true")]
    pub siem_send_new_app: bool,
    #[serde(default = "default_true")]
    pub siem_send_new_domain: bool,
    #[serde(default = "default_true")]
    pub siem_send_threats: bool,
    #[serde(default)]
    pub ai_enabled: bool,
    /// `TypeSafe` API token. Held in zeroizing memory after [`crate::Store::get_settings`].
    #[serde(
        default,
        serialize_with = "serialize_secret",
        deserialize_with = "deserialize_secret"
    )]
    pub ai_api_key: SecretBytes,
    /// `proactive` classifies before answering. `retroactive` answers first,
    /// then blocks the next query when the saved score meets a block action.
    #[serde(default = "default_ai_decision_mode")]
    pub ai_decision_mode: String,
    #[serde(default = "default_ai_confidence")]
    pub ai_confidence_advertising: i32,
    #[serde(default = "default_ai_confidence")]
    pub ai_confidence_tracking: i32,
    #[serde(default = "default_ai_confidence")]
    pub ai_confidence_telemetry: i32,
    #[serde(default = "default_ai_confidence")]
    pub ai_confidence_analytics: i32,
    #[serde(default = "default_ai_confidence")]
    pub ai_confidence_malicious: i32,
    #[serde(default = "default_ai_confidence")]
    pub ai_confidence_fraud: i32,
    #[serde(default = "default_ai_confidence")]
    pub ai_confidence_cryptomining: i32,
    #[serde(default = "default_ai_confidence")]
    pub ai_confidence_tunnel: i32,
    /// Whether each classification category is considered at all.
    #[serde(default = "default_true")]
    pub ai_advertising_enabled: bool,
    /// `block` enforces the decision; `record` only logs it.
    #[serde(default = "default_ai_action")]
    pub ai_advertising_action: String,
    #[serde(default = "default_true")]
    pub ai_tracking_enabled: bool,
    #[serde(default = "default_ai_action")]
    pub ai_tracking_action: String,
    #[serde(default = "default_true")]
    pub ai_telemetry_enabled: bool,
    #[serde(default = "default_ai_action")]
    pub ai_telemetry_action: String,
    #[serde(default = "default_true")]
    pub ai_analytics_enabled: bool,
    #[serde(default = "default_ai_action")]
    pub ai_analytics_action: String,
    #[serde(default = "default_true")]
    pub ai_malicious_enabled: bool,
    #[serde(default = "default_ai_action")]
    pub ai_malicious_action: String,
    #[serde(default = "default_true")]
    pub ai_fraud_enabled: bool,
    #[serde(default = "default_ai_action")]
    pub ai_fraud_action: String,
    #[serde(default = "default_true")]
    pub ai_cryptomining_enabled: bool,
    #[serde(default = "default_ai_action")]
    pub ai_cryptomining_action: String,
    #[serde(default = "default_true")]
    pub ai_tunnel_enabled: bool,
    #[serde(default = "default_ai_action")]
    pub ai_tunnel_action: String,
    /// When set, an advanced check stores the registration record.
    #[serde(default)]
    pub save_domain_lookups: bool,
    #[serde(default = "default_true")]
    pub log_retention_enabled: bool,
    #[serde(default = "default_log_retention_days")]
    pub log_retention_days: i32,
    #[serde(default = "default_true")]
    pub dns_resolver_enabled: bool,
    #[serde(default = "default_dns_protocol")]
    pub dns_protocol: String,
    #[serde(default = "default_true")]
    pub doh_blocking_enabled: bool,
    #[serde(default = "default_doh_provider")]
    pub doh_provider: String,
    #[serde(default)]
    pub doh_custom_url: String,
    #[serde(default)]
    pub hosts_blocklist_enabled: bool,
    #[serde(default = "default_hosts_lists")]
    pub hosts_blocklist_selected_lists: String,
    #[serde(default = "default_hosts_frequency")]
    pub hosts_blocklist_update_frequency: String,
    #[serde(default = "default_min_datetime")]
    pub hosts_blocklist_last_updated: OffsetDateTime,
    #[serde(default)]
    pub hosts_blocklist_custom_urls: String,
    #[serde(default)]
    pub notify_every_connection: bool,
    #[serde(default)]
    pub notify_new_connection: bool,
    #[serde(default = "default_true")]
    pub notify_new_app: bool,
    #[serde(default = "default_true")]
    pub notify_threat_detected: bool,
    #[serde(default)]
    pub persist_rules_offline: bool,
    #[serde(default)]
    pub geoip_enabled: bool,
    #[serde(default)]
    pub log_daemon_connections: bool,
    #[serde(default)]
    pub power_user_settings_enabled: bool,
    #[serde(default = "default_dns_block_mode")]
    pub dns_block_response_mode: String,
    #[serde(default)]
    pub dns_block_custom_ip: String,
    #[serde(default)]
    pub dns_rebinding_protection_enabled: bool,
    /// When false, `.local` names are forwarded upstream instead of answered locally.
    #[serde(default = "default_true")]
    pub dns_answer_local_names_enabled: bool,
    /// Blocks domains registered fewer than `dns_new_domain_max_age_days` ago.
    #[serde(default)]
    pub dns_new_domain_blocking_enabled: bool,
    /// One of 7, 14, 30 or 90.
    #[serde(default = "default_new_domain_max_age_days")]
    pub dns_new_domain_max_age_days: u32,
    /// `stable`, `beta`, or `nightly`; see [`normalize_update_channel`].
    #[serde(default = "default_update_channel")]
    pub update_channel: String,
    #[serde(default)]
    pub network_mapping_auto_enabled: bool,
    #[serde(default = "default_mapping_interval")]
    pub network_mapping_interval_minutes: i32,
    #[serde(default)]
    pub network_mapping_baseline_established: bool,
    #[serde(default = "default_min_datetime")]
    pub oui_database_last_updated: OffsetDateTime,
    #[serde(default = "default_min_datetime")]
    pub geoip_database_last_updated: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

fn default_true() -> bool {
    true
}

fn default_wazuh_transport() -> String {
    "file".to_owned()
}

fn default_wazuh_port() -> i32 {
    514
}

fn default_wazuh_protocol() -> String {
    "udp".to_owned()
}

pub(crate) fn default_ai_decision_mode() -> String {
    "retroactive".to_owned()
}

pub(crate) fn default_ai_confidence() -> i32 {
    80
}

/// Lowest score a category can require. Below this, classifications are too
/// uncertain to treat as a decision.
pub const MIN_AI_CONFIDENCE: i32 = 60;

pub fn clamp_ai_confidence(value: i32) -> i32 {
    value.clamp(MIN_AI_CONFIDENCE, 100)
}

pub(crate) fn normalize_ai_decision_mode(mode: &str) -> String {
    if mode == "proactive" {
        "proactive".to_owned()
    } else {
        default_ai_decision_mode()
    }
}

pub(crate) fn default_ai_action() -> String {
    "record".to_owned()
}

/// Coerces a stored action to `block` or `record`, defaulting to `record`.
fn default_update_channel() -> String {
    "stable".to_owned()
}

/// The update channel as stored: `beta` or `nightly` when asked for, and
/// `stable` for anything else, including a value from a newer client this
/// daemon does not know.
#[must_use]
pub fn normalize_update_channel(channel: &str) -> String {
    match channel.trim().to_ascii_lowercase().as_str() {
        "beta" => "beta".to_owned(),
        "nightly" => "nightly".to_owned(),
        _ => default_update_channel(),
    }
}

pub(crate) fn normalize_ai_action(action: &str) -> String {
    if action == "block" {
        "block".to_owned()
    } else {
        default_ai_action()
    }
}

fn default_log_retention_days() -> i32 {
    antiwire_tuning::DEFAULT_LOG_RETENTION_DAYS
}

fn default_dns_protocol() -> String {
    "doh".to_owned()
}

fn default_doh_provider() -> String {
    "cloudflare".to_owned()
}

fn default_hosts_lists() -> String {
    "hagezi_light".to_owned()
}

fn default_hosts_frequency() -> String {
    "24hours".to_owned()
}

fn default_dns_block_mode() -> String {
    "sinkhole".to_owned()
}

fn default_new_domain_max_age_days() -> u32 {
    30
}

fn default_mapping_interval() -> i32 {
    30
}

fn serialize_secret<S>(secret: &SecretBytes, serializer: S) -> std::result::Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let text = secret.as_str().map_err(serde::ser::Error::custom)?;
    serializer.serialize_str(text)
}

fn deserialize_secret<'de, D>(deserializer: D) -> std::result::Result<SecretBytes, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let text = String::deserialize(deserializer)?;
    Ok(SecretBytes::from_string(text))
}

fn default_min_datetime() -> OffsetDateTime {
    OffsetDateTime::UNIX_EPOCH
}

impl Default for DaemonSetting {
    fn default() -> Self {
        Self {
            id: 1,
            siem_enabled: false,
            wazuh_transport: default_wazuh_transport(),
            wazuh_file_path: String::new(),
            wazuh_manager_host: String::new(),
            wazuh_manager_port: default_wazuh_port(),
            wazuh_protocol: default_wazuh_protocol(),
            siem_file_enabled: true,
            siem_syslog_enabled: false,
            siem_webhook_enabled: false,
            siem_url: String::new(),
            siem_auth_token: String::new(),
            siem_auth_header: String::new(),
            siem_send_allowed: false,
            siem_send_blocked: true,
            siem_send_new_app: true,
            siem_send_new_domain: true,
            siem_send_threats: true,
            ai_enabled: false,
            ai_api_key: SecretBytes::default(),
            ai_decision_mode: default_ai_decision_mode(),
            ai_confidence_advertising: default_ai_confidence(),
            ai_confidence_tracking: default_ai_confidence(),
            ai_confidence_telemetry: default_ai_confidence(),
            ai_confidence_analytics: default_ai_confidence(),
            ai_confidence_malicious: default_ai_confidence(),
            ai_confidence_fraud: default_ai_confidence(),
            ai_confidence_cryptomining: default_ai_confidence(),
            ai_confidence_tunnel: default_ai_confidence(),
            ai_advertising_enabled: true,
            ai_advertising_action: default_ai_action(),
            ai_tracking_enabled: true,
            ai_tracking_action: default_ai_action(),
            ai_telemetry_enabled: true,
            ai_telemetry_action: default_ai_action(),
            ai_analytics_enabled: true,
            ai_analytics_action: default_ai_action(),
            ai_malicious_enabled: true,
            ai_malicious_action: default_ai_action(),
            ai_fraud_enabled: true,
            ai_fraud_action: default_ai_action(),
            ai_cryptomining_enabled: true,
            ai_cryptomining_action: default_ai_action(),
            ai_tunnel_enabled: true,
            ai_tunnel_action: default_ai_action(),
            save_domain_lookups: false,
            log_retention_enabled: true,
            log_retention_days: default_log_retention_days(),
            dns_resolver_enabled: true,
            dns_protocol: default_dns_protocol(),
            doh_blocking_enabled: true,
            doh_provider: default_doh_provider(),
            doh_custom_url: String::new(),
            hosts_blocklist_enabled: false,
            hosts_blocklist_selected_lists: default_hosts_lists(),
            hosts_blocklist_update_frequency: default_hosts_frequency(),
            hosts_blocklist_last_updated: default_min_datetime(),
            hosts_blocklist_custom_urls: String::new(),
            notify_every_connection: false,
            notify_new_connection: false,
            notify_new_app: true,
            notify_threat_detected: true,
            persist_rules_offline: false,
            geoip_enabled: false,
            log_daemon_connections: false,
            power_user_settings_enabled: false,
            dns_block_response_mode: default_dns_block_mode(),
            dns_block_custom_ip: String::new(),
            dns_rebinding_protection_enabled: false,
            dns_answer_local_names_enabled: true,
            dns_new_domain_blocking_enabled: false,
            dns_new_domain_max_age_days: default_new_domain_max_age_days(),
            update_channel: default_update_channel(),
            network_mapping_auto_enabled: false,
            network_mapping_interval_minutes: default_mapping_interval(),
            network_mapping_baseline_established: false,
            oui_database_last_updated: default_min_datetime(),
            geoip_database_last_updated: default_min_datetime(),
            updated_at: OffsetDateTime::now_utc(),
        }
    }
}

/// DNS reverse-lookup cache entry keyed by IP address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsCacheEntry {
    pub id: String,
    pub domain: String,
    pub last_seen: OffsetDateTime,
}

/// `TypeSafe` ratings and the applied decision for one classified domain.
///
/// One row per domain: `first_seen` is the original classification time and
/// `updated_at` the most recent. `rating_*` are the raw probabilities (0.0-1.0).
/// `verdict` is `block`, `record`, or empty when no category met its threshold;
/// `top_category` / `top_score` identify the category that drove it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DomainDecision {
    pub domain: String,
    #[serde(default)]
    pub model: String,
    #[serde(default)]
    pub rating_advertising: f64,
    #[serde(default)]
    pub rating_tracking: f64,
    #[serde(default)]
    pub rating_telemetry: f64,
    #[serde(default)]
    pub rating_analytics: f64,
    #[serde(default)]
    pub rating_malicious: f64,
    #[serde(default)]
    pub rating_fraud: f64,
    #[serde(default)]
    pub rating_cryptomining: f64,
    #[serde(default)]
    pub rating_tunnel: f64,
    #[serde(default)]
    pub rating_newly_registered: f64,
    #[serde(default)]
    pub rating_registry_hold: f64,
    #[serde(default)]
    pub rating_hidden_registrant: f64,
    #[serde(default)]
    pub rating_abusive_registrar: f64,
    #[serde(default)]
    pub verdict: String,
    #[serde(default)]
    pub top_category: String,
    #[serde(default)]
    pub top_score: f64,
    /// `basic` or `advanced`; advanced scans are not implemented yet.
    #[serde(default = "default_scan_tier")]
    pub scan_tier: String,
    pub first_seen: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

/// Official registration record saved for one domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainLookup {
    pub domain: String,
    pub source: String,
    pub registrar: Option<String>,
    pub registrar_id: Option<String>,
    pub statuses: Vec<String>,
    pub nameservers: Vec<String>,
    pub registered_at: Option<OffsetDateTime>,
    pub expires_at: Option<OffsetDateTime>,
    pub registry_updated_at: Option<OffsetDateTime>,
    pub registrant_name: Option<String>,
    pub registrant_organization: Option<String>,
    pub redacted: bool,
    pub dnssec: Option<bool>,
    pub fetched_at: OffsetDateTime,
}

/// Which saved decisions [`crate::Store::query_domain_decisions`] returns.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum DomainDecisionVerdictFilter {
    #[default]
    All,
    Block,
    Record,
    /// Classified domains where no category met its threshold.
    Clean,
}

/// One page of saved decisions, newest `updated_at` first.
#[derive(Debug, Clone, Default)]
pub struct DomainDecisionQuery {
    pub limit: usize,
    pub offset: usize,
    pub verdict: DomainDecisionVerdictFilter,
    /// Case-insensitive substring match on the domain.
    pub search_query: Option<String>,
}

/// Decisions matching a [`DomainDecisionQuery`].
///
/// `total_count` honors every filter. The per-verdict counts honor the search
/// but ignore the verdict filter, so a UI can label each verdict choice.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DomainDecisionPage {
    pub decisions: Vec<DomainDecision>,
    pub total_count: u64,
    pub block_count: u64,
    pub record_count: u64,
    pub clean_count: u64,
}

pub(crate) fn default_scan_tier() -> String {
    "basic".to_owned()
}

/// Coerces a stored scan tier to `basic` or `advanced`, defaulting to `basic`.
pub(crate) fn normalize_scan_tier(tier: &str) -> String {
    if tier == "advanced" {
        "advanced".to_owned()
    } else {
        default_scan_tier()
    }
}

/// LAN device discovered by network mapping.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkDevice {
    pub mac_address: String,
    #[serde(default)]
    pub ip_address: String,
    #[serde(default)]
    pub manufacturer: String,
    #[serde(default)]
    pub mdns_name: String,
    #[serde(default)]
    pub adapter_id: String,
    pub first_seen: OffsetDateTime,
    pub last_seen: OffsetDateTime,
    #[serde(default)]
    pub present: bool,
}

/// CIDR range to scan on a given network adapter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkScanRange {
    pub id: i32,
    #[serde(default)]
    pub adapter_id: String,
    #[serde(default)]
    pub cidr: String,
}

/// Scheduled presence watch for a specific device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkDeviceWatch {
    pub id: i32,
    #[serde(default)]
    pub ip_address: String,
    #[serde(default)]
    pub mac_address: String,
    #[serde(default)]
    pub adapter_id: String,
    #[serde(default)]
    pub cidr: String,
    #[serde(default = "default_mapping_interval")]
    pub interval_minutes: i32,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub present: bool,
    #[serde(default)]
    pub baseline_established: bool,
    #[serde(default = "default_min_datetime")]
    pub last_checked: OffsetDateTime,
}

/// Input for inserting a connection log without a database-assigned id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NewConnectionLog {
    pub timestamp: OffsetDateTime,
    pub app_id: i32,
    /// Executable path the connection ran from, captured at flow resolution.
    /// Written once with the row; later flushes never rewrite it.
    #[serde(default)]
    pub app_path: String,
    #[serde(default = "default_protocol")]
    pub protocol: String,
    #[serde(default)]
    pub src_ip: String,
    #[serde(default)]
    pub src_port: i32,
    #[serde(default)]
    pub dst_ip: String,
    #[serde(default)]
    pub dst_port: i32,
    #[serde(default)]
    pub dst_domain: String,
    #[serde(default)]
    pub bytes_sent: i64,
    #[serde(default)]
    pub bytes_received: i64,
    #[serde(default = "default_action_taken")]
    pub action_taken: String,
    pub last_seen: OffsetDateTime,
    #[serde(default)]
    pub country_code: String,
    #[serde(default)]
    pub isp: String,
    /// Newline-separated blocklist ids that produced this block, if any.
    #[serde(default)]
    pub blocklist_names: String,
    /// Per-connection session id from the tracker. Non-zero values upsert
    /// onto the owning row when `conn_pid` and the connection start match;
    /// 0 always inserts a fresh row.
    #[serde(default)]
    pub conn_id: i64,
    /// Pid observed when the connection opened. Must be the pinned open-time
    /// value, not the current pid, so the triple stays stable across flushes.
    #[serde(default)]
    pub conn_pid: i32,
    /// Marks this flush as the connection's end. The store records the close
    /// time and the row stops accumulating further flushes.
    #[serde(default)]
    pub is_close: bool,
    /// Sets the row's domain to `dst_domain` outright, even where it is
    /// weaker than the row's own or empty. Without it the stronger of the two
    /// is kept, so a confirmed domain is never replaced.
    ///
    /// For a connection whose name was judged again with more known of the
    /// moment it opened, where the earlier answer no longer stands.
    #[serde(default)]
    pub replace_domain: bool,
}

/// Serializes named blocklist ids for `connection_logs.blocklist_names`.
///
/// Labels are joined with a newline, and [`decode_blocklist_names`] splits on
/// it, so a label containing a control character could forge extra catalog ids
/// or inject log lines. Control characters are stripped and each label is
/// capped before encoding.
#[must_use]
pub fn encode_blocklist_names<I, S>(names: I) -> String
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    const MAX_LABEL_CHARS: usize = 128;
    let mut encoded = String::new();
    for name in names {
        let clean: String = name
            .as_ref()
            .trim()
            .chars()
            .filter(|character| !character.is_control())
            .take(MAX_LABEL_CHARS)
            .collect();
        if clean.is_empty() {
            continue;
        }
        if !encoded.is_empty() {
            encoded.push('\n');
        }
        encoded.push_str(&clean);
    }
    encoded
}

/// Splits a persisted `blocklist_names` column into catalog ids.
#[must_use]
pub fn decode_blocklist_names(raw: &str) -> Vec<String> {
    raw.split('\n')
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Identifies a persisted flow whose owning application was resolved after insertion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionLogAttribution {
    pub from_app_id: i32,
    pub to_app_id: i32,
    pub protocol: String,
    pub src_ip: String,
    pub dst_ip: String,
    pub dst_port: i32,
    /// Owning connection session id. Non-zero re-points exactly the row whose
    /// full identity triple matches; 0 falls back to the flow-tuple match.
    pub conn_id: i64,
    /// Pid observed when the connection opened (pinned identity component).
    pub conn_pid: i32,
    /// Connection start instant (pinned identity component).
    pub conn_start: OffsetDateTime,
}

/// A domain for a connection whose row is already written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionDomainUpgrade {
    /// Owning connection session id; never 0.
    pub conn_id: i64,
    /// Pid observed when the connection opened (pinned identity component).
    pub conn_pid: i32,
    /// Connection start instant (pinned identity component).
    pub conn_start: OffsetDateTime,
    /// The domain to prefer over the row's current one.
    pub dst_domain: String,
    /// Sets the row's domain to `dst_domain` outright, as
    /// [`NewConnectionLog::replace_domain`] does, where the row's own would
    /// otherwise be kept.
    pub replace: bool,
}

/// Filters for paginated connection-log queries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectionLogQuery {
    #[serde(default)]
    pub offset: u32,
    #[serde(default)]
    pub limit: u32,
    /// When zero, no time filter is applied.
    #[serde(default)]
    pub time_filter_seconds: u32,
    /// Absolute window start (UTC). When either bound is set, overrides
    /// `time_filter_seconds`.
    #[serde(default)]
    pub time_window_start: Option<OffsetDateTime>,
    /// Absolute window end (UTC, exclusive).
    #[serde(default)]
    pub time_window_end: Option<OffsetDateTime>,
    #[serde(default)]
    pub action_filter: Option<String>,
    #[serde(default)]
    pub order_by: Option<String>,
    #[serde(default)]
    pub sort_descending: bool,
    #[serde(default)]
    pub app_name: Option<String>,
    /// Exact application row id. When set, it narrows (not replaces) the
    /// `app_name` match so one install path can be selected out of several
    /// sharing a name. Absent preserves the legacy name-only match.
    #[serde(default)]
    pub app_id: Option<i32>,
    #[serde(default)]
    pub search_query: Option<String>,
    #[serde(default)]
    pub protocol_filter: Option<String>,
    #[serde(default)]
    pub country_code: Option<String>,
    /// Exact destination port.
    #[serde(default)]
    pub port: Option<u16>,
    /// Exact destination host: the domain (case-insensitive) or the IP.
    #[serde(default)]
    pub host: Option<String>,
}

impl Default for ConnectionLogQuery {
    fn default() -> Self {
        Self {
            offset: 0,
            limit: antiwire_tuning::DEFAULT_LOG_PAGE_SIZE as u32,
            time_filter_seconds: 0,
            time_window_start: None,
            time_window_end: None,
            action_filter: None,
            order_by: None,
            sort_descending: true,
            app_name: None,
            app_id: None,
            search_query: None,
            protocol_filter: None,
            country_code: None,
            port: None,
            host: None,
        }
    }
}

/// Paginated connection-log query result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectionLogPage {
    pub logs: Vec<ConnectionLog>,
    pub total_count: u64,
    pub blocked_count: u64,
    #[serde(default)]
    pub unique_domain_count: u64,
}

/// Country counts across every retained connection record, independent of paging.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CountryStatistics {
    pub country_counts: std::collections::BTreeMap<String, u64>,
    pub total_count: u64,
    pub unknown_count: u64,
}

/// Pre-aggregated connection activity for one 30-minute window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActivityBucket {
    pub bucket_start: OffsetDateTime,
    pub event_count: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub blocked_count: u64,
}

/// Filters for per-application log summaries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ApplicationLogSummaryQuery {
    #[serde(default)]
    pub time_filter_seconds: u32,
    #[serde(default)]
    pub time_window_start: Option<OffsetDateTime>,
    #[serde(default)]
    pub time_window_end: Option<OffsetDateTime>,
    #[serde(default)]
    pub action_filter: Option<String>,
}

/// Per-application log aggregation for the UI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplicationLogSummary {
    pub app_id: i32,
    pub app_name: String,
    pub app_path: String,
    pub connection_count: u64,
    pub blocked_count: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub last_seen: OffsetDateTime,
}

pub(crate) fn parse_timestamp(value: &str) -> Result<OffsetDateTime> {
    OffsetDateTime::parse(value, &Rfc3339)
        .map_err(|_| StoreError::InvalidTimestamp(value.to_owned()))
}

/// Width of each activity heatmap bucket.
pub const ACTIVITY_BUCKET_SECONDS: i64 = 30 * 60;

/// Floors `timestamp` to the start of its 30-minute bucket (UTC).
#[must_use]
pub fn activity_bucket_start(timestamp: OffsetDateTime) -> OffsetDateTime {
    let unix = timestamp.unix_timestamp();
    let floored = unix - (unix % ACTIVITY_BUCKET_SECONDS);
    OffsetDateTime::from_unix_timestamp(floored).unwrap_or(OffsetDateTime::UNIX_EPOCH)
}

pub(crate) fn format_timestamp(value: OffsetDateTime) -> String {
    format_dns_timestamp(value)
}

/// Canonical fixed-width UTC timestamp. Text ordering matches chronological
/// ordering, including whole seconds, fractional seconds and non-UTC inputs.
pub(crate) fn format_dns_timestamp(value: OffsetDateTime) -> String {
    const FORMAT: &[time::format_description::FormatItem<'static>] = time::macros::format_description!(
        "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:9]Z"
    );
    value
        .to_offset(time::UtcOffset::UTC)
        .format(FORMAT)
        .unwrap_or_else(|_| "1970-01-01T00:00:00.000000000Z".to_owned())
}

pub(crate) fn bool_to_i64(value: bool) -> i64 {
    i64::from(value)
}

pub(crate) fn i64_to_bool(value: i64) -> bool {
    value != 0
}

#[cfg(test)]
mod tests {
    use super::{
        decode_blocklist_names, encode_blocklist_names, format_timestamp, parse_timestamp,
    };

    #[test]
    fn timestamps_sort_chronologically_and_preserve_nanoseconds() {
        let raw = [
            "2026-10-16T00:00:05Z",
            "2026-10-16T00:00:05.000000001Z",
            "2026-10-15T17:00:05.5-07:00",
            "2026-10-16T00:00:05.999999999Z",
            "2026-10-16T00:00:06Z",
        ];
        let formatted: Vec<_> = raw
            .iter()
            .map(|raw| {
                let parsed = parse_timestamp(raw).unwrap();
                let formatted = format_timestamp(parsed);
                assert_eq!(formatted.len(), 30);
                assert_eq!(parse_timestamp(&formatted).unwrap(), parsed);
                formatted
            })
            .collect();
        assert_eq!(formatted[0], "2026-10-16T00:00:05.000000000Z");
        assert!(formatted.windows(2).all(|pair| pair[0] < pair[1]));
    }

    #[test]
    fn blocklist_name_encoding_round_trips_and_skips_blanks() {
        let encoded = encode_blocklist_names(["hagezi_light", "  ", "hagezi_tif"]);
        assert_eq!(encoded, "hagezi_light\nhagezi_tif");
        assert_eq!(
            decode_blocklist_names(&encoded),
            vec!["hagezi_light".to_owned(), "hagezi_tif".to_owned()]
        );
        assert!(decode_blocklist_names("").is_empty());
        assert!(encode_blocklist_names(Vec::<String>::new()).is_empty());
    }

    #[test]
    fn blocklist_name_encoding_cannot_forge_extra_ids() {
        let encoded = encode_blocklist_names(["evil\ninjected", "good"]);
        assert_eq!(encoded, "evilinjected\ngood");
        assert_eq!(
            decode_blocklist_names(&encoded),
            vec!["evilinjected".to_owned(), "good".to_owned()]
        );
    }

    #[test]
    fn blocklist_name_encoding_caps_label_length() {
        let long = "x".repeat(500);
        let encoded = encode_blocklist_names([long.as_str()]);
        assert_eq!(encoded.chars().count(), 128);
    }
}
