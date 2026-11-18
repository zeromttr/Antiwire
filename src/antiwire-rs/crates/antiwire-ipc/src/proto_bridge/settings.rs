//! Settings: store row to response, and merging client updates.

use super::ai_settings::{apply_ai_decision_types, request_specifies_ai_confidence};
use super::scalars::{clamp_confidence, i32_to_u32, u32_to_i32};
use super::timestamps::{format_timestamp_rfc3339, parse_timestamp_or_epoch};

use antiwire_proto::{SettingsRequest, SettingsResponse};
use antiwire_store::{DaemonSetting, SecretBytes};

pub(crate) fn settings_to_proto(settings: &DaemonSetting) -> SettingsResponse {
    SettingsResponse {
        siem_enabled: settings.siem_enabled,
        siem_url: settings.siem_url.clone(),
        // Secrets are write-only over IPC: report whether one is stored, never its value.
        siem_auth_token: String::new(),
        siem_auth_token_set: !settings.siem_auth_token.is_empty(),
        siem_auth_header: settings.siem_auth_header.clone(),
        wazuh_transport: settings.wazuh_transport.clone(),
        wazuh_file_path: settings.wazuh_file_path.clone(),
        wazuh_manager_host: settings.wazuh_manager_host.clone(),
        wazuh_manager_port: i32_to_u32(settings.wazuh_manager_port),
        wazuh_protocol: settings.wazuh_protocol.clone(),
        siem_file_enabled: settings.siem_file_enabled,
        siem_syslog_enabled: settings.siem_syslog_enabled,
        siem_webhook_enabled: settings.siem_webhook_enabled,
        siem_send_allowed: settings.siem_send_allowed,
        siem_send_blocked: settings.siem_send_blocked,
        siem_send_new_app: settings.siem_send_new_app,
        siem_send_new_domain: settings.siem_send_new_domain,
        siem_send_threats: settings.siem_send_threats,
        ai_enabled: settings.ai_enabled,
        ai_api_key: String::new(),
        ai_api_key_set: !settings.ai_api_key.expose_secret().is_empty(),
        ai_decision_mode: settings.ai_decision_mode.clone(),
        ai_confidence_advertising: i32_to_u32(settings.ai_confidence_advertising),
        ai_confidence_tracking: i32_to_u32(settings.ai_confidence_tracking),
        ai_confidence_telemetry: i32_to_u32(settings.ai_confidence_telemetry),
        ai_confidence_analytics: i32_to_u32(settings.ai_confidence_analytics),
        ai_confidence_malicious: i32_to_u32(settings.ai_confidence_malicious),
        ai_confidence_fraud: i32_to_u32(settings.ai_confidence_fraud),
        ai_confidence_cryptomining: i32_to_u32(settings.ai_confidence_cryptomining),
        ai_confidence_tunnel: i32_to_u32(settings.ai_confidence_tunnel),
        ai_advertising_enabled: settings.ai_advertising_enabled,
        ai_advertising_action: settings.ai_advertising_action.clone(),
        ai_tracking_enabled: settings.ai_tracking_enabled,
        ai_tracking_action: settings.ai_tracking_action.clone(),
        ai_telemetry_enabled: settings.ai_telemetry_enabled,
        ai_telemetry_action: settings.ai_telemetry_action.clone(),
        ai_analytics_enabled: settings.ai_analytics_enabled,
        ai_analytics_action: settings.ai_analytics_action.clone(),
        ai_malicious_enabled: settings.ai_malicious_enabled,
        ai_malicious_action: settings.ai_malicious_action.clone(),
        ai_fraud_enabled: settings.ai_fraud_enabled,
        ai_fraud_action: settings.ai_fraud_action.clone(),
        ai_cryptomining_enabled: settings.ai_cryptomining_enabled,
        ai_cryptomining_action: settings.ai_cryptomining_action.clone(),
        ai_tunnel_enabled: settings.ai_tunnel_enabled,
        ai_tunnel_action: settings.ai_tunnel_action.clone(),
        save_domain_lookups: settings.save_domain_lookups,
        log_retention_enabled: settings.log_retention_enabled,
        log_retention_days: i32_to_u32(settings.log_retention_days),
        dns_resolver_enabled: settings.dns_resolver_enabled,
        dns_protocol: settings.dns_protocol.clone(),
        doh_blocking_enabled: settings.doh_blocking_enabled,
        doh_provider: settings.doh_provider.clone(),
        doh_custom_url: settings.doh_custom_url.clone(),
        hosts_blocklist_enabled: settings.hosts_blocklist_enabled,
        hosts_blocklist_selected_lists: settings.hosts_blocklist_selected_lists.clone(),
        hosts_blocklist_update_frequency: settings.hosts_blocklist_update_frequency.clone(),
        hosts_blocklist_last_updated: format_timestamp_rfc3339(
            settings.hosts_blocklist_last_updated,
        ),
        hosts_blocklist_custom_urls: settings.hosts_blocklist_custom_urls.clone(),
        notify_every_connection: settings.notify_every_connection,
        notify_new_connection: settings.notify_new_connection,
        notify_new_app: settings.notify_new_app,
        notify_threat_detected: settings.notify_threat_detected,
        persist_rules_offline: settings.persist_rules_offline,
        geo_ip_enabled: settings.geoip_enabled,
        log_daemon_connections: settings.log_daemon_connections,
        power_user_settings_enabled: settings.power_user_settings_enabled,
        dns_block_response_mode: settings.dns_block_response_mode.clone(),
        dns_block_custom_ip: settings.dns_block_custom_ip.clone(),
        dns_rebinding_protection_enabled: settings.dns_rebinding_protection_enabled,
        dns_answer_local_names_enabled: settings.dns_answer_local_names_enabled,
        dns_new_domain_blocking_enabled: settings.dns_new_domain_blocking_enabled,
        dns_new_domain_max_age_days: settings.dns_new_domain_max_age_days,
        update_channel: settings.update_channel.clone(),
        private_relay_compatibility: settings.private_relay_compatibility,
        windivert_enabled: settings.windivert_enabled,
        windivert_supported: antiwire_dns::windivert_supported(),
        network_mapping_auto_enabled: settings.network_mapping_auto_enabled,
        network_mapping_interval_minutes: i32_to_u32(settings.network_mapping_interval_minutes),
        oui_database_last_updated: format_timestamp_rfc3339(settings.oui_database_last_updated),
        geoip_database_last_updated: format_timestamp_rfc3339(settings.geoip_database_last_updated),
    }
}

/// The new value of a write-only secret, or `None` to keep the stored one.
///
/// `GetSettings` never returns secrets, so an empty field means "unchanged", not
/// "remove": a client that saves what it loaded must not wipe the stored key.
/// Removal is the explicit `clear` flag, and a non-empty value wins over it.
pub(super) fn merged_secret(value: String, clear: bool) -> Option<String> {
    if !value.is_empty() {
        Some(value)
    } else if clear {
        Some(String::new())
    } else {
        None
    }
}

/// Applies a client settings update on top of the row already in the store.
///
/// Merging rather than building a fresh [`DaemonSetting`] is load-bearing. Several
/// columns are daemon-owned and have no field in `SettingsRequest`, so constructing a
/// default and letting `update_settings` write all 45 columns silently resets them:
///
/// - `geoip_database_last_updated` / `oui_database_last_updated` gate the download
///   schedulers, so resetting them re-downloads multi-megabyte databases.
/// - `network_mapping_baseline_established` gates duplicate new-device alerts.
///
/// Anything the request cannot express is carried over from `previous` untouched.
pub(crate) fn settings_merge_request(
    previous: &DaemonSetting,
    request: SettingsRequest,
) -> DaemonSetting {
    let specifies_confidence = request_specifies_ai_confidence(&request);
    let mut settings = previous.clone();
    // Applied before the field moves below so the whole request is still borrowable.
    apply_ai_decision_types(&mut settings, &request);
    settings.siem_enabled = request.siem_enabled;
    settings.siem_url = request.siem_url;
    if let Some(token) = merged_secret(request.siem_auth_token, request.clear_siem_auth_token) {
        settings.siem_auth_token = token;
    }
    settings.siem_auth_header = request.siem_auth_header;
    settings.wazuh_transport = request.wazuh_transport;
    settings.wazuh_file_path = request.wazuh_file_path;
    settings.wazuh_manager_host = request.wazuh_manager_host;
    settings.wazuh_manager_port = u32_to_i32(request.wazuh_manager_port);
    settings.wazuh_protocol = request.wazuh_protocol;
    settings.siem_file_enabled = request.siem_file_enabled;
    settings.siem_syslog_enabled = request.siem_syslog_enabled;
    settings.siem_webhook_enabled = request.siem_webhook_enabled;
    // Keep legacy diagnostic transport in sync with sink flags.
    if settings.siem_syslog_enabled && !settings.siem_file_enabled {
        "syslog".clone_into(&mut settings.wazuh_transport);
    } else if settings.siem_file_enabled {
        "file".clone_into(&mut settings.wazuh_transport);
    }
    settings.siem_send_allowed = request.siem_send_allowed;
    settings.siem_send_blocked = request.siem_send_blocked;
    settings.siem_send_new_app = request.siem_send_new_app;
    settings.siem_send_new_domain = request.siem_send_new_domain;
    settings.siem_send_threats = request.siem_send_threats;
    settings.ai_enabled = request.ai_enabled;
    if let Some(key) = merged_secret(request.ai_api_key, request.clear_ai_api_key) {
        settings.ai_api_key = SecretBytes::from_string(key);
    }
    if matches!(
        request.ai_decision_mode.as_str(),
        "proactive" | "retroactive"
    ) {
        settings.ai_decision_mode = request.ai_decision_mode;
    }
    if specifies_confidence {
        settings.ai_confidence_advertising =
            clamp_confidence(u32_to_i32(request.ai_confidence_advertising));
        settings.ai_confidence_tracking =
            clamp_confidence(u32_to_i32(request.ai_confidence_tracking));
        settings.ai_confidence_telemetry =
            clamp_confidence(u32_to_i32(request.ai_confidence_telemetry));
        settings.ai_confidence_analytics =
            clamp_confidence(u32_to_i32(request.ai_confidence_analytics));
        settings.ai_confidence_malicious =
            clamp_confidence(u32_to_i32(request.ai_confidence_malicious));
        settings.ai_confidence_fraud = clamp_confidence(u32_to_i32(request.ai_confidence_fraud));
        settings.ai_confidence_cryptomining =
            clamp_confidence(u32_to_i32(request.ai_confidence_cryptomining));
        settings.ai_confidence_tunnel = clamp_confidence(u32_to_i32(request.ai_confidence_tunnel));
    }
    settings.save_domain_lookups = request.save_domain_lookups;
    // A client that predates the field sends nothing and keeps the saved channel.
    if !request.update_channel.trim().is_empty() {
        settings.update_channel = antiwire_store::normalize_update_channel(&request.update_channel);
    }
    settings.log_retention_enabled = request.log_retention_enabled;
    settings.log_retention_days = u32_to_i32(request.log_retention_days);
    settings.dns_resolver_enabled = request.dns_resolver_enabled;
    settings.dns_protocol = request.dns_protocol;
    settings.doh_blocking_enabled = request.doh_blocking_enabled;
    settings.doh_provider = request.doh_provider;
    settings.doh_custom_url = request.doh_custom_url;
    settings.hosts_blocklist_enabled = request.hosts_blocklist_enabled;
    settings.hosts_blocklist_selected_lists = request.hosts_blocklist_selected_lists;
    settings.hosts_blocklist_update_frequency = request.hosts_blocklist_update_frequency;
    // This column has a proto field but is written by the sync path, not the user. An
    // empty string means "not supplied" rather than "reset to the epoch" — parsing it
    // as a timestamp would date the lists to year 1 and force a full re-sync.
    if !request.hosts_blocklist_last_updated.trim().is_empty() {
        settings.hosts_blocklist_last_updated =
            parse_timestamp_or_epoch(&request.hosts_blocklist_last_updated);
    }
    settings.hosts_blocklist_custom_urls = request.hosts_blocklist_custom_urls;
    settings.notify_every_connection = request.notify_every_connection;
    settings.notify_new_connection = request.notify_new_connection;
    settings.notify_new_app = request.notify_new_app;
    settings.notify_threat_detected = request.notify_threat_detected;
    settings.persist_rules_offline = request.persist_rules_offline;
    settings.private_relay_compatibility = request.private_relay_compatibility;
    settings.windivert_enabled = request.windivert_enabled;
    settings.geoip_enabled = request.geo_ip_enabled;
    settings.log_daemon_connections = request.log_daemon_connections;
    settings.power_user_settings_enabled = request.power_user_settings_enabled;
    settings.dns_block_response_mode = request.dns_block_response_mode;
    settings.dns_block_custom_ip = request.dns_block_custom_ip;
    settings.dns_rebinding_protection_enabled = request.dns_rebinding_protection_enabled;
    settings.dns_answer_local_names_enabled = request.dns_answer_local_names_enabled;
    settings.dns_new_domain_blocking_enabled = request.dns_new_domain_blocking_enabled;
    // Zero is a client that predates the field; it keeps the saved age. Any
    // other value is taken as asked and refused if the daemon cannot use it.
    if request.dns_new_domain_max_age_days != 0 {
        settings.dns_new_domain_max_age_days = request.dns_new_domain_max_age_days;
    }
    settings.network_mapping_auto_enabled = request.network_mapping_auto_enabled;
    settings.network_mapping_interval_minutes =
        u32_to_i32(request.network_mapping_interval_minutes);
    settings
}
