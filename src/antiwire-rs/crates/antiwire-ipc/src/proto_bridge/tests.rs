//! Unit tests for the protobuf conversions.

use super::activity::{activity_bucket_window, history_deletion_start};
use super::capture::{capture_frame_to_proto, capture_status_to_proto, CaptureId};
use super::logs::{connection_log_to_traffic_event, log_request_to_query};
use super::settings::{settings_merge_request, settings_to_proto};
use super::timestamps::{parse_timestamp_or_epoch, time_window_from_proto, unix_secs_to_datetime};
use std::collections::HashMap;

use antiwire_capture::{CaptureFrame, CaptureSnapshot, CaptureStatus as SessionCaptureStatus};
use antiwire_proto::{LogRequest, SettingsRequest};
use antiwire_store::{ConnectionLog, DaemonSetting, SecretBytes};
use time::OffsetDateTime;

/// A half-specified window must still filter: discarding the bound the
/// request did set would silently widen the query to all time.
#[test]
fn partially_specified_time_windows_are_honored() {
    let start = unix_secs_to_datetime(1_700_000_000).expect("start");
    let (since, until) = time_window_from_proto(1_700_000_000, 0);
    assert_eq!(since, Some(start));
    assert_eq!(until, None);

    let end = unix_secs_to_datetime(1_700_000_100).expect("end");
    let (since, until) = time_window_from_proto(0, 1_700_000_100);
    assert_eq!(since, None);
    assert_eq!(until, Some(end));

    let (since, until) = time_window_from_proto(0, 0);
    assert_eq!(since, None);
    assert_eq!(until, None);
}

#[test]
fn log_request_app_id_maps_to_exact_query_filter() {
    let query = log_request_to_query(LogRequest {
        app_id: 9,
        ..Default::default()
    });
    assert_eq!(query.app_id, Some(9));

    // Zero (and negative) ids mean unset, preserving the legacy
    // name-only match for older clients that cannot send one.
    let unset = log_request_to_query(LogRequest::default());
    assert_eq!(unset.app_id, None);
    let zero = log_request_to_query(LogRequest {
        app_id: 0,
        ..Default::default()
    });
    assert_eq!(zero.app_id, None);
}

#[test]
fn log_request_port_and_host_map_to_exact_query_filters() {
    let query = log_request_to_query(LogRequest {
        port_filter: 443,
        host_filter: "  example.com ".to_owned(),
        ..Default::default()
    });
    assert_eq!(query.port, Some(443));
    assert_eq!(query.host.as_deref(), Some("example.com"));

    // Zero, out-of-range ports and blank hosts are unset.
    let unset = log_request_to_query(LogRequest {
        port_filter: 70_000,
        host_filter: "   ".to_owned(),
        ..Default::default()
    });
    assert_eq!(unset.port, None);
    assert_eq!(unset.host, None);
}

#[test]
fn a_records_own_path_wins_over_the_applications_current_path() {
    let log = ConnectionLog {
        id: 1,
        timestamp: OffsetDateTime::UNIX_EPOCH,
        app_id: 7,
        app_path: r"C:\Apps\App-1.0\App.exe".to_owned(),
        protocol: "TCP".to_owned(),
        src_ip: String::new(),
        src_port: 0,
        dst_ip: String::new(),
        dst_port: 0,
        dst_domain: String::new(),
        bytes_sent: 0,
        bytes_received: 0,
        action_taken: "ALLOWED".to_owned(),
        last_seen: OffsetDateTime::UNIX_EPOCH,
        country_code: String::new(),
        isp: String::new(),
        blocklist_names: String::new(),
        conn_id: 0,
        conn_pid: 0,
        closed_at: None,
        is_active: false,
    };
    let apps = HashMap::from([(
        7,
        ("App.exe".to_owned(), r"C:\Apps\App-2.0\App.exe".to_owned()),
    )]);

    let event = connection_log_to_traffic_event(&log, &apps);
    assert_eq!(event.app_path, r"C:\Apps\App-1.0\App.exe");

    // A row the migration could not place falls back to the current path.
    let unplaced = ConnectionLog {
        app_path: String::new(),
        ..log
    };
    let event = connection_log_to_traffic_event(&unplaced, &apps);
    assert_eq!(event.app_path, r"C:\Apps\App-2.0\App.exe");
}

fn saved_settings() -> DaemonSetting {
    DaemonSetting {
        network_mapping_baseline_established: true,
        oui_database_last_updated: OffsetDateTime::from_unix_timestamp(1_700_000_000)
            .expect("oui timestamp"),
        geoip_database_last_updated: OffsetDateTime::from_unix_timestamp(1_700_000_001)
            .expect("geoip timestamp"),
        hosts_blocklist_last_updated: OffsetDateTime::from_unix_timestamp(1_700_000_002)
            .expect("blocklist timestamp"),
        ..DaemonSetting::default()
    }
}

/// The regression this guards: a settings save used to reset the columns the
/// daemon owns, so the download schedulers fetched their databases again and
/// new-device alerts repeated.
#[test]
fn merge_preserves_daemon_owned_columns_the_request_cannot_express() {
    let previous = saved_settings();
    // A client toggling one unrelated switch, with every other field defaulted.
    let request = SettingsRequest {
        notify_new_app: true,
        ..SettingsRequest::default()
    };

    let merged = settings_merge_request(&previous, request);

    assert!(merged.network_mapping_baseline_established);
    assert_eq!(
        merged.oui_database_last_updated,
        previous.oui_database_last_updated
    );
    assert_eq!(
        merged.geoip_database_last_updated,
        previous.geoip_database_last_updated
    );
    assert_eq!(
        merged.hosts_blocklist_last_updated, previous.hosts_blocklist_last_updated,
        "an unset timestamp must not date the lists to the epoch"
    );
    assert!(merged.notify_new_app, "the requested change must apply");
}

#[test]
fn merge_applies_every_field_the_request_owns() {
    let previous = saved_settings();
    let request = SettingsRequest {
        siem_enabled: true,
        wazuh_manager_host: "siem.example.test".to_owned(),
        wazuh_manager_port: 5514,
        log_retention_days: 7,
        dns_resolver_enabled: true,
        doh_provider: "cloudflare".to_owned(),
        hosts_blocklist_enabled: true,
        hosts_blocklist_selected_lists: "hagezi_light".to_owned(),
        hosts_blocklist_last_updated: "2026-01-02T03:04:05Z".to_owned(),
        geo_ip_enabled: true,
        network_mapping_interval_minutes: 15,
        ..SettingsRequest::default()
    };

    let merged = settings_merge_request(&previous, request);

    assert!(merged.siem_enabled);
    assert_eq!(merged.wazuh_manager_host, "siem.example.test");
    assert_eq!(merged.wazuh_manager_port, 5514);
    assert_eq!(merged.log_retention_days, 7);
    assert!(merged.dns_resolver_enabled);
    assert_eq!(merged.doh_provider, "cloudflare");
    assert!(merged.hosts_blocklist_enabled);
    assert_eq!(merged.hosts_blocklist_selected_lists, "hagezi_light");
    assert_eq!(
        merged.hosts_blocklist_last_updated,
        parse_timestamp_or_epoch("2026-01-02T03:04:05Z")
    );
    assert!(merged.geoip_enabled);
    assert_eq!(merged.network_mapping_interval_minutes, 15);
}

#[test]
fn merge_sets_the_update_channel_and_keeps_it_when_unset() {
    let previous = saved_settings();
    let request = SettingsRequest {
        update_channel: "Beta".to_owned(),
        ..SettingsRequest::default()
    };
    let merged = settings_merge_request(&previous, request);
    assert_eq!(merged.update_channel, "beta");

    let unset = SettingsRequest::default();
    assert_eq!(
        settings_merge_request(&merged, unset).update_channel,
        "beta",
        "a client that predates the field keeps the saved channel"
    );
}

#[test]
fn merge_applies_new_domain_blocking_and_keeps_the_age_only_when_unset() {
    let previous = saved_settings();
    let request = SettingsRequest {
        dns_new_domain_blocking_enabled: true,
        dns_new_domain_max_age_days: 14,
        ..SettingsRequest::default()
    };
    let merged = settings_merge_request(&previous, request);
    assert!(merged.dns_new_domain_blocking_enabled);
    assert_eq!(merged.dns_new_domain_max_age_days, 14);

    let unset = SettingsRequest {
        dns_new_domain_blocking_enabled: true,
        dns_new_domain_max_age_days: 0,
        ..SettingsRequest::default()
    };
    assert_eq!(
        settings_merge_request(&merged, unset).dns_new_domain_max_age_days,
        14,
        "a client that predates the field keeps the saved age"
    );
    // Anything else is carried as asked, for the settings service to refuse
    // if the daemon cannot use it, rather than dropped without a word.
    let unsupported = SettingsRequest {
        dns_new_domain_max_age_days: 45,
        ..SettingsRequest::default()
    };
    assert_eq!(
        settings_merge_request(&merged, unsupported).dns_new_domain_max_age_days,
        45
    );
}

#[test]
fn merge_applies_ai_decision_types_when_the_request_carries_actions() {
    let previous = saved_settings();
    let request = SettingsRequest {
        ai_advertising_enabled: false,
        ai_advertising_action: "block".to_owned(),
        ai_malicious_enabled: false,
        ai_malicious_action: "block".to_owned(),
        ..SettingsRequest::default()
    };

    let merged = settings_merge_request(&previous, request);

    assert!(!merged.ai_advertising_enabled);
    assert_eq!(merged.ai_advertising_action, "block");
    assert!(!merged.ai_malicious_enabled);
    assert_eq!(merged.ai_malicious_action, "block");
    assert!(merged.ai_tracking_enabled, "untouched categories stay on");
    assert_eq!(merged.ai_tracking_action, "record");
}

/// A legacy client sends empty action strings. That must not read as "record
/// everything" and wipe the per-category controls the daemon already holds.
#[test]
fn merge_preserves_ai_decision_types_for_a_legacy_request() {
    let mut previous = saved_settings();
    previous.ai_advertising_enabled = false;
    previous.ai_advertising_action = "block".to_owned();

    let request = SettingsRequest {
        ai_advertising_enabled: true,
        ..SettingsRequest::default()
    };

    let merged = settings_merge_request(&previous, request);

    assert!(!merged.ai_advertising_enabled);
    assert_eq!(merged.ai_advertising_action, "block");
}

/// Round-tripping what the daemon reports must be a no-op for the columns the
/// response carries, so an unmodified save cannot drift the stored row.
#[test]
fn response_round_trip_leaves_settings_unchanged() {
    let mut previous = saved_settings();
    previous.ai_api_key = SecretBytes::from_string("sk-stored".to_owned());
    previous.siem_auth_token = "Bearer stored".to_owned();
    previous.private_relay_compatibility = true;
    let response = settings_to_proto(&previous);
    let request = SettingsRequest {
        siem_enabled: response.siem_enabled,
        siem_url: response.siem_url,
        siem_auth_token: response.siem_auth_token,
        siem_auth_header: response.siem_auth_header,
        wazuh_transport: response.wazuh_transport,
        wazuh_file_path: response.wazuh_file_path,
        wazuh_manager_host: response.wazuh_manager_host,
        wazuh_manager_port: response.wazuh_manager_port,
        wazuh_protocol: response.wazuh_protocol,
        siem_file_enabled: response.siem_file_enabled,
        siem_syslog_enabled: response.siem_syslog_enabled,
        siem_webhook_enabled: response.siem_webhook_enabled,
        siem_send_allowed: response.siem_send_allowed,
        siem_send_blocked: response.siem_send_blocked,
        siem_send_new_app: response.siem_send_new_app,
        siem_send_new_domain: response.siem_send_new_domain,
        siem_send_threats: response.siem_send_threats,
        ai_enabled: response.ai_enabled,
        ai_api_key: response.ai_api_key,
        ai_decision_mode: response.ai_decision_mode,
        ai_confidence_advertising: response.ai_confidence_advertising,
        ai_confidence_tracking: response.ai_confidence_tracking,
        ai_confidence_telemetry: response.ai_confidence_telemetry,
        ai_confidence_analytics: response.ai_confidence_analytics,
        ai_confidence_malicious: response.ai_confidence_malicious,
        ai_confidence_fraud: response.ai_confidence_fraud,
        ai_confidence_cryptomining: response.ai_confidence_cryptomining,
        ai_confidence_tunnel: response.ai_confidence_tunnel,
        ai_advertising_enabled: response.ai_advertising_enabled,
        ai_advertising_action: response.ai_advertising_action,
        ai_tracking_enabled: response.ai_tracking_enabled,
        ai_tracking_action: response.ai_tracking_action,
        ai_telemetry_enabled: response.ai_telemetry_enabled,
        ai_telemetry_action: response.ai_telemetry_action,
        ai_analytics_enabled: response.ai_analytics_enabled,
        ai_analytics_action: response.ai_analytics_action,
        ai_malicious_enabled: response.ai_malicious_enabled,
        ai_malicious_action: response.ai_malicious_action,
        ai_fraud_enabled: response.ai_fraud_enabled,
        ai_fraud_action: response.ai_fraud_action,
        ai_cryptomining_enabled: response.ai_cryptomining_enabled,
        ai_cryptomining_action: response.ai_cryptomining_action,
        ai_tunnel_enabled: response.ai_tunnel_enabled,
        ai_tunnel_action: response.ai_tunnel_action,
        log_retention_enabled: response.log_retention_enabled,
        log_retention_days: response.log_retention_days,
        dns_resolver_enabled: response.dns_resolver_enabled,
        dns_protocol: response.dns_protocol,
        doh_blocking_enabled: response.doh_blocking_enabled,
        doh_provider: response.doh_provider,
        doh_custom_url: response.doh_custom_url,
        hosts_blocklist_enabled: response.hosts_blocklist_enabled,
        hosts_blocklist_selected_lists: response.hosts_blocklist_selected_lists,
        hosts_blocklist_update_frequency: response.hosts_blocklist_update_frequency,
        hosts_blocklist_last_updated: response.hosts_blocklist_last_updated,
        hosts_blocklist_custom_urls: response.hosts_blocklist_custom_urls,
        notify_every_connection: response.notify_every_connection,
        notify_new_connection: response.notify_new_connection,
        notify_new_app: response.notify_new_app,
        notify_threat_detected: response.notify_threat_detected,
        persist_rules_offline: response.persist_rules_offline,
        geo_ip_enabled: response.geo_ip_enabled,
        log_daemon_connections: response.log_daemon_connections,
        power_user_settings_enabled: response.power_user_settings_enabled,
        dns_block_response_mode: response.dns_block_response_mode,
        dns_block_custom_ip: response.dns_block_custom_ip,
        dns_rebinding_protection_enabled: response.dns_rebinding_protection_enabled,
        dns_answer_local_names_enabled: response.dns_answer_local_names_enabled,
        dns_new_domain_blocking_enabled: response.dns_new_domain_blocking_enabled,
        dns_new_domain_max_age_days: response.dns_new_domain_max_age_days,
        update_channel: response.update_channel,
        private_relay_compatibility: response.private_relay_compatibility,
        network_mapping_auto_enabled: response.network_mapping_auto_enabled,
        network_mapping_interval_minutes: response.network_mapping_interval_minutes,
        save_domain_lookups: response.save_domain_lookups,
        clear_ai_api_key: false,
        clear_siem_auth_token: false,
    };

    let merged = settings_merge_request(&previous, request);

    assert_eq!(merged, previous);
}

#[test]
fn settings_response_reports_secrets_without_their_values() {
    let mut settings = DaemonSetting::default();
    let response = settings_to_proto(&settings);
    assert!(!response.ai_api_key_set);
    assert!(!response.siem_auth_token_set);

    settings.ai_api_key = SecretBytes::from_string("sk-stored".to_owned());
    settings.siem_auth_token = "Bearer stored".to_owned();
    let response = settings_to_proto(&settings);
    assert!(response.ai_api_key_set);
    assert!(response.siem_auth_token_set);
    assert_eq!(response.ai_api_key, "");
    assert_eq!(response.siem_auth_token, "");
}

#[test]
fn merge_replaces_or_clears_secrets_only_when_asked() {
    let previous = DaemonSetting {
        ai_api_key: SecretBytes::from_string("sk-stored".to_owned()),
        siem_auth_token: "Bearer stored".to_owned(),
        ..DaemonSetting::default()
    };

    let replaced = settings_merge_request(
        &previous,
        SettingsRequest {
            ai_api_key: "sk-new".to_owned(),
            siem_auth_token: "Bearer new".to_owned(),
            clear_ai_api_key: true,
            clear_siem_auth_token: true,
            ..SettingsRequest::default()
        },
    );
    assert_eq!(replaced.ai_api_key.as_str(), Ok("sk-new"));
    assert_eq!(replaced.siem_auth_token, "Bearer new");

    let cleared = settings_merge_request(
        &previous,
        SettingsRequest {
            clear_ai_api_key: true,
            clear_siem_auth_token: true,
            ..SettingsRequest::default()
        },
    );
    assert_eq!(cleared.ai_api_key.as_str(), Ok(""));
    assert_eq!(cleared.siem_auth_token, "");
}

#[test]
fn capture_snapshot_preserves_daemon_counters_and_state() {
    let snapshot = CaptureSnapshot {
        status: SessionCaptureStatus::Running,
        packets: 42,
        bytes: 8_192,
        dropped_packets: 3,
        filtered_packets: 11,
        app_name: "Browser".to_owned(),
        elapsed_seconds: 7,
        device_name: "test-device".to_owned(),
        message: "Capturing".to_owned(),
    };

    let proto = capture_status_to_proto(CaptureId, &snapshot);

    assert_eq!(proto.capture_id, "default");
    assert_eq!(proto.state, "capturing");
    assert!(proto.active);
    assert_eq!(proto.packets, 42);
    assert_eq!(proto.bytes, 8_192);
    assert_eq!(proto.dropped_packets, 3);
    assert_eq!(proto.filtered_packets, 11);
    assert_eq!(proto.app_name, "Browser");
    assert_eq!(proto.device_name, "test-device");
}

#[test]
fn captured_packet_bridge_preserves_metadata_and_payload() {
    let frame = CaptureFrame {
        sequence: 9,
        timestamp_us: 1_700_000_000_123_456,
        captured_length: 4,
        original_length: 64,
        link_layer: 1,
        protocol: "TCP".to_owned(),
        source: "192.0.2.1".to_owned(),
        destination: "198.51.100.2".to_owned(),
        source_port: 51_234,
        destination_port: 443,
        info: "SYN".to_owned(),
        payload: vec![1, 2, 3, 4],
    };

    let proto = capture_frame_to_proto(&frame);

    assert_eq!(proto.sequence, frame.sequence);
    assert_eq!(proto.timestamp_us, frame.timestamp_us);
    assert_eq!(proto.original_length, 64);
    assert_eq!(proto.protocol, "TCP");
    assert_eq!(proto.source_port, 51_234);
    assert_eq!(proto.data, vec![1, 2, 3, 4]);
}

#[test]
fn history_deletion_needs_all_or_a_start() {
    use antiwire_proto::DeleteHistoryRequest;

    let all = DeleteHistoryRequest {
        all: true,
        since: 0,
    };
    assert_eq!(history_deletion_start(&all), Ok(None));
    let since = DeleteHistoryRequest {
        all: false,
        since: 1_700_000_000,
    };
    assert_eq!(
        history_deletion_start(&since).map(|start| start.map(time::OffsetDateTime::unix_timestamp)),
        Ok(Some(1_700_000_000))
    );
    // An unset start must not silently become "delete everything".
    assert!(history_deletion_start(&DeleteHistoryRequest::default()).is_err());
    assert!(history_deletion_start(&DeleteHistoryRequest {
        all: false,
        since: u64::MAX,
    })
    .is_err());
}

#[test]
fn activity_window_defaults_to_rolling_week() {
    let (since, until) = activity_bucket_window(0, 0, 0).expect("default window");
    assert!(since < until);
    assert_eq!((until - since).whole_days(), 7);
}

#[test]
fn activity_window_accepts_explicit_week_range() {
    let (since, until) = activity_bucket_window(7, 1_700_000_000, 1_700_000_000 + 7 * 86_400)
        .expect("explicit range");
    assert_eq!(since.unix_timestamp(), 1_700_000_000);
    assert_eq!(until.unix_timestamp(), 1_700_000_000 + 7 * 86_400);
}

#[test]
fn activity_window_rejects_partial_and_inverted_ranges() {
    assert!(activity_bucket_window(7, 1_700_000_000, 0).is_err());
    assert!(activity_bucket_window(7, 0, 1_700_000_000).is_err());
    assert!(activity_bucket_window(7, 1_700_000_100, 1_700_000_000).is_err());
    assert!(
        activity_bucket_window(7, 1_700_000_000, 1_700_000_000 + 367 * 86_400).is_err(),
        "unbounded ranges must not reach the store"
    );
}

#[test]
fn only_the_sessions_capture_id_is_found() {
    assert_eq!(CaptureId::from_proto("default").expect("found"), CaptureId);
    assert_eq!(
        CaptureId::from_proto("other").expect_err("missing").code(),
        tonic::Code::NotFound
    );
}
