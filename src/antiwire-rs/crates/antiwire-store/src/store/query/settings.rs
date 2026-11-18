//! Daemon settings queries, including encryption of the stored secrets at rest.

use rusqlite::Row;
use time::OffsetDateTime;

use antiwire_secrets::SecretBytes;

use crate::crypto;
use crate::error::{Result, StoreError};
use crate::models::{bool_to_i64, format_timestamp, i64_to_bool, DaemonSetting};

use crate::store::get_timestamp;

impl crate::store::Store {
    /// Returns the singleton daemon settings row (`id = 1`).
    pub fn get_settings(&self) -> Result<DaemonSetting> {
        let mut settings = self
            .db
            .query_optional(
                "SELECT id, siem_enabled, wazuh_transport, wazuh_file_path, wazuh_manager_host,
                        wazuh_manager_port, wazuh_protocol, siem_send_allowed, siem_send_blocked,
                        siem_send_new_app, siem_send_new_domain, siem_send_threats, ai_enabled,
                        ai_api_key, log_retention_enabled, log_retention_days, dns_resolver_enabled,
                        dns_protocol, doh_blocking_enabled,
                        doh_provider, doh_custom_url, hosts_blocklist_enabled,
                        hosts_blocklist_selected_lists, hosts_blocklist_update_frequency,
                        hosts_blocklist_last_updated, hosts_blocklist_custom_urls,
                        notify_every_connection, notify_new_connection, notify_new_app,
                        notify_threat_detected, persist_rules_offline, geoip_enabled,
                        log_daemon_connections, power_user_settings_enabled, dns_block_response_mode,
                        dns_block_custom_ip, dns_rebinding_protection_enabled,
                        network_mapping_auto_enabled, network_mapping_interval_minutes,
                        network_mapping_baseline_established, oui_database_last_updated,
                        geoip_database_last_updated, siem_file_enabled, siem_syslog_enabled,
                        siem_webhook_enabled, siem_url, siem_auth_token, siem_auth_header, updated_at,
                        ai_decision_mode, ai_confidence_advertising, ai_confidence_tracking,
                        ai_confidence_telemetry, ai_confidence_analytics, ai_confidence_malicious,
                        ai_confidence_fraud, ai_confidence_cryptomining, ai_confidence_tunnel,
                        ai_advertising_enabled, ai_advertising_action, ai_tracking_enabled,
                        ai_tracking_action, ai_telemetry_enabled, ai_telemetry_action,
                        ai_analytics_enabled, ai_analytics_action, ai_malicious_enabled,
                        ai_malicious_action, ai_fraud_enabled, ai_fraud_action,
                        ai_cryptomining_enabled, ai_cryptomining_action, ai_tunnel_enabled,
                        ai_tunnel_action, save_domain_lookups, dns_answer_local_names_enabled,
                        dns_new_domain_blocking_enabled, dns_new_domain_max_age_days,
                        update_channel, private_relay_compatibility, windivert_enabled
                 FROM daemon_settings
                 WHERE id = 1",
                [],
                map_daemon_setting,
            )?
            .ok_or(StoreError::SettingsMissing)?;

        if let Some(key) = &self.db_key {
            let encoded = settings
                .ai_api_key
                .as_str()
                .map_err(|_| StoreError::Crypto("ai api key is not utf-8".to_owned()))?;
            let plain = crypto::decrypt_field(encoded, key)?;
            settings.ai_api_key = SecretBytes::from_string(plain);
            settings.siem_auth_token = crypto::decrypt_field(&settings.siem_auth_token, key)?;
        }

        Ok(settings)
    }

    /// Replaces the singleton daemon settings row.
    ///
    /// Every column is written from `settings`, so a copy read earlier
    /// overwrites anything saved since. To change some fields of the current
    /// row use [`Self::modify_settings`] or a single-column setter.
    pub fn update_settings(&self, settings: &DaemonSetting) -> Result<()> {
        let _guard = self.settings_write_lock.lock();
        self.write_settings(settings)
    }

    /// Reads the settings, lets `merge` derive the new row from them, and
    /// saves it, with no other settings write in between. `merge` may refuse
    /// the change, and then nothing is saved.
    ///
    /// Returns the row as it was and as it was saved.
    ///
    /// # Errors
    ///
    /// What `merge` returned, or a failure reading or writing the row.
    pub fn modify_settings<F>(&self, merge: F) -> Result<(DaemonSetting, DaemonSetting)>
    where
        F: FnOnce(&DaemonSetting) -> Result<DaemonSetting>,
    {
        let _guard = self.settings_write_lock.lock();
        let previous = self.get_settings()?;
        let updated = merge(&previous)?;
        self.write_settings(&updated)?;
        Ok((previous, updated))
    }

    /// Records when the hosts blocklists last synced, leaving every other column alone.
    pub fn set_hosts_blocklist_last_updated(&self, at: OffsetDateTime) -> Result<()> {
        self.set_settings_timestamp(
            "UPDATE daemon_settings SET hosts_blocklist_last_updated = ?1, updated_at = ?2
             WHERE id = 1",
            at,
        )
    }

    /// Records when the `GeoIP` database last synced, leaving every other column alone.
    pub fn set_geoip_database_last_updated(&self, at: OffsetDateTime) -> Result<()> {
        self.set_settings_timestamp(
            "UPDATE daemon_settings SET geoip_database_last_updated = ?1, updated_at = ?2
             WHERE id = 1",
            at,
        )
    }

    fn set_settings_timestamp(&self, sql: &str, at: OffsetDateTime) -> Result<()> {
        let _guard = self.settings_write_lock.lock();
        let updated = self.db.execute(
            sql,
            rusqlite::params![
                format_timestamp(at),
                format_timestamp(OffsetDateTime::now_utc())
            ],
        )?;
        if updated == 0 {
            return Err(StoreError::SettingsMissing);
        }
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    fn write_settings(&self, settings: &DaemonSetting) -> Result<()> {
        let mut settings = settings.clone();
        settings.id = 1;
        settings.updated_at = OffsetDateTime::now_utc();

        let stored_ai_api_key = stored_ai_api_key(&settings.ai_api_key, self.db_key.as_ref())?;
        let stored_siem_auth_token =
            stored_secret(&settings.siem_auth_token, self.db_key.as_ref())?;

        let updated = self.db.execute(
            "UPDATE daemon_settings SET
                siem_enabled = ?2,
                wazuh_transport = ?3,
                wazuh_file_path = ?4,
                wazuh_manager_host = ?5,
                wazuh_manager_port = ?6,
                wazuh_protocol = ?7,
                siem_send_allowed = ?8,
                siem_send_blocked = ?9,
                siem_send_new_app = ?10,
                siem_send_new_domain = ?11,
                siem_send_threats = ?12,
                ai_enabled = ?13,
                ai_api_key = ?14,
                log_retention_enabled = ?15,
                log_retention_days = ?16,
                dns_resolver_enabled = ?17,
                dns_protocol = ?18,
                doh_blocking_enabled = ?19,
                doh_provider = ?20,
                doh_custom_url = ?21,
                hosts_blocklist_enabled = ?22,
                hosts_blocklist_selected_lists = ?23,
                hosts_blocklist_update_frequency = ?24,
                hosts_blocklist_last_updated = ?25,
                hosts_blocklist_custom_urls = ?26,
                notify_every_connection = ?27,
                notify_new_connection = ?28,
                notify_new_app = ?29,
                notify_threat_detected = ?30,
                persist_rules_offline = ?31,
                geoip_enabled = ?32,
                log_daemon_connections = ?33,
                power_user_settings_enabled = ?34,
                dns_block_response_mode = ?35,
                dns_block_custom_ip = ?36,
                dns_rebinding_protection_enabled = ?37,
                network_mapping_auto_enabled = ?38,
                network_mapping_interval_minutes = ?39,
                network_mapping_baseline_established = ?40,
                oui_database_last_updated = ?41,
                geoip_database_last_updated = ?42,
                siem_file_enabled = ?43,
                siem_syslog_enabled = ?44,
                siem_webhook_enabled = ?45,
                siem_url = ?46,
                siem_auth_token = ?47,
                siem_auth_header = ?48,
                updated_at = ?49,
                ai_decision_mode = ?50,
                ai_confidence_advertising = ?51,
                ai_confidence_tracking = ?52,
                ai_confidence_telemetry = ?53,
                ai_confidence_analytics = ?54,
                ai_confidence_malicious = ?55,
                ai_confidence_fraud = ?56,
                ai_confidence_cryptomining = ?57,
                ai_confidence_tunnel = ?58,
                ai_advertising_enabled = ?59,
                ai_advertising_action = ?60,
                ai_tracking_enabled = ?61,
                ai_tracking_action = ?62,
                ai_telemetry_enabled = ?63,
                ai_telemetry_action = ?64,
                ai_analytics_enabled = ?65,
                ai_analytics_action = ?66,
                ai_malicious_enabled = ?67,
                ai_malicious_action = ?68,
                ai_fraud_enabled = ?69,
                ai_fraud_action = ?70,
                ai_cryptomining_enabled = ?71,
                ai_cryptomining_action = ?72,
                ai_tunnel_enabled = ?73,
                ai_tunnel_action = ?74,
                save_domain_lookups = ?75,
                dns_answer_local_names_enabled = ?76,
                dns_new_domain_blocking_enabled = ?77,
                dns_new_domain_max_age_days = ?78,
                update_channel = ?79,
                private_relay_compatibility = ?80,
                windivert_enabled = ?81
             WHERE id = 1",
            rusqlite::params![
                settings.id,
                bool_to_i64(settings.siem_enabled),
                settings.wazuh_transport,
                settings.wazuh_file_path,
                settings.wazuh_manager_host,
                settings.wazuh_manager_port,
                settings.wazuh_protocol,
                bool_to_i64(settings.siem_send_allowed),
                bool_to_i64(settings.siem_send_blocked),
                bool_to_i64(settings.siem_send_new_app),
                bool_to_i64(settings.siem_send_new_domain),
                bool_to_i64(settings.siem_send_threats),
                bool_to_i64(settings.ai_enabled),
                stored_ai_api_key,
                bool_to_i64(settings.log_retention_enabled),
                settings.log_retention_days,
                bool_to_i64(settings.dns_resolver_enabled),
                settings.dns_protocol,
                bool_to_i64(settings.doh_blocking_enabled),
                settings.doh_provider,
                settings.doh_custom_url,
                bool_to_i64(settings.hosts_blocklist_enabled),
                settings.hosts_blocklist_selected_lists,
                settings.hosts_blocklist_update_frequency,
                format_timestamp(settings.hosts_blocklist_last_updated),
                settings.hosts_blocklist_custom_urls,
                bool_to_i64(settings.notify_every_connection),
                bool_to_i64(settings.notify_new_connection),
                bool_to_i64(settings.notify_new_app),
                bool_to_i64(settings.notify_threat_detected),
                bool_to_i64(settings.persist_rules_offline),
                bool_to_i64(settings.geoip_enabled),
                bool_to_i64(settings.log_daemon_connections),
                bool_to_i64(settings.power_user_settings_enabled),
                settings.dns_block_response_mode,
                settings.dns_block_custom_ip,
                bool_to_i64(settings.dns_rebinding_protection_enabled),
                bool_to_i64(settings.network_mapping_auto_enabled),
                settings.network_mapping_interval_minutes,
                bool_to_i64(settings.network_mapping_baseline_established),
                format_timestamp(settings.oui_database_last_updated),
                format_timestamp(settings.geoip_database_last_updated),
                bool_to_i64(settings.siem_file_enabled),
                bool_to_i64(settings.siem_syslog_enabled),
                bool_to_i64(settings.siem_webhook_enabled),
                settings.siem_url,
                stored_siem_auth_token,
                settings.siem_auth_header,
                format_timestamp(settings.updated_at),
                crate::models::normalize_ai_decision_mode(&settings.ai_decision_mode),
                crate::models::clamp_ai_confidence(settings.ai_confidence_advertising),
                crate::models::clamp_ai_confidence(settings.ai_confidence_tracking),
                crate::models::clamp_ai_confidence(settings.ai_confidence_telemetry),
                crate::models::clamp_ai_confidence(settings.ai_confidence_analytics),
                crate::models::clamp_ai_confidence(settings.ai_confidence_malicious),
                crate::models::clamp_ai_confidence(settings.ai_confidence_fraud),
                crate::models::clamp_ai_confidence(settings.ai_confidence_cryptomining),
                crate::models::clamp_ai_confidence(settings.ai_confidence_tunnel),
                bool_to_i64(settings.ai_advertising_enabled),
                crate::models::normalize_ai_action(&settings.ai_advertising_action),
                bool_to_i64(settings.ai_tracking_enabled),
                crate::models::normalize_ai_action(&settings.ai_tracking_action),
                bool_to_i64(settings.ai_telemetry_enabled),
                crate::models::normalize_ai_action(&settings.ai_telemetry_action),
                bool_to_i64(settings.ai_analytics_enabled),
                crate::models::normalize_ai_action(&settings.ai_analytics_action),
                bool_to_i64(settings.ai_malicious_enabled),
                crate::models::normalize_ai_action(&settings.ai_malicious_action),
                bool_to_i64(settings.ai_fraud_enabled),
                crate::models::normalize_ai_action(&settings.ai_fraud_action),
                bool_to_i64(settings.ai_cryptomining_enabled),
                crate::models::normalize_ai_action(&settings.ai_cryptomining_action),
                bool_to_i64(settings.ai_tunnel_enabled),
                crate::models::normalize_ai_action(&settings.ai_tunnel_action),
                bool_to_i64(settings.save_domain_lookups),
                bool_to_i64(settings.dns_answer_local_names_enabled),
                bool_to_i64(settings.dns_new_domain_blocking_enabled),
                settings.dns_new_domain_max_age_days,
                crate::models::normalize_update_channel(&settings.update_channel),
                bool_to_i64(settings.private_relay_compatibility),
                bool_to_i64(settings.windivert_enabled),
            ],
        )?;

        if updated == 0 {
            return Err(StoreError::SettingsMissing);
        }
        Ok(())
    }
}

fn stored_ai_api_key(secret: &SecretBytes, key: Option<&SecretBytes>) -> Result<String> {
    let plain = secret
        .as_str()
        .map_err(|_| StoreError::Crypto("ai api key is not utf-8".to_owned()))?;
    stored_secret(plain, key)
}

/// A secret as written to the database: encrypted when the store has a key.
/// A value written before it was encrypted still reads back as plaintext, and
/// is encrypted the next time settings are saved.
fn stored_secret(plain: &str, key: Option<&SecretBytes>) -> Result<String> {
    match key {
        Some(key) => crypto::encrypt_field(plain, key),
        None => Ok(plain.to_owned()),
    }
}

fn map_daemon_setting(row: &Row) -> std::result::Result<DaemonSetting, rusqlite::Error> {
    Ok(DaemonSetting {
        id: row.get(0)?,
        siem_enabled: i64_to_bool(row.get(1)?),
        wazuh_transport: row.get(2)?,
        wazuh_file_path: row.get(3)?,
        wazuh_manager_host: row.get(4)?,
        wazuh_manager_port: row.get(5)?,
        wazuh_protocol: row.get(6)?,
        siem_send_allowed: i64_to_bool(row.get(7)?),
        siem_send_blocked: i64_to_bool(row.get(8)?),
        siem_send_new_app: i64_to_bool(row.get(9)?),
        siem_send_new_domain: i64_to_bool(row.get(10)?),
        siem_send_threats: i64_to_bool(row.get(11)?),
        ai_enabled: i64_to_bool(row.get(12)?),
        ai_api_key: SecretBytes::from_string(row.get(13)?),
        log_retention_enabled: i64_to_bool(row.get(14)?),
        log_retention_days: row.get(15)?,
        dns_resolver_enabled: i64_to_bool(row.get(16)?),
        dns_protocol: row.get(17)?,
        doh_blocking_enabled: i64_to_bool(row.get(18)?),
        doh_provider: row.get(19)?,
        doh_custom_url: row.get(20)?,
        hosts_blocklist_enabled: i64_to_bool(row.get(21)?),
        hosts_blocklist_selected_lists: row.get(22)?,
        hosts_blocklist_update_frequency: row.get(23)?,
        hosts_blocklist_last_updated: get_timestamp(row, 24)?,
        hosts_blocklist_custom_urls: row.get(25)?,
        notify_every_connection: i64_to_bool(row.get(26)?),
        notify_new_connection: i64_to_bool(row.get(27)?),
        notify_new_app: i64_to_bool(row.get(28)?),
        notify_threat_detected: i64_to_bool(row.get(29)?),
        persist_rules_offline: i64_to_bool(row.get(30)?),
        geoip_enabled: i64_to_bool(row.get(31)?),
        log_daemon_connections: i64_to_bool(row.get(32)?),
        power_user_settings_enabled: i64_to_bool(row.get(33)?),
        dns_block_response_mode: row.get(34)?,
        dns_block_custom_ip: row.get(35)?,
        dns_rebinding_protection_enabled: i64_to_bool(row.get(36)?),
        network_mapping_auto_enabled: i64_to_bool(row.get(37)?),
        network_mapping_interval_minutes: row.get(38)?,
        network_mapping_baseline_established: i64_to_bool(row.get(39)?),
        oui_database_last_updated: get_timestamp(row, 40)?,
        geoip_database_last_updated: get_timestamp(row, 41)?,
        siem_file_enabled: i64_to_bool(row.get(42)?),
        siem_syslog_enabled: i64_to_bool(row.get(43)?),
        siem_webhook_enabled: i64_to_bool(row.get(44)?),
        siem_url: row.get(45)?,
        siem_auth_token: row.get(46)?,
        siem_auth_header: row.get(47)?,
        updated_at: get_timestamp(row, 48)?,
        ai_decision_mode: crate::models::normalize_ai_decision_mode(&row.get::<_, String>(49)?),
        ai_confidence_advertising: crate::models::clamp_ai_confidence(row.get(50)?),
        ai_confidence_tracking: crate::models::clamp_ai_confidence(row.get(51)?),
        ai_confidence_telemetry: crate::models::clamp_ai_confidence(row.get(52)?),
        ai_confidence_analytics: crate::models::clamp_ai_confidence(row.get(53)?),
        ai_confidence_malicious: crate::models::clamp_ai_confidence(row.get(54)?),
        ai_confidence_fraud: crate::models::clamp_ai_confidence(row.get(55)?),
        ai_confidence_cryptomining: crate::models::clamp_ai_confidence(row.get(56)?),
        ai_confidence_tunnel: crate::models::clamp_ai_confidence(row.get(57)?),
        ai_advertising_enabled: i64_to_bool(row.get(58)?),
        ai_advertising_action: crate::models::normalize_ai_action(&row.get::<_, String>(59)?),
        ai_tracking_enabled: i64_to_bool(row.get(60)?),
        ai_tracking_action: crate::models::normalize_ai_action(&row.get::<_, String>(61)?),
        ai_telemetry_enabled: i64_to_bool(row.get(62)?),
        ai_telemetry_action: crate::models::normalize_ai_action(&row.get::<_, String>(63)?),
        ai_analytics_enabled: i64_to_bool(row.get(64)?),
        ai_analytics_action: crate::models::normalize_ai_action(&row.get::<_, String>(65)?),
        ai_malicious_enabled: i64_to_bool(row.get(66)?),
        ai_malicious_action: crate::models::normalize_ai_action(&row.get::<_, String>(67)?),
        ai_fraud_enabled: i64_to_bool(row.get(68)?),
        ai_fraud_action: crate::models::normalize_ai_action(&row.get::<_, String>(69)?),
        ai_cryptomining_enabled: i64_to_bool(row.get(70)?),
        ai_cryptomining_action: crate::models::normalize_ai_action(&row.get::<_, String>(71)?),
        ai_tunnel_enabled: i64_to_bool(row.get(72)?),
        ai_tunnel_action: crate::models::normalize_ai_action(&row.get::<_, String>(73)?),
        save_domain_lookups: i64_to_bool(row.get(74)?),
        dns_answer_local_names_enabled: i64_to_bool(row.get(75)?),
        dns_new_domain_blocking_enabled: i64_to_bool(row.get(76)?),
        dns_new_domain_max_age_days: row.get(77)?,
        update_channel: crate::models::normalize_update_channel(&row.get::<_, String>(78)?),
        private_relay_compatibility: i64_to_bool(row.get(79)?),
        windivert_enabled: i64_to_bool(row.get(80)?),
    })
}
