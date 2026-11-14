import type { SettingsDto } from '#lib/api/daemon.ts';
import { normalizeNewDomainMaxAge } from '#lib/models/new-domain-age.ts';
import { normalizeUpdateChannel } from '#lib/models/update-status.ts';

function bool(data: Record<string, unknown>, camel: string, snake: string): boolean {
  return Boolean(data[camel] ?? data[snake] ?? false);
}

function str(data: Record<string, unknown>, camel: string, snake: string): string {
  return String(data[camel] ?? data[snake] ?? '');
}

function num(data: Record<string, unknown>, camel: string, snake: string): number {
  return Number(data[camel] ?? data[snake] ?? 0);
}

/** Same floor the daemon enforces. Scores below this are too uncertain to act on. */
const AI_CONFIDENCE_MIN = 60;
const AI_CONFIDENCE_MAX = 100;

function confidence(data: Record<string, unknown>, camel: string, snake: string): number {
  const raw = data[camel] ?? data[snake];
  const value = raw == null || raw === '' ? 80 : Number(raw);
  if (!Number.isFinite(value)) return 80;
  return Math.min(AI_CONFIDENCE_MAX, Math.max(AI_CONFIDENCE_MIN, Math.round(value)));
}

function decisionMode(data: Record<string, unknown>): string {
  return str(data, 'aiDecisionMode', 'ai_decision_mode') === 'proactive'
    ? 'proactive'
    : 'retroactive';
}

/** A switch that is on unless the daemon says otherwise; absent means the daemon predates the field. */
function onByDefault(data: Record<string, unknown>, camel: string, snake: string): boolean {
  const raw = data[camel] ?? data[snake];
  return raw == null ? true : Boolean(raw);
}

/** Per-category action; anything unrecognized records rather than blocks. */
function aiAction(data: Record<string, unknown>, camel: string, snake: string): string {
  return str(data, camel, snake) === 'block' ? 'block' : 'record';
}

/** Normalize daemon settings into a plain SettingsDto (mirrors Flutter's SettingsResponse). */
export function normalizeSettings(data: SettingsDto & Record<string, unknown>): SettingsDto {
  return {
    siemEnabled: bool(data, 'siemEnabled', 'siem_enabled'),
    aiEnabled: bool(data, 'aiEnabled', 'ai_enabled'),
    aiApiKey: str(data, 'aiApiKey', 'ai_api_key'),
    aiApiKeySet: bool(data, 'aiApiKeySet', 'ai_api_key_set'),
    clearAiApiKey: bool(data, 'clearAiApiKey', 'clear_ai_api_key'),
    aiDecisionMode: decisionMode(data),
    aiConfidenceAdvertising: confidence(
      data,
      'aiConfidenceAdvertising',
      'ai_confidence_advertising',
    ),
    aiConfidenceTracking: confidence(data, 'aiConfidenceTracking', 'ai_confidence_tracking'),
    aiConfidenceTelemetry: confidence(data, 'aiConfidenceTelemetry', 'ai_confidence_telemetry'),
    aiConfidenceAnalytics: confidence(data, 'aiConfidenceAnalytics', 'ai_confidence_analytics'),
    aiConfidenceMalicious: confidence(data, 'aiConfidenceMalicious', 'ai_confidence_malicious'),
    aiConfidenceFraud: confidence(data, 'aiConfidenceFraud', 'ai_confidence_fraud'),
    aiConfidenceCryptomining: confidence(
      data,
      'aiConfidenceCryptomining',
      'ai_confidence_cryptomining',
    ),
    aiConfidenceTunnel: confidence(data, 'aiConfidenceTunnel', 'ai_confidence_tunnel'),
    aiAdvertisingEnabled: onByDefault(data, 'aiAdvertisingEnabled', 'ai_advertising_enabled'),
    aiAdvertisingAction: aiAction(data, 'aiAdvertisingAction', 'ai_advertising_action'),
    aiTrackingEnabled: onByDefault(data, 'aiTrackingEnabled', 'ai_tracking_enabled'),
    aiTrackingAction: aiAction(data, 'aiTrackingAction', 'ai_tracking_action'),
    aiTelemetryEnabled: onByDefault(data, 'aiTelemetryEnabled', 'ai_telemetry_enabled'),
    aiTelemetryAction: aiAction(data, 'aiTelemetryAction', 'ai_telemetry_action'),
    aiAnalyticsEnabled: onByDefault(data, 'aiAnalyticsEnabled', 'ai_analytics_enabled'),
    aiAnalyticsAction: aiAction(data, 'aiAnalyticsAction', 'ai_analytics_action'),
    aiMaliciousEnabled: onByDefault(data, 'aiMaliciousEnabled', 'ai_malicious_enabled'),
    aiMaliciousAction: aiAction(data, 'aiMaliciousAction', 'ai_malicious_action'),
    aiFraudEnabled: onByDefault(data, 'aiFraudEnabled', 'ai_fraud_enabled'),
    aiFraudAction: aiAction(data, 'aiFraudAction', 'ai_fraud_action'),
    aiCryptominingEnabled: onByDefault(data, 'aiCryptominingEnabled', 'ai_cryptomining_enabled'),
    aiCryptominingAction: aiAction(data, 'aiCryptominingAction', 'ai_cryptomining_action'),
    aiTunnelEnabled: onByDefault(data, 'aiTunnelEnabled', 'ai_tunnel_enabled'),
    aiTunnelAction: aiAction(data, 'aiTunnelAction', 'ai_tunnel_action'),
    saveDomainLookups: bool(data, 'saveDomainLookups', 'save_domain_lookups'),
    updateChannel: normalizeUpdateChannel(str(data, 'updateChannel', 'update_channel')),
    logRetentionEnabled: bool(data, 'logRetentionEnabled', 'log_retention_enabled'),
    logRetentionDays: num(data, 'logRetentionDays', 'log_retention_days'),
    dohBlockingEnabled: bool(data, 'dohBlockingEnabled', 'doh_blocking_enabled'),
    dohProvider: str(data, 'dohProvider', 'doh_provider'),
    dohCustomUrl: str(data, 'dohCustomUrl', 'doh_custom_url'),
    dnsResolverEnabled: bool(data, 'dnsResolverEnabled', 'dns_resolver_enabled'),
    dnsProtocol: str(data, 'dnsProtocol', 'dns_protocol') || 'doh',
    wazuhTransport: str(data, 'wazuhTransport', 'wazuh_transport'),
    wazuhFilePath: str(data, 'wazuhFilePath', 'wazuh_file_path'),
    wazuhManagerHost: str(data, 'wazuhManagerHost', 'wazuh_manager_host'),
    wazuhManagerPort: num(data, 'wazuhManagerPort', 'wazuh_manager_port'),
    wazuhProtocol: str(data, 'wazuhProtocol', 'wazuh_protocol') || 'udp',
    siemFileEnabled: bool(data, 'siemFileEnabled', 'siem_file_enabled'),
    siemSyslogEnabled: bool(data, 'siemSyslogEnabled', 'siem_syslog_enabled'),
    siemWebhookEnabled: bool(data, 'siemWebhookEnabled', 'siem_webhook_enabled'),
    siemUrl: str(data, 'siemUrl', 'siem_url'),
    siemAuthToken: str(data, 'siemAuthToken', 'siem_auth_token'),
    siemAuthTokenSet: bool(data, 'siemAuthTokenSet', 'siem_auth_token_set'),
    clearSiemAuthToken: bool(data, 'clearSiemAuthToken', 'clear_siem_auth_token'),
    siemAuthHeader: str(data, 'siemAuthHeader', 'siem_auth_header'),
    siemSendAllowed: bool(data, 'siemSendAllowed', 'siem_send_allowed'),
    siemSendBlocked: bool(data, 'siemSendBlocked', 'siem_send_blocked'),
    siemSendNewApp: bool(data, 'siemSendNewApp', 'siem_send_new_app'),
    siemSendNewDomain: bool(data, 'siemSendNewDomain', 'siem_send_new_domain'),
    siemSendThreats: bool(data, 'siemSendThreats', 'siem_send_threats'),
    hostsBlocklistEnabled: bool(data, 'hostsBlocklistEnabled', 'hosts_blocklist_enabled'),
    hostsBlocklistSelectedLists: str(
      data,
      'hostsBlocklistSelectedLists',
      'hosts_blocklist_selected_lists',
    ),
    hostsBlocklistUpdateFrequency: str(
      data,
      'hostsBlocklistUpdateFrequency',
      'hosts_blocklist_update_frequency',
    ),
    hostsBlocklistLastUpdated: str(
      data,
      'hostsBlocklistLastUpdated',
      'hosts_blocklist_last_updated',
    ),
    hostsBlocklistCustomUrls: str(data, 'hostsBlocklistCustomUrls', 'hosts_blocklist_custom_urls'),
    notifyEveryConnection: bool(data, 'notifyEveryConnection', 'notify_every_connection'),
    notifyNewConnection: bool(data, 'notifyNewConnection', 'notify_new_connection'),
    notifyNewApp: bool(data, 'notifyNewApp', 'notify_new_app'),
    notifyThreatDetected: bool(data, 'notifyThreatDetected', 'notify_threat_detected'),
    persistRulesOffline: bool(data, 'persistRulesOffline', 'persist_rules_offline'),
    geoIpEnabled: bool(data, 'geoIpEnabled', 'geo_ip_enabled'),
    logDaemonConnections: bool(data, 'logDaemonConnections', 'log_daemon_connections'),
    powerUserSettingsEnabled: bool(data, 'powerUserSettingsEnabled', 'power_user_settings_enabled'),
    dnsBlockResponseMode: str(data, 'dnsBlockResponseMode', 'dns_block_response_mode'),
    dnsBlockCustomIp: str(data, 'dnsBlockCustomIp', 'dns_block_custom_ip'),
    dnsRebindingProtectionEnabled: bool(
      data,
      'dnsRebindingProtectionEnabled',
      'dns_rebinding_protection_enabled',
    ),
    dnsAnswerLocalNamesEnabled: onByDefault(
      data,
      'dnsAnswerLocalNamesEnabled',
      'dns_answer_local_names_enabled',
    ),
    dnsNewDomainBlockingEnabled: bool(
      data,
      'dnsNewDomainBlockingEnabled',
      'dns_new_domain_blocking_enabled',
    ),
    dnsNewDomainMaxAgeDays: normalizeNewDomainMaxAge(
      data.dnsNewDomainMaxAgeDays ?? data.dns_new_domain_max_age_days,
    ),
    networkMappingAutoEnabled: bool(
      data,
      'networkMappingAutoEnabled',
      'network_mapping_auto_enabled',
    ),
    networkMappingIntervalMinutes: num(
      data,
      'networkMappingIntervalMinutes',
      'network_mapping_interval_minutes',
    ),
  };
}

/** Normalized plain-object copy to send over IPC. */
function cloneSettings(settings: SettingsDto): SettingsDto {
  return normalizeSettings({ ...settings });
}

/** Restores power-user DNS options to daemon-safe defaults (mirrors settings_mapper.dart). */
export function resetPowerUserOptions(settings: SettingsDto): SettingsDto {
  return {
    ...settings,
    powerUserSettingsEnabled: false,
    dnsBlockResponseMode: 'sinkhole',
    dnsBlockCustomIp: '',
    dnsRebindingProtectionEnabled: false,
    dnsAnswerLocalNamesEnabled: true,
  };
}

/** Maps form state to the daemon update payload (mirrors settings_mapper.dart). */
export function settingsToUpdatePayload(settings: SettingsDto): SettingsDto {
  return cloneSettings(settings);
}
