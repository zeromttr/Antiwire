import { z } from 'zod';
import type { SettingsRequest, SettingsResponse } from '../daemon/messages';

type FieldKind = 'bool' | 'string' | 'u32';

/**
 * Every setting the daemon's request and response share, under the same
 * camelCase name in both and in the DTO. Listing each field once keeps the
 * conversions and the argument schema from drifting apart.
 *
 * The AI key and SIEM token are write-only: the response carries them empty
 * with a `*Set` flag, and the request sends an empty value to keep the stored
 * secret or a `clear*` flag to remove it.
 */
export const SETTINGS_FIELDS = {
  siemEnabled: 'bool',
  aiEnabled: 'bool',
  aiApiKey: 'string',
  aiDecisionMode: 'string',
  aiConfidenceAdvertising: 'u32',
  aiConfidenceTracking: 'u32',
  aiConfidenceTelemetry: 'u32',
  aiConfidenceAnalytics: 'u32',
  aiConfidenceMalicious: 'u32',
  aiConfidenceFraud: 'u32',
  aiConfidenceCryptomining: 'u32',
  aiConfidenceTunnel: 'u32',
  aiAdvertisingEnabled: 'bool',
  aiAdvertisingAction: 'string',
  aiTrackingEnabled: 'bool',
  aiTrackingAction: 'string',
  aiTelemetryEnabled: 'bool',
  aiTelemetryAction: 'string',
  aiAnalyticsEnabled: 'bool',
  aiAnalyticsAction: 'string',
  aiMaliciousEnabled: 'bool',
  aiMaliciousAction: 'string',
  aiFraudEnabled: 'bool',
  aiFraudAction: 'string',
  aiCryptominingEnabled: 'bool',
  aiCryptominingAction: 'string',
  aiTunnelEnabled: 'bool',
  aiTunnelAction: 'string',
  saveDomainLookups: 'bool',
  updateChannel: 'string',
  logRetentionEnabled: 'bool',
  logRetentionDays: 'u32',
  dohBlockingEnabled: 'bool',
  dohProvider: 'string',
  dohCustomUrl: 'string',
  dnsResolverEnabled: 'bool',
  dnsProtocol: 'string',
  wazuhTransport: 'string',
  wazuhFilePath: 'string',
  wazuhManagerHost: 'string',
  wazuhManagerPort: 'u32',
  wazuhProtocol: 'string',
  siemFileEnabled: 'bool',
  siemSyslogEnabled: 'bool',
  siemWebhookEnabled: 'bool',
  siemUrl: 'string',
  siemAuthToken: 'string',
  siemAuthHeader: 'string',
  siemSendAllowed: 'bool',
  siemSendBlocked: 'bool',
  siemSendNewApp: 'bool',
  siemSendNewDomain: 'bool',
  siemSendThreats: 'bool',
  hostsBlocklistEnabled: 'bool',
  hostsBlocklistSelectedLists: 'string',
  hostsBlocklistUpdateFrequency: 'string',
  hostsBlocklistLastUpdated: 'string',
  hostsBlocklistCustomUrls: 'string',
  notifyEveryConnection: 'bool',
  notifyNewConnection: 'bool',
  notifyNewApp: 'bool',
  notifyThreatDetected: 'bool',
  persistRulesOffline: 'bool',
  privateRelayCompatibility: 'bool',
  windivertEnabled: 'bool',
  dnsBypassBlockingEnabled: 'bool',
  geoIpEnabled: 'bool',
  logDaemonConnections: 'bool',
  powerUserSettingsEnabled: 'bool',
  dnsBlockResponseMode: 'string',
  dnsBlockCustomIp: 'string',
  dnsRebindingProtectionEnabled: 'bool',
  dnsAnswerLocalNamesEnabled: 'bool',
  dnsNewDomainBlockingEnabled: 'bool',
  dnsNewDomainMaxAgeDays: 'u32',
  networkMappingAutoEnabled: 'bool',
  networkMappingIntervalMinutes: 'u32',
} as const satisfies Record<string, FieldKind>;

type SettingsField = keyof typeof SETTINGS_FIELDS;
const FIELD_NAMES = Object.keys(SETTINGS_FIELDS) as SettingsField[];

/** Custom blocklist URLs can be long; nothing else comes close. */
const MAX_SETTING_LENGTH = 64 * 1024;

const kindSchema = {
  bool: () => z.boolean(),
  string: () => z.string().max(MAX_SETTING_LENGTH),
  u32: () => z.number().int().min(0).max(0xffff_ffff),
} satisfies Record<FieldKind, () => z.ZodType>;

/**
 * The `settings` argument of `update_settings`. Unknown keys are dropped, as
 * serde ignored them (the renderer sends back read-only fields it was given);
 * the read-only and write-only extras default like `#[serde(default)]`.
 */
export const settingsSchema = z.object({
  ...(Object.fromEntries(
    FIELD_NAMES.map((name) => [name, kindSchema[SETTINGS_FIELDS[name]]()]),
  ) as {
    [K in SettingsField]: ReturnType<(typeof kindSchema)[(typeof SETTINGS_FIELDS)[K]]>;
  }),
  /** Daemon-owned; surfaced read-only so the GeoIP row can show its age. */
  geoipDatabaseLastUpdated: z.string().max(256).default(''),
  /** Read-only: whether the daemon holds an AI API key. */
  aiApiKeySet: z.boolean().default(false),
  /** Read-only: whether the daemon holds a SIEM auth token. */
  siemAuthTokenSet: z.boolean().default(false),
  /** Read-only: whether the daemon can use WinDivert, so whether to offer the setting. */
  windivertSupported: z.boolean().default(false),
  /** Write-only: remove the stored AI API key. */
  clearAiApiKey: z.boolean().default(false),
  /** Write-only: remove the stored SIEM auth token. */
  clearSiemAuthToken: z.boolean().default(false),
});

export type SettingsDto = z.infer<typeof settingsSchema>;

export function settingsToDto(s: SettingsResponse): SettingsDto {
  const dto: Record<string, unknown> = {};
  for (const name of FIELD_NAMES) dto[name] = s[name];
  dto.geoipDatabaseLastUpdated = s.geoipDatabaseLastUpdated ?? '';
  dto.aiApiKeySet = s.aiApiKeySet ?? false;
  dto.siemAuthTokenSet = s.siemAuthTokenSet ?? false;
  dto.windivertSupported = s.windivertSupported ?? false;
  dto.clearAiApiKey = false;
  dto.clearSiemAuthToken = false;
  return dto as SettingsDto;
}

/** `geoipDatabaseLastUpdated` is daemon-owned: deliberately absent from the request. */
export function settingsToRequest(s: SettingsDto): SettingsRequest {
  const request: SettingsRequest = {};
  for (const name of FIELD_NAMES) request[name] = s[name];
  request.clearAiApiKey = s.clearAiApiKey;
  request.clearSiemAuthToken = s.clearSiemAuthToken;
  return request;
}
