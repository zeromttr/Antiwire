import { normalizeActiveApps } from '#lib/models/active-apps.ts';
import { normalizeDomainLookup } from '#lib/models/domain-lookup.ts';
import {
  normalizeCertificateSearch,
  normalizeDnsRecords,
  normalizeSeenSubdomains,
} from '#lib/models/domain-records.ts';
import { invoke } from '#lib/bridge.ts';
import type { CommandName } from '#shared/ipc.ts';
import { browserPreviewMode, callBrowserPreview } from '#lib/preview/runtime.ts';
import { isNative } from '#lib/utils/index.ts';
import type { HistoryDeletionRange } from '#lib/utils/history-deletion.ts';
import {
  AI_CATEGORIES,
  type AiCategory,
  type AiDecision,
  type AiVerdict,
  type AppSummary,
  type ConnectionLog,
  type CountryRule,
  type NotificationEvent,
  type Rule,
  type RuleDirection,
  type Stats,
  type UpdateStatus,
} from '#lib/types/index.ts';
import { normalizeSettings, settingsToUpdatePayload } from '#lib/models/settings-mapper.ts';
import { captureThemeSnapshot } from '#lib/models/theme-snapshot.ts';
import {
  normalizeAppSummary,
  normalizeConnectionLog,
  normalizeCountryRule,
  normalizeCountryStatistics,
  normalizeRule,
  normalizeStats,
} from '#lib/api/normalize.ts';

/** Result of a country mutation, carrying the daemon's reason on failure. */
export type CountryActionResult = { success: boolean; message: string };

/** Result of asking the daemon to start the confirmed update. */
export type UpdateActionResult = { success: boolean; message: string };

function normalizeConnectionLogsPage(
  data?: (ConnectionLogsPage & Record<string, unknown>) | null,
): ConnectionLogsPage {
  const d = (data && typeof data === 'object' ? data : {}) as Record<string, unknown>;
  const logs = Array.isArray(d.logs) ? d.logs : [];
  return {
    logs: logs.map((log) => normalizeConnectionLog(log as ConnectionLog & Record<string, unknown>)),
    totalCount: Number(d.totalCount ?? d.total_count ?? logs.length),
    blockedCount: Number(d.blockedCount ?? d.blocked_count ?? 0),
  };
}

function normalizeAppSummariesPage(
  data?: (AppSummariesPage & Record<string, unknown>) | null,
): AppSummariesPage {
  if (Array.isArray(data)) {
    const applications = data.map((row) =>
      normalizeAppSummary(row as AppSummary & Record<string, unknown>),
    );
    return {
      applications,
      totalCount: applications.reduce((sum, row) => sum + row.connectionCount, 0),
      blockedCount: applications.reduce((sum, row) => sum + row.blockedCount, 0),
    };
  }

  const d = (data && typeof data === 'object' ? data : {}) as Record<string, unknown>;
  const applications = Array.isArray(d.applications) ? d.applications : [];
  const normalized = applications.map((row) =>
    normalizeAppSummary(row as AppSummary & Record<string, unknown>),
  );
  const totalCount = Number(
    d.totalCount ?? d.total_count ?? normalized.reduce((sum, row) => sum + row.connectionCount, 0),
  );
  const blockedCount = Number(
    d.blockedCount ?? d.blocked_count ?? normalized.reduce((sum, row) => sum + row.blockedCount, 0),
  );
  return {
    applications: normalized,
    totalCount,
    blockedCount,
  };
}

export type AiVerdictFilter = 'all' | 'block' | 'record' | 'clean';

export interface AiDecisionsPage {
  decisions: AiDecision[];
  /** Rows matching every filter. */
  totalCount: number;
  /** Per-verdict counts honor the search but ignore the verdict filter. */
  blockCount: number;
  recordCount: number;
  cleanCount: number;
}

function unitScore(value: unknown): number {
  const n = Number(value);
  return Number.isFinite(n) ? Math.min(1, Math.max(0, n)) : 0;
}

function normalizeAiSignals(value: unknown): AiDecision['signals'] {
  const raw = (value && typeof value === 'object' ? value : {}) as Record<string, unknown>;
  return {
    newlyRegistered: unitScore(raw.newlyRegistered ?? raw.newly_registered),
    registryHold: unitScore(raw.registryHold ?? raw.registry_hold),
    hiddenRegistrant: unitScore(raw.hiddenRegistrant ?? raw.hidden_registrant),
    abusiveRegistrar: unitScore(raw.abusiveRegistrar ?? raw.abusive_registrar),
  };
}

function normalizeAiVerdict(value: unknown): AiVerdict {
  const verdict = String(value ?? '').toLowerCase();
  return verdict === 'block' || verdict === 'record' ? verdict : '';
}

export function normalizeAiDecision(row: Record<string, unknown>): AiDecision {
  const raw = (row.ratings && typeof row.ratings === 'object' ? row.ratings : {}) as Record<
    string,
    unknown
  >;
  const ratings = Object.fromEntries(
    AI_CATEGORIES.map((category) => [category, unitScore(raw[category])]),
  ) as Record<AiCategory, number>;
  return {
    domain: String(row.domain ?? ''),
    model: String(row.model ?? ''),
    verdict: normalizeAiVerdict(row.verdict),
    topCategory: String(row.topCategory ?? ''),
    topScore: unitScore(row.topScore),
    ratings,
    signals: normalizeAiSignals(row.signals ?? row),
    scanTier: String(row.scanTier ?? 'basic'),
    firstSeen: Number(row.firstSeen ?? 0),
    updatedAt: Number(row.updatedAt ?? 0),
  };
}

export function normalizeAiDecisionsPage(data: unknown): AiDecisionsPage {
  const d = (data && typeof data === 'object' ? data : {}) as Record<string, unknown>;
  const rows = Array.isArray(d.decisions) ? (d.decisions as Record<string, unknown>[]) : [];
  const decisions = rows.map((row) => normalizeAiDecision(row));
  return {
    decisions,
    totalCount: Number(d.totalCount ?? decisions.length),
    blockCount: Number(d.blockCount ?? 0),
    recordCount: Number(d.recordCount ?? 0),
    cleanCount: Number(d.cleanCount ?? 0),
  };
}

export interface ConnectionStatus {
  connected: boolean;
}

export interface ConnectionLogsPage {
  logs: ConnectionLog[];
  totalCount: number;
  blockedCount: number;
}

export interface AppSummariesPage {
  applications: AppSummary[];
  totalCount: number;
  blockedCount: number;
}

export interface CaptureDeviceDto {
  name: string;
  description: string;
  addresses: string[];
  loopback: boolean;
}

export interface CaptureStatusDto {
  captureId: string;
  state: string;
  active: boolean;
  packets: number;
  bytes: number;
  droppedPackets: number;
  /** Packets dropped because they belong to other applications. */
  filteredPackets: number;
  elapsedSeconds: number;
  deviceName: string;
  /** Empty when the capture covers every application. */
  appName: string;
  message: string;
}

export interface CapturedPacketDto {
  captureId: string;
  sequence: number;
  timestampUs: number;
  capturedLength: number;
  originalLength: number;
  linkLayer: number;
  protocol: string;
  source: string;
  destination: string;
  sourcePort: number;
  destinationPort: number;
  info: string;
  data: number[];
}

/** Outcome of a settings save. `notApplied` lists saved settings that did not take effect. */
export interface SettingsSaveResult {
  success: boolean;
  notApplied: string[];
}

export interface SettingsDto {
  siemEnabled: boolean;
  aiEnabled: boolean;
  /** Write-only: empty keeps the stored key. */
  aiApiKey: string;
  /** Read-only: whether the daemon holds an AI API key. */
  aiApiKeySet: boolean;
  /** Write-only: remove the stored AI API key on save. */
  clearAiApiKey: boolean;
  aiDecisionMode: string;
  aiConfidenceAdvertising: number;
  aiConfidenceTracking: number;
  aiConfidenceTelemetry: number;
  aiConfidenceAnalytics: number;
  aiConfidenceMalicious: number;
  aiConfidenceFraud: number;
  aiConfidenceCryptomining: number;
  aiConfidenceTunnel: number;
  aiAdvertisingEnabled: boolean;
  aiAdvertisingAction: string;
  aiTrackingEnabled: boolean;
  aiTrackingAction: string;
  aiTelemetryEnabled: boolean;
  aiTelemetryAction: string;
  aiAnalyticsEnabled: boolean;
  aiAnalyticsAction: string;
  aiMaliciousEnabled: boolean;
  aiMaliciousAction: string;
  aiFraudEnabled: boolean;
  aiFraudAction: string;
  aiCryptominingEnabled: boolean;
  aiCryptominingAction: string;
  aiTunnelEnabled: boolean;
  aiTunnelAction: string;
  saveDomainLookups: boolean;
  /** `stable`, `beta`, or `nightly`. */
  updateChannel: string;
  logRetentionEnabled: boolean;
  logRetentionDays: number;
  dohBlockingEnabled: boolean;
  dohProvider: string;
  dohCustomUrl: string;
  dnsResolverEnabled: boolean;
  dnsProtocol: string;
  wazuhTransport: string;
  wazuhFilePath: string;
  wazuhManagerHost: string;
  wazuhManagerPort: number;
  wazuhProtocol: string;
  siemFileEnabled: boolean;
  siemSyslogEnabled: boolean;
  siemWebhookEnabled: boolean;
  siemUrl: string;
  /** Write-only: empty keeps the stored token. */
  siemAuthToken: string;
  /** Read-only: whether the daemon holds a SIEM auth token. */
  siemAuthTokenSet: boolean;
  /** Write-only: remove the stored SIEM auth token on save. */
  clearSiemAuthToken: boolean;
  siemAuthHeader: string;
  siemSendAllowed: boolean;
  siemSendBlocked: boolean;
  siemSendNewApp: boolean;
  siemSendNewDomain: boolean;
  siemSendThreats: boolean;
  hostsBlocklistEnabled: boolean;
  hostsBlocklistSelectedLists: string;
  hostsBlocklistUpdateFrequency: string;
  hostsBlocklistLastUpdated: string;
  hostsBlocklistCustomUrls: string;
  notifyEveryConnection: boolean;
  notifyNewConnection: boolean;
  notifyNewApp: boolean;
  notifyThreatDetected: boolean;
  persistRulesOffline: boolean;
  geoIpEnabled: boolean;
  logDaemonConnections: boolean;
  powerUserSettingsEnabled: boolean;
  dnsBlockResponseMode: string;
  dnsBlockCustomIp: string;
  dnsRebindingProtectionEnabled: boolean;
  dnsAnswerLocalNamesEnabled: boolean;
  dnsNewDomainBlockingEnabled: boolean;
  /** 7, 14, 30 or 90; see `NEW_DOMAIN_MAX_AGE_DAYS`. */
  dnsNewDomainMaxAgeDays: number;
  networkMappingAutoEnabled: boolean;
  networkMappingIntervalMinutes: number;
}

const IPC_TIMEOUT_MS = 15_000;
/**
 * Connect, capture, export, and blocklist sync can outlive a single 10s RPC.
 * Longer than the main process's 120s slow-RPC deadline, so the daemon's own
 * error reaches the user rather than a generic timeout.
 */
const LONG_IPC_TIMEOUT_MS = 130_000;
/** A native dialog stays open until the person answers, so it gets far longer than an RPC. */
const DIALOG_IPC_TIMEOUT_MS = 600_000;

/** Bound `pending` without cancelling it; swallow a late rejection after timeout. */
export async function raceWithTimeout<T>(
  pending: Promise<T>,
  label: string,
  timeoutMs: number,
): Promise<T> {
  if (timeoutMs <= 0) return pending;

  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeoutPromise = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      reject(new Error(`IPC timeout: '${label}' failed to respond within ${timeoutMs}ms`));
    }, timeoutMs);
  });

  try {
    return await Promise.race([pending, timeoutPromise]);
  } catch (err) {
    void pending.catch(() => {});
    throw err;
  } finally {
    if (timer) clearTimeout(timer);
  }
}

export function requireMutationSuccess(success: boolean, command: string): void {
  if (!success) {
    throw new Error(`Daemon rejected mutation '${command}'`);
  }
}

async function call<T>(
  cmd: CommandName,
  args?: Record<string, unknown>,
  timeoutMs = IPC_TIMEOUT_MS,
): Promise<T> {
  if (import.meta.env?.DEV && browserPreviewMode) return (await callBrowserPreview(cmd, args)) as T;
  if (!isNative()) {
    throw new Error('Native bridge not available');
  }
  return raceWithTimeout(invoke<T>(cmd, args), cmd, timeoutMs);
}

/**
 * Fail-closed wrapper for boolean daemon mutations: a `false` resolution
 * throws instead of looking successful, so callers cannot forget the check.
 *
 * Deliberately NOT used for `addRule`, `addCountryRule`/`removeCountryRule`,
 * and `updateSettings`: those call sites surface localized or
 * daemon-provided messages (`result.message`) that this generic English
 * error would destroy. They keep explicit `if (!ok)` checks instead.
 */
function mutation(
  command: CommandName,
  args?: Record<string, unknown>,
  timeoutMs?: number,
): Promise<void> {
  return call<boolean>(command, args, timeoutMs).then((success) =>
    requireMutationSuccess(success, command),
  );
}

let connectDaemonInvoke: Promise<boolean> | null = null;

function connectDaemon(): Promise<boolean> {
  if (import.meta.env?.DEV && browserPreviewMode) return call<boolean>('connect_daemon');
  if (!isNative()) {
    return Promise.reject(new Error('Native bridge not available'));
  }
  if (!connectDaemonInvoke) {
    connectDaemonInvoke = invoke<boolean>('connect_daemon').finally(() => {
      connectDaemonInvoke = null;
    });
  }
  return raceWithTimeout(connectDaemonInvoke, 'connect_daemon', LONG_IPC_TIMEOUT_MS);
}

export const api = {
  getCountryStatistics: () =>
    call<unknown>('get_country_statistics').then(normalizeCountryStatistics),
  getConnectionStatus: () => call<ConnectionStatus>('get_connection_status'),
  connectDaemon,
  disconnectDaemon: () => call<void>('disconnect_daemon'),
  startRealtimeTraffic: () => call<void>('start_realtime_traffic'),
  stopRealtimeTraffic: () => call<void>('stop_realtime_traffic'),
  getAlerts: () =>
    call<(NotificationEvent & Record<string, unknown>)[]>('get_alerts').then((rows) =>
      Array.isArray(rows)
        ? rows.map((row) => ({
            id: String(row.id ?? ''),
            title: String(row.title ?? ''),
            body: String(row.body ?? ''),
            severity: row.severity as NotificationEvent['severity'],
            timestamp: String(row.timestamp ?? ''),
            tag: String(row.tag ?? ''),
          }))
        : [],
    ),
  getAiDecisions: (opts: {
    limit?: number;
    offset?: number;
    verdictFilter?: AiVerdictFilter;
    searchQuery?: string;
  }) => call<unknown>('get_ai_decisions', opts).then(normalizeAiDecisionsPage),
  deleteAiDecision: (domain: string) => mutation('delete_ai_decision', { domain }),
  refreshAiDecision: (domain: string) =>
    call<unknown>('refresh_ai_decision', { domain }).then((row) =>
      normalizeAiDecision((row && typeof row === 'object' ? row : {}) as Record<string, unknown>),
    ),
  advancedAiDecision: (domain: string) =>
    call<unknown>('advanced_ai_decision', { domain }).then((row) =>
      normalizeAiDecision((row && typeof row === 'object' ? row : {}) as Record<string, unknown>),
    ),
  dismissAlert: (id: string) => call<boolean>('dismiss_alert', { id }),
  clearAlerts: () => call<boolean>('clear_alerts'),
  /** Deletes connection history, its activity buckets and alerts; resolves to the rows removed. */
  deleteHistory: (range: HistoryDeletionRange) =>
    call<number>(
      'delete_history',
      range.all ? { all: true } : { all: false, since: range.since },
      LONG_IPC_TIMEOUT_MS,
    ).then(Number),
  getStats: () => call<Stats & Record<string, unknown>>('get_stats').then(normalizeStats),
  getActiveApplications: () => call<unknown>('get_active_applications').then(normalizeActiveApps),
  getUpdateStatus: () => call<UpdateStatus>('get_update_status'),
  /** Asks the daemon to read the release feeds now; never downloads or installs anything. */
  checkForUpdates: () => call<UpdateStatus>('check_for_updates', undefined, LONG_IPC_TIMEOUT_MS),
  /** Starts the update the user confirmed; the daemon downloads and applies it, restarting filtering. */
  installUpdate: (version: string) =>
    call<UpdateActionResult>('install_update', { version }, LONG_IPC_TIMEOUT_MS),
  /** Registry RDAP or WHOIS can be slow; the daemon's own client gives up after 20s per request. */
  lookupDomain: (domain: string) =>
    call<unknown>('lookup_domain', { domain }, LONG_IPC_TIMEOUT_MS).then(normalizeDomainLookup),
  /** Asks the configured DNS upstream directly; `address` adds reverse DNS. */
  lookupDnsRecords: (host: string, domain: string, address: string) =>
    call<unknown>('lookup_dns_records', { host, domain, address }, LONG_IPC_TIMEOUT_MS).then(
      normalizeDnsRecords,
    ),
  /**
   * Names under `host`'s registered domain from local connection and DNS
   * history. `domain` is the registered domain when known; otherwise the
   * daemon asks the DNS upstream for the host's zone.
   */
  getSeenSubdomains: (host: string, domain: string) =>
    call<unknown>('get_seen_subdomains', { host, domain }, LONG_IPC_TIMEOUT_MS).then(
      normalizeSeenSubdomains,
    ),
  /** Sends the registered domain to crt.sh, a third party; only on an explicit request. */
  /** Opens a reputation site's report on `domain` in the default browser; the URL is built natively. */
  openDomainReputation: (service: string, domain: string) =>
    call<void>('open_domain_reputation', { service, domain }),
  searchCertificates: (host: string, domain: string) =>
    call<unknown>('search_certificates', { host, domain }, LONG_IPC_TIMEOUT_MS).then(
      normalizeCertificateSearch,
    ),
  getRules: () =>
    call<(Rule & Record<string, unknown>)[]>('get_rules').then((rows) =>
      Array.isArray(rows) ? rows.map(normalizeRule) : [],
    ),
  addRule: (
    targetType: string,
    targetValue: string,
    action: string,
    direction: RuleDirection = 'OUTBOUND',
  ) => call<boolean>('add_rule', { targetType, targetValue, action, direction }),
  removeRule: (id: number, targetType: string, targetValue: string, action: string) =>
    mutation('remove_rule', { id, targetType, targetValue, action }),
  getCountryRules: () =>
    call<(CountryRule & Record<string, unknown>)[]>('get_country_rules').then((rows) =>
      Array.isArray(rows) ? rows.map(normalizeCountryRule) : [],
    ),
  addCountryRule: (
    countryCode: string,
    cidrs: string[],
    action: string,
    direction: RuleDirection = 'OUTBOUND',
  ) => call<CountryActionResult>('add_country_rule', { countryCode, cidrs, action, direction }),
  removeCountryRule: (id: number, countryCode: string) =>
    call<CountryActionResult>('remove_country_rule', { id, countryCode }),
  getSettings: () =>
    call<SettingsDto & Record<string, unknown>>('get_settings').then(normalizeSettings),
  updateSettings: (settings: SettingsDto) =>
    call<SettingsSaveResult>('update_settings', { settings: settingsToUpdatePayload(settings) }),
  syncHostsBlocklist: () => mutation('sync_hosts_blocklist', undefined, LONG_IPC_TIMEOUT_MS),
  getConnectionLogs: (opts: {
    offset?: number;
    limit?: number;
    applicationName?: string;
    applicationId?: number;
    actionFilter?: string;
    timeFilterSeconds?: number;
    timeWindowStart?: number;
    timeWindowEnd?: number;
    searchQuery?: string;
    orderBy?: string;
    sortDescending?: boolean;
    protocolFilter?: string;
    countryFilter?: string;
    portFilter?: number;
    hostFilter?: string;
  }) =>
    call<ConnectionLogsPage & Record<string, unknown>>('get_connection_logs', opts).then(
      normalizeConnectionLogsPage,
    ),
  getAppSummaries: (opts?: {
    actionFilter?: string;
    timeFilterSeconds?: number;
    timeWindowStart?: number;
    timeWindowEnd?: number;
  }) =>
    call<AppSummariesPage & Record<string, unknown>>('get_app_summaries', opts ?? {}).then(
      normalizeAppSummariesPage,
    ),
  getActivityBuckets: (opts?: { days?: number; since?: number; until?: number }) => {
    const args: Record<string, unknown> = {};
    if (opts?.days !== undefined) args.days = opts.days;
    if (opts?.since !== undefined) args.since = opts.since;
    if (opts?.until !== undefined) args.until = opts.until;
    return call<
      Array<
        {
          bucketStart: number;
          eventCount: number;
          bytesSent: number;
          bytesReceived: number;
          blockedCount: number;
        } & Record<string, unknown>
      >
    >('get_activity_buckets', args).then((rows) =>
      Array.isArray(rows)
        ? rows.map((row) => ({
            bucketStart: Number(row.bucketStart ?? row.bucket_start ?? 0),
            eventCount: Number(row.eventCount ?? row.event_count ?? 0),
            bytesSent: Number(row.bytesSent ?? row.bytes_sent ?? 0),
            bytesReceived: Number(row.bytesReceived ?? row.bytes_received ?? 0),
            blockedCount: Number(row.blockedCount ?? row.blocked_count ?? 0),
          }))
        : [],
    );
  },
  exportLogs: (path: string, format: 'csv' | 'json') =>
    call<boolean>('export_logs', { path, format }, LONG_IPC_TIMEOUT_MS),
  listCaptureDevices: () =>
    call<{ devices: CaptureDeviceDto[]; available: boolean; message: string }>(
      'list_capture_devices',
    ).then((result) => ({
      ...result,
      devices: (result.devices ?? []).map((device) => ({
        name: String(device.name ?? ''),
        description: String(device.description ?? ''),
        addresses: Array.isArray(device.addresses) ? device.addresses.map(String) : [],
        loopback: device.loopback === true,
      })),
    })),
  startCapture: (opts: {
    deviceName: string;
    appPath: string;
    appName: string;
    captureFilter: string;
    snapLength: number;
    promiscuous: boolean;
    maxSeconds: number;
    maxBytes: number;
  }) => call<string>('start_capture', opts, LONG_IPC_TIMEOUT_MS),
  stopCapture: (captureId: string) => mutation('stop_capture', { captureId }, LONG_IPC_TIMEOUT_MS),
  getCaptureStatus: (captureId: string) =>
    call<CaptureStatusDto>('get_capture_status', { captureId }),
  startCapturePacketStream: (captureId: string) =>
    call<void>('start_capture_packet_stream', { captureId }),
  /**
   * Native save dialog owned by the backend. Only a path returned here is accepted
   * by `downloadCapture` and `exportLogs`. Resolves `null` when cancelled.
   */
  pickSavePath: (defaultName: string, filterName: string, extensions: string[]) =>
    call<string | null>(
      'pick_save_path',
      { defaultName, filterName, extensions },
      DIALOG_IPC_TIMEOUT_MS,
    ),
  downloadCapture: (captureId: string, path: string) =>
    call<boolean>('download_capture', { captureId, path }, LONG_IPC_TIMEOUT_MS),
  getNetworkMappingState: () =>
    call<{
      devices: Array<{
        ipAddress: string;
        macAddress: string;
        manufacturer: string;
        mdnsName: string;
        isPresent: boolean;
        lastSeen: string;
        isWatched: boolean;
      }>;
      scanRanges: Array<{ id: number; adapterId: string; cidr: string }>;
      deviceWatches: Array<{
        id: number;
        ipAddress: string;
        macAddress: string;
        intervalMinutes: number;
        enabled: boolean;
        isPresent: boolean;
        lastChecked: string;
      }>;
      isScanning: boolean;
      supported: boolean;
      message: string;
    }>('get_network_mapping_state'),
  scanNetwork: (cidrRanges: string[]) => mutation('scan_network', { cidrRanges }),
  stopNetworkScan: () => mutation('stop_network_scan'),
  clearNetworkDevices: () => mutation('clear_network_devices'),
  saveNetworkDeviceWatch: (watch: {
    id?: number;
    ipAddress: string;
    macAddress: string;
    intervalMinutes: 1 | 5 | 10 | 30 | 60;
    enabled?: boolean;
  }) =>
    mutation('save_network_device_watch', {
      id: watch.id ?? 0,
      ipAddress: watch.ipAddress,
      macAddress: watch.macAddress,
      adapterId: '',
      cidr: '',
      intervalMinutes: watch.intervalMinutes,
      enabled: watch.enabled ?? true,
    }),
  removeNetworkDeviceWatch: (watch: { id: number; macAddress: string }) =>
    mutation('remove_network_device_watch', {
      id: watch.id,
      macAddress: watch.macAddress,
      adapterId: '',
      cidr: '',
    }),
  minimizeWindow: () => call<void>('minimize_window'),
  toggleMaximizeWindow: () => call<void>('toggle_maximize_window'),
  closeWindow: () => call<void>('close_window'),
  openPacketInspector: (packet: CapturedPacketDto) =>
    call<void>('open_packet_inspector', {
      packet,
      themeSnapshot: captureThemeSnapshot(),
    }),
  getPacketInspectorPacket: () => call<CapturedPacketDto | null>('get_packet_inspector_packet'),
  getPacketInspectorTheme: () => call<unknown>('get_packet_inspector_theme'),
};
