import type { RegionStats } from '#lib/utils/region-stats.ts';
import type {
  AppSummary,
  ConnectionLog,
  CountryRule,
  Rule,
  RuleDirection,
  Stats,
} from '#lib/types/index.ts';

/** Rules stored before direction existed carry no value and are outbound-only. */
function normalizeDirection(value: unknown): RuleDirection {
  const direction = String(value ?? '').toUpperCase();
  return direction === 'INBOUND' || direction === 'BOTH' ? direction : 'OUTBOUND';
}

function safeObject(data: unknown): Record<string, unknown> {
  return data && typeof data === 'object' ? (data as Record<string, unknown>) : {};
}

/** Proto `repeated string` arrives as an array; a stored column may still be newline-separated. */
function normalizeStringList(value: unknown): string[] {
  if (Array.isArray(value)) {
    return value.map((entry) => String(entry ?? '').trim()).filter(Boolean);
  }
  if (typeof value === 'string' && value.trim()) {
    return value
      .split('\n')
      .map((entry) => entry.trim())
      .filter(Boolean);
  }
  return [];
}

export function normalizeRule(data?: (Rule & Record<string, unknown>) | null): Rule {
  const d = safeObject(data);
  return {
    id: Number(d.id ?? 0),
    targetType: String(d.targetType ?? d.target_type ?? ''),
    targetValue: String(d.targetValue ?? d.target_value ?? ''),
    action: String(d.action ?? ''),
    direction: normalizeDirection(d.direction),
  };
}

export function normalizeCountryRule(
  data?: (CountryRule & Record<string, unknown>) | null,
): CountryRule {
  const d = safeObject(data);
  return {
    id: Number(d.id ?? 0),
    countryCode: String(d.countryCode ?? d.country_code ?? '').toUpperCase(),
    action: String(d.action ?? 'BLOCK'),
    direction: normalizeDirection(d.direction),
    cidrCount: Number(d.cidrCount ?? d.cidr_count ?? 0),
  };
}

export function normalizeAppSummary(
  data?: (AppSummary & Record<string, unknown>) | null,
): AppSummary {
  const d = safeObject(data);
  const bytesSent = Number(d.bytesSent ?? d.bytes_sent ?? 0);
  const bytesReceived = Number(d.bytesReceived ?? d.bytes_received ?? 0);
  const totalBytes = Number(d.totalBytes ?? d.total_bytes ?? bytesSent + bytesReceived);
  return {
    applicationId: Number(d.applicationId ?? d.application_id ?? 0),
    applicationName: String(d.applicationName ?? d.application_name ?? ''),
    applicationPath: String(d.applicationPath ?? d.application_path ?? ''),
    connectionCount: Number(d.connectionCount ?? d.connection_count ?? 0),
    blockedCount: Number(d.blockedCount ?? d.blocked_count ?? 0),
    totalBytes,
    bytesSent,
    bytesReceived,
  };
}

export function normalizeConnectionLog(
  data?: (ConnectionLog & Record<string, unknown>) | null,
): ConnectionLog {
  const d = safeObject(data);
  const timestamp = Number(d.timestamp ?? 0);
  const lastSeen = Number(d.lastSeen ?? d.last_seen ?? 0) || timestamp;
  return {
    id: Number(d.id ?? 0),
    closedAt: Number(d.closedAt ?? d.closed_at ?? 0),
    // Absent (legacy daemon) means unknown, never active. Close evidence
    // wins downstream in `recordConnectionStatus`.
    isActive: (d.isActive ?? d.is_active ?? false) === true,
    applicationName: String(d.applicationName ?? d.application_name ?? ''),
    applicationPath: String(d.applicationPath ?? d.application_path ?? ''),
    domain: String(d.domain ?? ''),
    sourceIp: String(d.sourceIp ?? d.source_ip ?? ''),
    sourcePort: Number(d.sourcePort ?? d.source_port ?? 0),
    destinationIp: String(d.destinationIp ?? d.destination_ip ?? ''),
    port: Number(d.port ?? 0),
    protocol: String(d.protocol ?? ''),
    action: String(d.action ?? ''),
    bytesSent: Number(d.bytesSent ?? d.bytes_sent ?? 0),
    bytesReceived: Number(d.bytesReceived ?? d.bytes_received ?? 0),
    timestamp,
    lastSeen,
    countryCode: String(d.countryCode ?? d.country_code ?? ''),
    blocklistNames: normalizeStringList(d.blocklistNames ?? d.blocklist_names),
  };
}

/** Database-wide country summary; unknown connections stay separate from known shares. */
export function normalizeCountryStatistics(data: unknown): RegionStats {
  const d = safeObject(data);
  const countryCounts = Object.fromEntries(
    Object.entries(safeObject(d.countryCounts ?? d.country_counts)).map(([code, count]) => [
      code,
      Number(count),
    ]),
  );
  const totalCount = Number(d.totalCount ?? d.total_count ?? 0);
  const unknownCount = Number(d.unknownCount ?? d.unknown_count ?? 0);
  return {
    countryCounts,
    totalCount,
    unknownCount,
    unknownPct: totalCount ? Math.round((unknownCount / totalCount) * 100) : 0,
  };
}

function nullableCount(value: unknown): number | null {
  const count = Number(value);
  return value == null || !Number.isFinite(count) || count < 0 ? null : Math.floor(count);
}

export function normalizeStats(data?: (Stats & Record<string, unknown>) | null): Stats {
  if (data == null || typeof data !== 'object' || Array.isArray(data)) {
    return {
      bytesSent: 0,
      bytesReceived: 0,
      activeConnections: 0,
      blockedConnections: 0,
      byteAccountingAvailable: false,
      collectorStatusDetail: '',
      activeConnectionsAvailable: false,
      activeConnectionsStale: false,
      activeApplications: null,
      databaseSizeBytes: null,
    };
  }
  const d = safeObject(data);
  return {
    bytesSent: Number(d.bytesSent ?? d.bytes_sent ?? 0),
    bytesReceived: Number(d.bytesReceived ?? d.bytes_received ?? 0),
    activeConnections: Number(d.activeConnections ?? d.active_connections ?? 0),
    blockedConnections: Number(d.blockedConnections ?? d.blocked_connections ?? 0),
    // Absent means an older daemon that cannot report collector health; assume healthy so a
    // version mismatch never shows a false warning.
    byteAccountingAvailable:
      (d.byteAccountingAvailable ?? d.byte_accounting_available ?? true) !== false,
    collectorStatusDetail: String(d.collectorStatusDetail ?? d.collector_status_detail ?? ''),
    // Absent (legacy daemon or omitted optional proto field) means the count is usable.
    activeConnectionsAvailable:
      (d.activeConnectionsAvailable ?? d.active_connections_available ?? true) !== false,
    activeConnectionsStale:
      (d.activeConnectionsStale ?? d.active_connections_stale ?? false) === true,
    // Absent means the daemon cannot attribute connections to applications.
    activeApplications: nullableCount(d.activeApplications ?? d.active_applications),
    // Absent means the daemon could not read the file, or predates the field.
    databaseSizeBytes: nullableCount(d.databaseSizeBytes ?? d.database_size_bytes),
  };
}
