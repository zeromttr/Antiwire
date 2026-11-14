import type {
  ApplicationLogSummaryResponse,
  CertificateSearchResponse,
  CountryStatisticsResponse,
  DnsRecordsResponse,
  LogRequest,
  LogResponse,
  LookupDomainResponse,
  LookupOutcome,
  SeenSubdomainsResponse,
  TrafficEvent,
} from '../daemon/messages';
import { pick } from './pick';

export interface ConnectionLogDto {
  id: number;
  closedAt: number;
  isActive: boolean;
  applicationName: string;
  applicationPath: string;
  domain: string;
  sourceIp: string;
  /** The local port the connection left from. 0 when the daemon did not record one. */
  sourcePort: number;
  destinationIp: string;
  port: number;
  protocol: string;
  action: string;
  bytesSent: number;
  bytesReceived: number;
  timestamp: number;
  lastSeen: number;
  countryCode: string;
  blocklistNames: string[];
}

/** Field order matches the Rust DTO, so the JSON export is byte-for-byte the same. */
export function logToDto(l: TrafficEvent): ConnectionLogDto {
  return {
    id: l.id,
    closedAt: l.closedAt,
    // Close evidence wins over liveness, mirroring the store.
    isActive: l.isActive && l.closedAt === 0,
    applicationName: l.appName,
    applicationPath: l.appPath,
    domain: l.dstDomain,
    sourceIp: l.srcIp,
    sourcePort: l.srcPort,
    destinationIp: l.dstIp,
    port: l.dstPort,
    protocol: l.protocol,
    action: l.action,
    bytesSent: l.bytesSent,
    bytesReceived: l.bytesReceived,
    timestamp: l.timestamp,
    lastSeen: l.lastSeen,
    countryCode: l.countryCode,
    blocklistNames: l.blocklistNames,
  };
}

export function logsPageToDto(page: LogResponse) {
  return {
    logs: page.logs.map(logToDto),
    totalCount: page.totalCount,
    blockedCount: page.blockedCount,
  };
}

/** Filters for one page of connection logs. Unset fields mean "no filter". */
export interface LogQuery {
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
}

export function logRequest(q: LogQuery): LogRequest {
  return {
    offset: q.offset ?? 0,
    limit: q.limit ?? 0,
    searchQuery: q.searchQuery ?? '',
    orderBy: q.orderBy ?? 'last_seen',
    appName: q.applicationName ?? '',
    appId: q.applicationId ?? 0,
    actionFilter: q.actionFilter ?? '',
    timeFilterSeconds: q.timeFilterSeconds ?? 0,
    timeWindowStart: q.timeWindowStart ?? 0,
    timeWindowEnd: q.timeWindowEnd ?? 0,
    sortDescending: q.sortDescending ?? true,
    protocolFilter: q.protocolFilter ?? '',
    countryFilter: q.countryFilter ?? '',
    portFilter: q.portFilter ?? 0,
    hostFilter: q.hostFilter ?? '',
  };
}

export function countryStatisticsToDto(s: CountryStatisticsResponse) {
  return { countryCounts: s.countryCounts, totalCount: s.totalCount, unknownCount: s.unknownCount };
}

export function appSummariesToDto(page: ApplicationLogSummaryResponse) {
  return {
    applications: page.applications.map((s) => ({
      applicationId: s.appId,
      applicationName: s.appName,
      applicationPath: s.appPath,
      connectionCount: s.totalCount,
      blockedCount: s.blockedCount,
      totalBytes: s.totalBytes,
      bytesSent: s.bytesSent,
      bytesReceived: s.bytesReceived,
    })),
    totalCount: page.totalCount,
    blockedCount: page.blockedCount,
  };
}

/**
 * Defuses spreadsheet formulas: cell values come from network traffic, so a
 * remote party controls them and a leading `=`, `+`, `-` or `@` would run.
 */
export function neutralizeFormula(value: string): string {
  return /^[=+\-@\t\r]/.test(value) ? `'${value}` : value;
}

/** Quotes a field only when needed, like the `csv` crate's default writer. */
function csvField(value: string): string {
  return /[",\r\n]/.test(value) ? `"${value.replaceAll('"', '""')}"` : value;
}

const CSV_HEADER = [
  'application',
  'domain',
  'source_ip',
  'destination_ip',
  'port',
  'protocol',
  'action',
  'bytes_sent',
  'bytes_received',
  'timestamp',
  'country',
];

export function logsToCsv(logs: readonly ConnectionLogDto[]): string {
  const rows = [CSV_HEADER];
  for (const log of logs) {
    rows.push([
      neutralizeFormula(log.applicationName),
      neutralizeFormula(log.domain),
      neutralizeFormula(log.sourceIp),
      neutralizeFormula(log.destinationIp),
      String(log.port),
      neutralizeFormula(log.protocol),
      neutralizeFormula(log.action),
      String(log.bytesSent),
      String(log.bytesReceived),
      String(log.timestamp),
      neutralizeFormula(log.countryCode),
    ]);
  }
  return rows.map((row) => row.map(csvField).join(',') + '\n').join('');
}

/** `serde_json::to_vec_pretty`: two-space indentation. */
export function logsToJson(logs: readonly ConnectionLogDto[]): string {
  // The export keeps the fields it has always had; `sourcePort` is for the details panel.
  const rows = logs.map(({ sourcePort: _sourcePort, ...exported }) => exported);
  return JSON.stringify(rows, null, 2);
}

const OUTCOME_NAMES: Record<string, string> = {
  LOOKUP_OUTCOME_FOUND: 'found',
  LOOKUP_OUTCOME_NOT_FOUND: 'not_found',
  LOOKUP_OUTCOME_RATE_LIMITED: 'rate_limited',
  LOOKUP_OUTCOME_NO_AUTHORITY: 'no_authority',
  LOOKUP_OUTCOME_UNAVAILABLE: 'unavailable',
  LOOKUP_OUTCOME_INVALID_DOMAIN: 'invalid_domain',
};

/**
 * `found`, `not_found`, `rate_limited`, `no_authority`, `unavailable` or
 * `invalid_domain`. A value this proto does not know reads as `found`, as
 * prost's enum getter falls back to the default variant.
 */
export function outcomeName(outcome: LookupOutcome): string {
  return (typeof outcome === 'string' && OUTCOME_NAMES[outcome]) || 'found';
}

const REGISTRATION_FIELDS = [
  'domain',
  'source',
  'registrar',
  'registrarId',
  'statuses',
  'nameservers',
  'registeredAt',
  'expiresAt',
  'updatedAt',
  'registrantName',
  'registrantOrganization',
  'redacted',
  'dnssec',
  'fetchedAt',
  'dsRecords',
  'nameserverAddresses',
  'handle',
  'unicodeName',
  'registrarUrl',
  'registrarCountry',
  'whoisServer',
  'abuseEmail',
  'abusePhone',
  'abuseUrl',
  'registrantCountry',
  'registrantRegion',
  'registrantContactUrl',
  'registrarExpiresAt',
  'transferredAt',
  'databaseUpdatedAt',
  'registrySource',
  'registrarSource',
] as const;

export function domainLookupToDto(r: LookupDomainResponse) {
  const record = r.registration;
  return {
    outcome: outcomeName(r.outcome),
    registration: record
      ? {
          ...pick(record, REGISTRATION_FIELDS),
          dsRecords: record.dsRecords.map((ds) =>
            pick(ds, ['keyTag', 'algorithm', 'digestType', 'digest'] as const),
          ),
          nameserverAddresses: record.nameserverAddresses.map((glue) =>
            pick(glue, ['name', 'addresses'] as const),
          ),
        }
      : null,
    detail: r.detail,
  };
}

export function dnsRecordsToDto(r: DnsRecordsResponse) {
  return {
    upstream: r.upstream,
    domain: r.domain,
    sets: r.sets.map((set) => ({
      ...pick(set, ['purpose', 'name', 'recordType', 'status', 'authenticated'] as const),
      answers: set.answers.map((a) => pick(a, ['name', 'recordType', 'ttl', 'data'] as const)),
    })),
  };
}

export function seenSubdomainsToDto(r: SeenSubdomainsResponse) {
  return {
    names: r.names.map((s) =>
      pick(s, ['name', 'connections', 'blocked', 'firstSeen', 'lastSeen'] as const),
    ),
    truncated: r.truncated,
    domain: r.domain,
  };
}

export function certificateSearchToDto(r: CertificateSearchResponse) {
  return {
    outcome: outcomeName(r.outcome),
    domain: r.domain,
    certificates: r.certificates,
    names: r.names.map((n) =>
      pick(n, ['name', 'certificates', 'firstIssued', 'latestExpiry', 'issuer'] as const),
    ),
    truncated: r.truncated,
    detail: r.detail,
  };
}
