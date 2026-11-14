import type { AppSummary, ConnectionLog } from '#lib/types/index.ts';
import { m } from '#lib/i18n/messages.ts';
import { formatBlocklistNames } from '#lib/models/blocklists.ts';
import {
  protocolFilterValue,
  sortDirToDescending,
  sortKeyToOrderBy,
  type RecordsSortKey,
} from '#lib/models/records-sort.ts';
import {
  parseApplicationIdParam,
  parseApplicationParam,
  parseTimeWindowParam,
} from '#lib/utils/records-url.ts';
import { recordStateTone } from '../detail/record-detail';

export type RecordsVerdict = 'all' | 'allowed' | 'blocked';

export type RecordsUrlFilters = {
  application?: string;
  applicationId?: number;
  timeWindowStart?: number;
  timeWindowEnd?: number;
};

export type RecordsAppRow = {
  name: string;
  value: string;
  /** Database row id; selects exactly one install path sharing the name. */
  appId: number;
  count: number;
  /** Blocked connections among `count`. */
  blocked: number;
  /** Present while the application has live connections. */
  live: RecordsAppLive | null;
  selected: boolean;
  isAll: boolean;
  key: string;
  path?: string;
  initials?: string;
};

/** The tail of an install path, e.g. `…\Cloud Sync\sync.exe`, keeping its separator. */
export function shortPath(path: string, segments = 2): string {
  const clean = path.trim();
  const parts = clean.split(/[\\/]/).filter(Boolean);
  if (parts.length <= segments) return clean;
  const separator = clean.includes('\\') ? '\\' : '/';
  return `…${separator}${parts.slice(-segments).join(separator)}`;
}

/** Which applications the panel lists. */
export type RecordsAppFilter = 'all' | 'live' | 'blocked';

export type RecordsAppLive = {
  connections: number;
  /** Bytes per second. */
  downloadRate: number;
  uploadRate: number;
};

/**
 * Pairs a history summary with its live entry: the install path when known
 * (case-insensitively, as Windows paths are), else the name.
 */
export function appMatchKey(path: string, name: string): string {
  const cleanPath = path.trim();
  return cleanPath ? `p:${cleanPath.toLowerCase()}` : `n:${name.trim().toLowerCase()}`;
}

/** Live applications keyed by [`appMatchKey`], for joining onto summaries. */
export function liveAppIndex(
  apps: readonly {
    name: string;
    path: string;
    connections: number;
    downloadRate: number;
    uploadRate: number;
  }[],
): Map<string, RecordsAppLive> {
  const index = new Map<string, RecordsAppLive>();
  for (const app of apps) {
    const live = {
      connections: app.connections,
      downloadRate: app.downloadRate,
      uploadRate: app.uploadRate,
    };
    index.set(appMatchKey(app.path, app.name), live);
    // A summary without a path still finds its live entry by name.
    const byName = appMatchKey('', app.name);
    if (!index.has(byName)) index.set(byName, live);
  }
  return index;
}

function liveFor(
  live: ReadonlyMap<string, RecordsAppLive> | undefined,
  row: AppSummary,
): RecordsAppLive | null {
  if (!live) return null;
  return (
    live.get(appMatchKey(row.applicationPath, row.applicationName)) ??
    (row.applicationPath ? null : (live.get(appMatchKey('', row.applicationName)) ?? null))
  );
}

/** How many applications each filter would list (All excludes the pinned row). */
export function recordsAppFilterCounts(
  summaries: readonly AppSummary[],
  live?: ReadonlyMap<string, RecordsAppLive>,
): Record<RecordsAppFilter, number> {
  let liveCount = 0;
  let blocked = 0;
  for (const row of summaries) {
    if (liveFor(live, row)) liveCount += 1;
    if (row.blockedCount > 0) blocked += 1;
  }
  return { all: summaries.length, live: liveCount, blocked };
}

export type RecordsStateStyle = {
  fg: string;
  bg: string;
  dot: string;
};

export type RecordsRefreshInput = {
  verdict: RecordsVerdict;
  pageOffset: number;
  selectedApp: string;
  selectedAppId?: number;
  filter: string;
  sortKey: RecordsSortKey | null;
  sortDir: 1 | -1;
  proto: string;
  /** Exact-match filters from the quick filter chips. */
  facets?: RecordFacets;
  timeWindowStart?: number;
  timeWindowEnd?: number;
  urlSearch?: string;
};

/** One exact value per kind; they stack with each other and with the search text. */
export type RecordFacets = {
  /** Destination port. */
  port?: number;
  /** ISO 3166 alpha-2 code. */
  country?: string;
  /** Destination domain or IP. */
  host?: string;
};

export const RECORDS_PAGE_SIZE = 200;

const STATE_STYLE: Record<ReturnType<typeof recordStateTone>, RecordsStateStyle> = {
  blocked: {
    fg: 'var(--bad)',
    bg: 'color-mix(in oklab, var(--bad) 13%, transparent)',
    dot: 'var(--bad)',
  },
  listen: {
    fg: 'var(--warn)',
    bg: 'color-mix(in oklab, var(--warn) 13%, transparent)',
    dot: 'var(--warn)',
  },
  allowed: {
    fg: 'var(--ok)',
    bg: 'color-mix(in oklab, var(--ok) 12%, transparent)',
    dot: 'var(--ok)',
  },
};

export function recordsUrlFilters(search: string): RecordsUrlFilters {
  const params = new URLSearchParams(search);
  const from = parseTimeWindowParam(params.get('from'));
  const to = parseTimeWindowParam(params.get('to'));
  return {
    application: parseApplicationParam(params.get('app')),
    applicationId: parseApplicationIdParam(params.get('appid')),
    timeWindowStart: from && to ? from : undefined,
    timeWindowEnd: from && to ? to : undefined,
  };
}

export function recordsHref(
  selectedApp: string,
  start?: number,
  end?: number,
  appId?: number,
): string {
  const params = new URLSearchParams();
  if (selectedApp !== 'ALL') params.set('app', selectedApp);
  if (appId) params.set('appid', String(appId));
  if (start && end) {
    params.set('from', String(start));
    params.set('to', String(end));
  }
  const qs = params.toString();
  return `/records${qs ? `?${qs}` : ''}`;
}

export function recordsUrlLoadKey(search: string): string {
  const filters = recordsUrlFilters(search);
  return `${search}|${filters.application ?? ''}|${filters.applicationId ?? ''}|${filters.timeWindowStart ?? ''}|${filters.timeWindowEnd ?? ''}`;
}

export function serverActionFilter(verdict: RecordsVerdict): string | undefined {
  if (verdict === 'all') return undefined;
  return verdict === 'allowed' ? 'Allowed' : 'Blocked';
}

export function recordsRefreshOptions(input: RecordsRefreshInput) {
  const filters = input.urlSearch === undefined ? null : recordsUrlFilters(input.urlSearch);
  const application =
    filters?.application ?? (input.selectedApp !== 'ALL' ? input.selectedApp : undefined);
  const applicationId = filters?.applicationId ?? input.selectedAppId;
  const windowStart = filters?.timeWindowStart ?? input.timeWindowStart;
  const windowEnd = filters?.timeWindowEnd ?? input.timeWindowEnd;
  return {
    actionFilter: serverActionFilter(input.verdict),
    offset: input.pageOffset,
    limit: RECORDS_PAGE_SIZE,
    applicationName: application,
    applicationId,
    searchQuery: input.filter.trim() || undefined,
    orderBy: sortKeyToOrderBy(input.sortKey),
    sortDescending: sortDirToDescending(input.sortKey, input.sortDir),
    protocolFilter: protocolFilterValue(input.proto),
    countryFilter: input.facets?.country,
    portFilter: input.facets?.port,
    hostFilter: input.facets?.host,
    timeWindowStart: windowStart,
    timeWindowEnd: windowEnd,
  };
}

export function recordsGrandTotal(
  summaries: readonly AppSummary[],
  logsTotalCount: number,
): number {
  return summaries.reduce((sum, summary) => sum + summary.connectionCount, 0) || logsTotalCount;
}

export type RecordsScopeStats = {
  allowed: number;
  blocked: number;
  bytesSent: number;
  bytesReceived: number;
};

/**
 * Connection and byte totals for the selected scope: every application, or
 * the selected one. They come from the application summaries, so the search
 * text and the quick filters do not narrow them.
 */
export function recordsScopeStats(
  summaries: readonly AppSummary[],
  selectedApp: string,
  selectedAppId?: number,
): RecordsScopeStats {
  // Prefer the exact install path: several summaries can share one name.
  const exact = selectedAppId
    ? summaries.filter((summary) => summary.applicationId === selectedAppId)
    : [];
  const rows =
    selectedApp === 'ALL'
      ? summaries
      : exact.length
        ? exact
        : summaries.filter((summary) => summary.applicationName === selectedApp);
  const stats = { allowed: 0, blocked: 0, bytesSent: 0, bytesReceived: 0 };
  for (const row of rows) {
    stats.allowed += Math.max(0, row.connectionCount - row.blockedCount);
    stats.blocked += row.blockedCount;
    stats.bytesSent += row.bytesSent;
    stats.bytesReceived += row.bytesReceived;
  }
  return stats;
}

export function buildRecordsAppList(
  summaries: readonly AppSummary[],
  options: {
    query: string;
    selectedApp: string;
    selectedAppId?: number;
    allLabel: string;
    grandTotal: number;
    filter?: RecordsAppFilter;
    live?: ReadonlyMap<string, RecordsAppLive>;
  },
): RecordsAppRow[] {
  const q = options.query.trim().toLowerCase();
  const filter = options.filter ?? 'all';
  const withLive = summaries.map((row) => ({ row, live: liveFor(options.live, row) }));
  const openConnections = (live: RecordsAppLive | null) => live?.connections ?? 0;
  // Live orders by open connections: steadier than throughput, which would
  // reshuffle the list under the pointer on every poll.
  const sorted = [...withLive].sort((a, b) =>
    filter === 'live'
      ? openConnections(b.live) - openConnections(a.live) ||
        b.row.connectionCount - a.row.connectionCount
      : b.row.connectionCount - a.row.connectionCount,
  );
  const filtered = sorted.filter(({ row, live }) => {
    if (filter === 'live' && !live) return false;
    if (filter === 'blocked' && row.blockedCount <= 0) return false;
    if (!q) return true;
    return (
      row.applicationName.toLowerCase().includes(q) || row.applicationPath.toLowerCase().includes(q)
    );
  });

  const allItem: RecordsAppRow = {
    name: options.allLabel,
    value: 'ALL',
    initials: 'ALL',
    appId: 0,
    count: options.grandTotal,
    blocked: 0,
    live: null,
    selected: options.selectedApp === 'ALL',
    isAll: true,
    key: 'ALL',
  };

  const items = filtered.map(({ row, live }, index) => {
    const name = row.applicationName;
    // An exact id selects one install path; a bare name keeps the legacy
    // behavior of highlighting every row sharing the name.
    const selected =
      options.selectedAppId && row.applicationId
        ? row.applicationId === options.selectedAppId
        : options.selectedApp === name;
    return {
      name,
      value: name,
      appId: row.applicationId,
      count: row.connectionCount,
      blocked: row.blockedCount,
      live,
      selected,
      isAll: false,
      path: row.applicationPath,
      key: `${name}::${row.applicationPath || index}`,
    };
  });

  return [allItem, ...items];
}

export function recordsAppItemKey(app: Pick<RecordsAppRow, 'key'>): string {
  return app.key;
}

export function recordsLogItemKey(row: ConnectionLog): string {
  // The database row id is the only identity that survives repeated rows:
  // two blocks (or two connections) can share every content field. The id is
  // also stable across live updates (lastSeen/bytes), so rows never remount.
  // Realtime events have no row yet (id 0) and keep the legacy content key.
  if (row.id) return `row:${row.id}`;
  // Identity only — lastSeen/bytes change on live updates and must not remount the row.
  return `${row.timestamp}\0${row.applicationPath}\0${row.applicationName}\0${row.sourceIp}\0${row.destinationIp}\0${row.port}\0${row.protocol}\0${row.action}\0${row.domain}`;
}

/**
 * List-aware keys for the virtualized log table. Parallel connections from one
 * app to one destination within one timestamp second share the base identity
 * (e.g. two gh.exe HTTPS flows to api.github.com), and duplicate React keys
 * make rows swap or vanish on re-render. The first occurrence keeps the
 * bare base key so unique rows (the common case) stay stable; later duplicates
 * get a `\0#n` suffix. The suffix adds a segment past the fixed field count,
 * so it can never collide with a bare base key.
 *
 * Scope this over the full `logs` page, not the virtual window — suffixing a
 * visible subset would reuse bare keys across scroll positions.
 */
export function recordsLogKeys(logs: readonly ConnectionLog[]): string[] {
  const seen = new Map<string, number>();
  return logs.map((row) => {
    const base = recordsLogItemKey(row);
    const count = (seen.get(base) ?? 0) + 1;
    seen.set(base, count);
    return count === 1 ? base : `${base}\0#${count}`;
  });
}

/** Daemon actions arrive upper-case (`ALLOW`, `BLOCK`); show them in sentence case. */
export function recordActionLabel(action: string): string {
  const value = action.trim();
  return value ? value.charAt(0).toUpperCase() + value.slice(1).toLowerCase() : value;
}

export function recordsStateStyle(row: ConnectionLog): RecordsStateStyle {
  return STATE_STYLE[recordStateTone(row.action)];
}

/** Tooltip for the blocked status dot and state chip: matching lists, otherwise empty. */
export function recordBlocklistTooltip(row: ConnectionLog): string {
  if (recordStateTone(row.action) !== 'blocked') return '';
  return formatBlocklistNames(row.blocklistNames);
}

export function destinationIpTooltip(row: ConnectionLog): string {
  if (!row.destinationIp) return '';
  if (row.countryCode) return `${row.destinationIp} · ${row.countryCode}`;
  return row.destinationIp;
}

export function nextRecordsSort(
  sortKey: RecordsSortKey | null,
  sortDir: 1 | -1,
  clicked: RecordsSortKey,
): { sortKey: RecordsSortKey | null; sortDir: 1 | -1 } {
  if (sortKey !== clicked) return { sortKey: clicked, sortDir: -1 };
  if (sortDir === -1) return { sortKey, sortDir: 1 };
  return { sortKey: null, sortDir: -1 };
}

export function recordsNoAppMatch(query: string, appListLength: number): boolean {
  return Boolean(query.trim() && appListLength === 1);
}

export function canPageBack(offset: number): boolean {
  return offset > 0;
}

export function canPageForward(offset: number, total: number): boolean {
  return offset + RECORDS_PAGE_SIZE < total;
}

export function recordsVisibleEnd(offset: number, visibleCount: number): number {
  return visibleCount === 0 ? 0 : offset + visibleCount;
}

export function shouldRefreshSummaries(reason: string): boolean {
  return (
    reason === 'manual-refresh' ||
    reason === 'url-change' ||
    reason === 'time-clear' ||
    reason === 'realtime'
  );
}

/**
 * Sortable columns, in table order. The Application column only appears for
 * "All applications": with one app selected every row would repeat it. Source
 * IP, state and country live in the record inspector instead.
 */
export function recordsColumnDefs(
  showApplication = true,
): { key: RecordsSortKey; label: string; just: string }[] {
  return [
    ...(showApplication
      ? [{ key: 'app' as const, label: m.records_col_application(), just: 'flex-start' }]
      : []),
    { key: 'host', label: m.records_detail_field_destination(), just: 'flex-start' },
    { key: 'port', label: m.records_col_port(), just: 'flex-start' },
    { key: 'up', label: m.records_col_sent(), just: 'flex-end' },
    { key: 'down', label: m.records_col_recv(), just: 'flex-end' },
    { key: 'lastSeen', label: m.records_col_last_seen(), just: 'flex-end' },
  ];
}
