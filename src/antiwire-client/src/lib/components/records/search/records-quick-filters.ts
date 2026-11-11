import type { ConnectionLog } from '#lib/types/index.ts';
import { recordProtocolLabel } from '#lib/models/well-known-ports.ts';
import type { ActivityBucket } from '#lib/models/activity-heatmap.ts';

export type TrafficDirection = 'up' | 'down' | 'balanced' | 'none';
/** One suggestion in a quick filter group: the exact value it filters on, its label and share. */
export type FacetOption<V extends string | number = string> = {
  value: V;
  label: string;
  /** Secondary text, e.g. the port behind a service name. */
  detail?: string;
  count: number;
  /** count / rows considered, 0..1. */
  share: number;
};
export type TrafficBucket = {
  key: string;
  sent: number;
  received: number;
  total: number;
  intensity: number;
  direction: TrafficDirection;
};

function localDateKey(date: Date): string {
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, '0');
  const day = String(date.getDate()).padStart(2, '0');
  return `${year}-${month}-${day}`;
}

export type FacetWindow = 'day' | 'week' | 'month';

/** Rolling windows: a day is 24 hours, a week 7 days, a month 30 days. */
const FACET_WINDOW_SECONDS: Record<FacetWindow, number> = {
  day: 24 * 60 * 60,
  week: 7 * 24 * 60 * 60,
  month: 30 * 24 * 60 * 60,
};

/** How many connection rows one facet page asks for, and where paging stops. */
export const FACET_PAGE_SIZE = 2_000;
export const FACET_ROW_CAP = 20_000;

export function facetWindowStart(window: FacetWindow, nowMs = Date.now()): number {
  return Math.floor(nowMs / 1000) - FACET_WINDOW_SECONDS[window];
}

/**
 * Rows active inside the rolling window. Same rule as the log query: a row
 * counts when either `lastSeen` or `timestamp` is inside the window.
 */
export function rowsInFacetWindow(
  rows: readonly ConnectionLog[],
  window: FacetWindow,
  nowMs = Date.now(),
): ConnectionLog[] {
  const since = facetWindowStart(window, nowMs);
  return rows.filter((row) => row.lastSeen >= since || row.timestamp >= since);
}

/** Most frequent values first, ties by label. Every distinct value is kept. */
function rank<V extends string | number>(
  rows: readonly ConnectionLog[],
  pick: (row: ConnectionLog) => { value: V; label: string; detail?: string } | null,
): FacetOption<V>[] {
  const counts = new Map<V, FacetOption<V>>();
  for (const row of rows) {
    const picked = pick(row);
    if (!picked) continue;
    const current = counts.get(picked.value);
    if (current) current.count += 1;
    else counts.set(picked.value, { ...picked, count: 1, share: 0 });
  }
  const total = rows.length || 1;
  return [...counts.values()]
    .map((option) => ({ ...option, share: option.count / total }))
    .sort((a, b) => b.count - a.count || a.label.localeCompare(b.label));
}

/**
 * Pages connection rows until the window is exhausted or `cap` is reached.
 * A page that repeats the first row is treated as a stuck offset and stops
 * the walk, so a backend that ignores `offset` cannot loop.
 */
export async function loadFacetRows(
  fetchPage: (
    offset: number,
    limit: number,
  ) => Promise<{ logs: readonly ConnectionLog[]; totalCount: number }>,
  options?: {
    pageSize?: number;
    cap?: number;
    /** Called after each page so the lists can grow before the walk finishes. */
    onPage?: (rows: readonly ConnectionLog[]) => void;
  },
): Promise<ConnectionLog[]> {
  const pageSize = options?.pageSize ?? FACET_PAGE_SIZE;
  const cap = options?.cap ?? FACET_ROW_CAP;
  const collected: ConnectionLog[] = [];
  let total = Number.POSITIVE_INFINITY;
  while (collected.length < total && collected.length < cap) {
    const limit = Math.min(pageSize, cap - collected.length);
    const page = await fetchPage(collected.length, limit);
    total = Number.isFinite(page.totalCount)
      ? page.totalCount
      : collected.length + page.logs.length;
    if (page.logs.length === 0) break;
    if (collected.length > 0 && page.logs[0]?.id === collected[0]?.id) break;
    collected.push(...page.logs);
    options?.onPage?.([...collected]);
    if (page.logs.length < limit) break;
  }
  return collected;
}

const regionNames = (() => {
  try {
    return new Intl.DisplayNames(undefined, { type: 'region' });
  } catch {
    return null;
  }
})();

export function countryLabel(code: string): string {
  try {
    return regionNames?.of(code) ?? code;
  } catch {
    return code;
  }
}

/** "HTTPS" with "443" as detail for well-known ports; just the number otherwise. */
export function serviceLabel(port: number, protocol: string): { label: string; detail?: string } {
  const name = recordProtocolLabel(protocol, port);
  return name && name.toUpperCase() !== protocol.toUpperCase()
    ? { label: name, detail: String(port) }
    : { label: String(port) };
}

/** Quick filter suggestions: exact values ranked by how often they appear in `rows`. */
export function buildFacetOptions(rows: readonly ConnectionLog[]) {
  return {
    services: rank(rows, (row) =>
      row.port > 0 ? { value: row.port, ...serviceLabel(row.port, row.protocol) } : null,
    ),
    countries: rank(rows, (row) => {
      const code = row.countryCode.trim().toUpperCase();
      return code ? { value: code, label: countryLabel(code) } : null;
    }),
    destinations: rank(rows, (row) => {
      const host = row.domain.trim() || row.destinationIp.trim();
      return host ? { value: host, label: host } : null;
    }),
  };
}

function finishBucket<T extends Omit<TrafficBucket, 'total' | 'intensity' | 'direction'>>(
  bucket: T,
  max: number,
): T & TrafficBucket {
  const total = bucket.sent + bucket.received;
  const direction: TrafficDirection =
    total === 0
      ? 'none'
      : bucket.sent === bucket.received
        ? 'balanced'
        : bucket.sent > bucket.received
          ? 'up'
          : 'down';
  return { ...bucket, total, intensity: max > 0 ? total / max : 0, direction };
}

type TrafficWindow = { sent: number; received: number };

function emptyHourly(): TrafficWindow[] {
  return Array.from({ length: 24 }, () => ({ sent: 0, received: 0 }));
}

function addTraffic(target: TrafficWindow, sent: number, received: number) {
  target.sent += sent;
  target.received += received;
}

/** Page-local fallback: bucket the loaded rows by local day and by hour for the selected date. */
function tallyLogs(logs: readonly ConnectionLog[], selectedDate: string) {
  const daily = new Map<string, TrafficWindow>();
  const hourly = emptyHourly();
  for (const log of logs) {
    const date = new Date(log.lastSeen * 1000);
    const key = localDateKey(date);
    const day = daily.get(key) ?? { sent: 0, received: 0 };
    addTraffic(day, log.bytesSent, log.bytesReceived);
    daily.set(key, day);
    if (key === selectedDate) addTraffic(hourly[date.getHours()], log.bytesSent, log.bytesReceived);
  }
  return { daily, hourly };
}

/** Real activity: 30-minute device buckets aggregated into local days and hours. */
function tallyActivity(buckets: readonly ActivityBucket[], selectedDate: string) {
  const daily = new Map<string, TrafficWindow>();
  const hourly = emptyHourly();
  for (const bucket of buckets) {
    const date = new Date(bucket.bucketStart * 1000);
    const key = localDateKey(date);
    const day = daily.get(key) ?? { sent: 0, received: 0 };
    addTraffic(day, bucket.bytesSent, bucket.bytesReceived);
    daily.set(key, day);
    if (key === selectedDate) {
      addTraffic(hourly[date.getHours()], bucket.bytesSent, bucket.bytesReceived);
    }
  }
  return { daily, hourly };
}

function trafficWindows(
  source: { daily: Map<string, TrafficWindow>; hourly: TrafficWindow[] },
  now: Date,
) {
  const daysBase = Array.from({ length: 7 }, (_, offset) => {
    const date = new Date(now);
    date.setHours(12, 0, 0, 0);
    date.setDate(date.getDate() - (6 - offset));
    const key = localDateKey(date);
    const bytes = source.daily.get(key) ?? { sent: 0, received: 0 };
    return { key, ...bytes };
  });
  const dayMax = Math.max(0, ...daysBase.map((item) => item.sent + item.received));
  const hourMax = Math.max(0, ...source.hourly.map((item) => item.sent + item.received));
  return {
    days: daysBase.map((item) => finishBucket(item, dayMax)),
    hours: source.hourly.map((item, hour) => finishBucket({ key: String(hour), ...item }, hourMax)),
  };
}

/** Daily and hourly traffic for the time filter: real activity when available, loaded rows otherwise. */
export function buildTimeFilterData(
  logs: readonly ConnectionLog[],
  now = new Date(),
  selectedDate = localDateKey(now),
  activityBuckets: readonly ActivityBucket[] = [],
) {
  const source =
    activityBuckets.length > 0
      ? tallyActivity(activityBuckets, selectedDate)
      : tallyLogs(logs, selectedDate);
  return trafficWindows(source, now);
}

export function customTimeWindow(date: string, startTime: string, endTime: string) {
  if (!date || !startTime || !endTime) return null;
  const start = new Date(`${date}T${startTime}`).getTime() / 1000;
  // The end minute is inclusive: "to 23:59" covers the whole of 23:59.
  const end = new Date(`${date}T${endTime}`).getTime() / 1000 + 60;
  if (!Number.isFinite(start) || !Number.isFinite(end) || end - 60 <= start) return null;
  return { start: Math.floor(start), end: Math.floor(end) };
}

export function hourTimeWindow(date: string, hour: number) {
  const start = new Date(`${date}T${String(hour).padStart(2, '0')}:00`).getTime() / 1000;
  return { start: Math.floor(start), end: Math.floor(start + 3600) };
}

export function dayTimeWindow(date: string) {
  const start = new Date(`${date}T00:00`);
  const end = new Date(start);
  end.setDate(end.getDate() + 1);
  return { start: Math.floor(start.getTime() / 1000), end: Math.floor(end.getTime() / 1000) };
}

const labelDay = new Intl.DateTimeFormat(undefined, {
  weekday: 'short',
  month: 'short',
  day: 'numeric',
});
const labelDate = new Intl.DateTimeFormat(undefined, { month: 'short', day: 'numeric' });
const labelClock = new Intl.DateTimeFormat(undefined, { hour: '2-digit', minute: '2-digit' });

/**
 * Short label for a time window: "Mon, Sep 28" for a whole day, "Sep 28, 14:00 – 15:00"
 * within one day, and both dates otherwise. `end` is exclusive.
 */
export function formatTimeWindowShort(start: number, end: number): string {
  const from = new Date(start * 1000);
  const to = new Date(end * 1000);
  const last = new Date(end * 1000 - 1);
  const midnight = (date: Date) => date.getHours() === 0 && date.getMinutes() === 0;
  if (midnight(from) && midnight(to) && localDateKey(from) === localDateKey(last)) {
    return labelDay.format(from);
  }
  if (localDateKey(from) === localDateKey(last)) {
    return `${labelDate.format(from)}, ${labelClock.format(from)} – ${labelClock.format(to)}`;
  }
  return `${labelDate.format(from)}, ${labelClock.format(from)} – ${labelDate.format(to)}, ${labelClock.format(to)}`;
}
