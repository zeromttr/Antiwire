export const DASHBOARD_SPARK_POINTS = 24;
export const DASHBOARD_SPARK_SOURCE_SEC = 60;
export const DASHBOARD_DELTA_WINDOW_SEC = 60;

export type StatDeltaTone = 'ok' | 'bad' | 'neutral';

function movingAverage(values: number[], window = 3): number[] {
  if (values.length < 2 || window <= 1) return values;
  return values.map((_, i) => {
    const from = Math.max(0, i - Math.floor(window / 2));
    const to = Math.min(values.length, i + Math.ceil(window / 2));
    const slice = values.slice(from, to);
    return slice.reduce((sum, value) => sum + value, 0) / slice.length;
  });
}

/**
 * Bucket the trailing window by fixed time slices anchored to the newest sample.
 * Only the trailing buckets change when a new second arrives, so the sparkline
 * does not fully reshuffle on every poll.
 */
export function sparkValuesFromTail(
  values: readonly number[],
  points = DASHBOARD_SPARK_POINTS,
  sourceSec = DASHBOARD_SPARK_SOURCE_SEC,
  smoothWindow = 3,
): number[] {
  const source = values.slice(-sourceSec);
  if (source.length < 2) return [];

  const bucketSec = sourceSec / points;
  const result: number[] = [];

  for (let i = 0; i < points; i++) {
    const newestIdx = source.length;
    const bucketStart = newestIdx - Math.ceil((points - i) * bucketSec);
    const bucketEnd = newestIdx - Math.floor((points - i - 1) * bucketSec);
    const start = Math.max(0, bucketStart);
    const end = Math.max(start + 1, Math.min(newestIdx, bucketEnd));
    const bucket = source.slice(start, end);
    result.push(bucket.length ? bucket.reduce((sum, value) => sum + value, 0) / bucket.length : 0);
  }

  return movingAverage(result, smoothWindow);
}

export function sampleAtOffset(samples: readonly number[], offsetSec: number): number {
  if (!samples.length) return 0;
  const idx = Math.max(0, samples.length - 1 - offsetSec);
  return samples[idx] ?? 0;
}

export function formatRatePercentDelta(
  current: number,
  previous: number,
): { text: string; tone: StatDeltaTone } {
  if (current === 0 && previous === 0) return { text: '0%', tone: 'neutral' };
  if (previous <= 0 && current > 0) return { text: '—', tone: 'neutral' };
  if (previous <= 0) return { text: '0%', tone: 'neutral' };

  const pct = Math.round(((current - previous) / previous) * 100);
  if (pct === 0) return { text: '0%', tone: 'neutral' };

  return {
    text: `${pct > 0 ? '+' : ''}${pct}%`,
    tone: pct > 0 ? 'ok' : 'bad',
  };
}

export function formatCountDelta(
  current: number,
  previous: number,
  moreIsBad = false,
): { text: string; tone: StatDeltaTone } {
  const delta = Math.round(current - previous);
  if (delta === 0) return { text: '0', tone: 'neutral' };

  const sign = delta > 0 ? '+' : '';
  const tone: StatDeltaTone = moreIsBad ? (delta > 0 ? 'bad' : 'ok') : delta > 0 ? 'ok' : 'bad';

  return { text: `${sign}${delta}`, tone };
}

export function statDeltaColor(tone: StatDeltaTone): string {
  if (tone === 'ok') return 'var(--ok)';
  if (tone === 'bad') return 'var(--bad)';
  return 'var(--t3)';
}

// --- Dashboard stat strip -------------------------------------------------

/** Daemon activity buckets are 30 minutes wide. */
export const ACTIVITY_BUCKET_SEC = 30 * 60;
const DAY_SEC = 24 * 60 * 60;
const HOUR_SEC = 60 * 60;

interface TrafficBucket {
  bucketStart: number;
  bytesSent: number;
  bytesReceived: number;
  blockedCount: number;
}

/**
 * Mean bytes/second for one direction over the trailing window, from the
 * daemon's activity buckets. The span is clamped to the history that exists,
 * so a daemon installed an hour ago averages over that hour. Returns `null`
 * until at least one full bucket of history is available.
 */
export function averageRateOverWindow(
  buckets: readonly TrafficBucket[],
  field: 'bytesSent' | 'bytesReceived',
  nowMs: number,
  windowSec = DAY_SEC,
): number | null {
  const nowSec = nowMs / 1000;
  const windowStart = nowSec - windowSec;
  let earliest = Infinity;
  let total = 0;
  for (const bucket of buckets) {
    if (bucket.bucketStart + ACTIVITY_BUCKET_SEC <= windowStart || bucket.bucketStart > nowSec) {
      continue;
    }
    earliest = Math.min(earliest, bucket.bucketStart);
    total += bucket[field];
  }
  if (!Number.isFinite(earliest)) return null;
  const span = nowSec - Math.max(windowStart, earliest);
  if (span < ACTIVITY_BUCKET_SEC) return null;
  return total / span;
}

export interface AverageDelta {
  direction: 'up' | 'down' | 'flat';
  /** Whole-number magnitude of the change, in percent. */
  percent: number;
}

/**
 * Compact magnitude for a delta: a percentage up to +200%, then a multiplier
 * (4.3×) so a burst against a quiet day stays readable; capped at 100×+.
 */
export function formatAverageDelta(delta: AverageDelta): string {
  if (delta.direction !== 'up' || delta.percent <= 200) return `${delta.percent}%`;
  const ratio = 1 + delta.percent / 100;
  if (ratio >= 100) return '100×+';
  return `${ratio >= 10 ? Math.round(ratio) : ratio.toFixed(1)}×`;
}

/** How the current rate compares with its average; `null` with nothing to compare. */
export function averageDelta(current: number, average: number | null): AverageDelta | null {
  if (average == null || !(average > 0) || !Number.isFinite(current)) return null;
  const percent = Math.round(((current - average) / average) * 100);
  if (percent === 0) return { direction: 'flat', percent: 0 };
  return { direction: percent > 0 ? 'up' : 'down', percent: Math.abs(percent) };
}

/**
 * Blocked connections in the most recent hour, aligned to whole buckets so the
 * count is exact: the returned `sinceSec` is the start of the oldest bucket
 * counted (between 30 and 60 minutes ago).
 */
export function blockedSince(
  buckets: readonly TrafficBucket[],
  nowMs: number,
): { count: number; sinceSec: number } {
  const nowSec = nowMs / 1000;
  const sinceSec = Math.ceil((nowSec - HOUR_SEC) / ACTIVITY_BUCKET_SEC) * ACTIVITY_BUCKET_SEC;
  let count = 0;
  for (const bucket of buckets) {
    if (bucket.bucketStart >= sinceSec && bucket.bucketStart <= nowSec) {
      count += bucket.blockedCount;
    }
  }
  return { count, sinceSec };
}

/** Blocked counts per hour for the trailing `hours`, oldest first; the last entry is the current hour. */
export function hourlyBlockedSeries(
  buckets: readonly TrafficBucket[],
  nowMs: number,
  hours = 12,
): number[] {
  const nowSec = nowMs / 1000;
  const currentHourStart = Math.floor(nowSec / HOUR_SEC) * HOUR_SEC;
  const firstHourStart = currentHourStart - (hours - 1) * HOUR_SEC;
  const series = new Array<number>(hours).fill(0);
  for (const bucket of buckets) {
    if (bucket.bucketStart < firstHourStart || bucket.bucketStart > nowSec) continue;
    const index = Math.floor((bucket.bucketStart - firstHourStart) / HOUR_SEC);
    if (index >= 0 && index < hours) series[index]! += bucket.blockedCount;
  }
  return series;
}
