export const ACTIVITY_BUCKET_SECONDS = 30 * 60;
export const ACTIVITY_BUCKETS_PER_DAY = 48;
export const ACTIVITY_DAYS = 7;
/** One calendar week in seconds; history pages by this stride. */
export const ACTIVITY_WEEK_SECONDS = 7 * 86_400;
/** Hard cap on week-pager depth so unlimited retention cannot page forever. */
export const MAX_ACTIVITY_HISTORY_WEEKS = 52;

/**
 * Heatmap bucket granularity. Everything coarser than the daemon's native
 * 30-minute buckets is aggregated client-side by summing whole base buckets,
 * so no backend changes are needed to offer larger intervals.
 */
export type ActivityInterval = '30m' | '1h' | '4h' | '1d';
export const ACTIVITY_INTERVALS: ActivityInterval[] = ['30m', '1h', '4h', '1d'];
export const ACTIVITY_INTERVAL_SECONDS: Record<ActivityInterval, number> = {
  '30m': 30 * 60,
  '1h': 60 * 60,
  '4h': 4 * 60 * 60,
  '1d': 24 * 60 * 60,
};

export interface ActivityBucket {
  bucketStart: number;
  eventCount: number;
  bytesSent: number;
  bytesReceived: number;
  blockedCount: number;
}

export interface ActivityHeatmapCell {
  bucketStart: number;
  /** Slot length in seconds; larger than the base 30 minutes when aggregated. */
  bucketSeconds: number;
  intensity: number;
  eventCount: number;
  bytesSent: number;
  bytesReceived: number;
}

export interface ActivityHeatmapRow {
  label: string;
  isToday: boolean;
  cells: ActivityHeatmapCell[];
}

function startOfLocalDay(date: Date): Date {
  return new Date(date.getFullYear(), date.getMonth(), date.getDate());
}

function localDayKey(date: Date): string {
  return `${date.getFullYear()}-${date.getMonth()}-${date.getDate()}`;
}

export function sumActivityBytesForLocalDay(
  buckets: ActivityBucket[],
  nowMs: number = Date.now(),
): number {
  const todayKey = localDayKey(new Date(nowMs));
  return buckets.reduce((total, bucket) => {
    const bucketDate = new Date(bucket.bucketStart * 1000);
    if (localDayKey(bucketDate) !== todayKey) return total;
    return total + bucket.bytesSent + bucket.bytesReceived;
  }, 0);
}

// Module-scope formatters: constructing Intl.DateTimeFormat costs ~ms each;
// the old code built one per buildActivityHeatmapRows call plus three per
// formatBucketTimeRange call (~336 cells per heatmap render).
const dayFormatter = new Intl.DateTimeFormat(undefined, { weekday: 'short' });
const bucketDateFmt = new Intl.DateTimeFormat(undefined, {
  weekday: 'short',
  month: 'short',
  day: 'numeric',
});
const bucketTimeFmt = new Intl.DateTimeFormat(undefined, {
  hour: '2-digit',
  minute: '2-digit',
});
const weekDayFmt = new Intl.DateTimeFormat(undefined, { month: 'short', day: 'numeric' });
const weekDayYearFmt = new Intl.DateTimeFormat(undefined, {
  month: 'short',
  day: 'numeric',
  year: 'numeric',
});
function bucketLocalSlot(
  bucketStartSec: number,
  intervalSec: number,
  slotsPerDay: number,
): { dayKey: string; slot: number } {
  const date = new Date(bucketStartSec * 1000);
  const minutes = date.getHours() * 60 + date.getMinutes();
  // Whole-day slots always resolve to slot 0; anything finer nests inside
  // the day because every offered interval divides 24 hours evenly.
  const slot = Math.min(slotsPerDay - 1, Math.floor(minutes / (intervalSec / 60)));
  return { dayKey: localDayKey(date), slot };
}

export function buildActivityHeatmapRows(
  buckets: ActivityBucket[],
  nowMs: number = Date.now(),
  intervalSec: number = ACTIVITY_BUCKET_SECONDS,
): ActivityHeatmapRow[] {
  const now = new Date(nowMs);
  const todayStart = startOfLocalDay(now);
  const dayStarts: Date[] = [];
  for (let offset = ACTIVITY_DAYS - 1; offset >= 0; offset -= 1) {
    dayStarts.push(new Date(todayStart.getTime() - offset * 86_400_000));
  }

  return buildRows(dayStarts, buckets, now, intervalSec);
}

/** Monday (local) of the week containing `nowMs`, at 00:00. */
export function startOfLocalWeekMondayMs(nowMs: number = Date.now()): number {
  const now = new Date(nowMs);
  const mondayOffset = (now.getDay() + 6) % 7;
  return startOfLocalDay(now).getTime() - mondayOffset * 86_400_000;
}

/**
 * Unix seconds for the Monday 00:00 (local) of the week `offsetWeeks` before
 * the current week. `0` is the current week; negative values page into
 * retained history. Positive offsets are clamped to the current week so the
 * pager can never address the future.
 */
export function activityWeekStartSecForOffset(nowMs: number = Date.now(), offsetWeeks = 0): number {
  const requested = Math.trunc(offsetWeeks);
  const clamped = Number.isFinite(requested) ? Math.min(0, requested) : 0;
  return Math.floor(
    (startOfLocalWeekMondayMs(nowMs) + clamped * ACTIVITY_WEEK_SECONDS * 1000) / 1000,
  );
}

/** Inclusive-`since` / exclusive-`until` range (unix seconds) for a week. */
export function activityWeekRangeSec(weekStartSec: number): { since: number; until: number } {
  return { since: weekStartSec, until: weekStartSec + ACTIVITY_WEEK_SECONDS };
}

/**
 * Week-pager offset for the calendar week (Mon–Sun local) containing
 * `targetMs`. Positive (future) results clamp to the current week, matching
 * `activityWeekStartSecForOffset`, and depth clamps to retained history.
 */
export function activityWeekOffsetForDate(targetMs: number, nowMs: number = Date.now()): number {
  if (!Number.isFinite(targetMs) || !Number.isFinite(nowMs)) return 0;
  const currentMonday = startOfLocalWeekMondayMs(nowMs);
  const targetMonday = startOfLocalWeekMondayMs(targetMs);
  const raw = Math.round((targetMonday - currentMonday) / (ACTIVITY_WEEK_SECONDS * 1000));
  if (!Number.isFinite(raw)) return 0;
  return Math.max(-MAX_ACTIVITY_HISTORY_WEEKS, Math.min(0, raw));
}

const ACTIVITY_DATE_KEY = /^(\d{4})-(\d{2})-(\d{2})$/;

/**
 * Week-pager offset for a `YYYY-MM-DD` date key, or `null` when the key is
 * not a real calendar date. Parsed at local noon so DST midnights cannot
 * shift the resolved week.
 */
export function activityWeekOffsetForDateKey(
  dateKey: string,
  nowMs: number = Date.now(),
): number | null {
  const match = ACTIVITY_DATE_KEY.exec(dateKey);
  if (!match) return null;
  const year = Number(match[1]);
  const month = Number(match[2]) - 1;
  const day = Number(match[3]);
  const date = new Date(year, month, day, 12);
  if (date.getFullYear() !== year || date.getMonth() !== month || date.getDate() !== day) {
    return null;
  }
  return activityWeekOffsetForDate(date.getTime(), nowMs);
}

/** Localized "Mar 3 – Mar 9" label for a week starting Monday. */
export function formatActivityWeekLabel(weekStartSec: number): string {
  const start = new Date(weekStartSec * 1000);
  const end = new Date((weekStartSec + 6 * 86_400) * 1000);
  if (start.getFullYear() !== end.getFullYear()) {
    return `${weekDayYearFmt.format(start)} – ${weekDayYearFmt.format(end)}`;
  }
  if (start.getFullYear() !== new Date().getFullYear()) {
    return `${weekDayFmt.format(start)} – ${weekDayFmt.format(end)}, ${start.getFullYear()}`;
  }
  return `${weekDayFmt.format(start)} – ${weekDayFmt.format(end)}`;
}

/**
 * Weekly history view: seven rows starting at the given local Monday, rather
 * than the rolling last-seven-days window. Bucket aggregation is identical;
 * only the day window changes.
 */
export function buildActivityHeatmapRowsForWeek(
  buckets: ActivityBucket[],
  weekStartMs: number,
  nowMs: number = Date.now(),
  intervalSec: number = ACTIVITY_BUCKET_SECONDS,
): ActivityHeatmapRow[] {
  const dayStarts: Date[] = [];
  for (let offset = 0; offset < ACTIVITY_DAYS; offset += 1) {
    dayStarts.push(new Date(weekStartMs + offset * 86_400_000));
  }
  return buildRows(dayStarts, buckets, new Date(nowMs), intervalSec);
}

function buildRows(
  dayStarts: Date[],
  buckets: ActivityBucket[],
  now: Date,
  intervalSec: number,
): ActivityHeatmapRow[] {
  // Every offered interval divides the day evenly (48/24/6/1 slots).
  const slotsPerDay = Math.max(1, Math.round(86_400 / intervalSec));
  const bucketsBySlot = new Map<
    string,
    { eventCount: number; bytesSent: number; bytesReceived: number }
  >();
  let maxCount = 0;
  for (const bucket of buckets) {
    const { dayKey, slot } = bucketLocalSlot(bucket.bucketStart, intervalSec, slotsPerDay);
    const key = `${dayKey}:${slot}`;
    const current = bucketsBySlot.get(key) ?? {
      eventCount: 0,
      bytesSent: 0,
      bytesReceived: 0,
    };
    current.eventCount += bucket.eventCount;
    current.bytesSent += bucket.bytesSent;
    current.bytesReceived += bucket.bytesReceived;
    bucketsBySlot.set(key, current);
    maxCount = Math.max(maxCount, current.eventCount);
  }

  return dayStarts.map((dayStart) => {
    const dayKey = localDayKey(dayStart);
    const cells: ActivityHeatmapCell[] = [];
    for (let slot = 0; slot < slotsPerDay; slot += 1) {
      const slotData = bucketsBySlot.get(`${dayKey}:${slot}`) ?? {
        eventCount: 0,
        bytesSent: 0,
        bytesReceived: 0,
      };
      const { eventCount, bytesSent, bytesReceived } = slotData;
      const inactive = isInactiveCell(bytesSent, bytesReceived);
      const intensity =
        inactive || eventCount === 0 || maxCount === 0 ? 0 : Math.pow(eventCount / maxCount, 0.72);
      const bucketStart = Math.floor(dayStart.getTime() / 1000) + slot * intervalSec;
      cells.push({
        bucketStart,
        bucketSeconds: intervalSec,
        intensity,
        eventCount,
        bytesSent,
        bytesReceived,
      });
    }
    return {
      label: dayFormatter.format(dayStart).toUpperCase(),
      isToday: dayKey === localDayKey(now),
      cells,
    };
  });
}

export function formatBucketTimeRange(
  bucketStart: number,
  bucketSeconds: number = ACTIVITY_BUCKET_SECONDS,
): string {
  const start = new Date(bucketStart * 1000);
  const end = new Date((bucketStart + bucketSeconds) * 1000);
  return `${bucketDateFmt.format(start)} · ${bucketTimeFmt.format(start)} – ${bucketTimeFmt.format(end)}`;
}

export function isInactiveCell(bytesSent: number, bytesReceived: number): boolean {
  return bytesSent === 0 && bytesReceived === 0;
}

/** Share of `--t1` mixed into `--activity-inactive` so empty slots stay visible on `--p1`. */
export const INACTIVE_CELL_T1_PERCENT = 18;

export function inactiveCellBackground(): string {
  return `color-mix(in oklab, var(--t1) ${INACTIVE_CELL_T1_PERCENT}%, var(--activity-inactive))`;
}

/** Number of distinct shades a cell with traffic can take. */
export const ACTIVITY_LEVELS = 5;

/** Map a 0..1 intensity to a stage from 1 to ACTIVITY_LEVELS; 0 means no traffic. */
export function activityLevel(intensity: number): number {
  if (!(intensity > 0)) return 0;
  return Math.min(ACTIVITY_LEVELS, Math.ceil(intensity * ACTIVITY_LEVELS));
}

/**
 * Busy slots step through `--heat-1`..`--heat-5` (per-theme shares of the
 * accent, see app.css). Mixing in oklch keeps the accent's chroma, so the
 * quiet stages read as dim accent rather than grey, and the top stage is the
 * accent itself. Upload-heavy slots use the secondary accent.
 */
export function cellBackground(intensity: number, bytesSent = 0, bytesReceived = 0): string {
  const level = activityLevel(intensity);
  if (isInactiveCell(bytesSent, bytesReceived) || level === 0) {
    return inactiveCellBackground();
  }
  const accent = bytesSent > bytesReceived ? 'var(--heat-up)' : 'var(--heat-down)';
  return `color-mix(in oklch, ${accent} var(--heat-${level}), var(--p1))`;
}
