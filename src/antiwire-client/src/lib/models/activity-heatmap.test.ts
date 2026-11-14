import { describe, expect, it } from 'bun:test';
import {
  ACTIVITY_BUCKET_SECONDS,
  ACTIVITY_BUCKETS_PER_DAY,
  ACTIVITY_DAYS,
  ACTIVITY_INTERVAL_SECONDS,
  ACTIVITY_WEEK_SECONDS,
  MAX_ACTIVITY_HISTORY_WEEKS,
  activityWeekOffsetForDate,
  activityWeekOffsetForDateKey,
  activityWeekRangeSec,
  activityWeekStartSecForOffset,
  buildActivityHeatmapRows,
  buildActivityHeatmapRowsForWeek,
  activityLevel,
  ACTIVITY_LEVELS,
  cellBackground,
  formatActivityWeekLabel,
  formatBucketTimeRange,
  inactiveCellBackground,
  INACTIVE_CELL_T1_PERCENT,
  isInactiveCell,
  startOfLocalWeekMondayMs,
  sumActivityBytesForLocalDay,
} from './activity-heatmap';

/** The heatmap tokens of the two themes, as defined in app.css. */
const THEME_TOKENS = [
  { name: 'obsidian', activityInactive: '#1d1e23', t1: '#ececef', p1: '#15161b' },
  { name: 'porcelain', activityInactive: '#e2e1dc', t1: '#1f1e1c', p1: '#f8f7f5' },
];

describe('activity-heatmap', () => {
  it('builds seven rows with forty-eight slots each', () => {
    const rows = buildActivityHeatmapRows([], Date.UTC(2026, 7, 2, 15, 0, 0));
    expect(rows).toHaveLength(ACTIVITY_DAYS);
    expect(rows.every((row) => row.cells.length === ACTIVITY_BUCKETS_PER_DAY)).toBe(true);
    expect(rows.at(-1)?.isToday).toBe(true);
  });

  it('places bucket counts into the matching local slot', () => {
    const now = Date.UTC(2026, 7, 2, 12, 0, 0);
    const local = new Date(now);
    const bucketStart = Math.floor(
      new Date(local.getFullYear(), local.getMonth(), local.getDate(), 9, 30, 0).getTime() / 1000,
    );
    const rows = buildActivityHeatmapRows(
      [{ bucketStart, eventCount: 4, bytesSent: 50, bytesReceived: 120, blockedCount: 0 }],
      now,
    );
    const today = rows.at(-1);
    const slot = Math.floor((9 * 60 + 30) / (ACTIVITY_BUCKET_SECONDS / 60));
    expect(today?.cells[slot]?.eventCount).toBe(4);
    expect(today?.cells[slot]?.intensity).toBeGreaterThan(0);
  });

  it('aggregates bytes into the matching local slot', () => {
    const now = Date.UTC(2026, 7, 2, 12, 0, 0);
    const local = new Date(now);
    const bucketStart = Math.floor(
      new Date(local.getFullYear(), local.getMonth(), local.getDate(), 9, 30, 0).getTime() / 1000,
    );
    const rows = buildActivityHeatmapRows(
      [{ bucketStart, eventCount: 2, bytesSent: 100, bytesReceived: 250, blockedCount: 0 }],
      now,
    );
    const today = rows.at(-1);
    const slot = Math.floor((9 * 60 + 30) / (ACTIVITY_BUCKET_SECONDS / 60));
    expect(today?.cells[slot]?.bytesSent).toBe(100);
    expect(today?.cells[slot]?.bytesReceived).toBe(250);
  });

  it('sums only the current local day', () => {
    const now = Date.UTC(2026, 7, 2, 12, 0, 0);
    const local = new Date(now);
    const today = Math.floor(
      new Date(local.getFullYear(), local.getMonth(), local.getDate(), 9, 30, 0).getTime() / 1000,
    );
    const yesterday = today - 86_400;
    const tomorrow = today + 86_400;

    expect(
      sumActivityBytesForLocalDay(
        [
          {
            bucketStart: yesterday,
            eventCount: 1,
            bytesSent: 10,
            bytesReceived: 20,
            blockedCount: 0,
          },
          {
            bucketStart: today,
            eventCount: 1,
            bytesSent: 100,
            bytesReceived: 250,
            blockedCount: 0,
          },
          {
            bucketStart: tomorrow,
            eventCount: 1,
            bytesSent: 1_000,
            bytesReceived: 2_000,
            blockedCount: 0,
          },
        ],
        now,
      ),
    ).toBe(350);
  });

  it('formats bucket time ranges with date and clock times', () => {
    const label = formatBucketTimeRange(1_756_838_400);
    expect(label).toContain('–');
  });

  it('returns a gray background for inactive cells', () => {
    const fill = inactiveCellBackground();
    expect(fill).toContain('--t1');
    expect(fill).toContain('--activity-inactive');
    expect(fill).toContain(`${INACTIVE_CELL_T1_PERCENT}%`);
    expect(cellBackground(0, 0, 0)).toBe(fill);
    expect(cellBackground(0.8, 0, 0)).toBe(fill);
    expect(isInactiveCell(0, 0)).toBe(true);
    expect(isInactiveCell(1, 0)).toBe(false);
  });

  it('keeps zero-activity buckets in the heatmap grid', () => {
    const now = Date.UTC(2026, 7, 2, 12, 0, 0);
    const local = new Date(now);
    const bucketStart = Math.floor(
      new Date(local.getFullYear(), local.getMonth(), local.getDate(), 9, 30, 0).getTime() / 1000,
    );
    const rows = buildActivityHeatmapRows(
      [{ bucketStart, eventCount: 4, bytesSent: 50, bytesReceived: 120, blockedCount: 0 }],
      now,
    );

    const cells = rows.flatMap((row) => row.cells);
    expect(rows).toHaveLength(ACTIVITY_DAYS);
    expect(cells).toHaveLength(ACTIVITY_DAYS * ACTIVITY_BUCKETS_PER_DAY);

    const emptyCells = cells.filter((cell) => cell.eventCount === 0);
    expect(emptyCells).toHaveLength(ACTIVITY_DAYS * ACTIVITY_BUCKETS_PER_DAY - 1);
    expect(emptyCells.every((cell) => isInactiveCell(cell.bytesSent, cell.bytesReceived))).toBe(
      true,
    );
    expect(
      emptyCells.every(
        (cell) =>
          cellBackground(cell.intensity, cell.bytesSent, cell.bytesReceived) ===
          inactiveCellBackground(),
      ),
    ).toBe(true);
  });

  it('keeps inactive cell fills distinct from the panel in both themes', () => {
    for (const palette of THEME_TOKENS) {
      const fill = mixOklab(palette.activityInactive, palette.t1, INACTIVE_CELL_T1_PERCENT / 100);
      expect(contrastRatio(fill, palette.p1)).toBeGreaterThan(1.15);
    }
  });

  it('returns accent mix for cells with traffic', () => {
    expect(cellBackground(0.5, 100, 0)).toContain('var(--heat-up)');
    expect(cellBackground(0.5, 0, 250)).toContain('var(--heat-down)');
    expect(cellBackground(0.5, 100, 100)).toContain('var(--heat-down)');
    expect(cellBackground(0.5, 300, 100)).toContain('var(--heat-up)');
    expect(cellBackground(0.5, 0, 250)).toContain('in oklch');
  });

  it('steps busy cells through five stages', () => {
    expect(activityLevel(0)).toBe(0);
    expect(activityLevel(0.01)).toBe(1);
    expect(activityLevel(0.2)).toBe(1);
    expect(activityLevel(0.21)).toBe(2);
    expect(activityLevel(0.6)).toBe(3);
    expect(activityLevel(1)).toBe(ACTIVITY_LEVELS);
    expect(activityLevel(1.4)).toBe(ACTIVITY_LEVELS);
    expect(cellBackground(0.1, 0, 1)).toContain('var(--heat-1)');
    expect(cellBackground(1, 0, 1)).toContain('var(--heat-5)');
  });

  it('grays out slots with events but zero bytes', () => {
    const now = Date.UTC(2026, 7, 2, 12, 0, 0);
    const local = new Date(now);
    const bucketStart = Math.floor(
      new Date(local.getFullYear(), local.getMonth(), local.getDate(), 14, 0, 0).getTime() / 1000,
    );
    const rows = buildActivityHeatmapRows(
      [{ bucketStart, eventCount: 3, bytesSent: 0, bytesReceived: 0, blockedCount: 1 }],
      now,
    );
    const today = rows.at(-1);
    const slot = Math.floor((14 * 60) / (ACTIVITY_BUCKET_SECONDS / 60));
    expect(today?.cells[slot]?.eventCount).toBe(3);
    expect(today?.cells[slot]?.intensity).toBe(0);
  });

  it('anchors weekly history on local Monday with a 7-day range', () => {
    // Wednesday 2026-08-05 noon local.
    const wednesday = new Date(2026, 7, 5, 12, 0, 0).getTime();
    const mondayMs = startOfLocalWeekMondayMs(wednesday);
    const monday = new Date(mondayMs);
    expect(monday.getDay()).toBe(1);
    expect(monday.getHours()).toBe(0);

    const weekStartSec = activityWeekStartSecForOffset(wednesday, 0);
    expect(weekStartSec).toBe(Math.floor(mondayMs / 1000));
    const prevStartSec = activityWeekStartSecForOffset(wednesday, -1);
    expect(weekStartSec - prevStartSec).toBe(ACTIVITY_WEEK_SECONDS);
    // Future offsets clamp to the current week.
    expect(activityWeekStartSecForOffset(wednesday, 3)).toBe(weekStartSec);

    const { since, until } = activityWeekRangeSec(weekStartSec);
    expect(until - since).toBe(ACTIVITY_WEEK_SECONDS);
    expect(formatActivityWeekLabel(weekStartSec)).toContain('–');
  });

  it('builds the week view Monday-first with identical slot mapping', () => {
    const wednesday = new Date(2026, 7, 5, 12, 0, 0).getTime();
    const weekStartMs = startOfLocalWeekMondayMs(wednesday);
    const mondayBucket = Math.floor(new Date(2026, 7, 3, 9, 30, 0).getTime() / 1000);
    const rows = buildActivityHeatmapRowsForWeek(
      [
        {
          bucketStart: mondayBucket,
          eventCount: 4,
          bytesSent: 50,
          bytesReceived: 120,
          blockedCount: 0,
        },
      ],
      weekStartMs,
      wednesday,
    );
    expect(rows).toHaveLength(ACTIVITY_DAYS);
    const slot = Math.floor((9 * 60 + 30) / (ACTIVITY_BUCKET_SECONDS / 60));
    expect(rows[0]?.cells[slot]?.eventCount).toBe(4);
    expect(rows[0]?.cells[slot]?.intensity).toBeGreaterThan(0);
  });

  it('maps dates to week-pager offsets for the date selector', () => {
    // Wednesday 2026-08-05 noon local; its week is offset 0.
    const wednesday = new Date(2026, 7, 5, 12, 0, 0).getTime();
    expect(activityWeekOffsetForDate(wednesday, wednesday)).toBe(0);
    // Sunday of the same Mon–Sun week stays on offset 0.
    expect(activityWeekOffsetForDate(new Date(2026, 7, 9, 23, 30, 0).getTime(), wednesday)).toBe(0);
    // Monday of the previous week steps back one.
    expect(activityWeekOffsetForDate(new Date(2026, 6, 27, 12, 0, 0).getTime(), wednesday)).toBe(
      -1,
    );
    // Future dates clamp to the current week.
    expect(activityWeekOffsetForDate(new Date(2026, 7, 12, 12, 0, 0).getTime(), wednesday)).toBe(0);
    // Non-finite inputs fall back to the current week.
    expect(activityWeekOffsetForDate(Number.NaN, wednesday)).toBe(0);

    expect(activityWeekOffsetForDateKey('2026-08-05', wednesday)).toBe(0);
    expect(activityWeekOffsetForDateKey('2026-08-09', wednesday)).toBe(0);
    expect(activityWeekOffsetForDateKey('2026-07-27', wednesday)).toBe(-1);
    expect(activityWeekOffsetForDateKey('not-a-date', wednesday)).toBeNull();
    expect(activityWeekOffsetForDateKey('2026-02-30', wednesday)).toBeNull();
  });

  it('clamps the date selector to retained history', () => {
    const wednesday = new Date(2026, 7, 5, 12, 0, 0).getTime();
    expect(activityWeekOffsetForDate(new Date(1900, 0, 1, 12, 0, 0).getTime(), wednesday)).toBe(
      -MAX_ACTIVITY_HISTORY_WEEKS,
    );
    expect(activityWeekOffsetForDateKey('1900-01-01', wednesday)).toBe(-MAX_ACTIVITY_HISTORY_WEEKS);
  });

  it('aggregates base buckets into hourly slots', () => {
    const wednesday = new Date(2026, 7, 5, 12, 0, 0).getTime();
    const weekStartMs = startOfLocalWeekMondayMs(wednesday);
    const at = (dayOffset: number, hour: number, minute: number) =>
      Math.floor((weekStartMs + ((dayOffset * 24 + hour) * 60 + minute) * 60_000) / 1000);
    const buckets = [
      {
        bucketStart: at(0, 9, 0),
        eventCount: 2,
        bytesSent: 100,
        bytesReceived: 200,
        blockedCount: 0,
      },
      {
        bucketStart: at(0, 9, 30),
        eventCount: 4,
        bytesSent: 50,
        bytesReceived: 60,
        blockedCount: 0,
      },
      {
        bucketStart: at(0, 10, 0),
        eventCount: 1,
        bytesSent: 10,
        bytesReceived: 10,
        blockedCount: 0,
      },
      { bucketStart: at(1, 0, 0), eventCount: 3, bytesSent: 5, bytesReceived: 5, blockedCount: 0 },
    ];
    const rows = buildActivityHeatmapRowsForWeek(
      buckets,
      weekStartMs,
      wednesday,
      ACTIVITY_INTERVAL_SECONDS['1h'],
    );
    expect(rows).toHaveLength(ACTIVITY_DAYS);
    expect(rows.every((row) => row.cells.length === 24)).toBe(true);

    const monday = rows[0];
    expect(monday?.cells[9]?.eventCount).toBe(6);
    expect(monday?.cells[9]?.bytesSent).toBe(150);
    expect(monday?.cells[9]?.bytesReceived).toBe(260);
    expect(monday?.cells[9]?.bucketSeconds).toBe(3_600);
    expect(monday?.cells[9]?.intensity).toBe(1);
    expect(monday?.cells[10]?.eventCount).toBe(1);
    expect(monday?.cells[10]?.intensity).toBeLessThan(1);
    expect(rows[1]?.cells[0]?.eventCount).toBe(3);
  });

  it('aggregates base buckets into 4-hour and daily slots', () => {
    const wednesday = new Date(2026, 7, 5, 12, 0, 0).getTime();
    const weekStartMs = startOfLocalWeekMondayMs(wednesday);
    const at = (dayOffset: number, hour: number, minute: number) =>
      Math.floor((weekStartMs + ((dayOffset * 24 + hour) * 60 + minute) * 60_000) / 1000);
    const buckets = [
      {
        bucketStart: at(0, 9, 0),
        eventCount: 2,
        bytesSent: 100,
        bytesReceived: 200,
        blockedCount: 0,
      },
      {
        bucketStart: at(0, 9, 30),
        eventCount: 4,
        bytesSent: 50,
        bytesReceived: 60,
        blockedCount: 0,
      },
      {
        bucketStart: at(0, 10, 0),
        eventCount: 1,
        bytesSent: 10,
        bytesReceived: 10,
        blockedCount: 0,
      },
      { bucketStart: at(1, 0, 0), eventCount: 3, bytesSent: 5, bytesReceived: 5, blockedCount: 0 },
    ];

    const fourHour = buildActivityHeatmapRowsForWeek(
      buckets,
      weekStartMs,
      wednesday,
      ACTIVITY_INTERVAL_SECONDS['4h'],
    );
    expect(fourHour.every((row) => row.cells.length === 6)).toBe(true);
    expect(fourHour[0]?.cells[2]?.eventCount).toBe(7);
    expect(fourHour[0]?.cells[2]?.bytesSent).toBe(160);
    expect(fourHour[0]?.cells[2]?.bytesReceived).toBe(270);
    expect(fourHour[0]?.cells[2]?.bucketSeconds).toBe(14_400);
    expect(fourHour[1]?.cells[0]?.eventCount).toBe(3);

    const daily = buildActivityHeatmapRowsForWeek(
      buckets,
      weekStartMs,
      wednesday,
      ACTIVITY_INTERVAL_SECONDS['1d'],
    );
    expect(daily).toHaveLength(ACTIVITY_DAYS);
    expect(daily.every((row) => row.cells.length === 1)).toBe(true);
    expect(daily[0]?.cells[0]?.eventCount).toBe(7);
    expect(daily[0]?.cells[0]?.bytesSent).toBe(160);
    expect(daily[0]?.cells[0]?.bytesReceived).toBe(270);
    expect(daily[0]?.cells[0]?.bucketSeconds).toBe(86_400);
    expect(daily[1]?.cells[0]?.eventCount).toBe(3);
    expect(daily[2]?.cells[0]?.eventCount).toBe(0);
    expect(daily[2]?.cells[0]?.intensity).toBe(0);
  });

  it('formats bucket ranges with the cell duration', () => {
    const start = 1_756_838_400;
    expect(formatBucketTimeRange(start, 3_600)).not.toBe(formatBucketTimeRange(start, 1_800));
    expect(formatBucketTimeRange(start)).toBe(formatBucketTimeRange(start, 1_800));
  });
});

function parseHex(value: string): { r: number; g: number; b: number } {
  const raw = value.replace('#', '');
  const n = parseInt(raw, 16);
  return { r: (n >> 16) & 255, g: (n >> 8) & 255, b: n & 255 };
}

type Rgb = { r: number; g: number; b: number };
type Oklab = { l: number; a: number; b: number };

function srgbToLinear(value: number): number {
  const channel = value / 255;
  return channel <= 0.04045 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4;
}

function linearToSrgb(value: number): number {
  const channel =
    value <= 0.0031308 ? value * 12.92 : 1.055 * Math.max(0, value) ** (1 / 2.4) - 0.055;
  return Math.max(0, Math.min(255, channel * 255));
}

function rgbToOklab({ r, g, b }: Rgb): Oklab {
  const red = srgbToLinear(r);
  const green = srgbToLinear(g);
  const blue = srgbToLinear(b);
  const l = Math.cbrt(0.4122214708 * red + 0.5363325363 * green + 0.0514459929 * blue);
  const m = Math.cbrt(0.2119034982 * red + 0.6806995451 * green + 0.1073969566 * blue);
  const s = Math.cbrt(0.0883024619 * red + 0.2817188376 * green + 0.6299787005 * blue);
  return {
    l: 0.2104542553 * l + 0.793617785 * m - 0.0040720468 * s,
    a: 1.9779984951 * l - 2.428592205 * m + 0.4505937099 * s,
    b: 0.0259040371 * l + 0.7827717662 * m - 0.808675766 * s,
  };
}

function oklabToRgb({ l, a, b }: Oklab): Rgb {
  const lRoot = l + 0.3963377774 * a + 0.2158037573 * b;
  const mRoot = l - 0.1055613458 * a - 0.0638541728 * b;
  const sRoot = l - 0.0894841775 * a - 1.291485548 * b;
  const lLinear = lRoot ** 3;
  const mLinear = mRoot ** 3;
  const sLinear = sRoot ** 3;
  return {
    r: linearToSrgb(4.0767416621 * lLinear - 3.3077115913 * mLinear + 0.2309699292 * sLinear),
    g: linearToSrgb(-1.2684380046 * lLinear + 2.6097574011 * mLinear - 0.3413193965 * sLinear),
    b: linearToSrgb(-0.0041960863 * lLinear - 0.7034186147 * mLinear + 1.707614701 * sLinear),
  };
}

function mixOklab(from: string, to: string, t: number): Rgb {
  const start = rgbToOklab(parseHex(from));
  const end = rgbToOklab(parseHex(to));
  return oklabToRgb({
    l: start.l * (1 - t) + end.l * t,
    a: start.a * (1 - t) + end.a * t,
    b: start.b * (1 - t) + end.b * t,
  });
}

function channelLuminance(value: number): number {
  const s = value / 255;
  return s <= 0.04045 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
}

function relativeLuminance({ r, g, b }: { r: number; g: number; b: number }): number {
  return 0.2126 * channelLuminance(r) + 0.7152 * channelLuminance(g) + 0.0722 * channelLuminance(b);
}

function contrastRatio(a: { r: number; g: number; b: number }, b: string): number {
  const l1 = relativeLuminance(a);
  const l2 = relativeLuminance(parseHex(b));
  const lighter = Math.max(l1, l2);
  const darker = Math.min(l1, l2);
  return (lighter + 0.05) / (darker + 0.05);
}
