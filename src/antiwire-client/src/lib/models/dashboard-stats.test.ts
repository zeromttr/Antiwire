import { describe, expect, test } from 'bun:test';
import {
  ACTIVITY_BUCKET_SEC,
  averageDelta,
  formatAverageDelta,
  averageRateOverWindow,
  blockedSince,
  hourlyBlockedSeries,
  DASHBOARD_DELTA_WINDOW_SEC,
  DASHBOARD_SPARK_POINTS,
  formatCountDelta,
  formatRatePercentDelta,
  sampleAtOffset,
  sparkValuesFromTail,
  statDeltaColor,
} from './dashboard-stats';

describe('dashboard-stats', () => {
  test('sparkValuesFromTail needs at least two source samples', () => {
    expect(sparkValuesFromTail([1])).toEqual([]);
    expect(sparkValuesFromTail([1, 2, 3])).toHaveLength(DASHBOARD_SPARK_POINTS);
  });

  test('sampleAtOffset reads history by seconds', () => {
    const series = Array.from({ length: 80 }, (_, i) => i);
    expect(sampleAtOffset(series, 0)).toBe(79);
    expect(sampleAtOffset(series, DASHBOARD_DELTA_WINDOW_SEC)).toBe(19);
    expect(sampleAtOffset([5], 10)).toBe(5);
  });

  test('formatRatePercentDelta', () => {
    expect(formatRatePercentDelta(0, 0)).toEqual({ text: '0%', tone: 'neutral' });
    expect(formatRatePercentDelta(150, 100)).toEqual({ text: '+50%', tone: 'ok' });
    expect(formatRatePercentDelta(50, 100)).toEqual({ text: '-50%', tone: 'bad' });
    expect(formatRatePercentDelta(42, 0)).toEqual({ text: '—', tone: 'neutral' });
  });

  test('formatCountDelta', () => {
    expect(formatCountDelta(5, 2)).toEqual({ text: '+3', tone: 'ok' });
    expect(formatCountDelta(2, 5)).toEqual({ text: '-3', tone: 'bad' });
    expect(formatCountDelta(5, 2, true)).toEqual({ text: '+3', tone: 'bad' });
    expect(formatCountDelta(2, 5, true)).toEqual({ text: '-3', tone: 'ok' });
  });

  test('statDeltaColor maps tones to theme variables', () => {
    expect(statDeltaColor('ok')).toBe('var(--ok)');
    expect(statDeltaColor('bad')).toBe('var(--bad)');
    expect(statDeltaColor('neutral')).toBe('var(--t3)');
  });
});

describe('dashboard stat strip', () => {
  const bucket = (bucketStart: number, bytesReceived = 0, bytesSent = 0, blockedCount = 0) => ({
    bucketStart,
    bytesReceived,
    bytesSent,
    blockedCount,
  });
  // 2026-09-27 14:40:00 UTC; bucket boundaries fall on :00 and :30.
  const nowSec = Date.UTC(2026, 8, 27, 14, 40) / 1000;
  const nowMs = nowSec * 1000;
  const at = (h: number, m: number) => Date.UTC(2026, 8, 27, h, m) / 1000;

  test('averageRateOverWindow divides by the history that exists', () => {
    // Two full buckets plus the current partial one: 70 minutes of history.
    const buckets = [bucket(at(13, 30), 4200), bucket(at(14, 0), 4200), bucket(at(14, 30), 0)];
    expect(averageRateOverWindow(buckets, 'bytesReceived', nowMs)).toBeCloseTo(8400 / 4200);
    expect(averageRateOverWindow(buckets, 'bytesSent', nowMs)).toBe(0);
  });

  test('averageRateOverWindow ignores buckets outside the window and needs one bucket of history', () => {
    const old = bucket(at(14, 30) - 2 * 86_400, 1_000_000);
    expect(averageRateOverWindow([old], 'bytesReceived', nowMs)).toBeNull();
    expect(averageRateOverWindow([bucket(at(14, 30), 500)], 'bytesReceived', nowMs)).toBeNull();
    expect(averageRateOverWindow([], 'bytesReceived', nowMs)).toBeNull();
  });

  test('averageRateOverWindow spans the full day once history exceeds it', () => {
    const buckets = Array.from({ length: 60 }, (_, i) =>
      bucket(at(14, 30) - i * ACTIVITY_BUCKET_SEC, 1800),
    );
    // 49 buckets overlap the trailing 24h window (the oldest one partially).
    expect(averageRateOverWindow(buckets, 'bytesReceived', nowMs)).toBeCloseTo(
      (49 * 1800) / 86_400,
    );
  });

  test('averageDelta reports direction and rounded magnitude', () => {
    expect(averageDelta(118, 100)).toEqual({ direction: 'up', percent: 18 });
    expect(averageDelta(96, 100)).toEqual({ direction: 'down', percent: 4 });
    expect(averageDelta(100.2, 100)).toEqual({ direction: 'flat', percent: 0 });
    expect(averageDelta(5, null)).toBeNull();
    expect(averageDelta(5, 0)).toBeNull();
  });

  test('formatAverageDelta switches to a multiplier for large increases', () => {
    expect(formatAverageDelta({ direction: 'up', percent: 18 })).toBe('18%');
    expect(formatAverageDelta({ direction: 'up', percent: 200 })).toBe('200%');
    expect(formatAverageDelta({ direction: 'up', percent: 330 })).toBe('4.3×');
    expect(formatAverageDelta({ direction: 'up', percent: 1_900 })).toBe('20×');
    expect(formatAverageDelta({ direction: 'up', percent: 43_357 })).toBe('100×+');
    expect(formatAverageDelta({ direction: 'down', percent: 96 })).toBe('96%');
  });

  test('blockedSince counts whole buckets within the last hour', () => {
    const buckets = [
      bucket(at(13, 0), 0, 0, 9),
      bucket(at(13, 30), 0, 0, 1),
      bucket(at(14, 0), 0, 0, 2),
      bucket(at(14, 30), 0, 0, 3),
    ];
    // 14:40 minus an hour is 13:40; the first whole bucket after it starts at 14:00.
    expect(blockedSince(buckets, nowMs)).toEqual({ count: 5, sinceSec: at(14, 0) });
  });

  test('hourlyBlockedSeries folds half-hour buckets into hours ending now', () => {
    const buckets = [
      bucket(at(12, 0), 0, 0, 1),
      bucket(at(12, 30), 0, 0, 2),
      bucket(at(14, 0), 0, 0, 4),
      bucket(at(14, 30), 0, 0, 1),
    ];
    expect(hourlyBlockedSeries(buckets, nowMs, 3)).toEqual([3, 0, 5]);
    expect(hourlyBlockedSeries([], nowMs, 2)).toEqual([0, 0]);
  });
});
