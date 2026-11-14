/// <reference types="bun-types" />
import { describe, expect, it } from 'bun:test';
import {
  appTint,
  formatBytes,
  formatCompactCount,
  formatDate,
  formatDateTime,
  formatThroughput,
  formatThroughputAxisTick,
  formatTimeAgo,
  initials,
  toEpochMs,
} from './format';

describe('formatters', () => {
  it('formats bytes', () => {
    expect(formatBytes(1536)).toBe('1.5 KB');
    expect(formatBytes(1048576)).toBe('1.0 MB');
  });

  it('formats throughput for low activity', () => {
    expect(formatThroughput(0)).toEqual({ value: '0', unit: 'B/s', label: '0 B/s' });
    expect(formatThroughput(42)).toEqual({ value: '42', unit: 'B/s', label: '42 B/s' });
    expect(formatThroughput(512)).toEqual({ value: '512', unit: 'B/s', label: '512 B/s' });
    expect(formatThroughput(1536)).toEqual({ value: '1.5', unit: 'KB/s', label: '1.5 KB/s' });
    expect(formatThroughput(125000)).toEqual({ value: '122', unit: 'KB/s', label: '122 KB/s' });
  });

  it('formats throughput above one megabyte per second in byte units', () => {
    expect(formatThroughput(2 * 1024 * 1024)).toEqual({
      value: '2',
      unit: 'MB/s',
      label: '2 MB/s',
    });
    expect(formatThroughput(1.5 * 1024 * 1024)).toEqual({
      value: '1.5',
      unit: 'MB/s',
      label: '1.5 MB/s',
    });
    expect(formatThroughput(2.5 * 1024 * 1024 * 1024)).toEqual({
      value: '2.5',
      unit: 'GB/s',
      label: '2.5 GB/s',
    });
  });

  it('formats throughput axis ticks as whole numbers with byte units', () => {
    expect(formatThroughputAxisTick(0)).toBe('0 B');
    expect(formatThroughputAxisTick(42)).toBe('42 B');
    expect(formatThroughputAxisTick(1536)).toBe('2 KB');
    expect(formatThroughputAxisTick(125000)).toBe('122 KB');
    expect(formatThroughputAxisTick(2 * 1024 * 1024)).toBe('2 MB');
    expect(formatThroughputAxisTick(3 * 1024 * 1024 * 1024)).toBe('3 GB');
  });

  it('initials from name', () => {
    expect(initials('Chrome Helper')).toBe('CH');
    expect(initials('Steam')).toBe('ST');
  });

  it('converts unix seconds to epoch milliseconds', () => {
    expect(toEpochMs(1_700_000_000)).toBe(1_700_000_000_000);
    expect(toEpochMs(1_700_000_000_000)).toBe(1_700_000_000_000);
  });

  it('formats compact counts', () => {
    expect(formatCompactCount(999)).toBe('999');
    expect(formatCompactCount(1100)).toBe('1.1k');
    expect(formatCompactCount(1200)).toBe('1.2k');
    expect(formatCompactCount(12_000)).toBe('12k');
    expect(formatCompactCount(1_000_000)).toBe('1m');
    expect(formatCompactCount(5_400_000)).toBe('5.4m');
  });

  it('formats full date and time for tooltips', () => {
    const label = formatDateTime(1_700_000_000);
    expect(label).toContain('2023');
    expect(label).toMatch(/\d{2}:\d{2}:\d{2}/);
  });

  it('formats a calendar date without the time', () => {
    const label = formatDate(808_372_800);
    expect(label).toContain('1995');
    expect(label).not.toMatch(/\d{2}:\d{2}/);
    expect(formatDate(0)).toBe('');
  });

  it('formats relative time since an event', () => {
    const now = Date.UTC(2026, 6, 30, 12, 0, 0);
    expect(formatTimeAgo(now / 1000 - 15, now)).toBe('15s');
    expect(formatTimeAgo(now / 1000 - 120, now)).toBe('2m');
    expect(formatTimeAgo(now / 1000 - 7200, now)).toBe('2h');
    expect(formatTimeAgo(now / 1000 - 86400 * 3, now)).toBe('3d');
    expect(formatTimeAgo(now / 1000 - 86400 * 10, now)).toBe('1w');
    expect(formatTimeAgo(now / 1000 - 86400 * 45, now)).toBe('1mo');
  });

  it('handles null, undefined, and empty names in initials() safely', () => {
    expect(initials(null)).toBe('');
    expect(initials(undefined)).toBe('');
    expect(initials('')).toBe('');
    expect(initials('   ')).toBe('');
    expect(initials('A')).toBe('A');
    expect(initials('Chrome')).toBe('CH');
    expect(initials('Chrome Helper Service')).toBe('CH');
  });

  it('handles null, undefined, and empty names in appTint() safely', () => {
    expect(appTint(null)).toBe('#7EC8E3');
    expect(appTint(undefined)).toBe('#7EC8E3');
    expect(appTint('')).toBe('#7EC8E3');
    expect(typeof appTint('Chrome')).toBe('string');
  });
});
