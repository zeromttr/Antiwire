/// <reference types="bun-types" />
import { describe, expect, it } from 'bun:test';
import {
  daysInMonth,
  firstDayOfWeek,
  isAfterDay,
  monthGrid,
  parseDateKey,
  sameDay,
  shiftDays,
  shiftMonths,
  toDateKey,
  viewKey,
  viewOf,
  weekdayLabels,
  yearWindowStart,
} from './date-input';

describe('date input helpers', () => {
  it('parses date keys and rejects malformed or impossible dates', () => {
    const parsed = parseDateKey('2026-01-15');
    expect(parsed && toDateKey(parsed)).toBe('2026-01-15');
    expect(parseDateKey('2026-1-5')).toBeNull();
    expect(parseDateKey('2026-02-30')).toBeNull();
    expect(parseDateKey('')).toBeNull();
    expect(parseDateKey('not-a-date')).toBeNull();
  });

  it('round-trips local dates without timezone drift', () => {
    const date = new Date(2026, 8, 12, 23, 30);
    expect(toDateKey(date)).toBe('2026-09-12');
    expect(parseDateKey('2026-09-12')?.getTime()).toBe(new Date(2026, 8, 12).getTime());
    expect(sameDay(date, new Date(2026, 8, 13))).toBe(false);
  });

  it('steps days across month and year boundaries', () => {
    expect(toDateKey(shiftDays(new Date(2026, 11, 31), 1))).toBe('2027-01-01');
    expect(toDateKey(shiftDays(new Date(2026, 0, 1), -1))).toBe('2025-12-31');
  });

  it('clamps shifted months to the last valid day', () => {
    expect(toDateKey(shiftMonths(new Date(2026, 0, 31), 1))).toBe('2026-02-28');
    expect(toDateKey(shiftMonths(new Date(2024, 0, 31), 1))).toBe('2024-02-29');
    expect(toDateKey(shiftMonths(new Date(2026, 0, 15), -1))).toBe('2025-12-15');
    expect(toDateKey(shiftMonths(new Date(2026, 11, 31), 1))).toBe('2027-01-31');
    expect(daysInMonth(2024, 1)).toBe(29);
  });

  it('builds a six-week grid aligned to the configured week start', () => {
    const grid = monthGrid({ year: 2026, month: 2 }, 1);
    expect(grid).toHaveLength(42);
    expect(toDateKey(grid[0])).toBe('2026-02-23');
    expect(grid[0].getDay()).toBe(1);
    expect(grid.some((day) => toDateKey(day) === '2026-03-01')).toBe(true);
    expect(toDateKey(grid[41])).toBe('2026-04-05');

    const sundayGrid = monthGrid(viewOf(new Date(2026, 2, 1)), 0);
    expect(sundayGrid[0].getDay()).toBe(0);
    expect(toDateKey(sundayGrid[0])).toBe('2026-03-01');
  });

  it('orders weekday labels from the locale week start', () => {
    expect(weekdayLabels('en-US', 0)).toEqual(['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat']);
    expect(weekdayLabels('en-US', 1)).toEqual(['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']);
  });

  it('falls back to a monday week start for unknown locales', () => {
    expect(firstDayOfWeek(undefined)).toBe(1);
    expect(firstDayOfWeek('not a locale')).toBe(1);
    const en = firstDayOfWeek('en-US');
    expect(en).toBeGreaterThanOrEqual(0);
    expect(en).toBeLessThanOrEqual(6);
  });

  it('keys views by year and padded month', () => {
    expect(viewKey({ year: 2026, month: 0 })).toBe('2026-01');
    expect(viewKey(viewOf(new Date(2026, 11, 1)))).toBe('2026-12');
  });

  it('compares whole calendar days', () => {
    expect(isAfterDay(new Date(2026, 8, 13), new Date(2026, 8, 12))).toBe(true);
    expect(isAfterDay(new Date(2026, 8, 12, 23, 59), new Date(2026, 8, 12))).toBe(false);
    expect(isAfterDay(new Date(2026, 8, 11), new Date(2026, 8, 12))).toBe(false);
    expect(isAfterDay(new Date(2026, 9, 1), new Date(2026, 8, 30))).toBe(true);
  });

  it('aligns years to fixed windows', () => {
    expect(yearWindowStart(2026)).toBe(2016);
    expect(yearWindowStart(2016)).toBe(2016);
    expect(yearWindowStart(2015)).toBe(2004);
    expect(yearWindowStart(2026, 10)).toBe(2020);
  });
});
