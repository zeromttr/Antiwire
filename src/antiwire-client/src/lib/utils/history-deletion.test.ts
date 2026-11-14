import { describe, expect, test } from 'bun:test';
import {
  historyDeletionStart,
  historyDeletionUnitLabel,
  isValidHistoryDeletionAmount,
  MAX_HISTORY_DELETION_AMOUNT,
} from './history-deletion';

const seconds = (date: Date) => Math.floor(date.getTime() / 1000);

describe('historyDeletionStart', () => {
  const now = new Date(2026, 9, 18, 14, 30, 15);

  test('hours count back exact elapsed time', () => {
    expect(historyDeletionStart(1, 'hours', now)).toBe(seconds(now) - 3600);
    expect(historyDeletionStart(36, 'hours', now)).toBe(seconds(now) - 36 * 3600);
  });

  test('days and weeks keep the local time of day', () => {
    expect(historyDeletionStart(1, 'days', now)).toBe(seconds(new Date(2026, 9, 17, 14, 30, 15)));
    expect(historyDeletionStart(2, 'weeks', now)).toBe(seconds(new Date(2026, 9, 4, 14, 30, 15)));
  });

  test('months are calendar months, crossing years', () => {
    expect(historyDeletionStart(1, 'months', now)).toBe(seconds(new Date(2026, 8, 18, 14, 30, 15)));
    expect(historyDeletionStart(12, 'months', now)).toBe(
      seconds(new Date(2025, 9, 18, 14, 30, 15)),
    );
  });

  test('a month back from a long month lands on the shorter month’s last day', () => {
    const endOfMarch = new Date(2026, 2, 31, 9, 0, 0);
    expect(historyDeletionStart(1, 'months', endOfMarch)).toBe(
      seconds(new Date(2026, 1, 28, 9, 0, 0)),
    );
    const leapYear = new Date(2028, 2, 31, 9, 0, 0);
    expect(historyDeletionStart(1, 'months', leapYear)).toBe(
      seconds(new Date(2028, 1, 29, 9, 0, 0)),
    );
  });

  test('rejects amounts the control would also reject', () => {
    for (const amount of [0, -1, 1.5, Number.NaN, MAX_HISTORY_DELETION_AMOUNT + 1]) {
      expect(isValidHistoryDeletionAmount(amount)).toBe(false);
      expect(() => historyDeletionStart(amount, 'hours', now)).toThrow(RangeError);
    }
    expect(isValidHistoryDeletionAmount(1)).toBe(true);
    expect(isValidHistoryDeletionAmount(MAX_HISTORY_DELETION_AMOUNT)).toBe(true);
  });
});

describe('historyDeletionUnitLabel', () => {
  test('follows the amount’s plural form', () => {
    expect(historyDeletionUnitLabel('hours', 1, 'en')).toBe('hour');
    expect(historyDeletionUnitLabel('hours', 2, 'en')).toBe('hours');
    expect(historyDeletionUnitLabel('months', 5, 'en')).toBe('months');
  });

  test('uses the locale’s own words', () => {
    expect(historyDeletionUnitLabel('days', 2, 'de')).toBe('Tage');
  });
});
