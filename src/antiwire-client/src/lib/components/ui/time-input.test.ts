/// <reference types="bun-types" />
import { describe, expect, it } from 'bun:test';
import { clampTime, isAfterTime, parseTimeKey, toTimeKey } from './time-input';

describe('time input helpers', () => {
  it('parses time keys and rejects malformed or impossible times', () => {
    expect(parseTimeKey('09:30')).toEqual({ hours: 9, minutes: 30 });
    expect(parseTimeKey('00:00')).toEqual({ hours: 0, minutes: 0 });
    expect(parseTimeKey('23:59')).toEqual({ hours: 23, minutes: 59 });
    expect(parseTimeKey('9:30')).toBeNull();
    expect(parseTimeKey('24:00')).toBeNull();
    expect(parseTimeKey('23:60')).toBeNull();
    expect(parseTimeKey('')).toBeNull();
  });

  it('formats parts back into a padded 24-hour key', () => {
    expect(toTimeKey(0, 0)).toBe('00:00');
    expect(toTimeKey(9, 5)).toBe('09:05');
    expect(toTimeKey(23, 59)).toBe('23:59');
  });

  it('compares times on a 24-hour clock', () => {
    expect(isAfterTime({ hours: 14, minutes: 6 }, { hours: 14, minutes: 5 })).toBe(true);
    expect(isAfterTime({ hours: 14, minutes: 5 }, { hours: 14, minutes: 5 })).toBe(false);
    expect(isAfterTime({ hours: 13, minutes: 59 }, { hours: 14, minutes: 5 })).toBe(false);
    expect(isAfterTime({ hours: 15, minutes: 0 }, { hours: 14, minutes: 59 })).toBe(true);
  });

  it('clamps out-of-range times to the bound', () => {
    expect(clampTime({ hours: 23, minutes: 59 }, { hours: 14, minutes: 5 })).toEqual({
      hours: 14,
      minutes: 5,
    });
    expect(clampTime({ hours: 9, minutes: 30 }, { hours: 14, minutes: 5 })).toEqual({
      hours: 9,
      minutes: 30,
    });
    expect(clampTime({ hours: 23, minutes: 59 }, null)).toEqual({ hours: 23, minutes: 59 });
  });
});
