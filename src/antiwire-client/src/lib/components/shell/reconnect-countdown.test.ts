import { expect, test } from 'bun:test';
import { secondsUntil } from './reconnect-countdown.ts';

test('nothing scheduled has no countdown', () => {
  expect(secondsUntil(null, 1_000)).toBeNull();
});

test('a partial second counts as a whole one', () => {
  expect(secondsUntil(6_000, 1_000)).toBe(5);
  expect(secondsUntil(6_000, 1_001)).toBe(5);
  expect(secondsUntil(6_000, 5_999)).toBe(1);
});

test('a due or overdue attempt reads zero', () => {
  expect(secondsUntil(6_000, 6_000)).toBe(0);
  expect(secondsUntil(6_000, 9_000)).toBe(0);
});
