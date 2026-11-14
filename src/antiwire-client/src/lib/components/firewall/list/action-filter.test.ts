import { describe, expect, test } from 'bun:test';
import { matchesActionFilter } from './action-filter';

describe('matchesActionFilter', () => {
  test('all keeps allow and block actions', () => {
    expect(matchesActionFilter('ALLOW', 'all')).toBe(true);
    expect(matchesActionFilter('BLOCK', 'all')).toBe(true);
  });

  test('allowed and blocked match the daemon action text', () => {
    expect(matchesActionFilter('ALLOW', 'allowed')).toBe(true);
    expect(matchesActionFilter('allow', 'allowed')).toBe(true);
    expect(matchesActionFilter('BLOCK', 'allowed')).toBe(false);
    expect(matchesActionFilter('BLOCK', 'blocked')).toBe(true);
    expect(matchesActionFilter('block', 'blocked')).toBe(true);
    expect(matchesActionFilter('ALLOW', 'blocked')).toBe(false);
  });
});
