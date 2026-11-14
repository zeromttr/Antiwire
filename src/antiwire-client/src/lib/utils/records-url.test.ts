import { describe, expect, it } from 'bun:test';
import {
  parseApplicationIdParam,
  parseTimeWindowParam,
  recordsApplicationUrl,
  recordsTimeWindowUrl,
} from './records-url';

describe('records-url', () => {
  it('parseTimeWindowParam rejects invalid values', () => {
    expect(parseTimeWindowParam(null)).toBeUndefined();
    expect(parseTimeWindowParam('abc')).toBeUndefined();
    expect(parseTimeWindowParam('0')).toBeUndefined();
    expect(parseTimeWindowParam('1700000000')).toBe(1700000000);
  });

  it('recordsTimeWindowUrl encodes from and to', () => {
    expect(recordsTimeWindowUrl(100, 200)).toBe('/records?from=100&to=200');
  });

  it('parseApplicationIdParam accepts positive integer ids only', () => {
    expect(parseApplicationIdParam(null)).toBeUndefined();
    expect(parseApplicationIdParam('abc')).toBeUndefined();
    expect(parseApplicationIdParam('0')).toBeUndefined();
    expect(parseApplicationIdParam('-3')).toBeUndefined();
    expect(parseApplicationIdParam('12')).toBe(12);
  });

  it('recordsApplicationUrl encodes app name', () => {
    expect(recordsApplicationUrl('Google Chrome')).toBe('/records?app=Google+Chrome');
  });
});
