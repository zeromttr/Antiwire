import { describe, expect, it } from 'bun:test';
import { normalizeThemeSnapshot } from './theme-snapshot';

describe('normalizeThemeSnapshot', () => {
  it('returns null for empty payloads', () => {
    expect(normalizeThemeSnapshot(null)).toBeNull();
    expect(normalizeThemeSnapshot({})).toBeNull();
  });

  it('keeps the theme and only the accent properties', () => {
    expect(
      normalizeThemeSnapshot({
        theme: 'light',
        palette: 'navy',
        saturation: '80',
        vars: { '--bg': '#1a3f78', '--acc-base': '#b026ff', '--acc': 'stale', ignored: 'nope' },
      }),
    ).toEqual({
      theme: 'light',
      vars: { '--acc-base': '#b026ff' },
    });
  });
});
