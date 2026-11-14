import { describe, expect, test } from 'bun:test';
import { hexToHsv, hsvToHex, normalizeHex, stepFor } from './color-picker';

describe('color-picker', () => {
  test('normalizeHex accepts short and long forms with or without #', () => {
    expect(normalizeHex('#3EE6A0')).toBe('#3ee6a0');
    expect(normalizeHex('3ee6a0')).toBe('#3ee6a0');
    expect(normalizeHex('#abc')).toBe('#aabbcc');
    expect(normalizeHex(' fff ')).toBe('#ffffff');
    expect(normalizeHex('#12345')).toBeNull();
    expect(normalizeHex('red')).toBeNull();
    expect(normalizeHex('')).toBeNull();
  });

  test('hex round-trips through HSV', () => {
    for (const hex of [
      '#3ee6a0',
      '#b026ff',
      '#ffb000',
      '#000000',
      '#ffffff',
      '#7f7f7f',
      '#ff0000',
    ]) {
      expect(hsvToHex(hexToHsv(hex))).toBe(hex);
    }
  });

  test('hexToHsv reports hue in degrees and s/v in 0..1', () => {
    expect(hexToHsv('#ff0000')).toEqual({ h: 0, s: 1, v: 1 });
    expect(hexToHsv('#00ff00')).toEqual({ h: 120, s: 1, v: 1 });
    expect(hexToHsv('#0000ff')).toEqual({ h: 240, s: 1, v: 1 });
    expect(hexToHsv('#000000')).toEqual({ h: 0, s: 0, v: 0 });
  });

  test('hsvToHex clamps and wraps out-of-range input', () => {
    expect(hsvToHex({ h: 360, s: 1, v: 1 })).toBe('#ff0000');
    expect(hsvToHex({ h: -120, s: 1, v: 1 })).toBe('#0000ff');
    expect(hsvToHex({ h: 0, s: 2, v: -1 })).toBe('#000000');
  });

  test('stepFor uses a coarse step with Shift', () => {
    expect(stepFor({ shiftKey: false })).toBe(0.01);
    expect(stepFor({ shiftKey: true })).toBe(0.1);
  });
});
