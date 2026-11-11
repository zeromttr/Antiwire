import { describe, expect, test } from 'bun:test';
import { statusToneFromColor } from './status-tone';

describe('statusToneFromColor', () => {
  test('maps theme colour references to tones', () => {
    expect(statusToneFromColor('var(--bad)')).toBe('bad');
    expect(statusToneFromColor('var(--warn)')).toBe('warn');
    expect(statusToneFromColor('var(--ok)')).toBe('ok');
    expect(statusToneFromColor('var(--acc-sub)')).toBe('info');
    expect(statusToneFromColor('var(--acc)')).toBe('accent');
  });

  test('falls back to idle for anything else', () => {
    expect(statusToneFromColor('var(--t3)')).toBe('idle');
    expect(statusToneFromColor('#ff0000')).toBe('idle');
    expect(statusToneFromColor(undefined)).toBe('idle');
  });
});
