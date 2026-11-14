import { describe, expect, test } from 'bun:test';
import {
  accentForTheme,
  accentInkColor,
  accentPresetById,
  normalizeAccentId,
  relativeLuminance,
} from './accent-colors';
import { normalizeClientSettings } from './client-settings';
import { normalizeLocale } from './locales';
import { parseThemeBootState, normalizeThemePreference, resolveTheme } from './theme';

describe('accent-colors', () => {
  test('normalizeAccentId falls back to mint for unknown ids', () => {
    expect(normalizeAccentId('unknown')).toBe('mint');
    expect(accentPresetById('unknown').color).toBe('#3ee6a0');
    expect(accentPresetById('unknown').subColor).toBe('#5ce8ff');
  });

  test('custom hex accents are kept, lowercased, with a derived secondary', () => {
    expect(normalizeAccentId('#12AB9F')).toBe('#12ab9f');
    const custom = accentPresetById('#12AB9F');
    expect(custom.color).toBe('#12ab9f');
    expect(custom.subColor).toMatch(/^#[0-9a-f]{6}$/);
    expect(custom.subColor).not.toBe(custom.color);
    expect(normalizeAccentId('#12ab9')).toBe('mint');
    expect(normalizeAccentId('#6B9EFF')).toBe('sapphire');
    expect(normalizeAccentId('red')).toBe('mint');
  });

  test('accentInkColor picks whichever ink contrasts more with the fill', () => {
    expect(accentInkColor('#3ee6a0')).toBe('#0b0f0c');
    expect(accentInkColor('#b6ff00')).toBe('#0b0f0c');
    expect(accentInkColor('#b026ff')).toBe('#ffffff');
    expect(accentInkColor('#1f3a8a')).toBe('#ffffff');
  });

  test('accentForTheme keeps dark accents and deepens light ones to text contrast', () => {
    expect(accentForTheme('#3ee6a0', 'dark')).toBe('#3ee6a0');
    const panel = relativeLuminance('#f8f7f5');
    for (const hex of ['#3ee6a0', '#b6ff00', '#55fbff', '#ffb000', '#e4c88a']) {
      const deep = accentForTheme(hex, 'light');
      const contrast = (panel + 0.05) / (relativeLuminance(deep) + 0.05);
      expect(contrast).toBeGreaterThanOrEqual(4.5);
    }
    // Already-dark accents are left alone.
    expect(accentForTheme('#1f3a8a', 'light')).toBe('#1f3a8a');
  });
});

describe('client-settings', () => {
  test('normalizeClientSettings applies defaults', () => {
    expect(normalizeClientSettings({})).toEqual({
      accentColorId: 'mint',
      theme: 'system',
      onboardingDone: false,
      locale: 'en',
    });
  });

  test('normalizeClientSettings normalizes locale', () => {
    expect(normalizeClientSettings({ locale: 'de' }).locale).toBe('de');
    expect(normalizeClientSettings({ locale: 'es-MX' }).locale).toBe('es');
    expect(normalizeClientSettings({ locale: 'zz' }).locale).toBe('en');
  });

  test('normalizeClientSettings normalizes theme', () => {
    expect(normalizeClientSettings({ theme: 'light' }).theme).toBe('light');
    expect(normalizeClientSettings({ theme: 'dark' }).theme).toBe('dark');
    expect(normalizeClientSettings({ theme: 'system' }).theme).toBe('system');
    expect(normalizeClientSettings({ theme: 'neon' as never }).theme).toBe('system');
  });

  test('normalizeClientSettings drops retired color-scheme fields', () => {
    const legacy = {
      theme: 'dark',
      themeColorId: 'navy',
      themeSaturation: 80,
      themeDarkness: 20,
      darkPaletteId: 'forest',
    } as Parameters<typeof normalizeClientSettings>[0];
    const settings = normalizeClientSettings(legacy);
    expect(settings.theme).toBe('dark');
    expect(Object.keys(settings).sort()).toEqual([
      'accentColorId',
      'locale',
      'onboardingDone',
      'theme',
    ]);
  });
});

describe('theme', () => {
  test('normalizeThemePreference falls back to system', () => {
    expect(normalizeThemePreference('light')).toBe('light');
    expect(normalizeThemePreference('dark')).toBe('dark');
    expect(normalizeThemePreference('system')).toBe('system');
    expect(normalizeThemePreference('nope')).toBe('system');
    expect(normalizeThemePreference(undefined)).toBe('system');
  });

  test('resolveTheme maps system to the current color scheme', () => {
    expect(resolveTheme('light', true)).toBe('light');
    expect(resolveTheme('dark', false)).toBe('dark');
    expect(resolveTheme('system', true)).toBe('dark');
    expect(resolveTheme('system', false)).toBe('light');
  });

  test('parseThemeBootState accepts legacy preference strings and JSON', () => {
    expect(parseThemeBootState('dark')).toEqual({ theme: 'dark' });
    expect(
      parseThemeBootState(
        '{"preference":"light","themeColorId":"navy","themeSaturation":35,"themeDarkness":70}',
      ),
    ).toEqual({ theme: 'light' });
    expect(parseThemeBootState('{"preference":"dark","darkPaletteId":"forest"}')).toEqual({
      theme: 'dark',
    });
    expect(parseThemeBootState('{"preference":"neon"}')).toEqual({});
  });
});

describe('locales', () => {
  test('normalizeLocale accepts supported tags and falls back', () => {
    expect(normalizeLocale('fr')).toBe('fr');
    expect(normalizeLocale('nb-NO')).toBe('nb');
    expect(normalizeLocale(undefined)).toBe('en');
    expect(normalizeLocale('nope')).toBe('en');
  });
});
