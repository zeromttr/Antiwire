import { describe, expect, test } from 'bun:test';
import { locales } from '#lib/paraglide/runtime.js';
import { loadMessages, m, MESSAGE_LOCALE_LOADERS } from './messages';

describe('message locale loaders', () => {
  test('every compiled locale has a dedicated loader', () => {
    expect(Object.keys(MESSAGE_LOCALE_LOADERS).sort()).toEqual([...locales].sort());
  });

  test('loadMessages pulls one catalog and serves strings from it', async () => {
    await loadMessages('en');
    expect<string>(m.common_em_dash()).toBe('—');
    expect<string>(m.common_cancel()).toBeTypeOf('string');
    expect<string>(m.error_page_title()).toBe('Something went wrong');
    expect<string>(m.error_recover_view()).toBe('Recover View');
    expect<string>(m.error_status({ status: 500 })).toBe('Error 500');
  });

  test('missing keys and failed locale chunks fall back to english instead of throwing', async () => {
    expect<string>(m.common_em_dash()).toBe('—');
    expect((m as Record<string, (...args: unknown[]) => unknown>).not_a_real_message()).toBe(
      'not_a_real_message',
    );

    await loadMessages('en');
    const original = MESSAGE_LOCALE_LOADERS.de;
    MESSAGE_LOCALE_LOADERS.de = async () => {
      throw new Error('chunk load failed');
    };
    try {
      await loadMessages('de');
      expect<string>(m.common_em_dash()).toBe('—');
      expect<string>(m.common_cancel()).toBeTypeOf('string');
    } finally {
      MESSAGE_LOCALE_LOADERS.de = original;
      await loadMessages('en');
    }
  });

  test('a failed locale switch still falls back when another catalog was already active', async () => {
    await loadMessages('en');
    const originalDe = MESSAGE_LOCALE_LOADERS.de;
    const originalFr = MESSAGE_LOCALE_LOADERS.fr;
    MESSAGE_LOCALE_LOADERS.de = async () => {
      throw new Error('chunk load failed');
    };
    MESSAGE_LOCALE_LOADERS.fr = async () => {
      throw new Error('chunk load failed');
    };
    try {
      await loadMessages('de');
      expect<string>(m.common_em_dash()).toBe('—');
      await loadMessages('fr');
      expect<string>(m.common_cancel()).toBeTypeOf('string');
    } finally {
      MESSAGE_LOCALE_LOADERS.de = originalDe;
      MESSAGE_LOCALE_LOADERS.fr = originalFr;
      await loadMessages('en');
    }
  });
});

describe('message catalogs', () => {
  // A key missing from one catalog makes Paraglide import the English catalog into it, so that
  // language would load both at start-up, and the string would show in English.
  test('every catalog has exactly the English keys and the same placeholders', async () => {
    const { readdirSync, readFileSync } = await import('node:fs');
    const dir = new URL('../../../messages/', import.meta.url);
    const read = (file: string) =>
      JSON.parse(readFileSync(new URL(file, dir), 'utf8')) as Record<string, string>;
    const placeholders = (text: string) => [...text.matchAll(/\{(\w+)\}/g)].map((p) => p[1]).sort();
    const english = read('en.json');
    const problems: string[] = [];
    for (const file of readdirSync(dir).filter((name) => name.endsWith('.json'))) {
      const catalog = read(file);
      for (const key of Object.keys(english)) {
        if (!(key in catalog)) problems.push(`${file}: missing ${key}`);
        else if (`${placeholders(catalog[key])}` !== `${placeholders(english[key])}`) {
          problems.push(`${file}: ${key} has other placeholders`);
        }
      }
      for (const key of Object.keys(catalog)) {
        if (!(key in english)) problems.push(`${file}: extra ${key}`);
      }
    }
    expect(problems).toEqual([]);
  });
});
