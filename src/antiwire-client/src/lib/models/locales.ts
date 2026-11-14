import { baseLocale, locales as paraglideLocales, type Locale } from '#lib/paraglide/runtime.js';

export const SUPPORTED_LOCALES = [...paraglideLocales] as const;

export type AppLocale = Locale;

export const DEFAULT_LOCALE: AppLocale = baseLocale;

const LOCALE_SET = new Set<string>(SUPPORTED_LOCALES);

export function isAppLocale(value: string | null | undefined): value is AppLocale {
  return typeof value === 'string' && LOCALE_SET.has(value);
}

export function normalizeLocale(value: string | null | undefined): AppLocale {
  if (!value) return DEFAULT_LOCALE;
  if (isAppLocale(value)) return value;

  const base = value.toLowerCase().split('-')[0] ?? '';
  if (isAppLocale(base)) return base;

  return DEFAULT_LOCALE;
}
