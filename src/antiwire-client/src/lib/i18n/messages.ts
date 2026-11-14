import { baseLocale, getLocale, locales, type Locale } from '#lib/paraglide/runtime.js';

type LocaleMessageCatalog = typeof import('../paraglide/messages/en.js');
type MessageCatalog = typeof import('../paraglide/messages/_index.js');

/**
 * One dynamic import per locale so Vite emits a separate chunk for each
 * language. The generated `#lib/paraglide/messages/_index.js` statically
 * imports all 24 catalogs; this module is the runtime replacement.
 *
 * English is loaded only when it is the user's language or a locale chunk
 * fails to load, so other languages do not also parse the English catalog at
 * start-up. Every catalog has every key (messages.test.ts checks it), so a
 * loaded catalog never needs English to fill a gap. `main.tsx` renders only
 * after `loadMessages()`; before that, and if even English fails, `m.foo()`
 * returns the key name instead of throwing.
 */
export const MESSAGE_LOCALE_LOADERS: Record<Locale, () => Promise<LocaleMessageCatalog>> = {
  bg: () => import('../paraglide/messages/bg.js'),
  cs: () => import('../paraglide/messages/cs.js'),
  da: () => import('../paraglide/messages/da.js'),
  de: () => import('../paraglide/messages/de.js'),
  el: () => import('../paraglide/messages/el.js'),
  en: () => import('../paraglide/messages/en.js'),
  es: () => import('../paraglide/messages/es.js'),
  et: () => import('../paraglide/messages/et.js'),
  fi: () => import('../paraglide/messages/fi.js'),
  fr: () => import('../paraglide/messages/fr.js'),
  hr: () => import('../paraglide/messages/hr.js'),
  hu: () => import('../paraglide/messages/hu.js'),
  it: () => import('../paraglide/messages/it.js'),
  lt: () => import('../paraglide/messages/lt.js'),
  lv: () => import('../paraglide/messages/lv.js'),
  nb: () => import('../paraglide/messages/nb.js'),
  nl: () => import('../paraglide/messages/nl.js'),
  pl: () => import('../paraglide/messages/pl.js'),
  pt: () => import('../paraglide/messages/pt.js'),
  ro: () => import('../paraglide/messages/ro.js'),
  sk: () => import('../paraglide/messages/sk.js'),
  sl: () => import('../paraglide/messages/sl.js'),
  sv: () => import('../paraglide/messages/sv.js'),
  uk: () => import('../paraglide/messages/uk.js'),
};

let active: LocaleMessageCatalog | null = null;
let activeLocale: Locale | undefined;
let inflight: Promise<void> | null = null;

/** Installs a pre-imported catalog without an async module boundary. */
export function installMessages(locale: Locale, catalog: LocaleMessageCatalog): void {
  active = catalog;
  activeLocale = locale;
  inflight = null;
}

function resolveLocale(locale?: string): Locale {
  if (locale && (locales as readonly string[]).includes(locale)) {
    return locale as Locale;
  }
  try {
    return getLocale();
  } catch {
    return baseLocale;
  }
}

export async function loadMessages(locale?: string): Promise<void> {
  const next = resolveLocale(locale);
  if (activeLocale === next) return;
  if (inflight) {
    await inflight;
    if (activeLocale === next) return;
  }

  const pending = (async () => {
    const loader = MESSAGE_LOCALE_LOADERS[next] ?? MESSAGE_LOCALE_LOADERS[baseLocale];
    try {
      active = await loader();
      activeLocale = next;
    } catch (err) {
      console.warn('[antiwire] failed to load locale catalog, falling back to english', err);
      try {
        active = await MESSAGE_LOCALE_LOADERS[baseLocale]();
        activeLocale = baseLocale;
      } catch (fallbackErr) {
        // Keep whatever was showing; with nothing loaded, `m.foo()` returns the key name.
        console.error('[antiwire] failed to load the english catalog too', fallbackErr);
      }
    }
  })();

  inflight = pending;
  try {
    await pending;
  } finally {
    if (inflight === pending) inflight = null;
  }
}

function resolveMessageFn(prop: string | symbol): ((...args: unknown[]) => unknown) | undefined {
  if (!active) return undefined;
  const current = Reflect.get(active, prop);
  return typeof current === 'function' ? (current as (...args: unknown[]) => unknown) : undefined;
}

/**
 * Looks up the current catalog on every call so stored `m.foo` references
 * stay valid after `loadMessages()` swaps the locale without a reload.
 * Property access is lazy so modules can capture `m.foo` before init.
 * A failed catalog falls back to English; an unknown key, or a message that
 * throws, shows the key name.
 */
export const m = new Proxy({} as MessageCatalog, {
  get(_target, prop) {
    const wrapped = (...args: unknown[]) => {
      const currentFn = resolveMessageFn(prop);
      if (!currentFn) return String(prop);
      try {
        return currentFn(...args);
      } catch {
        return String(prop);
      }
    };
    if (typeof prop === 'string') {
      const value = resolveMessageFn(prop);
      if (value) {
        return Object.assign(wrapped, value);
      }
    }
    return wrapped;
  },
});
