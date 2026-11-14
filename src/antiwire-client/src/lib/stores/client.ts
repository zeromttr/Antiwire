import { accentForTheme, accentInkColor, accentPresetById } from '#lib/models/accent-colors.ts';
import { refreshDocumentProtocolColors } from '#lib/models/protocol-colors.ts';
import { DEFAULT_CLIENT_SETTINGS, type ClientSettings } from '#lib/models/client-settings.ts';
import { normalizeLocale, type AppLocale } from '#lib/models/locales.ts';
import {
  applyThemeAppearance,
  normalizeThemePreference,
  onResolvedThemeChange,
  type ResolvedTheme,
} from '#lib/models/theme.ts';
import { persistThemeSnapshot } from '#lib/models/theme-snapshot.ts';
import { readClientSettings, writeClientSettings } from '#lib/api/client-settings.ts';
import { loadMessages } from '#lib/i18n/messages.ts';
import { getLocale, localStorageKey, setLocale } from '#lib/paraglide/runtime.js';
import { Reactive } from '#lib/state/reactive.ts';

function applyAccentColor(accentColorId: string) {
  if (typeof document === 'undefined') return;
  const preset = accentPresetById(accentColorId);
  const root = document.documentElement.style;
  // app.css derives --acc / --acc-sub / --acc-fill from these per theme; an
  // inline --acc left by an older build would pin the dark-mode value.
  root.removeProperty('--acc');
  root.removeProperty('--acc-sub');
  root.setProperty('--acc-base', preset.color);
  root.setProperty('--acc-sub-base', preset.subColor);
  root.setProperty('--on-acc', accentInkColor(preset.color));
  refreshDocumentProtocolColors();
  persistThemeSnapshot();
}

function applyAppearance(settings: ClientSettings) {
  applyThemeAppearance({ theme: settings.theme });
}

function applyDocumentLocale(locale: AppLocale) {
  if (typeof document === 'undefined') return;
  document.documentElement.lang = locale;
}

function syncParaglideLocalStorage(locale: AppLocale) {
  if (typeof localStorage === 'undefined') return;
  localStorage.setItem(localStorageKey, locale);
}

export type ChartColors = { download: string; upload: string };

/**
 * Client-only preferences. `state` is replaced, never mutated, whenever the
 * settings change, so `useSelector(client, (c) => c.state.theme)` and
 * `useSelector(client, (c) => c.state)` both compare by reference.
 */
export class ClientStore extends Reactive {
  #state: ClientSettings = { ...DEFAULT_CLIENT_SETTINGS };
  /** The first load; later callers share it. Cleared on failure so a later call retries. */
  #init: Promise<void> | null = null;
  #resolvedTheme: ResolvedTheme = 'dark';
  /** Accent shown while the custom color picker is being dragged; not yet saved. */
  #previewAccentId: string | null = null;
  #chartColors: { accentId: string; theme: ResolvedTheme; colors: ChartColors } | null = null;

  constructor() {
    super();
    onResolvedThemeChange((next) => {
      if (next === this.#resolvedTheme) return;
      this.#resolvedTheme = next;
      this.changed();
    });
  }

  get state(): ClientSettings {
    return this.#state;
  }

  get resolvedTheme(): ResolvedTheme {
    return this.#resolvedTheme;
  }

  /** Literal colors for canvas/SVG charts, which cannot resolve CSS variables. Stable until they change. */
  get chartColors(): ChartColors {
    const accentId = this.#previewAccentId ?? this.#state.accentColorId;
    const theme = this.#resolvedTheme;
    const cached = this.#chartColors;
    if (cached && cached.accentId === accentId && cached.theme === theme) return cached.colors;
    const preset = accentPresetById(accentId);
    const colors = {
      download: accentForTheme(preset.color, theme),
      upload: accentForTheme(preset.subColor, theme),
    };
    this.#chartColors = { accentId, theme, colors };
    return colors;
  }

  #setState(next: ClientSettings) {
    this.#state = next;
    this.changed();
  }

  /**
   * Loads the stored settings once. Every caller waits for the same load, so a
   * second caller (StrictMode re-running the start-up effect in dev) never
   * sees the defaults, and would otherwise reopen onboarding.
   */
  readonly init = (): Promise<void> => {
    this.#init ??= this.#load().catch((error: unknown) => {
      this.#init = null;
      throw error;
    });
    return this.#init;
  };

  async #load() {
    const settings = await readClientSettings();
    this.#setState(settings);
    const locale = normalizeLocale(settings.locale);
    syncParaglideLocalStorage(locale);
    applyDocumentLocale(locale);
    if (getLocale() !== locale) {
      setLocale(locale, { reload: false });
    }
    await loadMessages(locale);
    applyAccentColor(settings.accentColorId);
    applyAppearance(settings);
  }

  readonly setAccentColor = async (accentColorId: string) => {
    this.#previewAccentId = null;
    const next = await writeClientSettings({ accentColorId });
    this.#setState(next);
    applyAccentColor(next.accentColorId);
  };

  readonly previewAccentColor = (accentColorId: string) => {
    if (this.#previewAccentId !== accentColorId) {
      this.#previewAccentId = accentColorId;
      this.changed();
    }
    applyAccentColor(accentColorId);
  };

  readonly setTheme = async (theme: string) => {
    const nextTheme = normalizeThemePreference(theme);
    if (nextTheme === this.#state.theme) {
      applyAppearance(this.#state);
      return;
    }
    const next = await writeClientSettings({ theme: nextTheme });
    this.#setState(next);
    applyAppearance(next);
  };

  readonly setAppLocale = async (locale: string) => {
    const nextLocale = normalizeLocale(locale);
    if (nextLocale === normalizeLocale(this.#state.locale) && nextLocale === getLocale()) {
      return;
    }

    const next = await writeClientSettings({ locale: nextLocale });
    this.#setState(next);
    applyDocumentLocale(nextLocale);
    // Do not write PARAGLIDE_LOCALE before setLocale — that makes getLocale()
    // already return the new locale, so Paraglide skips its document reload and
    // the UI only updates after the next navigation remounts components.
    setLocale(nextLocale);
  };

  readonly completeOnboarding = async () => {
    const next = await writeClientSettings({ onboardingDone: true });
    this.#setState(next);
  };
}

export const client = new ClientStore();
