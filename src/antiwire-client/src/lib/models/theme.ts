import { refreshDocumentProtocolColors } from './protocol-colors';
import { persistThemeSnapshot } from './theme-snapshot';

export const THEME_PREFERENCES = ['light', 'dark', 'system'] as const;

export type ThemePreference = (typeof THEME_PREFERENCES)[number];
export type ResolvedTheme = 'light' | 'dark';

export const DEFAULT_THEME_PREFERENCE: ThemePreference = 'system';
export const THEME_STORAGE_KEY = 'antiwire-theme';

export interface ThemeAppearance {
  theme: ThemePreference;
}

const PREFERENCE_SET = new Set<string>(THEME_PREFERENCES);

export function isThemePreference(value: string | null | undefined): value is ThemePreference {
  return typeof value === 'string' && PREFERENCE_SET.has(value);
}

export function normalizeThemePreference(value: string | null | undefined): ThemePreference {
  return isThemePreference(value) ? value : DEFAULT_THEME_PREFERENCE;
}

export function resolveTheme(preference: ThemePreference, systemPrefersDark = true): ResolvedTheme {
  if (preference === 'light' || preference === 'dark') return preference;
  return systemPrefersDark ? 'dark' : 'light';
}

export function readSystemPrefersDark(): boolean {
  if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') {
    return true;
  }
  return window.matchMedia('(prefers-color-scheme: dark)').matches;
}

let systemMedia: MediaQueryList | null = null;
let systemListener: (() => void) | null = null;
let activeAppearance: ThemeAppearance | null = null;

export function serializeThemeBootState(appearance: ThemeAppearance): string {
  return JSON.stringify({ preference: appearance.theme });
}

export function parseThemeBootState(raw: string | null | undefined): Partial<ThemeAppearance> {
  if (!raw) return {};
  if (isThemePreference(raw)) return { theme: raw };
  try {
    // Older builds also stored palette and tone fields here; they are ignored.
    const parsed = JSON.parse(raw) as { preference?: string; theme?: string };
    const theme = isThemePreference(parsed.preference)
      ? parsed.preference
      : isThemePreference(parsed.theme)
        ? parsed.theme
        : undefined;
    return theme ? { theme } : {};
  } catch {
    return {};
  }
}

function persistThemeAppearance(appearance: ThemeAppearance) {
  if (typeof localStorage === 'undefined') return;
  localStorage.setItem(THEME_STORAGE_KEY, serializeThemeBootState(appearance));
}

const resolvedListeners = new Set<(resolved: ResolvedTheme) => void>();

/** Called with the resolved theme each time it is painted, including system flips. */
export function onResolvedThemeChange(listener: (resolved: ResolvedTheme) => void): () => void {
  resolvedListeners.add(listener);
  return () => resolvedListeners.delete(listener);
}

function paintResolved(appearance: ThemeAppearance, systemPrefersDark: boolean) {
  if (typeof document === 'undefined') return;
  const resolved = resolveTheme(appearance.theme, systemPrefersDark);
  for (const listener of resolvedListeners) listener(resolved);
  // Both themes live in app.css, keyed on data-theme.
  document.documentElement.dataset.theme = resolved;
  document.documentElement.style.colorScheme = resolved;
  refreshDocumentProtocolColors();
  persistThemeSnapshot();
}

function bindSystemListener(appearance: ThemeAppearance) {
  if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') return;

  if (!systemMedia) {
    systemMedia = window.matchMedia('(prefers-color-scheme: dark)');
  }
  if (systemListener) {
    systemMedia.removeEventListener('change', systemListener);
    systemListener = null;
  }
  if (appearance.theme !== 'system') return;

  systemListener = () => {
    if (!activeAppearance) return;
    paintResolved(activeAppearance, systemMedia?.matches ?? true);
  };
  systemMedia.addEventListener('change', systemListener);
}

export function applyThemeAppearance(appearance: ThemeAppearance) {
  const next: ThemeAppearance = { theme: normalizeThemePreference(appearance.theme) };
  activeAppearance = next;
  persistThemeAppearance(next);
  paintResolved(next, readSystemPrefersDark());
  bindSystemListener(next);
}
