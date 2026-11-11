import { invoke } from '#lib/bridge.ts';
import {
  DEFAULT_CLIENT_SETTINGS,
  normalizeClientSettings,
  type ClientSettings,
} from '#lib/models/client-settings.ts';
import { THEME_STORAGE_KEY, serializeThemeBootState } from '#lib/models/theme.ts';
import { isNative } from '#lib/utils/index.ts';

/**
 * Client-only preferences (theme, accent, locale, onboarding). In the app they
 * live in a file the main process owns; the browser preview keeps them in
 * localStorage. Either way the theme is mirrored to localStorage so the boot
 * script can paint the right theme before any module loads.
 */
const BROWSER_STORAGE_KEY = 'antiwire-client-settings';
const LEGACY_ONBOARDING_KEY = 'antiwire-onboarding-done';

function browserLoad(): ClientSettings {
  if (typeof localStorage === 'undefined') return { ...DEFAULT_CLIENT_SETTINGS };
  try {
    const raw = localStorage.getItem(BROWSER_STORAGE_KEY);
    if (!raw) return { ...DEFAULT_CLIENT_SETTINGS };
    return normalizeClientSettings(JSON.parse(raw) as Partial<ClientSettings>);
  } catch {
    return { ...DEFAULT_CLIENT_SETTINGS };
  }
}

function persistThemeBootKey(settings: ClientSettings) {
  if (typeof localStorage === 'undefined') return;
  localStorage.setItem(THEME_STORAGE_KEY, serializeThemeBootState({ theme: settings.theme }));
}

export async function readClientSettings(): Promise<ClientSettings> {
  if (!isNative()) return browserLoad();
  const stored = normalizeClientSettings(
    (await invoke<Partial<ClientSettings> | null>('get_client_settings')) ?? {},
  );
  if (!stored.onboardingDone && typeof localStorage !== 'undefined') {
    if (localStorage.getItem(LEGACY_ONBOARDING_KEY)) {
      localStorage.removeItem(LEGACY_ONBOARDING_KEY);
      return writeClientSettings({ onboardingDone: true });
    }
  }
  return stored;
}

let writeQueue: Promise<ClientSettings> = Promise.resolve(DEFAULT_CLIENT_SETTINGS);

/** Applies `patch` on top of the stored settings. Writes are serialized. */
export function writeClientSettings(patch: Partial<ClientSettings>): Promise<ClientSettings> {
  writeQueue = writeQueue
    .catch(() => DEFAULT_CLIENT_SETTINGS)
    .then(async () => {
      if (!isNative()) {
        const next = normalizeClientSettings({ ...browserLoad(), ...patch });
        localStorage.setItem(BROWSER_STORAGE_KEY, JSON.stringify(next));
        persistThemeBootKey(next);
        return next;
      }
      const next = normalizeClientSettings(
        (await invoke<Partial<ClientSettings>>('set_client_settings', { patch })) ?? {},
      );
      persistThemeBootKey(next);
      return next;
    });
  return writeQueue;
}
