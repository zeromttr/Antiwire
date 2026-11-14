import { DEFAULT_ACCENT_ID, normalizeAccentId } from './accent-colors';
import { DEFAULT_LOCALE, normalizeLocale } from './locales';
import { DEFAULT_THEME_PREFERENCE, normalizeThemePreference, type ThemePreference } from './theme';

export interface ClientSettings {
  accentColorId: string;
  theme: ThemePreference;
  onboardingDone: boolean;
  locale: string;
}

type ClientSettingsInput = Partial<Omit<ClientSettings, 'theme'>> & {
  theme?: string | null;
};

export const DEFAULT_CLIENT_SETTINGS: ClientSettings = {
  accentColorId: DEFAULT_ACCENT_ID,
  theme: DEFAULT_THEME_PREFERENCE,
  onboardingDone: false,
  locale: DEFAULT_LOCALE,
};

export function normalizeClientSettings(
  partial: ClientSettingsInput | null | undefined,
): ClientSettings {
  return {
    accentColorId: normalizeAccentId(
      partial?.accentColorId ?? DEFAULT_CLIENT_SETTINGS.accentColorId,
    ),
    theme: normalizeThemePreference(partial?.theme ?? DEFAULT_CLIENT_SETTINGS.theme),
    onboardingDone: partial?.onboardingDone ?? DEFAULT_CLIENT_SETTINGS.onboardingDone,
    locale: normalizeLocale(partial?.locale ?? DEFAULT_CLIENT_SETTINGS.locale),
  };
}
