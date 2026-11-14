export const THEME_CSS_STORAGE_KEY = 'antiwire-theme-css';

/**
 * Only the user's accent is snapshotted: surface and text colors come from
 * app.css per `data-theme`, and restoring them inline would pin one theme's
 * values over the other's.
 */
export const THEME_SNAPSHOT_VARS = ['--acc-base', '--acc-sub-base', '--on-acc'] as const;

export interface ThemeSnapshot {
  theme: 'light' | 'dark';
  vars: Record<string, string>;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value && typeof value === 'object' ? (value as Record<string, unknown>) : null;
}

export function normalizeThemeSnapshot(value: unknown): ThemeSnapshot | null {
  const row = asRecord(value);
  if (!row) return null;
  const theme = row.theme === 'light' || row.theme === 'dark' ? row.theme : null;
  const rawVars = asRecord(row.vars) ?? row;
  const vars: Record<string, string> = {};
  for (const name of THEME_SNAPSHOT_VARS) {
    const next = rawVars[name];
    if (typeof next === 'string' && next.trim()) vars[name] = next.trim();
  }
  if (!theme && Object.keys(vars).length === 0) return null;
  return { theme: theme ?? 'dark', vars };
}

export function captureThemeSnapshot(): ThemeSnapshot | null {
  if (typeof document === 'undefined') return null;
  const root = document.documentElement;
  const styles = getComputedStyle(root);
  const vars: Record<string, string> = {};
  for (const name of THEME_SNAPSHOT_VARS) {
    const next = styles.getPropertyValue(name).trim() || root.style.getPropertyValue(name).trim();
    if (next) vars[name] = next;
  }
  const theme = root.dataset.theme === 'light' ? 'light' : 'dark';
  return { theme, vars };
}

export function applyThemeSnapshot(value: unknown): ThemeSnapshot | null {
  const snapshot = normalizeThemeSnapshot(value);
  if (!snapshot || typeof document === 'undefined') return snapshot;
  const root = document.documentElement;
  root.dataset.theme = snapshot.theme;
  root.style.colorScheme = snapshot.theme;
  for (const [name, next] of Object.entries(snapshot.vars)) {
    root.style.setProperty(name, next);
  }
  return snapshot;
}

export function persistThemeSnapshot(
  snapshot: ThemeSnapshot | null = captureThemeSnapshot(),
): void {
  if (!snapshot || typeof localStorage === 'undefined') return;
  localStorage.setItem(THEME_CSS_STORAGE_KEY, JSON.stringify(snapshot));
}

export function readPersistedThemeSnapshot(): ThemeSnapshot | null {
  if (typeof localStorage === 'undefined') return null;
  try {
    return normalizeThemeSnapshot(JSON.parse(localStorage.getItem(THEME_CSS_STORAGE_KEY) ?? ''));
  } catch {
    return null;
  }
}
