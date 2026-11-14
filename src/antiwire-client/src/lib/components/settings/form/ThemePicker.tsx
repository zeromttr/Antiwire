import clsx from 'clsx';
import { useRef, type KeyboardEvent } from 'react';
import { moveActiveIndex, type ListboxNavKey } from '#lib/components/ui/listbox-nav.ts';
import { m } from '#lib/i18n/messages.ts';
import { THEME_PREFERENCES, type ThemePreference } from '#lib/models/theme.ts';
import { useSelector } from '#lib/state/reactive.ts';
import { client } from '#lib/stores/client.ts';
import { daemon } from '#lib/stores/daemon.ts';
import { ThemeThumbnail } from './ThemeThumbnail.tsx';
import styles from './ThemePicker.module.css';

const THEME_LABELS: Record<ThemePreference, () => string> = {
  light: () => m.settings_theme_light(),
  dark: () => m.settings_theme_dark(),
  system: () => m.settings_theme_system(),
};

// Dark first: it is the default and the app's home look.
const ORDER: ThemePreference[] = (['dark', 'light', 'system'] as const).filter((value) =>
  THEME_PREFERENCES.includes(value),
);
const NAV_KEYS = new Set(['ArrowDown', 'ArrowUp', 'ArrowLeft', 'ArrowRight', 'Home', 'End']);

async function choose(value: ThemePreference) {
  if (value === client.state.theme) return;
  try {
    await client.setTheme(value);
  } catch (error) {
    daemon.addToast(
      m.settings_toast_save_failed_title(),
      error instanceof Error ? error.message : String(error),
      'var(--bad)',
    );
  }
}

export function ThemePicker() {
  const theme = useSelector(client, (c) => c.state.theme);
  const buttons = useRef<(HTMLButtonElement | null)[]>([]);

  function onKeyDown(event: KeyboardEvent<HTMLButtonElement>, index: number) {
    if (!NAV_KEYS.has(event.key)) return;
    const next = moveActiveIndex(index, ORDER.length, event.key as ListboxNavKey);
    if (next < 0 || next === index) return;
    event.preventDefault();
    buttons.current[next]?.focus();
    void choose(ORDER[next]);
  }

  return (
    <div className={styles.themePicker}>
      <div>
        <div className={styles.label} id="theme-picker-label">
          {m.settings_theme_label()}
        </div>
        <div className={styles.desc}>{m.settings_theme_desc()}</div>
      </div>
      <div className={styles.cards} role="radiogroup" aria-labelledby="theme-picker-label">
        {ORDER.map((value, index) => {
          const selected = theme === value;
          return (
            <button
              key={value}
              type="button"
              role="radio"
              className={clsx(styles.card, selected && styles.selected)}
              aria-checked={selected}
              tabIndex={selected ? 0 : -1}
              ref={(element) => {
                buttons.current[index] = element;
              }}
              onClick={() => void choose(value)}
              onKeyDown={(event) => onKeyDown(event, index)}
            >
              <ThemeThumbnail theme={value} />
              <span className={styles.caption}>
                <span className={styles.radio} aria-hidden="true"></span>
                {THEME_LABELS[value]()}
              </span>
            </button>
          );
        })}
      </div>
    </div>
  );
}

export default ThemePicker;
