import clsx from 'clsx';
import { Plus } from 'lucide-react';
import type { CSSProperties } from 'react';
import { ColorPicker } from '#lib/components/ui/ColorPicker.tsx';
import { m } from '#lib/i18n/messages.ts';
import { ACCENT_PRESETS, accentPresetById, isCustomAccentId } from '#lib/models/accent-colors.ts';
import { useSelector } from '#lib/state/reactive.ts';
import { client } from '#lib/stores/client.ts';
import { daemon } from '#lib/stores/daemon.ts';
import { fireUiAction } from '#lib/utils/ui-action.ts';
import styles from './AccentColorPicker.module.css';

interface Props {
  onchange?: (accentColorId: string) => void;
  /** Settings > Appearance styling: a flat section with a bolder label. */
  appearance?: boolean;
}

const ACCENT_LABEL_FNS: Record<string, () => string> = {
  cyan: m.settings_accent_cyan,
  plasma: m.settings_accent_plasma,
  violet: m.settings_accent_violet,
  magenta: m.settings_accent_magenta,
  mint: m.settings_accent_mint,
  lime: m.settings_accent_lime,
  amber: m.settings_accent_amber,
  rose: m.settings_accent_rose,
  sapphire: m.settings_accent_sapphire,
  champagne: m.settings_accent_champagne,
  lavender: m.settings_accent_lavender,
  copper: m.settings_accent_copper,
};

function accentLabel(id: string): string {
  if (isCustomAccentId(id)) return m.settings_accent_custom();
  return (ACCENT_LABEL_FNS[id] ?? m.settings_accent_mint)();
}

export function AccentColorPicker({ onchange, appearance = false }: Props) {
  const selectedId = useSelector(client, (c) => c.state.accentColorId);
  const customSelected = isCustomAccentId(selectedId);
  const current = accentPresetById(selectedId);

  async function select(id: string) {
    // A custom colour that equals a preset selects the preset itself.
    const preset = ACCENT_PRESETS.find((p) => p.color === id.toLowerCase());
    const next = preset?.id ?? id;
    await client.setAccentColor(next);
    onchange?.(next);
  }

  function onSwatchSelect(id: string) {
    fireUiAction(() => select(id), {
      onError: (message) =>
        daemon.addToast(m.settings_toast_save_failed_title(), message, 'var(--bad)'),
    });
  }

  // Dragging in the picker previews without writing settings; the colour is
  // persisted once the change settles.
  return (
    <div className={clsx(styles.accentPicker, appearance && styles.appearance)}>
      <div>
        <div className={styles.accentLabel}>{m.settings_accent_label()}</div>
        <div className={styles.accentDesc}>{m.settings_accent_desc()}</div>
      </div>
      <div className={styles.accentRow}>
        <div className={styles.swatches} role="radiogroup" aria-label={m.settings_accent_aria()}>
          {ACCENT_PRESETS.map((preset) => {
            const selected = selectedId === preset.id;
            const label = accentLabel(preset.id);
            return (
              <button
                key={preset.id}
                type="button"
                role="radio"
                aria-checked={selected}
                aria-label={label}
                className={clsx(styles.swatch, selected && styles.selected)}
                title={label}
                style={{ '--swatch': preset.color } as CSSProperties}
                onClick={() => onSwatchSelect(preset.id)}
              ></button>
            );
          })}
          <span className={styles.divider} aria-hidden="true"></span>
          <ColorPicker
            value={current.color}
            label={m.settings_accent_custom_aria()}
            className={clsx(styles.swatch, styles.custom, customSelected && styles.selected)}
            style={customSelected ? ({ '--swatch': current.color } as CSSProperties) : undefined}
            onPreview={(hex) => client.previewAccentColor(hex)}
            onChange={onSwatchSelect}
          >
            {!customSelected && <Plus size={13} strokeWidth={2} aria-hidden="true" />}
          </ColorPicker>
        </div>
        <div className={styles.current} aria-live="polite">
          <span className={styles.currentName}>{accentLabel(selectedId)}</span>
          <span className={clsx(styles.currentHex, 'mono')}>{current.color.toUpperCase()}</span>
        </div>
      </div>
    </div>
  );
}

export default AccentColorPicker;
