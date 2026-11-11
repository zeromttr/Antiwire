import clsx from 'clsx';
import { memo, type CSSProperties } from 'react';
import styles from './ValueSlider.module.css';

interface Props {
  value: number;
  label: string;
  disabled?: boolean;
  /** Unit rendered after the number inside the knob, e.g. `%`. */
  suffix?: string;
  /** Inclusive ends of the range. Defaults cover a percentage. */
  min?: number;
  max?: number;
  /** Fires on every movement with the new value. */
  onInput?: (value: number) => void;
}

export const ValueSlider = memo(function ValueSlider({
  value,
  label,
  disabled = false,
  suffix = '',
  min = 0,
  max = 100,
  onInput,
}: Props) {
  const shown = Math.min(max, Math.max(min, value));
  const pct = max === min ? 0 : (shown - min) / (max - min);
  return (
    <div
      className={clsx(
        styles.valueSlider,
        disabled && styles.disabled,
        suffix !== '' && styles.hasSuffix,
      )}
    >
      <div className={styles.sliderField} style={{ '--pct': pct } as CSSProperties}>
        <input
          className={styles.valueInput}
          type="range"
          min={min}
          max={max}
          step="1"
          aria-valuemin={min}
          aria-valuemax={max}
          aria-valuenow={shown}
          aria-label={label}
          value={shown}
          disabled={disabled}
          onChange={(event) => onInput?.(Number(event.currentTarget.value))}
        />
        <span className={clsx(styles.valueKnob, 'mono')} aria-hidden="true">
          {shown}
          {suffix}
        </span>
      </div>
    </div>
  );
});

export default ValueSlider;
