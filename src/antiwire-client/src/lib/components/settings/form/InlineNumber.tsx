import { SettingsInput } from '#lib/components/ui/SettingsInput.tsx';
import styles from './InlineNumber.module.css';

/**
 * A short number with its unit, e.g. "30 days", sized to sit beside a
 * row's toggle rather than across the whole card.
 */
interface Props {
  id: string;
  value: number;
  unit: string;
  /** Accessible name; the unit is added to it. */
  label: string;
  min?: number;
  max?: number;
  invalid?: boolean;
  describedBy?: string;
  onchange: (value: number) => void;
}

export function InlineNumber({
  id,
  value,
  unit,
  label,
  min,
  max,
  invalid = false,
  describedBy,
  onchange,
}: Props) {
  return (
    <span className={styles.inlineNumber}>
      <SettingsInput
        id={id}
        type="number"
        min={min}
        max={max}
        value={value}
        invalid={invalid}
        aria-invalid={invalid}
        aria-describedby={describedBy}
        aria-label={`${label} (${unit})`}
        onInput={(event) => onchange(Number(event.currentTarget.value))}
      />
      <span className={styles.unit} aria-hidden="true">
        {unit}
      </span>
    </span>
  );
}

export default InlineNumber;
