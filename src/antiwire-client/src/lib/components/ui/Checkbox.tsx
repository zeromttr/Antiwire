import clsx from 'clsx';
import { Check, Minus } from 'lucide-react';
import { memo } from 'react';
import styles from './Checkbox.module.css';

interface Props {
  checked?: boolean;
  indeterminate?: boolean;
  disabled?: boolean;
  ariaLabel?: string;
  /** Render as a circle, for single-choice lists. */
  round?: boolean;
  /**
   * Draw the mark only, for rows that are themselves the control (a list
   * option or a choice card): a nested button would be invalid there.
   */
  decorative?: boolean;
  /** Called with the toggled value. */
  onCheckedChange?: (checked: boolean) => void;
  /** Same as `onCheckedChange`; kept for call sites that used `onchange`. */
  onChange?: (checked: boolean) => void;
}

/** Controlled: clicking reports `!checked`; the parent owns the value. */
export const Checkbox = memo(function Checkbox({
  checked = false,
  indeterminate = false,
  disabled = false,
  ariaLabel,
  round = false,
  decorative = false,
  onCheckedChange,
  onChange,
}: Props) {
  function toggle() {
    if (disabled) return;
    const next = !checked;
    onCheckedChange?.(next);
    onChange?.(next);
  }

  const mark = round ? (
    checked ? (
      <span className={clsx(styles.pip, styles.mark)} aria-hidden="true"></span>
    ) : null
  ) : indeterminate ? (
    <span className={styles.mark} aria-hidden="true">
      <Minus size={11} strokeWidth={3} />
    </span>
  ) : checked ? (
    <span className={styles.mark} aria-hidden="true">
      <Check size={11} strokeWidth={3} />
    </span>
  ) : null;

  const on = checked || indeterminate;

  if (decorative) {
    return (
      <span
        className={clsx(
          styles.checkbox,
          round && styles.round,
          on && styles.on,
          disabled && styles.disabled,
        )}
        aria-hidden="true"
      >
        {mark}
      </span>
    );
  }

  return (
    <button
      type="button"
      role={round ? 'radio' : 'checkbox'}
      className={clsx(styles.checkbox, round && styles.round, on && styles.on)}
      aria-checked={indeterminate ? 'mixed' : checked}
      aria-label={ariaLabel}
      disabled={disabled}
      onClick={toggle}
    >
      {mark}
    </button>
  );
});

export default Checkbox;
