import clsx from 'clsx';
import { ChevronDown, ChevronUp } from 'lucide-react';
import type { ChangeEvent, InputHTMLAttributes } from 'react';
import { m } from '#lib/i18n/messages.ts';
import styles from './SettingsInput.module.css';

type Props = Omit<
  InputHTMLAttributes<HTMLInputElement>,
  'className' | 'value' | 'onInput' | 'onChange'
> & {
  invalid?: boolean;
  className?: string;
  value?: string | number;
  /**
   * `bind:value`: the new text, or for `type="number"` the number
   * (`undefined` while the field is empty).
   */
  onValueChange?: (value: string | number | undefined) => void;
  /**
   * Every edit, read as `event.currentTarget.value`. The stepper buttons call
   * it too, with an event-like object carrying only `currentTarget.value`.
   */
  onInput?: (event: ChangeEvent<HTMLInputElement>) => void;
};

const INPUT_ATTRS = {
  autoComplete: 'off',
  autoCapitalize: 'off',
  autoCorrect: 'off',
  spellCheck: false,
  'data-lpignore': 'true',
  'data-1p-ignore': true,
  'data-form-type': 'other',
} as const;

export function SettingsInput({
  invalid = false,
  className = '',
  type = 'text',
  value,
  onValueChange,
  onInput,
  min,
  max,
  step,
  disabled = false,
  ...rest
}: Props) {
  const stepSize = Number(step ?? 1) || 1;
  const numericValue = Number(value ?? 0) || 0;
  const minVal = min != null && min !== '' ? Number(min) : undefined;
  const maxVal = max != null && max !== '' ? Number(max) : undefined;
  const canIncrement = !disabled && (maxVal == null || numericValue + stepSize <= maxVal);
  const canDecrement = !disabled && (minVal == null || numericValue - stepSize >= minVal);

  function handleChange(event: ChangeEvent<HTMLInputElement>) {
    const raw = event.currentTarget.value;
    onValueChange?.(type === 'number' ? (raw === '' ? undefined : Number(raw)) : raw);
    onInput?.(event);
  }

  function adjust(delta: number) {
    if (disabled) return;
    let next = numericValue + delta * stepSize;
    if (minVal != null && next < minVal) next = minVal;
    if (maxVal != null && next > maxVal) next = maxVal;
    if (next === numericValue) return;
    onValueChange?.(next);
    onInput?.({
      currentTarget: { value: String(next) },
    } as unknown as ChangeEvent<HTMLInputElement>);
  }

  const shown = value ?? '';

  if (type === 'number') {
    return (
      <div className={clsx(styles.settingsNumberWrap, disabled && styles.disabled)}>
        <input
          {...rest}
          {...INPUT_ATTRS}
          type="number"
          min={min}
          max={max}
          step={step}
          disabled={disabled}
          value={shown}
          onChange={handleChange}
          className={clsx(
            styles.settingsInput,
            styles.settingsInputNumber,
            'mono',
            className,
            invalid && styles.invalid,
          )}
        />
        <div className={styles.steppers}>
          <button
            type="button"
            className={styles.stepperBtn}
            disabled={!canIncrement}
            aria-label={m.common_increase_value_aria()}
            tabIndex={-1}
            onClick={() => adjust(1)}
          >
            <ChevronUp size={12} strokeWidth={2.25} />
          </button>
          <button
            type="button"
            className={styles.stepperBtn}
            disabled={!canDecrement}
            aria-label={m.common_decrease_value_aria()}
            tabIndex={-1}
            onClick={() => adjust(-1)}
          >
            <ChevronDown size={12} strokeWidth={2.25} />
          </button>
        </div>
      </div>
    );
  }

  return (
    <input
      {...rest}
      {...INPUT_ATTRS}
      type={type}
      disabled={disabled}
      value={shown}
      onChange={handleChange}
      className={clsx(styles.settingsInput, 'mono', className, invalid && styles.invalid)}
    />
  );
}

export default SettingsInput;
