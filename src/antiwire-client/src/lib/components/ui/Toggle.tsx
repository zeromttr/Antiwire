import { memo } from 'react';
import { fireUiAction } from '#lib/utils/ui-action.ts';
import styles from './Toggle.module.css';

interface Props {
  checked?: boolean;
  disabled?: boolean;
  ariaLabel?: string;
  /** Called with the new value; may be async. The parent owns `checked`. */
  onCheckedChange?: (checked: boolean) => unknown;
  /** Receives a failed (sync or async) `onCheckedChange`. */
  onError?: (message: string, error: unknown) => void;
}

/** A switch. Native `button role="switch"` replacing the Bits UI Switch, same data attributes. */
export const Toggle = memo(function Toggle({
  checked = false,
  disabled = false,
  ariaLabel,
  onCheckedChange,
  onError,
}: Props) {
  function toggle() {
    if (disabled) return;
    const next = !checked;
    // Async settings/storage failures must surface through onError rather
    // than unhandled rejections.
    fireUiAction(() => onCheckedChange?.(next), { onError });
  }

  return (
    <div className={styles.toggleRoot}>
      <button
        type="button"
        role="switch"
        className="toggle"
        aria-checked={checked}
        aria-label={ariaLabel}
        disabled={disabled}
        data-state={checked ? 'checked' : 'unchecked'}
        data-disabled={disabled ? '' : undefined}
        onClick={toggle}
      >
        <span
          className="toggle-thumb"
          data-state={checked ? 'checked' : 'unchecked'}
          data-disabled={disabled ? '' : undefined}
        ></span>
      </button>
    </div>
  );
});

export default Toggle;
