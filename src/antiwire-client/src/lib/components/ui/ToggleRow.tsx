import clsx from 'clsx';
import type { ReactNode } from 'react';
import { Toggle } from './Toggle.tsx';
import styles from './ToggleRow.module.css';

interface Props {
  checked?: boolean;
  disabled?: boolean;
  label: string;
  description?: string;
  onCheckedChange?: (checked: boolean) => unknown;
  onError?: (message: string, error: unknown) => void;
  /** Shown next to the toggle while it is on. Was the `actions` snippet. */
  actions?: ReactNode;
  /** Shown under the description while the toggle is on, e.g. what it applies to. */
  details?: ReactNode;
}

export function ToggleRow({
  checked = false,
  disabled = false,
  label,
  description,
  onCheckedChange,
  onError,
  actions,
  details,
}: Props) {
  const hasDetails = details != null && details !== false;
  const hasActions = actions != null && actions !== false;
  return (
    <div className={clsx(styles.toggleRow, checked && hasDetails && styles.hasDetails)}>
      <div className={styles.text}>
        <div className={styles.label}>{label}</div>
        {description && <div className={styles.desc}>{description}</div>}
        {checked && hasDetails && <div className={styles.details}>{details}</div>}
      </div>
      <div className={styles.controls}>
        {checked && hasActions && <div className={styles.actions}>{actions}</div>}
        <Toggle
          checked={checked}
          disabled={disabled}
          onCheckedChange={onCheckedChange}
          onError={onError}
          ariaLabel={label}
        />
      </div>
    </div>
  );
}

export default ToggleRow;
