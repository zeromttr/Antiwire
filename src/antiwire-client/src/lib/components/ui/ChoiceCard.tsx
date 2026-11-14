import clsx from 'clsx';
import type { ReactNode } from 'react';
import styles from './ChoiceCard.module.css';

interface Props {
  selected?: boolean;
  disabled?: boolean;
  /**
   * `radio` / `checkbox` when the card sits in a radiogroup or a
   * multi-select list; otherwise it is a toggle button (aria-pressed).
   */
  role?: 'radio' | 'checkbox';
  title?: string;
  ariaLabel?: string;
  className?: string;
  onClick?: () => void;
  children?: ReactNode;
}

/**
 * The selectable-card surface shared by every "pick one of these" group:
 * scan ranges, watch intervals, snap lengths, setup choices. The caller owns
 * the content and its layout; this owns the states.
 */
export function ChoiceCard({
  selected = false,
  disabled = false,
  role,
  title,
  ariaLabel,
  className = '',
  onClick,
  children,
}: Props) {
  return (
    <button
      type="button"
      className={clsx(styles.choice, className, selected && styles.selected)}
      role={role}
      aria-checked={role ? selected : undefined}
      aria-pressed={role ? undefined : selected}
      aria-label={ariaLabel}
      title={title}
      disabled={disabled}
      onClick={onClick ? () => onClick() : undefined}
    >
      {children}
    </button>
  );
}

export default ChoiceCard;
