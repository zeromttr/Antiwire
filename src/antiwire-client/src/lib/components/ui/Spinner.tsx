import clsx from 'clsx';
import { memo, type CSSProperties } from 'react';
import styles from './Spinner.module.css';

interface Props {
  /** Diameter in pixels. */
  size?: number;
  /** Accessible label; omit when nearby text already says what is loading. */
  label?: string;
  className?: string;
}

export const Spinner = memo(function Spinner({ size = 16, label, className = '' }: Props) {
  return (
    <span
      className={clsx(styles.spinner, className)}
      style={{ '--size': `${size}px` } as CSSProperties}
      role={label ? 'status' : undefined}
      aria-label={label}
      aria-hidden={label ? undefined : 'true'}
    ></span>
  );
});

export default Spinner;
