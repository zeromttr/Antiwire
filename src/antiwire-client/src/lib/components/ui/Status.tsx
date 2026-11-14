import clsx from 'clsx';
import { memo, type ReactNode } from 'react';
import type { StatusTone } from './status-tone';
import styles from './Status.module.css';

interface Props {
  tone?: StatusTone;
  /** Softer text colour for dense tables; the dot keeps the tone. */
  quiet?: boolean;
  title?: string;
  className?: string;
  children?: ReactNode;
}

/** State reads as a 6px dot plus a word, never a filled pill. */
export const Status = memo(function Status({
  tone = 'idle',
  quiet = false,
  title,
  className = '',
  children,
}: Props) {
  return (
    <span
      className={clsx(styles.status, styles[tone], className, quiet && styles.quiet)}
      title={title}
    >
      {/* `dot` is also a global hook (background-mode pause in app.css). */}
      <span className={clsx(styles.dot, 'dot')} aria-hidden="true"></span>
      {children != null && children !== false && <span className={styles.text}>{children}</span>}
    </span>
  );
});

export default Status;
