import clsx from 'clsx';
import type { ReactNode } from 'react';
import styles from './EmptyState.module.css';

interface Props {
  text?: string;
  detail?: string;
  panel?: boolean;
  compact?: boolean;
  className?: string;
  children?: ReactNode;
}

export function EmptyState({
  text = '',
  detail = '',
  panel = false,
  compact = false,
  className = '',
  children,
}: Props) {
  return (
    <div
      className={clsx(styles.emptyState, className, panel && 'panel', compact && styles.compact)}
      role="status"
    >
      {text && <div className={styles.emptyText}>{text}</div>}
      {detail && <div className={styles.emptyDetail}>{detail}</div>}
      {children}
    </div>
  );
}

export default EmptyState;
