import clsx from 'clsx';
import { memo } from 'react';
import styles from './RecordsPanelSkeleton.module.css';

interface Props {
  variant: 'sidebar' | 'grid';
  rows?: number;
}

const GRID_CELLS = [
  'app',
  'host',
  'sip',
  'ip',
  'port',
  'proto',
  'state',
  'up',
  'down',
  'seen',
  'geo',
];

export const RecordsPanelSkeleton = memo(function RecordsPanelSkeleton({
  variant,
  rows = variant === 'sidebar' ? 8 : 10,
}: Props) {
  const indexes = Array.from({ length: rows }, (_, index) => index);
  if (variant === 'sidebar') {
    return (
      <div className={clsx(styles.skeletonList, styles.sidebar)} aria-hidden="true">
        {indexes.map((index) => (
          <div key={index} className={clsx(styles.skeletonRow, styles.sidebarRow)}>
            <span className={clsx(styles.shimmer, styles.avatar)}></span>
            <span className={clsx(styles.shimmer, styles.line, styles.name)}></span>
            <span className={clsx(styles.shimmer, styles.line, styles.count)}></span>
          </div>
        ))}
      </div>
    );
  }
  return (
    <div className={clsx(styles.skeletonList, styles.grid)} aria-hidden="true">
      {indexes.map((index) => (
        <div key={index} className={clsx(styles.skeletonRow, styles.gridRow)}>
          {GRID_CELLS.map((cell) => (
            <span key={cell} className={clsx(styles.shimmer, styles.cell, styles[cell])}></span>
          ))}
        </div>
      ))}
    </div>
  );
});

export default RecordsPanelSkeleton;
