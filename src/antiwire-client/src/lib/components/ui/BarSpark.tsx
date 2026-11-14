import clsx from 'clsx';
import { memo, type CSSProperties } from 'react';
import styles from './BarSpark.module.css';

interface Props {
  values: readonly number[];
  /** Bar colour; any CSS colour, including theme variables. */
  color?: string;
  /** Emphasise the newest bar and fade the history behind it. */
  highlightLast?: boolean;
  /** Pixels, or any CSS length such as `100%` to fill the container. */
  width?: number | string;
  height?: number;
  /** Gap between bars in pixels. */
  gap?: number;
  /**
   * Fixed bar count. Shorter series are padded with empty slots on the left,
   * so bars keep a steady width and fill in from the right as data arrives.
   */
  slots?: number;
  label?: string;
}

export const BarSpark = memo(function BarSpark({
  values,
  color = 'var(--acc)',
  highlightLast = true,
  width = 88,
  height = 30,
  gap = 2,
  slots,
  label,
}: Props) {
  const series =
    slots && values.length < slots
      ? [...new Array<number>(slots - values.length).fill(0), ...values]
      : slots
        ? values.slice(-slots)
        : values;
  const peak = Math.max(0, ...series.map((value) => (Number.isFinite(value) ? value : 0)));
  // Zero-height bars keep a 1.5px tick so an idle series still reads as a baseline.
  const bars = series.map((value) => (peak > 0 && value > 0 ? Math.max(0.06, value / peak) : 0));

  return (
    <div
      className={clsx(styles.barSpark, highlightLast && styles.highlight)}
      style={
        {
          '--bar-color': color,
          width: typeof width === 'number' ? `${width}px` : width,
          gap: `${gap}px`,
          height: `${height}px`,
        } as CSSProperties
      }
      role={label ? 'img' : undefined}
      aria-label={label}
      aria-hidden={label ? undefined : 'true'}
    >
      {bars.map((fraction, index) => (
        <span
          key={index}
          className={styles.bar}
          style={{ '--fraction': fraction } as CSSProperties}
        ></span>
      ))}
    </div>
  );
});

export default BarSpark;
