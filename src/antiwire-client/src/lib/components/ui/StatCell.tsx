import type { ReactNode } from 'react';
import { AnimatedText } from './AnimatedText.tsx';
import { BarSpark } from './BarSpark.tsx';
import styles from './StatCell.module.css';

interface Props {
  label: string;
  value: string;
  unit?: string;
  /** Series colour: the label swatch and the bars. */
  color: string;
  /** Value text colour; defaults to primary text. */
  valueColor?: string;
  bars?: readonly number[];
  /** Fixed bar count; see BarSpark. */
  barSlots?: number;
  barsLabel?: string;
  /** Supporting line under the value (delta, context). Was the `caption` snippet. */
  caption?: ReactNode;
}

const NO_BARS: readonly number[] = [];

export function StatCell({
  label,
  value,
  unit = '',
  color,
  valueColor = 'var(--t1)',
  bars = NO_BARS,
  barSlots,
  barsLabel,
  caption,
}: Props) {
  const displayKey = unit ? `${value}\u0000${unit}` : value;
  return (
    <div className={styles.statCell}>
      <div className={styles.label}>
        <span className={styles.swatch} style={{ background: color }} aria-hidden="true"></span>
        {label}
      </div>
      <div className={styles.valueRow}>
        <AnimatedText text={displayKey} className="value-layer">
          <span className={styles.value} style={{ color: valueColor }}>
            {value}
          </span>
          {unit && <span className={styles.unit}>{unit}</span>}
        </AnimatedText>
        {(bars.length > 0 || barSlots) && (
          <BarSpark values={bars} color={color} slots={barSlots} label={barsLabel} />
        )}
      </div>
      <div className={styles.caption}>{caption}</div>
    </div>
  );
}

export default StatCell;
