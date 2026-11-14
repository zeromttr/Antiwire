import clsx from 'clsx';
import { memo } from 'react';
import type { ThemePreference } from '#lib/models/theme.ts';
import styles from './ThemeThumbnail.module.css';

interface Props {
  theme: ThemePreference;
}

const CURVE = 'M0,24 C14,22 20,10 34,12 C48,14 54,26 68,19 C80,13 88,7 100,8';

/**
 * A miniature of the app: top bar with tabs, a stat strip and a chart card.
 * Colours are the real Obsidian / Porcelain surfaces (fixed, since each card
 * shows one theme regardless of the current one) with the live accent.
 */
function Mini({ kind }: { kind: 'dark' | 'light' }) {
  return (
    <span className={clsx(styles.mini, kind === 'light' && styles.light)}>
      <span className={styles.bar}>
        <span className={styles.logo}></span>
        <span className={clsx(styles.tab, styles.on)}></span>
        <span className={styles.tab}></span>
        <span className={styles.tab}></span>
      </span>
      <span className={styles.body}>
        <span className={styles.stats}>
          <span className={styles.stat}>
            <span className={styles.value}></span>
          </span>
          <span className={styles.stat}>
            <span className={clsx(styles.value, styles.short)}></span>
          </span>
          <span className={styles.stat}>
            <span className={styles.value}></span>
          </span>
        </span>
        <span className={styles.chart}>
          <svg viewBox="0 0 100 32" preserveAspectRatio="none" aria-hidden="true">
            <path className={styles.area} d={`${CURVE} L100,32 L0,32 Z`} />
            <path className={styles.line} d={CURVE} />
          </svg>
        </span>
      </span>
    </span>
  );
}

export const ThemeThumbnail = memo(function ThemeThumbnail({ theme }: Props) {
  return (
    <span className={styles.thumb} aria-hidden="true">
      {theme === 'system' ? (
        <>
          <Mini kind="light" />
          <span className={styles.half}>
            <Mini kind="dark" />
          </span>
        </>
      ) : (
        <Mini kind={theme} />
      )}
    </span>
  );
});

export default ThemeThumbnail;
