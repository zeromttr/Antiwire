import clsx from 'clsx';
import { useEffect, useRef, type KeyboardEvent } from 'react';
import { moveActiveIndex } from './listbox-nav';
import type { UnderlineTab } from './underline-tabs';
import styles from './UnderlineTabs.module.css';

interface Props {
  tabs: readonly UnderlineTab[];
  value: string;
  ariaLabel?: string;
  onChange: (value: string) => void;
}

/** Section tabs in the top bar's style: text with an underline for the active one. */
export function UnderlineTabs({ tabs, value, ariaLabel, onChange }: Props) {
  const root = useRef<HTMLDivElement | null>(null);
  /** Tab to focus once the parent has applied the keyboard selection. */
  const pendingFocus = useRef<number | null>(null);

  useEffect(() => {
    const index = pendingFocus.current;
    if (index === null) return;
    pendingFocus.current = null;
    root.current?.querySelectorAll<HTMLButtonElement>('[role="tab"]')[index]?.focus();
  }, [value]);

  function onKeyDown(event: KeyboardEvent<HTMLDivElement>) {
    if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
    event.preventDefault();
    const current = tabs.findIndex((tab) => tab.value === value);
    const next = moveActiveIndex(
      current,
      tabs.length,
      event.key as 'ArrowLeft' | 'ArrowRight' | 'Home' | 'End',
      'horizontal',
    );
    const tab = tabs[next];
    if (!tab) return;
    if (tab.value === value) {
      root.current?.querySelectorAll<HTMLButtonElement>('[role="tab"]')[next]?.focus();
      return;
    }
    pendingFocus.current = next;
    onChange(tab.value);
  }

  return (
    <div
      className={styles.tabs}
      role="tablist"
      aria-label={ariaLabel}
      tabIndex={-1}
      ref={root}
      onKeyDown={onKeyDown}
    >
      {tabs.map((tab) => {
        const active = tab.value === value;
        return (
          <button
            key={tab.value}
            type="button"
            role="tab"
            className={clsx(styles.tab, active && styles.active)}
            aria-selected={active}
            tabIndex={active ? 0 : -1}
            onClick={() => onChange(tab.value)}
          >
            {tab.label}
            {tab.count !== undefined && <span className={styles.count}>{tab.count}</span>}
          </button>
        );
      })}
    </div>
  );
}

export default UnderlineTabs;
