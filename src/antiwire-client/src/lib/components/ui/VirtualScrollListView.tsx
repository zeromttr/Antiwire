import { useVirtualizer } from '@tanstack/react-virtual';
import clsx from 'clsx';
import { useCallback, useEffect, useRef, type ReactNode } from 'react';
import { resolveVirtualItemKey, type VirtualItemKeyFn } from './virtual-scroll-list';
import styles from './VirtualScrollListView.module.css';

export interface VirtualScrollListProps<T> {
  items: readonly T[];
  /** Fixed row height in pixels (rows are not measured). */
  estimateSize?: number;
  overscan?: number;
  /** Stable row key; falls back to the index (see `resolveVirtualItemKey`). */
  getItemKey?: VirtualItemKeyFn<T>;
  /**
   * Renders one row (was the `row` snippet). Keep it cheap and render a
   * memoized row component from it: it runs for every visible row on scroll.
   */
  row: (args: { item: T; index: number }) => ReactNode;
  /** Shown instead of the list while `items` is empty (was the `empty` snippet). */
  empty?: ReactNode;
  className?: string;
}

const SCROLL_IDLE_MS = 100;

export function VirtualScrollListView<T>({
  items,
  estimateSize = 42,
  overscan = 8,
  getItemKey,
  row,
  empty,
  className = '',
}: VirtualScrollListProps<T>) {
  const scrollEl = useRef<HTMLDivElement | null>(null);
  const scrollIdleTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const estimate = useCallback(() => estimateSize, [estimateSize]);
  const itemKey = useCallback(
    (index: number) => resolveVirtualItemKey(index, items, getItemKey),
    [items, getItemKey],
  );
  // eslint-disable-next-line react-hooks/incompatible-library -- TanStack Virtual returns mutable instance methods; this component is not compiled by React Compiler.
  const virtualizer = useVirtualizer<HTMLDivElement, HTMLDivElement>({
    count: items.length,
    getScrollElement: () => scrollEl.current,
    estimateSize: estimate,
    overscan,
    getItemKey: itemKey,
  });

  // Pointer events pause while scrolling so rows do not run hover work under
  // a moving list. A class toggle, not state: scrolling must not re-render.
  function onScroll() {
    const el = scrollEl.current;
    if (!el) return;
    el.classList.add(styles.isScrolling);
    if (scrollIdleTimer.current) clearTimeout(scrollIdleTimer.current);
    scrollIdleTimer.current = setTimeout(() => {
      el.classList.remove(styles.isScrolling);
      scrollIdleTimer.current = null;
    }, SCROLL_IDLE_MS);
  }

  useEffect(
    () => () => {
      if (scrollIdleTimer.current) clearTimeout(scrollIdleTimer.current);
    },
    [],
  );

  return (
    <div className={clsx(styles.virtualScroll, className)} ref={scrollEl} onScroll={onScroll}>
      {items.length === 0 ? (
        empty
      ) : (
        <div className={styles.virtualInner} style={{ height: `${virtualizer.getTotalSize()}px` }}>
          {virtualizer.getVirtualItems().map((vRow) => {
            const item = items[vRow.index];
            if (item === undefined) return null;
            return (
              <div
                key={vRow.key}
                className={styles.virtualRow}
                style={{
                  height: `${vRow.size}px`,
                  transform: `translate3d(0, ${vRow.start}px, 0)`,
                }}
              >
                {row({ item, index: vRow.index })}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

export default VirtualScrollListView;
