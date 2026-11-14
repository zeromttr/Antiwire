import clsx from 'clsx';
import {
  useCallback,
  useEffect,
  useRef,
  useState,
  type CSSProperties,
  type ReactNode,
} from 'react';
import styles from './ScrollFade.module.css';

interface Props {
  /** Rows visible before the content scrolls. */
  visibleRows: number;
  /** Height of one row, in pixels. */
  rowHeight: number;
  /**
   * Horizontal bleed of the rows (their negative margin), so hover fills
   * are not clipped by the scroll container.
   */
  bleed?: number;
  className?: string;
  children?: ReactNode;
}

/**
 * A list viewport a fixed number of rows tall. Edge fades appear only on the
 * side that has more to scroll, so the list reads as scrollable without a
 * visible scrollbar fighting the design.
 */
export function ScrollFade({ visibleRows, rowHeight, bleed = 0, className = '', children }: Props) {
  const viewport = useRef<HTMLDivElement | null>(null);
  const content = useRef<HTMLDivElement | null>(null);
  const [edges, setEdges] = useState({ above: false, below: false });

  const update = useCallback(() => {
    const el = viewport.current;
    if (!el) return;
    const { scrollTop, scrollHeight, clientHeight } = el;
    const above = scrollTop > 1;
    const below = scrollTop + clientHeight < scrollHeight - 1;
    setEdges((prev) => (prev.above === above && prev.below === below ? prev : { above, below }));
  }, []);

  // Re-measure when either box changes size, e.g. rows arriving or leaving.
  useEffect(() => {
    const el = viewport.current;
    const inner = content.current;
    if (!el || !inner) return;
    // ResizeObserver reports the initial size too, so no separate first measure.
    const observer = new ResizeObserver(update);
    observer.observe(el);
    observer.observe(inner);
    return () => observer.disconnect();
  }, [update]);

  return (
    <div
      className={clsx(
        styles.scrollFade,
        className,
        edges.above && styles.moreAbove,
        edges.below && styles.moreBelow,
      )}
      style={
        {
          '--visible-rows': visibleRows,
          '--row-height': `${rowHeight}px`,
          '--bleed': `${bleed}px`,
        } as CSSProperties
      }
      ref={viewport}
      onScroll={update}
    >
      <div ref={content}>{children}</div>
    </div>
  );
}

export default ScrollFade;
