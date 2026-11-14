import clsx from 'clsx';
import { Check } from 'lucide-react';
import {
  memo,
  useCallback,
  useEffect,
  useLayoutEffect,
  useRef,
  useState,
  type CSSProperties,
  type FocusEvent,
  type KeyboardEvent,
  type MouseEvent,
  type ReactNode,
} from 'react';
import { createPortal } from 'react-dom';
import { m } from '#lib/i18n/messages.ts';
import { copyText } from '#lib/utils/clipboard.ts';
import { onPointerOutside } from '#lib/utils/floating-tip.ts';
import styles from './Tooltip.module.css';

/** When a tooltip closed moments ago, the next one opens without waiting:
 * scanning along a row of icons should not re-pay the hover delay. */
const WARM_WINDOW_MS = 500;
let lastHiddenAt = 0;

const VIEWPORT_MARGIN = 8;
const GAP = 8;
const SHOW_DELAY_MS = 250;
const COPIED_FEEDBACK_MS = 1400;
const HIDE_DELAY_MS = 120;

interface Props {
  /** The full value: shown in the tip and copied on click / Enter. Empty renders the children only. */
  text: string;
  /** Small heading above the value; also names the copy action. */
  label?: string;
  children?: ReactNode;
}

interface Position {
  x: number;
  y: number;
  arrow: number;
  placement: 'top' | 'bottom';
}

function getAnchorRect(el: HTMLElement): DOMRect {
  const box = el.getBoundingClientRect();
  if (!el.textContent?.trim()) return box;

  try {
    const range = document.createRange();
    range.selectNodeContents(el);
    const textRect = range.getBoundingClientRect();
    if (!textRect.width && !textRect.height) return box;

    // Clamp to the trigger's visible box so ellipsized overflow isn't included.
    const visibleLeft = Math.max(textRect.left, box.left);
    const visibleRight = Math.min(textRect.right, box.right);
    const visibleWidth = Math.max(0, visibleRight - visibleLeft);
    if (visibleWidth <= 0) return box;
    return new DOMRect(visibleLeft, box.top, visibleWidth, box.height);
  } catch {
    return box;
  }
}

/** Copy-on-click text with a detail tip showing the full value. */
export const Tooltip = memo(function Tooltip({ text, label = 'DETAILS', children }: Props) {
  const [visible, setVisible] = useState(false);
  const [hovered, setHovered] = useState(false);
  const [copied, setCopied] = useState(false);
  const [pinned, setPinned] = useState(false);
  const [position, setPosition] = useState<Position>({ x: 0, y: 0, arrow: 0, placement: 'top' });

  const tooltipEl = useRef<HTMLDivElement | null>(null);
  const triggerEl = useRef<HTMLElement | null>(null);
  const pinnedRef = useRef(false);
  const hoveredRef = useRef(false);
  const visibleRef = useRef(false);
  const resetTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const hideTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const showTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const positionFrame = useRef<number | null>(null);

  useLayoutEffect(() => {
    pinnedRef.current = pinned;
    hoveredRef.current = hovered;
    visibleRef.current = visible;
  });

  const clearTimer = (timer: { current: ReturnType<typeof setTimeout> | null }) => {
    if (timer.current) {
      clearTimeout(timer.current);
      timer.current = null;
    }
  };

  const updatePosition = useCallback(() => {
    const trigger = triggerEl.current;
    const tip = tooltipEl.current;
    if (!trigger || !tip) return;

    const rect = getAnchorRect(trigger);
    const tipRect = tip.getBoundingClientRect();
    const vw = window.innerWidth;
    const vh = window.innerHeight;

    const spaceAbove = rect.top;
    const spaceBelow = vh - rect.bottom;
    const tipHeight = tipRect.height || 48;
    const placement =
      spaceAbove < tipHeight + GAP + VIEWPORT_MARGIN && spaceBelow > spaceAbove ? 'bottom' : 'top';

    let left = rect.left + rect.width / 2 - tipRect.width / 2;
    left = Math.max(VIEWPORT_MARGIN, Math.min(left, vw - tipRect.width - VIEWPORT_MARGIN));

    const anchorX = rect.left + rect.width / 2;
    const arrow = Math.max(14, Math.min(tipRect.width - 14, anchorX - left));
    const y = placement === 'top' ? rect.top - GAP : rect.bottom + GAP;
    setPosition((prev) =>
      prev.x === left && prev.y === y && prev.arrow === arrow && prev.placement === placement
        ? prev
        : { x: left, y, arrow, placement },
    );
  }, []);

  const schedulePosition = useCallback(() => {
    if (positionFrame.current != null) cancelAnimationFrame(positionFrame.current);
    positionFrame.current = requestAnimationFrame(() => {
      positionFrame.current = requestAnimationFrame(() => {
        positionFrame.current = null;
        updatePosition();
      });
    });
  }, [updatePosition]);

  useEffect(
    () => () => {
      clearTimer(showTimer);
      clearTimer(hideTimer);
      clearTimer(resetTimer);
      if (positionFrame.current != null) cancelAnimationFrame(positionFrame.current);
    },
    [],
  );

  function show(event: FocusEvent<HTMLElement>) {
    if (!text || pinnedRef.current) return;
    clearTimer(hideTimer);
    clearTimer(showTimer);
    triggerEl.current = event.currentTarget;
    setVisible(true);
  }

  function scheduleShow(event: MouseEvent<HTMLElement>) {
    if (!text || pinnedRef.current) return;
    clearTimer(hideTimer);
    clearTimer(showTimer);
    triggerEl.current = event.currentTarget;
    showTimer.current = setTimeout(
      () => {
        showTimer.current = null;
        if (!hoveredRef.current || pinnedRef.current) return;
        setVisible(true);
      },
      performance.now() - lastHiddenAt < WARM_WINDOW_MS ? 0 : SHOW_DELAY_MS,
    );
  }

  function hideSoon() {
    if (pinnedRef.current) return;
    clearTimer(showTimer);
    clearTimer(hideTimer);
    hideTimer.current = setTimeout(() => {
      if (pinnedRef.current) return;
      clearTimer(resetTimer);
      if (visibleRef.current) lastHiddenAt = performance.now();
      setVisible(false);
      setCopied(false);
      setHovered(false);
      triggerEl.current = null;
    }, HIDE_DELAY_MS);
  }

  function onMouseEnter(event: MouseEvent<HTMLElement>) {
    setHovered(true);
    hoveredRef.current = true;
    scheduleShow(event);
  }

  function onMouseLeave() {
    if (pinnedRef.current) return;
    setHovered(false);
    hoveredRef.current = false;
    clearTimer(showTimer);
    hideSoon();
  }

  function resetCopiedState() {
    clearTimer(resetTimer);
    setCopied(false);
    setPinned(false);
    pinnedRef.current = false;
    setVisible(false);
    setHovered(false);
    triggerEl.current = null;
  }

  function beginCopiedFeedback(event: MouseEvent<HTMLElement> | KeyboardEvent<HTMLElement>) {
    if (!text) return;
    event.preventDefault();
    event.stopPropagation();

    clearTimer(showTimer);
    clearTimer(hideTimer);
    triggerEl.current = event.currentTarget;
    setVisible(true);
    setPinned(true);
    pinnedRef.current = true;
    setCopied(true);
    schedulePosition();

    clearTimer(resetTimer);
    resetTimer.current = setTimeout(resetCopiedState, COPIED_FEEDBACK_MS);
  }

  function onTriggerClick(event: MouseEvent<HTMLElement>) {
    if (!text) return;
    beginCopiedFeedback(event);
    void copyText(text);
  }

  function onTriggerKeyDown(event: KeyboardEvent<HTMLElement>) {
    if (event.key !== 'Enter' && event.key !== ' ') return;
    beginCopiedFeedback(event);
    void copyText(text);
  }

  // `mouseleave` never arrives if the row holding this trigger is moved while
  // hovered (live lists re-sort); see `onPointerOutside`.
  useEffect(() => {
    if (!hovered) return;
    return onPointerOutside(() => triggerEl.current, onMouseLeave);
    // `onMouseLeave` only reads refs and stable setters.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [hovered]);

  const open = visible && Boolean(text);

  useEffect(() => {
    if (!open || !tooltipEl.current || !triggerEl.current) return;
    schedulePosition();
    window.addEventListener('resize', schedulePosition);
    window.addEventListener('scroll', schedulePosition, true);
    return () => {
      window.removeEventListener('resize', schedulePosition);
      window.removeEventListener('scroll', schedulePosition, true);
    };
  }, [open, schedulePosition]);

  useEffect(() => {
    if (!open || !copied) return;
    schedulePosition();
  }, [open, copied, schedulePosition]);

  return (
    <>
      {text ? (
        <button
          type="button"
          className={clsx(
            // Global hook: parents restyle the trigger with `:global(.tooltip-trigger)`.
            'tooltip-trigger',
            styles.tooltipTrigger,
            styles.copyable,
            hovered && styles.hovered,
            pinned && styles.pinned,
          )}
          onMouseEnter={onMouseEnter}
          onMouseLeave={onMouseLeave}
          onFocus={show}
          onBlur={hideSoon}
          onClick={onTriggerClick}
          onKeyDown={onTriggerKeyDown}
          aria-label={m.common_copy_aria({ label: label.toLowerCase() })}
        >
          {children}
        </button>
      ) : (
        <span className={clsx('tooltip-trigger', styles.tooltipTrigger)}>{children}</span>
      )}

      {open &&
        createPortal(
          <div
            ref={tooltipEl}
            className={clsx(
              styles.tooltip,
              'mono',
              position.placement === 'bottom' && styles.below,
              copied && styles.copied,
            )}
            style={
              {
                '--tip-x': `${position.x}px`,
                '--tip-y': `${position.y}px`,
                '--arrow-x': `${position.arrow}px`,
              } as CSSProperties
            }
            role="tooltip"
          >
            <div className={styles.tooltipBody}>
              <div className={clsx(styles.tooltipDetail, copied && styles.hide)}>
                <span className={styles.tooltipLabel}>{label}</span>
                <span className={styles.tooltipText}>{text}</span>
              </div>
              <div className={clsx(styles.copiedRow, copied && styles.show)}>
                <Check size={12} strokeWidth={2.5} aria-hidden="true" />
                <span>{m.common_copied()}</span>
              </div>
            </div>
          </div>,
          document.body,
        )}
    </>
  );
});

export default Tooltip;
