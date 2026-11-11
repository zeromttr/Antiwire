import clsx from 'clsx';
import {
  memo,
  useCallback,
  useEffect,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
  type KeyboardEvent,
} from 'react';
import {
  normalizeSegmentedOptions,
  type SegmentedOption,
  type SegmentedTone,
} from './segmented-control.ts';
import { moveActiveIndex } from './listbox-nav';
import { fireUiAction } from '#lib/utils/ui-action.ts';
import styles from './SegmentedControl.module.css';

interface Props {
  options: SegmentedOption[];
  /** Selected option value; the parent owns it and updates it from `onChange`. */
  value: string;
  ariaLabel?: string;
  disabled?: boolean;
  /** Called with the chosen value (only when it differs); may be async. */
  onChange?: (value: string) => unknown;
  onError?: (message: string, error: unknown) => void;
}

interface Indicator {
  x: number;
  width: number;
  tone: SegmentedTone;
  ready: boolean;
}

const HIDDEN: Indicator = { x: 0, width: 0, tone: 'accent', ready: false };

export const SegmentedControl = memo(function SegmentedControl({
  options,
  value,
  ariaLabel,
  disabled = false,
  onChange,
  onError,
}: Props) {
  const root = useRef<HTMLDivElement | null>(null);
  const track = useRef<HTMLDivElement | null>(null);
  const [indicator, setIndicator] = useState<Indicator>(HIDDEN);
  const [motionReady, setMotionReady] = useState(false);
  const pendingFocus = useRef<number | null>(null);

  const normalizedOptions = useMemo(() => normalizeSegmentedOptions(options), [options]);
  const activeIndex = normalizedOptions.findIndex((option) => option.value === value);

  const layoutIndicator = useCallback(() => {
    const el = track.current;
    if (!el) return;
    const buttons = Array.from(el.querySelectorAll<HTMLButtonElement>('[data-segment]'));
    const index = normalizedOptions.findIndex((option) => option.value === value);
    const active = buttons[index];
    if (!active) {
      setIndicator(HIDDEN);
      setMotionReady(false);
      return;
    }
    // Layout coordinates stay accurate during the containing page's entrance animation.
    const next: Indicator = {
      x: active.offsetLeft,
      width: active.offsetWidth,
      tone: normalizedOptions[index]?.tone ?? 'accent',
      ready: true,
    };
    setIndicator((prev) =>
      prev.x === next.x && prev.width === next.width && prev.tone === next.tone && prev.ready
        ? prev
        : next,
    );
  }, [normalizedOptions, value]);

  useLayoutEffect(() => {
    layoutIndicator();
  }, [layoutIndicator]);

  // First paint starts in place; subsequent selections glide from the current position.
  const ready = indicator.ready;
  useEffect(() => {
    if (!ready) return;
    const frame = requestAnimationFrame(() => setMotionReady(true));
    return () => cancelAnimationFrame(frame);
  }, [ready]);

  useEffect(() => {
    const el = root.current;
    if (!el) return;
    const observer = new ResizeObserver(() => layoutIndicator());
    observer.observe(el);
    if (track.current) observer.observe(track.current);
    return () => observer.disconnect();
  }, [layoutIndicator]);

  useEffect(() => {
    const index = pendingFocus.current;
    if (index === null) return;
    pendingFocus.current = null;
    track.current?.querySelectorAll<HTMLButtonElement>('[data-segment]')[index]?.focus();
  }, [value]);

  function choose(nextValue: string) {
    if (disabled || nextValue === value) return;
    fireUiAction(() => onChange?.(nextValue), { onError });
  }

  function onTrackKeyDown(event: KeyboardEvent<HTMLDivElement>) {
    const count = normalizedOptions.length;
    if (count === 0 || disabled) return;
    let next: number;
    switch (event.key) {
      case 'ArrowRight':
      case 'ArrowLeft':
      case 'Home':
      case 'End':
        next = moveActiveIndex(activeIndex, count, event.key, 'horizontal');
        break;
      default:
        return;
    }
    event.preventDefault();
    const option = normalizedOptions[next];
    if (!option) return;
    // Automatic activation: moving focus selects the option.
    if (option.value === value) {
      track.current?.querySelectorAll<HTMLButtonElement>('[data-segment]')[next]?.focus();
      return;
    }
    pendingFocus.current = next;
    choose(option.value);
  }

  return (
    <div
      className={clsx(styles.segmented, disabled && styles.disabled)}
      ref={root}
      role="tablist"
      aria-label={ariaLabel}
      tabIndex={-1}
      onKeyDown={onTrackKeyDown}
    >
      <div className={styles.track} ref={track}>
        <div
          className={clsx(
            styles.indicator,
            indicator.tone === 'ok' && styles.ok,
            indicator.tone === 'bad' && styles.bad,
            indicator.ready && styles.ready,
            motionReady && indicator.ready && styles.glide,
          )}
          style={{ width: `${indicator.width}px`, transform: `translateX(${indicator.x}px)` }}
          aria-hidden="true"
        ></div>

        {normalizedOptions.map((option) => {
          const active = value === option.value;
          return (
            <button
              key={option.value}
              type="button"
              role="tab"
              data-segment
              className={clsx(
                styles.chip,
                active && styles.active,
                active && option.tone === 'ok' && styles.onOk,
                active && option.tone === 'bad' && styles.onBad,
              )}
              aria-selected={active}
              tabIndex={active ? 0 : -1}
              disabled={disabled}
              onClick={() => choose(option.value)}
            >
              <span className={styles.label}>{option.label}</span>
              {option.count !== undefined && <span className={styles.count}>{option.count}</span>}
            </button>
          );
        })}
      </div>
    </div>
  );
});

export default SegmentedControl;
