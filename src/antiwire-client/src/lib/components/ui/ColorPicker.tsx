import clsx from 'clsx';
import {
  useEffect,
  useLayoutEffect,
  useRef,
  useState,
  type CSSProperties,
  type KeyboardEvent,
  type PointerEvent as ReactPointerEvent,
  type ReactNode,
} from 'react';
import { createPortal } from 'react-dom';
import { m } from '#lib/i18n/messages.ts';
import { popoverIn, popoverOut } from '#lib/motion.ts';
import { usePresence } from '#lib/use-presence.ts';
import { clamp01, hexToHsv, hsvToHex, normalizeHex, stepFor, type Hsv } from './color-picker';
import styles from './ColorPicker.module.css';

interface Props {
  /** Current colour as `#rrggbb`. */
  value: string;
  /** Accessible name of the trigger. */
  label: string;
  /** Fires continuously while dragging or stepping; nothing is saved yet. */
  onPreview?: (hex: string) => void;
  /** Fires once a change is settled (pointer released, key released, hex entered). */
  onChange?: (hex: string) => void;
  className?: string;
  style?: CSSProperties;
  /** Trigger content; the trigger itself is a button owned by this component. */
  children?: ReactNode;
}

const POPOVER_WIDTH = 240;
const POPOVER_HEIGHT = 246;
const GAP = 8;

export function ColorPicker({
  value,
  label,
  onPreview,
  onChange,
  className = '',
  style,
  children,
}: Props) {
  const [open, setOpen] = useState(false);
  const [hsv, setHsv] = useState<Hsv>(() => hexToHsv('#000000'));
  const [hexDraft, setHexDraft] = useState('');
  const [position, setPosition] = useState({ top: 0, left: 0 });
  /** The popover grows from the edge nearest its trigger. */
  const [growFrom, setGrowFrom] = useState<'top' | 'bottom'>('top');
  const triggerEl = useRef<HTMLButtonElement | null>(null);
  const areaEl = useRef<HTMLDivElement | null>(null);
  const hueEl = useRef<HTMLDivElement | null>(null);
  const { present: popoverPresent, ref: popoverRef } = usePresence<HTMLDivElement>(
    open,
    popoverIn({ from: growFrom }),
    popoverOut({ from: growFrom }),
  );

  /** Latest values for pointer handlers that outlive a render. */
  const latest = useRef({ hsv, onPreview, onChange });
  useLayoutEffect(() => {
    latest.current = { hsv, onPreview, onChange };
  });

  const hex = hsvToHex(hsv);
  const hueColor = hsvToHex({ h: hsv.h, s: 1, v: 1 });

  function syncFromValue() {
    const next = hexToHsv(value);
    // Keep the user's hue when the colour collapses to grey, so the area does
    // not snap back to red as saturation reaches zero.
    setHsv((prev) => (next.s === 0 || next.v === 0 ? { ...next, h: prev.h } : next));
    setHexDraft(normalizeHex(value) ?? value);
  }

  function place() {
    const trigger = triggerEl.current;
    if (!trigger) return;
    const rect = trigger.getBoundingClientRect();
    const below = rect.bottom + GAP;
    const fitsBelow = below + POPOVER_HEIGHT <= window.innerHeight - GAP;
    const top = fitsBelow ? below : Math.max(GAP, rect.top - GAP - POPOVER_HEIGHT);
    setGrowFrom(fitsBelow ? 'top' : 'bottom');
    const left = Math.min(
      Math.max(GAP, rect.left + rect.width / 2 - POPOVER_WIDTH / 2),
      window.innerWidth - POPOVER_WIDTH - GAP,
    );
    setPosition({ top, left });
  }

  const placeRef = useRef(place);
  useLayoutEffect(() => {
    placeRef.current = place;
  });

  function show() {
    syncFromValue();
    place();
    setOpen(true);
  }

  // Focus the area once the popover has mounted.
  useLayoutEffect(() => {
    if (open) areaEl.current?.focus({ preventScroll: true });
  }, [open]);

  function hide(returnFocus = false) {
    setOpen(false);
    if (returnFocus) triggerEl.current?.focus();
  }

  function toggle() {
    if (open) hide();
    else show();
  }

  function preview(next: Hsv) {
    latest.current.hsv = next;
    setHsv(next);
    const nextHex = hsvToHex(next);
    setHexDraft(nextHex);
    latest.current.onPreview?.(nextHex);
  }

  function commit() {
    latest.current.onChange?.(hsvToHex(latest.current.hsv));
  }

  function dragWith(
    el: HTMLElement | null,
    update: (x: number, y: number) => void,
    event: ReactPointerEvent<HTMLElement>,
  ) {
    if (!el || event.button !== 0) return;
    event.preventDefault();
    el.setPointerCapture(event.pointerId);
    const move = (e: PointerEvent) => {
      const rect = el.getBoundingClientRect();
      update(
        clamp01((e.clientX - rect.left) / rect.width),
        clamp01((e.clientY - rect.top) / rect.height),
      );
    };
    const up = (e: PointerEvent) => {
      el.releasePointerCapture(e.pointerId);
      el.removeEventListener('pointermove', move);
      el.removeEventListener('pointerup', up);
      commit();
    };
    el.addEventListener('pointermove', move);
    el.addEventListener('pointerup', up);
    move(event.nativeEvent);
  }

  function onAreaPointer(event: ReactPointerEvent<HTMLDivElement>) {
    dragWith(areaEl.current, (x, y) => preview({ ...latest.current.hsv, s: x, v: 1 - y }), event);
  }

  function onHuePointer(event: ReactPointerEvent<HTMLDivElement>) {
    dragWith(
      hueEl.current,
      (x) => preview({ ...latest.current.hsv, h: Math.min(359.9, x * 360) }),
      event,
    );
  }

  function onAreaKey(event: KeyboardEvent<HTMLDivElement>) {
    const step = stepFor(event);
    const moves: Record<string, Partial<Hsv>> = {
      ArrowLeft: { s: clamp01(hsv.s - step) },
      ArrowRight: { s: clamp01(hsv.s + step) },
      ArrowUp: { v: clamp01(hsv.v + step) },
      ArrowDown: { v: clamp01(hsv.v - step) },
    };
    const move = moves[event.key];
    if (!move) return;
    event.preventDefault();
    preview({ ...hsv, ...move });
  }

  function onHueKey(event: KeyboardEvent<HTMLDivElement>) {
    const step = stepFor(event) * 360;
    const delta = (
      { ArrowLeft: -step, ArrowDown: -step, ArrowRight: step, ArrowUp: step } as Record<
        string,
        number
      >
    )[event.key];
    if (delta === undefined) return;
    event.preventDefault();
    preview({ ...hsv, h: (hsv.h + delta + 360) % 360 });
  }

  function onStepKeyUp(event: KeyboardEvent<HTMLDivElement>) {
    if (event.key.startsWith('Arrow')) commit();
  }

  function applyHexDraft() {
    const next = normalizeHex(hexDraft);
    if (!next) {
      setHexDraft(hex);
      return;
    }
    const nextHsv = hexToHsv(next);
    latest.current.hsv = nextHsv;
    setHsv(nextHsv);
    setHexDraft(next);
    onPreview?.(next);
    onChange?.(next);
  }

  function onHexKey(event: KeyboardEvent<HTMLInputElement>) {
    if (event.key === 'Enter') {
      event.preventDefault();
      applyHexDraft();
    }
  }

  function onPopoverKey(event: KeyboardEvent<HTMLDivElement>) {
    if (event.key === 'Escape') {
      event.preventDefault();
      hide(true);
    }
  }

  useEffect(() => {
    if (!open) return;
    const onDown = (event: PointerEvent) => {
      const target = event.target as Node;
      if (popoverRef.current?.contains(target) || triggerEl.current?.contains(target)) return;
      setOpen(false);
    };
    const onViewport = () => placeRef.current();
    document.addEventListener('pointerdown', onDown, true);
    window.addEventListener('resize', onViewport);
    window.addEventListener('scroll', onViewport, true);
    return () => {
      document.removeEventListener('pointerdown', onDown, true);
      window.removeEventListener('resize', onViewport);
      window.removeEventListener('scroll', onViewport, true);
    };
  }, [open, popoverRef]);

  return (
    <>
      <button
        type="button"
        className={clsx(styles.trigger, className)}
        style={style}
        ref={triggerEl}
        aria-label={label}
        title={label}
        aria-haspopup="dialog"
        aria-expanded={open}
        onClick={toggle}
      >
        {children}
      </button>

      {popoverPresent &&
        createPortal(
          <div
            className={styles.popover}
            role="dialog"
            aria-label={label}
            tabIndex={-1}
            ref={popoverRef}
            style={
              {
                top: `${position.top}px`,
                left: `${position.left}px`,
                '--hue': hueColor,
              } as CSSProperties
            }
            onKeyDown={onPopoverKey}
          >
            <div
              className={styles.area}
              ref={areaEl}
              role="slider"
              tabIndex={0}
              aria-label={m.common_color_area_aria()}
              aria-valuemin={0}
              aria-valuemax={100}
              aria-valuenow={Math.round(hsv.s * 100)}
              aria-valuetext={m.common_color_area_value({
                saturation: Math.round(hsv.s * 100),
                brightness: Math.round(hsv.v * 100),
              })}
              onPointerDown={onAreaPointer}
              onKeyDown={onAreaKey}
              onKeyUp={onStepKeyUp}
            >
              <span
                className={styles.thumb}
                style={{ left: `${hsv.s * 100}%`, top: `${(1 - hsv.v) * 100}%`, background: hex }}
                aria-hidden="true"
              ></span>
            </div>

            <div
              className={styles.hue}
              ref={hueEl}
              role="slider"
              tabIndex={0}
              aria-label={m.common_color_hue_aria()}
              aria-valuemin={0}
              aria-valuemax={360}
              aria-valuenow={Math.round(hsv.h)}
              onPointerDown={onHuePointer}
              onKeyDown={onHueKey}
              onKeyUp={onStepKeyUp}
            >
              <span
                className={clsx(styles.thumb, styles.hueThumb)}
                style={{ left: `${(hsv.h / 360) * 100}%` }}
                aria-hidden="true"
              ></span>
            </div>

            <div className={styles.hexRow}>
              <span
                className={styles.preview}
                style={{ background: hex }}
                aria-hidden="true"
              ></span>
              <label className={styles.hexField}>
                <span className={styles.hexLabel}>{m.common_color_hex_label()}</span>
                <input
                  className={clsx(styles.hexInput, 'mono')}
                  value={hexDraft}
                  onChange={(event) => setHexDraft(event.currentTarget.value)}
                  spellCheck={false}
                  autoComplete="off"
                  maxLength={7}
                  onKeyDown={onHexKey}
                  onBlur={applyHexDraft}
                />
              </label>
            </div>
          </div>,
          document.body,
        )}
    </>
  );
}

export default ColorPicker;
