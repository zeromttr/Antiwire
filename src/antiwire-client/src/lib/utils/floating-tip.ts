import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';

export type FloatingTipPlacement = 'top' | 'bottom';

export interface FloatingTipOptions {
  estimatedTipHeight?: number;
  hideOnScroll?: boolean;
  /**
   * Track the pointer horizontally instead of centring on the trigger. For
   * wide triggers such as list rows, where the centre can be far from the
   * cursor. Keyboard focus has no pointer and still centres.
   */
  followPointer?: boolean;
}

/** The parts of a React mouse or focus event the tip reads. */
interface TipEvent {
  currentTarget: EventTarget | null;
  clientX?: number;
}

export interface FloatingTip<T> {
  /** The hovered value, or null while hidden. Render the tip only when set. */
  hover: T | null;
  placement: FloatingTipPlacement;
  /**
   * Ref callback for the tip element. The tip is positioned by writing
   * `--tip-x` / `--tip-y` on it directly, so following the pointer never
   * re-renders the component.
   */
  tipRef: (element: HTMLElement | null) => void;
  show: (value: T, event: TipEvent) => void;
  /** Pointer moved over the trigger: keep the tip under it (with `followPointer`). */
  move: (event: TipEvent) => void;
  hide: () => void;
}

const GAP = 8;
const VIEWPORT_MARGIN = 8;

/**
 * Calls `onLeave` when the pointer enters an element outside the current
 * trigger. A backstop for `mouseleave`: Chromium never fires `mouseout` /
 * `mouseleave` on a hovered node that is moved in the DOM, which is exactly
 * what a keyed live list does when it re-sorts under the pointer. Without
 * this, such a row's tip stays open after the pointer has left.
 *
 * Bubble phase on `document`, so React's own `onMouseEnter` (delegated to the
 * root container, below `document`) has already switched `getTrigger()` to a
 * newly entered trigger and the tip does not flicker between triggers.
 */
export function onPointerOutside(
  getTrigger: () => Element | null,
  onLeave: () => void,
): () => void {
  const onOver = (event: MouseEvent) => {
    const trigger = getTrigger();
    if (!trigger) return;
    if (event.target instanceof Node && trigger.contains(event.target)) return;
    onLeave();
  };
  document.addEventListener('mouseover', onOver);
  return () => document.removeEventListener('mouseover', onOver);
}

/**
 * A tooltip that floats above (or below, near the top edge) a trigger and
 * stays inside the viewport. Render the tip in a portal on `document.body`.
 */
export function useFloatingTip<T>(options: FloatingTipOptions = {}): FloatingTip<T> {
  const estimatedTipHeight = options.estimatedTipHeight ?? 56;
  const hideOnScroll = options.hideOnScroll ?? false;
  const followPointer = options.followPointer ?? false;

  const [hover, setHover] = useState<T | null>(null);
  /** Shown by the pointer (not keyboard focus), so leaving it with the pointer hides it. */
  const [byPointer, setByPointer] = useState(false);
  const [placement, setPlacement] = useState<FloatingTipPlacement>('top');
  const tipEl = useRef<HTMLElement | null>(null);
  const triggerEl = useRef<HTMLElement | null>(null);
  /** Last pointer x within the trigger, when following the pointer. */
  const pointerX = useRef<number | null>(null);
  const position = useRef({ x: 0, y: 0 });
  const config = useRef({ estimatedTipHeight, followPointer });
  useLayoutEffect(() => {
    config.current = { estimatedTipHeight, followPointer };
  });

  const applyPosition = useCallback(() => {
    const el = tipEl.current;
    if (!el) return;
    el.style.setProperty('--tip-x', `${position.current.x}px`);
    el.style.setProperty('--tip-y', `${position.current.y}px`);
  }, []);

  const positionTip = useCallback(
    (trigger: HTMLElement) => {
      const rect = trigger.getBoundingClientRect();
      const tipRect = tipEl.current?.getBoundingClientRect();
      const tipHeight = tipRect?.height ?? config.current.estimatedTipHeight;
      const spaceAbove = rect.top;
      const spaceBelow = window.innerHeight - rect.bottom;

      const next: FloatingTipPlacement =
        spaceAbove < tipHeight + GAP + VIEWPORT_MARGIN && spaceBelow > spaceAbove
          ? 'bottom'
          : 'top';

      const px = pointerX.current;
      const centerX =
        px !== null ? Math.min(Math.max(px, rect.left), rect.right) : rect.left + rect.width / 2;
      const halfTipWidth = (tipRect?.width ?? 0) / 2;
      const x =
        halfTipWidth > 0
          ? Math.min(
              Math.max(centerX, VIEWPORT_MARGIN + halfTipWidth),
              window.innerWidth - VIEWPORT_MARGIN - halfTipWidth,
            )
          : centerX;
      position.current = { x, y: next === 'top' ? rect.top - GAP : rect.bottom + GAP };
      setPlacement(next);
      applyPosition();
    },
    [applyPosition],
  );

  const show = useCallback(
    (value: T, event: TipEvent) => {
      const trigger = event.currentTarget as HTMLElement | null;
      if (!trigger) return;
      setHover(() => value);
      setByPointer(typeof event.clientX === 'number');
      triggerEl.current = trigger;
      pointerX.current =
        config.current.followPointer && typeof event.clientX === 'number' ? event.clientX : null;
      positionTip(trigger);
    },
    [positionTip],
  );

  const move = useCallback(
    (event: TipEvent) => {
      const trigger = triggerEl.current;
      if (!config.current.followPointer || !trigger || typeof event.clientX !== 'number') return;
      pointerX.current = event.clientX;
      positionTip(trigger);
    },
    [positionTip],
  );

  const hide = useCallback(() => {
    setHover(null);
    triggerEl.current = null;
    pointerX.current = null;
  }, []);

  const tipRef = useCallback(
    (element: HTMLElement | null) => {
      tipEl.current = element;
      // Re-measure with the real tip size once it exists.
      if (element && triggerEl.current) positionTip(triggerEl.current);
    },
    [positionTip],
  );

  const visible = hover !== null;
  useEffect(() => {
    if (!visible) return;
    const reposition = () => {
      if (triggerEl.current) positionTip(triggerEl.current);
    };
    const onScroll = hideOnScroll ? hide : reposition;
    window.addEventListener('resize', reposition);
    window.addEventListener('scroll', onScroll, true);
    return () => {
      window.removeEventListener('resize', reposition);
      window.removeEventListener('scroll', onScroll, true);
    };
  }, [visible, hideOnScroll, hide, positionTip]);

  const watchPointer = visible && byPointer;
  useEffect(() => {
    if (!watchPointer) return;
    return onPointerOutside(() => triggerEl.current, hide);
  }, [watchPointer, hide]);

  return useMemo(
    () => ({ hover, placement, tipRef, show, move, hide }),
    [hover, placement, tipRef, show, move, hide],
  );
}
