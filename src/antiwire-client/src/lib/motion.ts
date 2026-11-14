/**
 * The app's motion vocabulary. CSS uses the matching custom properties in
 * app.css (`--dur-*`, `--ease-*`); components that animate mounting and
 * unmounting elements use the `MotionSpec` factories below with
 * `usePresence` / `useEnterMotion` from `#lib/use-presence.ts`.
 *
 * Rules of thumb:
 * - Things arriving or moving decelerate (`expoOut`); things leaving
 *   accelerate away (`exitIn`) and take less time than they took to arrive.
 * - Only transform and opacity animate, so motion never triggers layout.
 * - Reduced motion collapses everything to an instant change.
 */
import { NAV_ITEMS } from '#lib/types/index.ts';

export const MOTION = {
  /** Press feedback. */
  instant: 80,
  /** Hover and colour changes. */
  fast: 120,
  /** Small movements: menus, toggles, popovers. */
  base: 180,
  /** Panels, dialogs and page changes. */
  slow: 260,
  /** Leaving is quicker than arriving. */
  exit: 120,
} as const;

/** CSS easing strings matching the `--ease-*` tokens in app.css. */
export const EASING = {
  /** `expoOut`; `--ease-out`. */
  out: 'cubic-bezier(0.16, 1, 0.3, 1)',
  /** `exitIn`; `--ease-in`. */
  in: 'cubic-bezier(0.55, 0, 1, 0.45)',
  standard: 'cubic-bezier(0.2, 0, 0, 1)',
  inOut: 'cubic-bezier(0.65, 0, 0.35, 1)',
  /** `popOut`; `--ease-pop`. */
  pop: 'cubic-bezier(0.34, 1.4, 0.64, 1)',
} as const;

/** Exponential ease-out: fast start, long soft landing. Matches `--ease-out`. */
export function expoOut(t: number): number {
  return t >= 1 ? 1 : 1 - Math.pow(2, -10 * t);
}

/** Cubic ease-in for exits. Matches `--ease-in`. */
export function exitIn(t: number): number {
  return t * t * t;
}

/** Ease-out with a small overshoot, for confirmations. Matches `--ease-pop`. */
export function popOut(t: number): number {
  const c1 = 1.4;
  const c3 = c1 + 1;
  return 1 + c3 * Math.pow(t - 1, 3) + c1 * Math.pow(t - 1, 2);
}

export function prefersReducedMotion(): boolean {
  return (
    typeof window !== 'undefined' &&
    typeof window.matchMedia === 'function' &&
    window.matchMedia('(prefers-reduced-motion: reduce)').matches
  );
}

/**
 * One Web Animations API animation: keyframes from the hidden state to the
 * shown one for entrances, and from shown to hidden for exits.
 */
export interface MotionSpec {
  keyframes: Keyframe[];
  duration: number;
  easing: string;
}

interface PopoverParams {
  /** Which edge the surface grows from; it drifts in from that side. */
  from?: 'top' | 'bottom';
  duration?: number;
}

/** Menus and popovers: a short drift plus a barely-there scale from their anchor. */
export function popoverIn({
  from = 'top',
  duration = MOTION.base,
}: PopoverParams = {}): MotionSpec {
  const shift = from === 'top' ? -4 : 4;
  const transformOrigin = `${from === 'top' ? 'top' : 'bottom'} center`;
  return {
    duration,
    easing: EASING.out,
    keyframes: [
      { opacity: 0, transform: `translateY(${shift}px) scale(0.98)`, transformOrigin },
      { opacity: 1, transform: 'translateY(0px) scale(1)', transformOrigin },
    ],
  };
}

export function popoverOut({
  from = 'top',
  duration = MOTION.exit,
}: PopoverParams = {}): MotionSpec {
  const shift = from === 'top' ? -3 : 3;
  const transformOrigin = `${from === 'top' ? 'top' : 'bottom'} center`;
  return {
    duration,
    easing: EASING.in,
    keyframes: [
      { opacity: 1, transform: 'translateY(0px) scale(1)', transformOrigin },
      { opacity: 0, transform: `translateY(${shift}px) scale(0.985)`, transformOrigin },
    ],
  };
}

/** Dialogs rise a few pixels and sharpen into place (they are centred with translate -50%). */
export function dialogIn(): MotionSpec {
  return {
    duration: MOTION.slow,
    easing: EASING.out,
    keyframes: [
      { opacity: 0, transform: 'translate3d(-50%, calc(-50% + 8px), 0) scale(0.97)' },
      { opacity: 1, transform: 'translate3d(-50%, -50%, 0) scale(1)' },
    ],
  };
}

export function dialogOut(): MotionSpec {
  return {
    duration: MOTION.exit + 20,
    easing: EASING.in,
    keyframes: [
      { opacity: 1, transform: 'translate3d(-50%, -50%, 0) scale(1)' },
      { opacity: 0, transform: 'translate3d(-50%, calc(-50% + 4px), 0) scale(0.985)' },
    ],
  };
}

/** Scrims fade; they never move. Use the reversed spec (`reverseMotion`) for the exit. */
export function scrimFade({ duration = MOTION.base }: { duration?: number } = {}): MotionSpec {
  return { duration, easing: 'linear', keyframes: [{ opacity: 0 }, { opacity: 1 }] };
}

/** Content swapping in place (wizard steps, tab panels) drifts in from the side it came from. */
export function stepIn({ direction = 1 }: { direction?: number } = {}): MotionSpec {
  const shift = direction >= 0 ? 16 : -16;
  return {
    duration: MOTION.slow,
    easing: EASING.out,
    keyframes: [
      { opacity: 0, transform: `translateX(${shift}px)` },
      { opacity: 1, transform: 'translateX(0px)' },
    ],
  };
}

/** Toasts slide up into the stack and leave sideways, towards the edge they sit on. */
export function toastIn(): MotionSpec {
  return {
    duration: MOTION.slow,
    easing: EASING.out,
    keyframes: [
      { opacity: 0, transform: 'translateY(12px) scale(0.97)' },
      { opacity: 1, transform: 'translateY(0px) scale(1)' },
    ],
  };
}

export function toastOut(): MotionSpec {
  return {
    duration: MOTION.base,
    easing: EASING.in,
    keyframes: [
      { opacity: 1, transform: 'translateX(0px)' },
      { opacity: 0, transform: 'translateX(24px)' },
    ],
  };
}

/** The same animation played backwards, e.g. a fade-in used as the fade-out. */
export function reverseMotion(spec: MotionSpec, easing: string = spec.easing): MotionSpec {
  return { ...spec, easing, keyframes: [...spec.keyframes].reverse() };
}

/**
 * Plays `spec` on `element` unless the user prefers reduced motion. Returns
 * the running animation, or null when nothing was played.
 */
export function playMotion(
  element: Element,
  spec: MotionSpec,
  fill: FillMode = 'none',
): Animation | null {
  if (prefersReducedMotion() || typeof element.animate !== 'function') return null;
  return element.animate(spec.keyframes, {
    duration: spec.duration,
    easing: spec.easing,
    fill,
  });
}

function navIndex(pathname: string | null | undefined): number {
  if (!pathname) return -1;
  const exact = NAV_ITEMS.findIndex((item) => item.href === pathname);
  if (exact >= 0) return exact;
  return NAV_ITEMS.findIndex((item) => item.href !== '/' && pathname.startsWith(`${item.href}/`));
}

/**
 * Which way a navigation moves along the tab bar: 1 is rightwards, -1 is
 * leftwards, 0 when either end is not a tab (or it is the same tab).
 */
export function navDirection(
  from: string | null | undefined,
  to: string | null | undefined,
): -1 | 0 | 1 {
  const a = navIndex(from);
  const b = navIndex(to);
  if (a < 0 || b < 0 || a === b) return 0;
  return b > a ? 1 : -1;
}
