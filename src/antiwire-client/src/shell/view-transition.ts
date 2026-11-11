import { flushSync } from 'react-dom';
import type { NavigateOptions } from '#lib/navigation.ts';
import { navDirection, prefersReducedMotion } from '#lib/motion.ts';

/**
 * Page changes run as a view transition scoped to the page area (see
 * page-motion.css): the old page drifts away, the new one slides in from the
 * side the user is moving towards along the tab bar.
 */
export const supportsViewTransitions =
  typeof document !== 'undefined' && 'startViewTransition' in document;

/**
 * Wraps a router navigate function so pathname changes animate. Query-only
 * changes (filters, deep links within a page) stay put.
 */
export function withViewTransition(
  navigate: (to: string, options?: NavigateOptions) => void,
): (to: string, options?: NavigateOptions) => void {
  return (to, options) => {
    const from = window.location.pathname;
    const target = new URL(to, window.location.href).pathname;
    if (!supportsViewTransitions || prefersReducedMotion() || from === target) {
      navigate(to, options);
      return;
    }
    const root = document.documentElement;
    root.style.setProperty('--nav-dir', String(navDirection(from, target)));
    // The update must commit synchronously inside the callback so the browser
    // snapshots the new page, not the old one.
    const transition = document.startViewTransition(() => {
      flushSync(() => navigate(to, options));
    });
    void transition.finished.finally(() => root.style.removeProperty('--nav-dir'));
  };
}
