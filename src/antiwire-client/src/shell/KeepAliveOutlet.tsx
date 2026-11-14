import { Activity, useState, type ReactNode } from 'react';
import { useLocation, useOutlet } from 'react-router';
import { ErrorBoundary } from '#lib/components/ui/ErrorBoundary.tsx';
import { NAV_ITEMS } from '#lib/types/index.ts';
import { emptyKeptPages, markKeptPageFailed, showKeptPage } from './kept-pages.ts';

/** Only the tab pages are kept; redirects and unknown paths render normally. */
const KEPT_ROUTES: ReadonlySet<string> = new Set(NAV_ITEMS.map((item) => item.href));

/**
 * The shell's `<Outlet>`, except that tab pages the user leaves stay mounted
 * inside a hidden `<Activity>` (up to `MAX_KEPT_PAGES`). Coming back reveals
 * the page with its state, data and DOM intact instead of rebuilding it.
 *
 * While hidden a page's effects are cleaned up, exactly as on unmount, so its
 * timers, store subscriptions and streams stop, and they run again when it is
 * revealed. Pages must therefore tolerate cleanup followed by a re-run, which
 * StrictMode already exercises in development.
 *
 * Each page has its own error boundary. A page that failed is dropped when the
 * user navigates away, so returning to it mounts it afresh.
 */
export function KeepAliveOutlet() {
  const { pathname } = useLocation();
  const outlet = useOutlet();
  const [stored, setStored] = useState(emptyKeptPages<ReactNode>);

  if (!KEPT_ROUTES.has(pathname)) {
    return (
      <ErrorBoundary key={pathname} kind="page">
        {outlet}
      </ErrorBoundary>
    );
  }

  // Adjusting state while rendering: React discards this pass and renders
  // again with the new cache before committing, so nothing flashes.
  const kept = showKeptPage(stored, pathname, outlet);
  if (kept !== stored) setStored(kept);

  return kept.pages.map(({ key, element }) => {
    const visible = key === pathname;
    return (
      <Activity key={key} mode={visible ? 'visible' : 'hidden'}>
        <ErrorBoundary
          kind="page"
          onError={() => setStored((current) => markKeptPageFailed(current, key))}
        >
          {visible ? outlet : element}
        </ErrorBoundary>
      </Activity>
    );
  });
}
