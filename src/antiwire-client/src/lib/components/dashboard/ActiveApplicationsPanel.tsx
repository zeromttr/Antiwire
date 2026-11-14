import clsx from 'clsx';
import { ArrowDown, ArrowUp, Cable, ChevronRight } from 'lucide-react';
import {
  memo,
  useCallback,
  useEffect,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
  type FocusEvent,
  type PointerEvent,
} from 'react';
import { Link } from 'react-router';
import { AnimatedText } from '#lib/components/ui/AnimatedText.tsx';
import { AppAvatar } from '#lib/components/ui/AppAvatar.tsx';
import { ScrollFade } from '#lib/components/ui/ScrollFade.tsx';
import { m } from '#lib/i18n/messages.ts';
import {
  ACTIVE_APPS_VISIBLE_ROWS,
  destinationSummary,
  isNewlyActive,
  rankActiveApps,
  type ActiveApp,
} from '#lib/models/active-apps.ts';
import { EASING, MOTION, playMotion } from '#lib/motion.ts';
import { useSelector } from '#lib/state/reactive.ts';
import { activeApps } from '#lib/stores/active-apps.ts';
import { displayText, formatThroughput } from '#lib/utils/index.ts';
import styles from './ActiveApplicationsPanel.module.css';

interface Props {
  connected: boolean;
  onOpen: (applicationName: string) => void;
}

function nowMs(): number {
  return Date.now();
}

const appKey = (app: { path: string; name: string }) => app.path || app.name;

interface RowProps {
  app: ActiveApp;
  fresh: boolean;
  onOpen: (applicationName: string) => void;
}

const ActiveAppRow = memo(function ActiveAppRow({ app, fresh, onOpen }: RowProps) {
  const destination = destinationSummary(app);
  return (
    <button type="button" className={styles.row} onClick={() => onOpen(app.name)}>
      <span className={styles.avatar}>
        <AppAvatar name={app.name} path={app.path} size={24} />
        {fresh && (
          <span
            className={clsx(styles.newDot, 'new-dot')}
            role="img"
            aria-label={m.dashboard_active_new_aria()}
          ></span>
        )}
      </span>
      <span className={styles.identity}>
        <span className={styles.name}>{displayText(app.name)}</span>
        {destination.primary && (
          <span className={styles.destination}>
            <span className={styles.host}>{displayText(destination.primary)}</span>
            {destination.more > 0 && <span className={styles.more}>+{destination.more}</span>}
          </span>
        )}
      </span>
      <span
        className={styles.conns}
        aria-label={m.dashboard_active_connections_aria({ count: app.connections })}
      >
        <Cable size={12} strokeWidth={2} aria-hidden="true" />
        {app.connections}
      </span>
      <span className={styles.rates}>
        <span className={clsx(styles.rate, styles.down)}>
          <ArrowDown size={11} strokeWidth={2.2} aria-hidden="true" />
          <AnimatedText text={formatThroughput(app.downloadRate).label} />
        </span>
        <span className={clsx(styles.rate, styles.up)}>
          <ArrowUp size={11} strokeWidth={2.2} aria-hidden="true" />
          <AnimatedText text={formatThroughput(app.uploadRate).label} />
        </span>
      </span>
    </button>
  );
});

/**
 * Plays a FLIP move for rows whose position changed since the last render
 * and fades in rows that were not there before (not on the list's first
 * paint).
 */
function useListMotion(keys: readonly string[]) {
  const elements = useRef(new Map<string, HTMLLIElement>());
  const positions = useRef<Map<string, number> | null>(null);

  const register = useCallback((key: string, element: HTMLLIElement | null) => {
    if (element) elements.current.set(key, element);
    else elements.current.delete(key);
  }, []);

  useLayoutEffect(() => {
    if (keys.length === 0) {
      // The list unmounts; its next first paint does not animate either.
      positions.current = null;
      return;
    }
    const previous = positions.current;
    const next = new Map<string, number>();
    for (const key of keys) {
      const element = elements.current.get(key);
      if (!element) continue;
      const top = element.offsetTop;
      next.set(key, top);
      if (!previous) continue;
      const before = previous.get(key);
      if (before === undefined) {
        playMotion(element, {
          duration: MOTION.base,
          easing: 'linear',
          keyframes: [{ opacity: 0 }, { opacity: 1 }],
        });
      } else if (before !== top) {
        playMotion(element, {
          duration: MOTION.slow,
          easing: EASING.out,
          keyframes: [
            { transform: `translateY(${before - top}px)` },
            { transform: 'translateY(0px)' },
          ],
        });
      }
    }
    positions.current = next;
  }, [keys]);

  return register;
}

export const ActiveApplicationsPanel = memo(function ActiveApplicationsPanel({
  connected,
  onOpen,
}: Props) {
  const page = useSelector(activeApps, (store) => store.page);
  const fetchedAt = useSelector(activeApps, (store) => store.fetchedAt);
  const now = fetchedAt || nowMs();

  /**
   * While the pointer or keyboard focus is in the list, rows keep their order
   * (values still update, newcomers go last) so nothing slides out from under
   * a click or a scroll. The live ranking resumes on leave.
   */
  const [heldOrder, setHeldOrder] = useState<string[] | null>(null);
  const ranked = useMemo(() => (page ? rankActiveApps(page.applications) : []), [page]);
  const rows = useMemo(() => {
    if (!heldOrder) return ranked;
    const position = new Map(heldOrder.map((key, index) => [key, index]));
    return [...ranked].sort(
      (a, b) =>
        (position.get(appKey(a)) ?? Number.MAX_SAFE_INTEGER) -
        (position.get(appKey(b)) ?? Number.MAX_SAFE_INTEGER),
    );
  }, [ranked, heldOrder]);
  const keys = useMemo(() => rows.map(appKey), [rows]);
  const register = useListMotion(keys);

  const holdOrder = () => {
    setHeldOrder((held) => held ?? keys);
  };

  const releaseOnFocusOut = (event: FocusEvent<HTMLUListElement>) => {
    const list = event.currentTarget;
    // Keep holding while focus is still inside, or the pointer is still over it.
    if (list.contains(event.relatedTarget as Node | null)) return;
    if (list.matches(':hover')) return;
    setHeldOrder(null);
  };

  const releaseOnPointerLeave = (event: PointerEvent<HTMLUListElement>) => {
    if (event.currentTarget.contains(document.activeElement)) return;
    setHeldOrder(null);
  };

  // The shared poll runs while this panel is on screen and connected.
  useEffect(() => {
    if (!connected) return;
    return activeApps.retain();
  }, [connected]);

  return (
    <section className={clsx('panel', styles.activeApps)} aria-labelledby="active-apps-title">
      <div className={styles.sectionHeader}>
        <h2 className={styles.sectionTitle} id="active-apps-title">
          {m.dashboard_active_title()}
        </h2>
        {page?.available && rows.length > 0 && (
          <span className={styles.count} aria-hidden="true">
            {rows.length}
          </span>
        )}
        <span className={styles.sectionSub}>
          <span className={clsx(styles.liveDot, 'live-dot')} aria-hidden="true"></span>
          {m.dashboard_active_sub()}
        </span>
        <Link className={styles.link} to="/records">
          {m.dashboard_view_all()}
          <ChevronRight size={13} strokeWidth={2} aria-hidden="true" />
        </Link>
      </div>

      {page === null ? (
        Array.from({ length: ACTIVE_APPS_VISIBLE_ROWS }, (_, index) => (
          <div key={index} className={clsx(styles.row, styles.placeholder)} aria-hidden="true">
            <span className={styles.phAvatar}></span>
            <span className={styles.phLines}>
              <span></span>
              <span className={styles.short}></span>
            </span>
            <span className={styles.phRate}></span>
          </div>
        ))
      ) : !page.available ? (
        <p className={styles.note}>{m.dashboard_active_unavailable()}</p>
      ) : rows.length === 0 ? (
        <p className={styles.note}>{m.dashboard_active_empty()}</p>
      ) : (
        <ScrollFade visibleRows={ACTIVE_APPS_VISIBLE_ROWS} rowHeight={44} bleed={8}>
          <ul
            className={styles.rows}
            onPointerEnter={holdOrder}
            onPointerLeave={releaseOnPointerLeave}
            onFocus={holdOrder}
            onBlur={releaseOnFocusOut}
          >
            {rows.map((app) => {
              const key = appKey(app);
              return (
                <li key={key} ref={(element) => register(key, element)}>
                  <ActiveAppRow app={app} fresh={isNewlyActive(app, now)} onOpen={onOpen} />
                </li>
              );
            })}
          </ul>
        </ScrollFade>
      )}
    </section>
  );
});

export default ActiveApplicationsPanel;
