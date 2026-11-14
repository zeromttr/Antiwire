// Reads a mutable workspace while rendering, so React Compiler must not
// cache it (see src/lib/state/compiler-opt-out.test.ts).
'use no memo';

import clsx from 'clsx';
import { CheckCheck, Trash2 } from 'lucide-react';
import {
  createElement,
  Fragment,
  memo,
  useCallback,
  useEffect,
  useLayoutEffect,
  useRef,
  useState,
  type CSSProperties,
  type KeyboardEvent,
} from 'react';
import { AlertDetail } from '#lib/components/alerts/AlertDetail.tsx';
import { alertIcon, alertTone } from '#lib/components/alerts/alert-visuals.ts';
import { Button } from '#lib/components/ui/Button.tsx';
import { EmptyState } from '#lib/components/ui/EmptyState.tsx';
import DaemonOffline from '#lib/components/shell/DaemonOffline.tsx';
import { UnderlineTabs } from '#lib/components/ui/UnderlineTabs.tsx';
import { m } from '#lib/i18n/messages.ts';
import {
  ALERT_TABS,
  alertTabCounts,
  filterAlertsByTab,
  formatAlertAge,
  groupAlertsByDay,
  type AlertTab,
} from '#lib/models/alerts.ts';
import { playMotion, stepIn } from '#lib/motion.ts';
import { useReactive, useSelector } from '#lib/state/reactive.ts';
import { alertReads } from '#lib/stores/alert-reads.ts';
import { daemon } from '#lib/stores/daemon.ts';
import type { NotificationEvent } from '#lib/types/index.ts';
import { displayText } from '#lib/utils/index.ts';
import styles from './AlertsPage.module.css';

const TAB_LABELS: Record<AlertTab, () => string> = {
  all: () => m.alerts_tab_all(),
  threats: () => m.alerts_tab_threats(),
  activity: () => m.alerts_tab_activity(),
  system: () => m.alerts_tab_system(),
};

interface ItemProps {
  alert: NotificationEvent;
  selected: boolean;
  read: boolean;
  now: number;
  onSelect: (id: string) => void;
}

const AlertItem = memo(function AlertItem({ alert, selected, read, now, onSelect }: ItemProps) {
  return (
    <div
      id={`alert-${alert.id}`}
      className={clsx(styles.item, selected && styles.selected, !read && styles.unread)}
      role="option"
      tabIndex={-1}
      aria-selected={selected}
      data-alert-id={alert.id}
      onClick={() => onSelect(alert.id)}
      onKeyDown={(event) => {
        if (event.key === 'Enter' || event.key === ' ') onSelect(alert.id);
      }}
    >
      <span
        className={styles.glyph}
        style={{ '--tone': alertTone(alert.severity) } as CSSProperties}
        aria-hidden="true"
      >
        {createElement(alertIcon(alert), { size: 15, strokeWidth: 1.9 })}
      </span>
      <span className={styles.copy}>
        <span className={styles.title}>{displayText(alert.title)}</span>
        {alert.body && <span className={styles.snippet}>{displayText(alert.body)}</span>}
      </span>
      <span className={styles.aside}>
        <span className={styles.age}>{formatAlertAge(alert.timestamp, now)}</span>
        {!read && <span className={styles.unreadDot} aria-hidden="true"></span>}
      </span>
    </div>
  );
});

export default function AlertsPage() {
  const connected = useSelector(daemon, (d) => d.state.connected);
  const alerts = useSelector(daemon, (d) => d.state.notifications);
  useReactive(alertReads);
  const [tab, setTab] = useState<AlertTab>('all');
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [direction, setDirection] = useState(1);
  const [clearing, setClearing] = useState(false);
  const [dismissing, setDismissing] = useState(false);
  const [now, setNow] = useState(() => Date.now());
  const listEl = useRef<HTMLDivElement | null>(null);
  const paneEl = useRef<HTMLDivElement | null>(null);

  const counts = alertTabCounts(alerts);
  const visible = filterAlertsByTab(alerts, tab);
  const groups = groupAlertsByDay(visible, now);
  const unread = alerts.filter((alert) => !alertReads.has(alert.id)).length;
  let selected = visible.find((alert) => alert.id === selectedId) ?? null;

  // Keep something selected: the first alert of the tab, or its neighbour
  // when the selected one is dismissed or filtered away.
  if (!selected && visible.length > 0) {
    selected = visible[0];
    setSelectedId(selected.id);
  }
  const selectedKey = selected?.id ?? null;

  // Opening an alert reads it.
  useEffect(() => {
    if (selectedKey) alertReads.markRead(selectedKey);
  }, [selectedKey]);

  // The detail drifts in from the side of the newly selected alert.
  const shownKey = useRef<string | null>(null);
  useLayoutEffect(() => {
    const previous = shownKey.current;
    shownKey.current = selectedKey;
    if (!previous || !selectedKey || previous === selectedKey || !paneEl.current) return;
    const animation = playMotion(paneEl.current, stepIn({ direction }));
    return () => animation?.cancel();
  }, [selectedKey, direction]);

  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 30_000);
    return () => clearInterval(timer);
  }, []);

  // Latest values for the stable callbacks below.
  const latest = useRef({ visible, selectedId: selectedKey });
  useLayoutEffect(() => {
    latest.current = { visible, selectedId: selectedKey };
  });

  const select = useCallback((id: string) => {
    const { visible: list, selectedId: current } = latest.current;
    if (id === current) return;
    const from = list.findIndex((alert) => alert.id === current);
    const to = list.findIndex((alert) => alert.id === id);
    setDirection(to >= from ? 1 : -1);
    setSelectedId(id);
  }, []);

  function onListKeydown(event: KeyboardEvent<HTMLDivElement>) {
    if (
      event.key !== 'ArrowDown' &&
      event.key !== 'ArrowUp' &&
      event.key !== 'Home' &&
      event.key !== 'End'
    ) {
      return;
    }
    event.preventDefault();
    if (visible.length === 0) return;
    const index = visible.findIndex((alert) => alert.id === selectedKey);
    const next =
      event.key === 'Home'
        ? 0
        : event.key === 'End'
          ? visible.length - 1
          : Math.min(visible.length - 1, Math.max(0, index + (event.key === 'ArrowDown' ? 1 : -1)));
    const id = visible[next].id;
    select(id);
    // The row already exists; only the selection moves.
    listEl.current
      ?.querySelector<HTMLElement>(`[data-alert-id="${CSS.escape(id)}"]`)
      ?.scrollIntoView({ block: 'nearest' });
  }

  async function dismiss(id: string) {
    if (dismissing) return;
    setDismissing(true);
    const index = visible.findIndex((alert) => alert.id === id);
    const neighbour = visible[index + 1] ?? visible[index - 1] ?? null;
    try {
      await daemon.dismissNotification(id);
      setSelectedId(neighbour?.id ?? null);
    } catch (error) {
      daemon.addToast(
        m.alerts_toast_dismiss_failed_title(),
        error instanceof Error ? error.message : String(error),
        'var(--bad)',
      );
    } finally {
      setDismissing(false);
    }
  }

  async function clearAll() {
    if (clearing || alerts.length === 0) return;
    setClearing(true);
    try {
      await daemon.clearAlerts();
      setTab('all');
      setSelectedId(null);
    } catch (error) {
      daemon.addToast(
        m.alerts_toast_clear_failed_title(),
        error instanceof Error ? error.message : String(error),
        'var(--bad)',
      );
    } finally {
      setClearing(false);
    }
  }

  return (
    <div className={styles.page} data-testid="page-alerts" data-page-motion="alerts">
      <header className={styles.pageHead}>
        <h1>{m.nav_alerts()}</h1>
        {alerts.length > 0 && (
          <p className={styles.sub}>
            {unread > 0 ? m.alerts_unread({ count: unread }) : m.alerts_all_read()}
          </p>
        )}
        <div className={styles.headActions}>
          <Button
            variant="ghost"
            disabled={unread === 0}
            onClick={() => alertReads.markAllRead(alerts.map((alert) => alert.id))}
          >
            <CheckCheck size={15} />
            {m.alerts_mark_all_read()}
          </Button>
          <Button
            variant="ghost"
            disabled={clearing || alerts.length === 0}
            onClick={() => void clearAll()}
          >
            <Trash2 size={14} />
            {clearing ? m.alerts_clearing() : m.alerts_clear_all()}
          </Button>
        </div>
      </header>

      <div className={styles.tabs} data-motion-stage="1">
        <UnderlineTabs
          tabs={ALERT_TABS.map((id) => ({ value: id, label: TAB_LABELS[id](), count: counts[id] }))}
          value={tab}
          ariaLabel={m.alerts_tabs_aria()}
          onChange={(next) => setTab(next as AlertTab)}
        />
      </div>

      {alerts.length === 0 ? (
        <div className={styles.empty} data-motion-stage="2">
          {connected ? (
            <EmptyState text={m.alerts_empty_none()} panel />
          ) : (
            <DaemonOffline text={m.alerts_empty_disconnected()} />
          )}
        </div>
      ) : (
        <div className={clsx(styles.workspace, 'panel')} data-motion-stage="2">
          <div
            className={clsx(styles.list, styles.scroll, 'scroll')}
            role="listbox"
            tabIndex={0}
            aria-label={m.alerts_list_aria()}
            aria-activedescendant={selectedKey ? `alert-${selectedKey}` : undefined}
            ref={listEl}
            onKeyDown={onListKeydown}
          >
            {visible.length === 0 && <EmptyState text={m.alerts_empty_tab()} compact />}
            {groups.map((group) => (
              <Fragment key={group.key}>
                <div className={styles.groupLabel} role="presentation">
                  {group.label}
                </div>
                {group.alerts.map((alert) => (
                  <AlertItem
                    key={alert.id}
                    alert={alert}
                    selected={alert.id === selectedKey}
                    read={alertReads.has(alert.id)}
                    now={now}
                    onSelect={select}
                  />
                ))}
              </Fragment>
            ))}
          </div>

          <section className={clsx(styles.pane, styles.scroll, 'scroll')}>
            {selected && (
              <div className={styles.paneInner} ref={paneEl}>
                <AlertDetail
                  alert={selected}
                  dismissing={dismissing}
                  onDismiss={(id) => void dismiss(id)}
                />
              </div>
            )}
          </section>
        </div>
      )}
    </div>
  );
}
