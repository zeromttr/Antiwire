import clsx from 'clsx';
import { RefreshCw } from 'lucide-react';
import { useEffect, useState } from 'react';
import Button from '#lib/components/ui/Button.tsx';
import EmptyState from '#lib/components/ui/EmptyState.tsx';
import { m } from '#lib/i18n/messages.ts';
import { useSelector } from '#lib/state/reactive.ts';
import { daemon } from '#lib/stores/daemon.ts';
import { secondsUntil } from './reconnect-countdown.ts';
import styles from './DaemonOffline.module.css';

/** How often the countdown is recomputed; well under a second so no number is skipped. */
const TICK_MS = 250;

/** Whole seconds until `at`, re-rendering as they pass; null while nothing is scheduled. */
function useSecondsUntil(at: number | null): number | null {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (at === null) return;
    const tick = () => setNow(Date.now());
    const timer = setInterval(tick, TICK_MS);
    return () => clearInterval(timer);
  }, [at]);
  // `now` is up to one tick old, which right after scheduling would read a second high.
  return secondsUntil(at, now + TICK_MS);
}

/** "Next attempt in 12s", counting down; "Connecting…" during an attempt. */
export function ReconnectCountdown() {
  const connecting = useSelector(daemon, (d) => d.state.connecting);
  const nextReconnectAt = useSelector(daemon, (d) => d.state.nextReconnectAt);
  const seconds = useSecondsUntil(nextReconnectAt);

  return (
    // Often inside a live region (the empty state); a ticking number must not be read out.
    <span className={clsx('mono', styles.next)} aria-live="off">
      {connecting
        ? m.capture_connecting()
        : seconds !== null &&
          m.common_reconnect_next_attempt({
            time: m.common_format_time_ago_s({ count: seconds }),
          })}
    </span>
  );
}

/**
 * When the next connection attempt starts, and a button to make it now. Shown wherever
 * a page has nothing to show without the daemon.
 */
export function ReconnectStatus() {
  const connecting = useSelector(daemon, (d) => d.state.connecting);

  return (
    <div className={styles.reconnect}>
      <ReconnectCountdown />
      <Button size="sm" disabled={connecting} onClick={() => void daemon.connect()}>
        <span className={clsx(styles.icon, connecting && styles.spin)}>
          <RefreshCw size={13} aria-hidden="true" />
        </span>
        {m.capture_retry_connection()}
      </Button>
    </div>
  );
}

/** A page's "daemon not connected" panel: its own message, then `ReconnectStatus`. */
export function DaemonOffline({ text }: { text: string }) {
  return (
    <EmptyState text={text} panel>
      <ReconnectStatus />
    </EmptyState>
  );
}

export default DaemonOffline;
