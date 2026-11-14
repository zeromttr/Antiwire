// Reads a mutable workspace while rendering, so React Compiler must not
// cache it (see src/lib/state/compiler-opt-out.test.ts).
'use no memo';

import clsx from 'clsx';
import { RotateCcw, Trash2 } from 'lucide-react';
import { memo } from 'react';
import { Button } from '#lib/components/ui/Button.tsx';
import { formatCaptureDuration } from '#lib/models/capture.ts';
import { formatBytes } from '#lib/utils/index.ts';
import { m } from '#lib/i18n/messages.ts';
import { getLocale } from '#lib/paraglide/runtime.js';
import { shallowEqual, useSelector } from '#lib/state/reactive.ts';
import { historyElapsedSeconds } from './view/capture-view';
import type { CaptureWorkspace } from './capture-workspace';
import styles from './CaptureHistoryPanel.module.css';

interface Props {
  cap: CaptureWorkspace;
}

export const CaptureHistoryPanel = memo(function CaptureHistoryPanel({ cap }: Props) {
  const { history, capturing } = useSelector(
    cap,
    (c) => ({ history: c.history, capturing: c.capturing }),
    shallowEqual,
  );
  if (!history.length) return null;
  const locale = getLocale();

  return (
    <section className={clsx(styles['history-panel'], 'panel')}>
      <div className={styles['panel-heading']}>
        <h2>{m.capture_history_title()}</h2>
        <span className={styles.meta}>{m.capture_history_kicker()}</span>
        <Button variant="ghost" size="sm" onClick={cap.clearHistory}>
          <Trash2 size={12} /> {m.capture_history_clear()}
        </Button>
      </div>
      <div className={styles['history-list']}>
        {history.map((item) => (
          <div key={item.id} className={styles['history-row']}>
            <div className={styles['history-state']}>
              <span></span>
            </div>
            <div className={styles['history-main']}>
              <strong>{item.deviceName || m.capture_history_interface_fallback()}</strong>
              <span>
                {new Date(item.startedAt).toLocaleString(locale)} &middot; {item.outcome}
              </span>
            </div>
            <div className={clsx(styles['history-stat'], 'mono')}>
              <strong>{item.packets.toLocaleString()}</strong>
              <span>{m.capture_history_packets()}</span>
            </div>
            <div className={clsx(styles['history-stat'], 'mono')}>
              <strong>{formatBytes(item.bytes)}</strong>
              <span>{m.capture_history_pcap_size()}</span>
            </div>
            <div className={clsx(styles['history-stat'], 'mono')}>
              <strong>
                {formatCaptureDuration(historyElapsedSeconds(item.startedAt, item.endedAt))}
              </strong>
              <span>{m.capture_history_duration()}</span>
            </div>
            <Button
              variant="secondary"
              size="sm"
              onClick={() => cap.reuseSession(item)}
              disabled={capturing}
            >
              <RotateCcw size={13} /> {m.capture_history_reuse()}
            </Button>
          </div>
        ))}
      </div>
    </section>
  );
});

export default CaptureHistoryPanel;
