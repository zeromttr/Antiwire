// Reads a mutable workspace while rendering, so React Compiler must not
// cache it (see src/lib/state/compiler-opt-out.test.ts).
'use no memo';

import clsx from 'clsx';
import { Database, Network, Radio, RefreshCw, Shield } from 'lucide-react';
import { memo } from 'react';
import { ReconnectCountdown } from '#lib/components/shell/DaemonOffline.tsx';
import { Button } from '#lib/components/ui/Button.tsx';
import { m } from '#lib/i18n/messages.ts';
import type { CaptureWorkspace } from './capture-workspace';
import styles from './CaptureOfflinePanel.module.css';

interface Props {
  cap: CaptureWorkspace;
  /**
   * The daemon's connecting flag. `cap.connecting` reads the host, which does
   * not notify the workspace, so the page passes it in to re-render on change.
   */
  connecting: boolean;
}

export const CaptureOfflinePanel = memo(function CaptureOfflinePanel({ cap, connecting }: Props) {
  return (
    <section className={clsx(styles.offline, 'panel')} aria-labelledby="capture-offline-title">
      <div className={styles['offline-mark']}>
        <Radio size={28} strokeWidth={1.7} />
      </div>
      <div className={styles['offline-copy']}>
        <div className={styles.eyebrow}>
          <span></span> {m.capture_offline_eyebrow()}
        </div>
        <h2 id="capture-offline-title">{m.capture_offline_title()}</h2>
        <p>{m.capture_offline_body()}</p>
        <div className={styles.requirements}>
          <div>
            <Shield size={16} />
            <span>
              <strong>{m.capture_offline_local_title()}</strong>
              {m.capture_offline_local_body()}
            </span>
          </div>
          <div>
            <Network size={16} />
            <span>
              <strong>{m.capture_offline_driver_title()}</strong>
              {m.capture_offline_driver_body()}
            </span>
          </div>
          <div>
            <Database size={16} />
            <span>
              <strong>{m.capture_offline_bounded_title()}</strong>
              {m.capture_offline_bounded_body()}
            </span>
          </div>
        </div>
        <div className={styles.retry}>
          <Button variant="primary" onClick={cap.connect} disabled={connecting}>
            <span className={clsx(connecting && styles.spin)}>
              <RefreshCw size={15} />
            </span>
            {connecting ? m.capture_connecting() : m.capture_retry_connection()}
          </Button>
          {/* The button already says when an attempt is running. */}
          {!connecting && <ReconnectCountdown />}
        </div>
      </div>
    </section>
  );
});

export default CaptureOfflinePanel;
