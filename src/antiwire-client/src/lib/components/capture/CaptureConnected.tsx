// Reads a mutable workspace while rendering, so React Compiler must not
// cache it (see src/lib/state/compiler-opt-out.test.ts).
'use no memo';

import { memo } from 'react';
import { CaptureCommandBar } from './CaptureCommandBar.tsx';
import { CaptureConfigPanel } from './CaptureConfigPanel.tsx';
import { CaptureHistoryPanel } from './CaptureHistoryPanel.tsx';
import { CaptureMetrics } from './CaptureMetrics.tsx';
import { CaptureTelemetryPanel } from './CaptureTelemetryPanel.tsx';
import type { CaptureWorkspace } from './capture-workspace';
import styles from './CaptureConnected.module.css';

interface Props {
  cap: CaptureWorkspace;
  /** The daemon connection, which the command bar reads (see CaptureCommandBar). */
  connected: boolean;
}

/**
 * Each panel subscribes to its own slice of `cap`, so a packet batch
 * re-renders the telemetry list without touching the configuration form.
 */
export const CaptureConnected = memo(function CaptureConnected({ cap, connected }: Props) {
  return (
    <>
      <CaptureCommandBar cap={cap} connected={connected} />
      <div className={styles.workspace}>
        <CaptureConfigPanel cap={cap} />
        <div className={styles.live}>
          <CaptureMetrics cap={cap} />
          <CaptureTelemetryPanel cap={cap} />
        </div>
      </div>
      <CaptureHistoryPanel cap={cap} />
    </>
  );
});

export default CaptureConnected;
