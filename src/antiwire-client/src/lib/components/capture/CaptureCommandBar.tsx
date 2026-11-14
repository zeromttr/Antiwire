// Reads a mutable workspace while rendering, so React Compiler must not
// cache it (see src/lib/state/compiler-opt-out.test.ts).
'use no memo';

import clsx from 'clsx';
import { AlertTriangle, Download, Play, RefreshCw, Square, Trash2 } from 'lucide-react';
import { memo } from 'react';
import { Button } from '#lib/components/ui/Button.tsx';
import { Status } from '#lib/components/ui/Status.tsx';
import type { StatusTone } from '#lib/components/ui/status-tone.ts';
import { formatCaptureDuration } from '#lib/models/capture.ts';
import { m } from '#lib/i18n/messages.ts';
import { shallowEqual, useSelector } from '#lib/state/reactive.ts';
import type { CaptureWorkspace } from './capture-workspace';
import { canStartCapture, captureStateLabel, isProviderUnavailable } from './view/capture-view';
import styles from './CaptureCommandBar.module.css';

interface Props {
  cap: CaptureWorkspace;
  /**
   * The daemon connection. `cap.connected` reads the host, which does not
   * notify the workspace, so the page passes it in to re-render on change.
   */
  connected: boolean;
}

export const CaptureCommandBar = memo(function CaptureCommandBar({ cap, connected }: Props) {
  const s = useSelector(
    cap,
    (c) => ({
      devicesLoaded: c.devicesLoaded,
      devicesAvailable: c.devicesAvailable,
      devicesMessage: c.devicesMessage,
      selectedDevice: c.selectedDevice,
      captureState: c.captureState,
      capturing: c.capturing,
      starting: c.starting,
      stopping: c.stopping,
      downloading: c.downloading,
      elapsedSeconds: c.elapsedSeconds,
      maxSeconds: c.configuration.maxSeconds,
      statusError: c.statusError,
      statusMessage: c.statusMessage,
      showsClear: c.showsClear,
      showsDownload: c.showsDownload,
      showsStop: c.showsStop,
    }),
    shallowEqual,
  );

  const providerUnavailable = isProviderUnavailable(connected, s.devicesLoaded, s.devicesAvailable);
  const canStart = canStartCapture({
    connected,
    devicesAvailable: s.devicesAvailable,
    selectedDevice: s.selectedDevice,
    capturing: s.capturing,
    starting: s.starting,
  });
  const tone: StatusTone = providerUnavailable
    ? 'warn'
    : s.captureState === 'faulted'
      ? 'bad'
      : s.capturing
        ? 'ok'
        : 'idle';
  const elapsedText = m.capture_elapsed_of_limit({
    elapsed: formatCaptureDuration(s.elapsedSeconds),
    limit: formatCaptureDuration(s.maxSeconds),
  });

  return (
    <>
      {providerUnavailable && (
        <div className={styles['driver-notice']} role="status">
          <AlertTriangle size={16} />
          <div>
            <strong>{m.capture_provider_unavailable_title()}</strong>
            <span>{s.devicesMessage || m.capture_provider_unavailable_fallback()}</span>
          </div>
          <Button variant="secondary" size="sm" onClick={cap.loadDevices}>
            <RefreshCw size={13} />
            {m.capture_check_again()}
          </Button>
        </div>
      )}

      <header className={styles['capture-head']}>
        <h1>{m.capture_title()}</h1>
        <Status tone={tone} className={s.capturing ? 'live' : ''}>
          {captureStateLabel(s.captureState, providerUnavailable)}
        </Status>
        {(s.capturing || s.elapsedSeconds > 0) && (
          <span className={styles.elapsed}>{elapsedText}</span>
        )}
        <p className={clsx(styles.message, s.statusError && styles.error)}>
          {s.statusError || s.statusMessage}
        </p>
        <div className={styles.actions}>
          {s.showsClear && (
            <Button
              variant="ghost"
              iconOnly
              aria-label={m.capture_clear_session_aria()}
              title={m.capture_clear_session_aria()}
              onClick={cap.clearCurrentSession}
            >
              <Trash2 size={15} />
            </Button>
          )}
          {s.showsDownload && (
            <Button variant="ghost" onClick={cap.downloadCurrentCapture} disabled={s.downloading}>
              <Download size={14} />
              {s.downloading ? m.capture_saving() : m.capture_save_pcap()}
            </Button>
          )}
          {s.showsStop ? (
            <Button variant="danger" onClick={cap.stopCapture} disabled={s.stopping}>
              <Square size={13} />
              {s.stopping ? m.capture_stopping() : m.capture_stop()}
            </Button>
          ) : providerUnavailable ? (
            <Button variant="secondary" disabled>
              <AlertTriangle size={14} />
              {m.capture_unavailable_button()}
            </Button>
          ) : (
            <Button variant="primary" onClick={cap.startCapture} disabled={!canStart}>
              <Play size={14} />
              {s.starting ? m.capture_starting() : m.capture_start()}
            </Button>
          )}
        </div>
      </header>
    </>
  );
});

export default CaptureCommandBar;
