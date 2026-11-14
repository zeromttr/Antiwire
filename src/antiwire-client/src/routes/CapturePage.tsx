// Reads a mutable workspace while rendering, so React Compiler must not
// cache it (see src/lib/state/compiler-opt-out.test.ts).
'use no memo';

import { useEffect, useState } from 'react';
import type { CapturedPacketDto } from '#lib/api/daemon.ts';
import { listen } from '#lib/bridge.ts';
import { CaptureConnected } from '#lib/components/capture/CaptureConnected.tsx';
import { CaptureOfflinePanel } from '#lib/components/capture/CaptureOfflinePanel.tsx';
import { createCaptureWorkspace } from '#lib/components/capture/capture-workspace.ts';
import { createCaptureIpc } from '#lib/components/capture/session/capture-ipc.ts';
import { browserPreviewMode } from '#lib/preview/runtime.ts';
import { useSelector } from '#lib/state/reactive.ts';
import { daemon } from '#lib/stores/daemon.ts';
import styles from './CapturePage.module.css';

function createWorkspace() {
  return createCaptureWorkspace(
    {
      get connected() {
        return daemon.state.connected;
      },
      get connecting() {
        return daemon.state.connecting;
      },
      connect: () => daemon.connect(),
      toast: (title, body, color) => daemon.addToast(title, body, color),
    },
    createCaptureIpc(),
  );
}

export default function CapturePage() {
  const [cap] = useState(createWorkspace);
  const connected = useSelector(daemon, (d) => d.state.connected);
  const connecting = useSelector(daemon, (d) => d.state.connecting);
  // The page itself only needs what its effects depend on; panels select their own slices.
  const configuration = useSelector(cap, (c) => c.configuration);
  const capturing = useSelector(cap, (c) => c.capturing);
  const captureId = useSelector(cap, (c) => c.captureId);

  // Declared first so the session is mounted before the connection and
  // configuration effects run (both are no-ops until it is).
  useEffect(() => {
    cap.mount();
    const stopPackets = listen('capture://packets', (payload) => {
      const sessionId = cap.captureId;
      if (!sessionId || !Array.isArray(payload)) return;
      const packetsForSession = (payload as CapturedPacketDto[]).filter(
        (packet) => packet.captureId === sessionId,
      );
      if (packetsForSession.length) cap.enqueueSessionPackets(packetsForSession);
    });
    const stopStreamErrors = listen('capture://stream-error', (event) => {
      if (event.captureId === cap.captureId) cap.reportStreamError(event.message);
    });
    return () => {
      stopPackets();
      stopStreamErrors();
      // `unmount`, not `dispose`: StrictMode remounts the same workspace, and
      // `dispose` would stop it forwarding session changes for good.
      cap.unmount();
    };
  }, [cap]);

  useEffect(() => {
    cap.onConnectionChange();
  }, [cap, connected]);

  // The configuration is replaced on every edit, so its reference tracks the fields.
  useEffect(() => {
    cap.onConfigurationChange();
  }, [cap, configuration]);

  useEffect(() => {
    if (!import.meta.env.DEV || browserPreviewMode !== 'sample' || !capturing) return;
    let disposed = false;
    const timer = setInterval(() => {
      void import('#lib/preview/backend.ts').then(({ previewBackend }) => {
        if (!disposed) cap.enqueueSessionPackets(previewBackend.packets(captureId));
      });
    }, 500);
    return () => {
      disposed = true;
      clearInterval(timer);
    };
  }, [cap, capturing, captureId]);

  return (
    <div className={styles.page} data-testid="page-capture" data-page-motion="capture">
      <div className={styles.scroll}>
        {!connected ? (
          <CaptureOfflinePanel cap={cap} connecting={connecting} />
        ) : (
          <CaptureConnected cap={cap} connected={connected} />
        )}
      </div>
    </div>
  );
}
