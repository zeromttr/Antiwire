// Reads a mutable workspace while rendering, so React Compiler must not
// cache it (see src/lib/state/compiler-opt-out.test.ts).
'use no memo';

import { useCallback, useEffect, useState } from 'react';
import EmptyState from '#lib/components/ui/EmptyState.tsx';
import DaemonOffline from '#lib/components/shell/DaemonOffline.tsx';
import DeviceWatchDialog from '#lib/components/network/dialogs/DeviceWatchDialog.tsx';
import NetworkControls from '#lib/components/network/NetworkControls.tsx';
import NetworkDeviceList from '#lib/components/network/NetworkDeviceList.tsx';
import { NetworkWorkspace, type NetworkHost } from '#lib/components/network/network-workspace.ts';
import type { WatchInterval } from '#lib/models/network-watch.ts';
import { useReactive, useSelector } from '#lib/state/reactive.ts';
import { daemon } from '#lib/stores/daemon.ts';
import { api } from '#lib/api/daemon.ts';
import { m } from '#lib/i18n/messages.ts';
import styles from './NetworkPage.module.css';

// Reads the daemon store directly, so it is stable for the page's lifetime.
/** Writes a tracked workspace field (the former `bind:` target). */
function setField<T extends object, K extends keyof T>(target: T, key: K, value: T[K]): void {
  target[key] = value;
}

const networkHost: NetworkHost = {
  get connected() {
    return daemon.state.connected;
  },
  toast: (title, body, color) => daemon.addToast(title, body, color),
};

export default function NetworkPage() {
  const [net] = useState(() => new NetworkWorkspace(api, networkHost));
  useReactive(net);
  const connected = useSelector(daemon, (d) => d.state.connected);

  useEffect(() => {
    net.mount();
    return () => net.dispose();
  }, [net]);

  useEffect(() => {
    net.onConnectionChange();
  }, [net, connected]);

  const onWatchOpenChange = useCallback(
    (open: boolean) => setField(net, 'watchDialogOpen', open),
    [net],
  );
  const onIntervalChange = useCallback(
    (interval: WatchInterval) => setField(net, 'selectedWatchInterval', interval),
    [net],
  );

  return (
    <>
      <div className={styles.page} data-testid="page-network" data-page-motion="network">
        <div className={styles.scroll}>
          {!connected ? (
            <DaemonOffline text={m.network_empty_disconnected()} />
          ) : net.ready && !net.supported ? (
            <EmptyState text={net.message || m.network_empty_unsupported()} panel />
          ) : net.ready ? (
            <>
              <NetworkControls net={net} />
              <NetworkDeviceList net={net} />
            </>
          ) : null}
        </div>
      </div>

      <DeviceWatchDialog
        open={net.watchDialogOpen}
        onOpenChange={onWatchOpenChange}
        interval={net.selectedWatchInterval}
        onIntervalChange={onIntervalChange}
        mode={net.watchDialogMode}
        device={net.selectedDevice}
        watch={net.selectedWatch}
        submitting={net.watchSubmitting}
        onConfirm={net.confirmWatchDialog}
        onCancel={net.closeWatchDialog}
      />
    </>
  );
}
