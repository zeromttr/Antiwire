import { afterEach, beforeAll, describe, expect, mock, test } from 'bun:test';
import { loadMessages, m } from '#lib/i18n/messages.ts';
import { formatWatchInterval } from '#lib/models/network-watch.ts';
import type { DeviceWatch, NetworkDeviceRow } from '#lib/models/network-watch.ts';
import { NetworkWorkspace, type NetworkApiClient, type NetworkHost } from './network-workspace';

function device(overrides: Partial<NetworkDeviceRow> = {}): NetworkDeviceRow {
  return {
    ipAddress: '192.168.1.10',
    macAddress: 'AA:BB:CC:DD:EE:10',
    manufacturer: 'Acme',
    mdnsName: 'lamp.local',
    isPresent: true,
    lastSeen: '2026-09-05T12:00:00.000Z',
    isWatched: false,
    ...overrides,
  };
}

function watch(overrides: Partial<DeviceWatch> = {}): DeviceWatch {
  return {
    id: 7,
    ipAddress: '192.168.1.10',
    macAddress: 'AA:BB:CC:DD:EE:10',
    intervalMinutes: 10,
    enabled: true,
    isPresent: true,
    lastChecked: '2026-09-05T12:00:00.000Z',
    ...overrides,
  };
}

function mappingState(
  overrides: Partial<Awaited<ReturnType<NetworkApiClient['getNetworkMappingState']>>> = {},
) {
  return {
    devices: [device()],
    scanRanges: [{ id: 1, adapterId: 'Ethernet', cidr: '192.168.1.0/24' }],
    deviceWatches: [] as DeviceWatch[],
    isScanning: false,
    supported: true,
    message: 'idle',
    ...overrides,
  };
}

function workspace(options?: { connected?: boolean; client?: Partial<NetworkApiClient> }) {
  const toasts: Array<[string, string, string]> = [];
  let connected = options?.connected ?? true;
  const host: NetworkHost = {
    get connected() {
      return connected;
    },
    toast: (title, body, color) => {
      toasts.push([title, body, color]);
    },
  };
  const client = {
    getNetworkMappingState: mock(async () => mappingState()),
    scanNetwork: mock(async () => undefined),
    stopNetworkScan: mock(async () => undefined),
    clearNetworkDevices: mock(async () => undefined),
    saveNetworkDeviceWatch: mock(async () => undefined),
    removeNetworkDeviceWatch: mock(async () => undefined),
    ...options?.client,
  } as NetworkApiClient;
  const net = new NetworkWorkspace(client, host);
  return {
    net,
    client,
    toasts,
    setConnected: (next: boolean) => {
      connected = next;
    },
  };
}

const workspaces: NetworkWorkspace[] = [];

function mountedWorkspace(options?: { connected?: boolean; client?: Partial<NetworkApiClient> }) {
  const created = workspace(options);
  created.net.mount();
  workspaces.push(created.net);
  return created;
}

beforeAll(async () => {
  await loadMessages('en');
});

afterEach(() => {
  for (const net of workspaces) net.unmount();
  workspaces.length = 0;
});

describe('NetworkWorkspace.loadState', () => {
  test('does nothing until mount', async () => {
    const { net, client } = workspace();
    await net.loadState();
    expect(client.getNetworkMappingState).not.toHaveBeenCalled();
    expect(net.ready).toBe(false);
  });

  test('merges devices with watches and marks ready', async () => {
    const { net } = mountedWorkspace({
      client: {
        getNetworkMappingState: mock(async () =>
          mappingState({
            devices: [device({ isWatched: false })],
            deviceWatches: [watch()],
          }),
        ),
      },
    });
    await net.loadState();
    expect(net.ready).toBe(true);
    expect(net.supported).toBe(true);
    expect(net.devices[0]?.isWatched).toBe(true);
    expect(net.suggestedRanges[0]?.cidr).toBe('192.168.1.0/24');
    expect(net.deviceCountText).toBe(m.network_device_count_one({ count: 1 }));
  });

  test('records a load error without throwing', async () => {
    const { net } = mountedWorkspace({
      client: {
        getNetworkMappingState: mock(async () => {
          throw new Error('mapping down');
        }),
      },
    });
    await net.loadState();
    expect(net.ready).toBe(true);
    expect(net.message).toBe('mapping down');
  });

  test('does not call the daemon while disconnected', async () => {
    const { net, client } = mountedWorkspace({ connected: false });
    await net.loadState();
    expect(client.getNetworkMappingState).not.toHaveBeenCalled();
  });
});

describe('NetworkWorkspace scan controls', () => {
  test('startScan is a no-op while disconnected', async () => {
    const { net, client } = mountedWorkspace({ connected: false });
    await net.startScan();
    expect(client.scanNetwork).not.toHaveBeenCalled();
  });

  test('startScan uses a custom CIDR and toasts', async () => {
    const { net, client, toasts } = mountedWorkspace();
    await net.loadState();
    net.customCidr = '10.0.0.0/8';
    await net.startScan();
    expect(client.scanNetwork).toHaveBeenCalledWith(['10.0.0.0/8']);
    expect(net.isScanning).toBe(false);
    expect(toasts[0]?.[0]).toBe(m.network_toast_scan_started_title());
  });

  test('startScan toasts a failure without marking a scan running', async () => {
    const { net, toasts } = mountedWorkspace({
      client: {
        scanNetwork: mock(async () => {
          throw new Error('busy');
        }),
      },
    });
    await net.startScan();
    expect(net.isScanning).toBe(false);
    expect(toasts[0]).toEqual([m.network_toast_scan_failed_title(), 'busy', 'var(--bad)']);
  });

  test('stopScan and clearDevices toast failures', async () => {
    const { net, toasts } = mountedWorkspace({
      client: {
        stopNetworkScan: mock(async () => {
          throw new Error('stop');
        }),
        clearNetworkDevices: mock(async () => {
          throw new Error('clear');
        }),
      },
    });
    await net.stopScan();
    await net.clearDevices();
    expect(toasts.map((toast) => toast[1])).toEqual(['stop', 'clear']);
  });

  test('chooseScanRange toggles the custom CIDR', () => {
    const { net } = workspace();
    net.chooseScanRange('10.0.0.0/8');
    expect(net.customCidr).toBe('10.0.0.0/8');
    net.chooseScanRange('10.0.0.0/8');
    expect(net.customCidr).toBe('');
  });
});

describe('NetworkWorkspace watches and sort', () => {
  test('opens configure and remove dialogs', () => {
    const { net } = workspace();
    const row = device();
    const existing = watch({ intervalMinutes: 30 });
    net.openWatchSettings(row);
    expect(net.watchDialogOpen).toBe(true);
    expect(net.watchDialogMode).toBe('configure');
    expect(net.selectedWatchInterval).toBe(5);
    net.openRemoveWatch(row, existing);
    expect(net.watchDialogMode).toBe('remove');
    expect(net.selectedWatchInterval).toBe(30);
  });

  test('closeWatchDialog is a no-op while submitting', () => {
    const { net } = workspace();
    net.watchDialogOpen = true;
    net.watchSubmitting = true;
    net.closeWatchDialog();
    expect(net.watchDialogOpen).toBe(true);
  });

  test('confirmWatchDialog saves a watch and closes', async () => {
    const { net, client, toasts } = mountedWorkspace();
    const row = device();
    net.openWatchSettings(row);
    await net.confirmWatchDialog(5);
    expect(client.saveNetworkDeviceWatch).toHaveBeenCalledWith({
      ipAddress: row.ipAddress,
      macAddress: row.macAddress,
      intervalMinutes: 5,
    });
    expect(net.watchDialogOpen).toBe(false);
    expect(toasts[0]?.[1]).toBe(
      m.network_toast_watch_added_body({ interval: formatWatchInterval(5) }),
    );
  });

  test('confirmWatchDialog removes a watch', async () => {
    const { net, client } = mountedWorkspace();
    const row = device();
    const existing = watch();
    net.openRemoveWatch(row, existing);
    await net.confirmWatchDialog(10);
    expect(client.removeNetworkDeviceWatch).toHaveBeenCalledWith(existing);
    expect(net.watchDialogOpen).toBe(false);
  });

  test('toggleSort cycles the last-seen column', () => {
    const { net } = workspace();
    net.toggleSort('lastSeen');
    expect(net.activeSortKey).toBe('lastSeen');
    expect(net.activeSortDir).toBe(-1);
    net.toggleSort('lastSeen');
    expect(net.activeSortDir).toBe(1);
    net.toggleSort('lastSeen');
    expect(net.sortKey).toBeNull();
    expect(net.activeSortDir).toBe(-1);
  });
});

describe('NetworkWorkspace reactivity', () => {
  test('a load notifies subscribers once', async () => {
    const { net } = mountedWorkspace();
    let calls = 0;
    net.subscribe(() => calls++);
    await net.loadState();
    await Promise.resolve();
    expect(calls).toBe(1);
    expect(net.devices).toHaveLength(1);
  });

  test('sortedDevices keeps its identity until its inputs change', async () => {
    const { net } = mountedWorkspace();
    await net.loadState();
    const sorted = net.sortedDevices;
    expect(net.sortedDevices).toBe(sorted);
    net.toggleSort('device');
    expect(net.sortedDevices).not.toBe(sorted);
  });

  test('dispose clears the poll timer', async () => {
    const { net, client } = mountedWorkspace();
    await net.loadState();
    const calls = (client.getNetworkMappingState as ReturnType<typeof mock>).mock.calls.length;
    net.dispose();
    // The poll was scheduled by loadState; after dispose nothing is pending.
    expect((net as unknown as { pollTimer: unknown }).pollTimer).toBeNull();
    expect((client.getNetworkMappingState as ReturnType<typeof mock>).mock.calls.length).toBe(
      calls,
    );
  });
});
