import { afterEach, describe, expect, it } from 'bun:test';
import { DEFAULT_CAPTURE_CONFIGURATION, type CaptureConfiguration } from '#lib/models/capture.ts';
import type { CapturedPacketDto, CaptureDeviceDto, CaptureStatusDto } from '#lib/api/daemon.ts';
import {
  CaptureSessionController,
  type CaptureHistoryItem,
  type CaptureSessionEvents,
  type CaptureSessionTexts,
} from './capture-session';
import type { CaptureIpc, CaptureStartOptions } from './capture-ipc';

const devices: CaptureDeviceDto[] = [
  { name: 'eth0', description: 'Ethernet', addresses: [], loopback: false },
  { name: 'wifi0', description: 'Wi-Fi', addresses: [], loopback: false },
];

function activeStatus(overrides?: Partial<CaptureStatusDto>): CaptureStatusDto {
  return {
    captureId: 'cap-1',
    state: 'capturing',
    active: true,
    packets: 10,
    bytes: 512,
    droppedPackets: 0,
    filteredPackets: 0,
    elapsedSeconds: 5,
    deviceName: 'eth0',
    appName: '',
    message: '',
    ...overrides,
  };
}

function stoppedStatus(overrides?: Partial<CaptureStatusDto>): CaptureStatusDto {
  return activeStatus({
    state: 'completed',
    active: false,
    packets: 25,
    ...overrides,
  });
}

function packet(sequence: number): CapturedPacketDto {
  return {
    captureId: 'cap-1',
    sequence,
    timestampUs: sequence * 1000,
    capturedLength: 64,
    originalLength: 64,
    linkLayer: 1,
    protocol: 'TCP',
    source: '10.0.0.1',
    destination: '10.0.0.2',
    sourcePort: 1234,
    destinationPort: 80,
    info: '',
    data: [],
  };
}

const texts: CaptureSessionTexts = {
  ready: () => 'ready',
  opening: () => 'opening',
  closing: () => 'closing',
  receiving: () => 'receiving',
  ended: () => 'ended',
  couldNotStart: () => 'could-not-start',
  completedOutcome: () => 'completed',
  unavailableOutcome: () => 'unavailable',
  stopWaiting: () => 'stop-waiting',
  installProvider: () => 'install-provider',
  interfacesAvailable: (count) => `interfaces:${count}`,
  interfaceOne: () => 'interface',
  interfaceOther: () => 'interfaces',
  streamUnavailable: (error) => `stream-unavailable:${error}`,
  toastStartedTitle: () => 'started',
  toastStartedBody: (device) => `started:${device}`,
  toastFailedTitle: () => 'failed',
  toastSavedTitle: () => 'saved',
  toastSaveFailedTitle: () => 'save-failed',
  toastStoppedTitle: () => 'stopped',
  toastStoppedBody: () => 'stopped-body',
  toastStopRequestedTitle: () => 'stop-requested',
  toastStopRequestedBody: () => 'stop-requested-body',
  toastStopFailedTitle: () => 'stop-failed',
  restored: () => 'restored',
  saveFilterName: () => 'pcap-filter',
};

function historyItem(deviceName: string, captureFilter: string): CaptureHistoryItem {
  return {
    id: `${deviceName}:${captureFilter}`,
    startedAt: 1,
    endedAt: 2,
    deviceName,
    packets: 1,
    bytes: 1,
    droppedPackets: 0,
    configuration: { ...DEFAULT_CAPTURE_CONFIGURATION, captureFilter },
    outcome: 'completed',
  };
}

interface Harness {
  controller: CaptureSessionController;
  ipc: CaptureIpc;
  notices: Array<{ title: string; body: string; color: string }>;
  persisted: CaptureConfiguration[];
  remembered: Array<string | null>;
  started: CaptureStartOptions[];
  downloads: Array<{ captureId: string; path: string }>;
  saveDialogs: Array<{ defaultPath: string; filterName: string }>;
  setNow: (ms: number) => void;
}

const live: CaptureSessionController[] = [];
afterEach(() => {
  for (const controller of live.splice(0)) controller.unmount();
});

function createHarness(
  ipcOverrides?: Partial<CaptureIpc>,
  eventOverrides?: Partial<CaptureSessionEvents>,
): Harness {
  let nowMs = 1_000_000;
  const notices: Harness['notices'] = [];
  const persisted: CaptureConfiguration[] = [];
  const remembered: Array<string | null> = [];
  const started: CaptureStartOptions[] = [];
  const downloads: Harness['downloads'] = [];
  const saveDialogs: Harness['saveDialogs'] = [];

  const ipc: CaptureIpc = {
    listDevices: async () => ({ devices, available: true, message: 'ok' }),
    startCapture: async (options) => {
      started.push(options);
      return 'cap-1';
    },
    stopCapture: async () => {},
    getStatus: async () => activeStatus(),
    startPacketStream: async () => {},
    downloadCapture: async (captureId, path) => {
      downloads.push({ captureId, path });
      return true;
    },
    openPacketInspector: async () => {},
    pickSavePath: async () => null,
    ...ipcOverrides,
  };
  // Observe dialog calls even when tests override the dialog itself.
  const dialogInner = ipc.pickSavePath;
  ipc.pickSavePath = async (defaultPath, filterName) => {
    saveDialogs.push({ defaultPath, filterName });
    return dialogInner(defaultPath, filterName);
  };
  const events: CaptureSessionEvents = {
    notify: (title, body, color) => {
      notices.push({ title, body, color });
    },
    persistConfiguration: (configuration) => {
      persisted.push(configuration);
    },
    readPersistedConfiguration: () => null,
    rememberActiveCapture: (captureId) => {
      remembered.push(captureId);
    },
    readActiveCapture: () => null,
    ...eventOverrides,
  };
  const controller = new CaptureSessionController(
    ipc,
    texts,
    events,
    { ...DEFAULT_CAPTURE_CONFIGURATION },
    {
      now: () => nowMs,
      flushScheduler: (flush) => {
        flush();
        return 0;
      },
      cancelScheduledFlush: () => {},
    },
  );
  live.push(controller);
  return {
    controller,
    ipc,
    notices,
    persisted,
    remembered,
    started,
    downloads,
    saveDialogs,
    setNow: (ms: number) => {
      nowMs = ms;
    },
  };
}

/** Lets the controller's fire-and-forget mount/initialize chain settle. */
function settle(): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, 5));
}

describe('mount and devices', () => {
  it('prefers the first class A/B/C interface over loopback', async () => {
    const { controller } = createHarness({
      listDevices: async () => ({
        available: true,
        message: 'ok',
        devices: [
          { name: 'lo', description: 'Loopback', addresses: ['127.0.0.1'], loopback: true },
          {
            name: 'eth0',
            description: 'Ethernet',
            addresses: ['192.168.1.20'],
            loopback: false,
          },
        ],
      }),
    });

    controller.mount(true);
    await settle();

    expect(controller.selectedDevice).toBe('eth0');
  });

  it('loads devices and selects the first interface when connected', async () => {
    const { controller } = createHarness();

    controller.mount(true);
    await settle();

    expect(controller.devices).toHaveLength(2);
    expect(controller.devicesLoaded).toBe(true);
    expect(controller.devicesAvailable).toBe(true);
    expect(controller.selectedDevice).toBe('eth0');
    expect(controller.statusMessage).toBe('interfaces:2');
    expect(controller.canStart).toBe(true);
  });

  it('stays uninitialized until the connection arrives', async () => {
    const { controller } = createHarness();

    controller.mount(false);
    await settle();
    expect(controller.devicesLoaded).toBe(false);
    expect(controller.canStart).toBe(false);

    controller.onConnectionChange(true);
    await settle();
    expect(controller.devicesLoaded).toBe(true);
    expect(controller.canStart).toBe(true);
  });

  it('reports device failures without throwing', async () => {
    const { controller } = createHarness({
      listDevices: async () => {
        throw new Error('no daemon');
      },
    });

    controller.mount(true);
    await settle();

    expect(controller.devicesAvailable).toBe(false);
    expect(controller.devices).toHaveLength(0);
    expect(controller.devicesMessage).toBe('no daemon');
    expect(controller.devicesLoaded).toBe(true);
    expect(controller.canStart).toBe(false);
  });
});

describe('startCapture', () => {
  it('runs the happy path and polls the first status', async () => {
    const { controller, notices, remembered, started } = createHarness();
    controller.mount(true);
    await settle();

    await controller.startCapture();

    expect(started).toHaveLength(1);
    expect(started[0]).toMatchObject({ deviceName: 'eth0', snapLength: 65535 });
    expect(controller.captureId).toBe('cap-1');
    expect(controller.captureState).toBe('capturing');
    expect(controller.capturing).toBe(true);
    expect(controller.packets).toBe(10);
    expect(controller.starting).toBe(false);
    expect(remembered).toContain('cap-1');
    expect(notices[0]).toMatchObject({ title: 'started', body: 'started:Ethernet' });
  });

  it('captures every application by default', async () => {
    const { controller, started } = createHarness();
    controller.mount(true);
    await settle();

    await controller.startCapture();

    expect(started[0]).toMatchObject({ appPath: '', appName: '' });
    expect(controller.appName).toBe('');
  });

  it('restricts the capture to the selected application and reports its skipped packets', async () => {
    const { controller, started } = createHarness({
      getStatus: async () => activeStatus({ filteredPackets: 7, appName: 'Edge' }),
    });
    controller.mount(true);
    await settle();
    controller.configuration.appPath = 'C:\\Apps\\edge.exe';
    controller.configuration.appName = 'Edge';

    await controller.startCapture();

    expect(started[0]).toMatchObject({ appPath: 'C:\\Apps\\edge.exe', appName: 'Edge' });
    expect(controller.appName).toBe('Edge');
    expect(controller.filteredPackets).toBe(7);
  });

  it('does nothing when it cannot start', async () => {
    const { controller, started } = createHarness();
    controller.mount(false);

    await controller.startCapture();

    expect(started).toHaveLength(0);
    expect(controller.captureId).toBe('');
    expect(controller.captureState).toBe('idle');
  });

  it('faults with user feedback when the daemon rejects start', async () => {
    const { controller, notices, remembered } = createHarness({
      startCapture: async () => {
        throw new Error('device busy');
      },
    });
    controller.mount(true);
    await settle();

    await controller.startCapture();

    expect(controller.captureState).toBe('faulted');
    expect(controller.capturing).toBe(false);
    expect(controller.captureId).toBe('');
    expect(controller.statusError).toBe('device busy');
    expect(controller.statusMessage).toBe('could-not-start');
    expect(remembered).toContain(null);
    expect(notices).toHaveLength(1);
    expect(notices[0]).toMatchObject({ title: 'failed', body: 'device busy' });
  });
});

describe('stopCapture', () => {
  it('notifies stop-requested while the daemon is still active', async () => {
    const { controller, notices } = createHarness();
    controller.mount(true);
    await settle();
    await controller.startCapture();
    notices.length = 0;

    await controller.stopCapture();

    expect(controller.capturing).toBe(true);
    expect(notices).toHaveLength(1);
    expect(notices[0]).toMatchObject({ title: 'stop-requested' });
  });

  it('records a completed session when the daemon has stopped', async () => {
    let calls = 0;
    const { controller, notices, remembered } = createHarness({
      getStatus: async () => {
        calls += 1;
        return calls === 1 ? activeStatus() : stoppedStatus();
      },
    });
    controller.mount(true);
    await settle();
    await controller.startCapture();
    notices.length = 0;

    await controller.stopCapture();

    expect(controller.capturing).toBe(false);
    expect(controller.history).toHaveLength(1);
    expect(controller.history[0]).toMatchObject({ packets: 25, outcome: 'completed' });
    expect(notices).toHaveLength(1);
    expect(notices[0]).toMatchObject({ title: 'stopped' });
    expect(remembered[remembered.length - 1]).toBeNull();
  });

  it('returns to capturing with an error toast when stop is rejected', async () => {
    const { controller, notices } = createHarness({
      stopCapture: async () => {
        throw new Error('daemon busy');
      },
    });
    controller.mount(true);
    await settle();
    await controller.startCapture();
    notices.length = 0;

    await controller.stopCapture();

    expect(controller.captureState).toBe('capturing');
    expect(controller.statusError).toBe('daemon busy');
    expect(notices).toHaveLength(1);
    expect(notices[0]).toMatchObject({ title: 'stop-failed', body: 'daemon busy' });
  });
});

describe('pollStatus fault policy', () => {
  it('faults the session after consecutive poll failures', async () => {
    const { controller } = createHarness({
      getStatus: async () => {
        throw new Error('socket gone');
      },
    });
    controller.mount(false);
    controller.onConnectionChange(true);
    await settle();
    await controller.startCapture();
    expect(controller.capturing).toBe(true);

    await controller.pollStatus();
    await controller.pollStatus();

    expect(controller.captureState).toBe('faulted');
    expect(controller.capturing).toBe(false);
    expect(controller.history).toHaveLength(1);
    expect(controller.history[0].outcome).toBe('unavailable');
  });

  it('recovers the failure count after a successful poll', async () => {
    let calls = 0;
    const { controller } = createHarness({
      getStatus: async () => {
        calls += 1;
        if (calls <= 1) throw new Error('transient');
        return activeStatus();
      },
    });
    controller.mount(false);
    controller.onConnectionChange(true);
    await settle();
    await controller.startCapture();
    expect(controller.statusError).toBe('transient');

    await controller.pollStatus();

    expect(controller.captureState).toBe('capturing');
    expect(controller.capturing).toBe(true);
    expect(controller.statusError).toBe('');
    expect(controller.history).toHaveLength(0);
  });
});

describe('downloadCurrentCapture', () => {
  function stoppedHarness(
    ipcOverrides?: Partial<CaptureIpc>,
    eventOverrides?: Partial<CaptureSessionEvents>,
  ): Harness {
    return createHarness(
      { getStatus: async () => stoppedStatus(), ...ipcOverrides },
      eventOverrides,
    );
  }

  it('saves with the chosen path and toasts', async () => {
    const harness = stoppedHarness({
      pickSavePath: async () => '/tmp/antiwire.pcap',
    });
    const { controller, notices, downloads, saveDialogs } = harness;
    controller.mount(true);
    await settle();
    await controller.startCapture();
    expect(controller.capturing).toBe(false);
    notices.length = 0;

    await controller.downloadCurrentCapture('default-name.pcap');

    expect(saveDialogs).toEqual([{ defaultPath: 'default-name.pcap', filterName: 'pcap-filter' }]);
    expect(downloads).toEqual([{ captureId: 'cap-1', path: '/tmp/antiwire.pcap' }]);
    expect(notices).toHaveLength(1);
    expect(notices[0]).toMatchObject({ title: 'saved', body: '/tmp/antiwire.pcap' });
    expect(controller.downloading).toBe(false);
  });

  it('treats dialog cancellation as a no-op', async () => {
    const { controller, notices, downloads } = stoppedHarness();
    controller.mount(true);
    await settle();
    await controller.startCapture();
    notices.length = 0;

    await controller.downloadCurrentCapture('default-name.pcap');

    expect(downloads).toHaveLength(0);
    expect(notices).toHaveLength(0);
  });

  it('toasts dialog failures instead of rejecting', async () => {
    const { controller, notices, downloads } = stoppedHarness({
      pickSavePath: async () => {
        throw new Error('dialog unavailable');
      },
    });
    controller.mount(true);
    await settle();
    await controller.startCapture();
    notices.length = 0;

    await controller.downloadCurrentCapture('default-name.pcap');

    expect(downloads).toHaveLength(0);
    expect(notices).toHaveLength(1);
    expect(notices[0]).toMatchObject({ title: 'save-failed', body: 'dialog unavailable' });
  });

  it('does nothing while capturing', async () => {
    const { controller, downloads, saveDialogs } = createHarness({
      pickSavePath: async () => '/tmp/antiwire.pcap',
    });
    controller.mount(true);
    await settle();
    await controller.startCapture();
    expect(controller.capturing).toBe(true);

    await controller.downloadCurrentCapture('default-name.pcap');

    expect(saveDialogs).toHaveLength(0);
    expect(downloads).toHaveLength(0);
  });
});

describe('history and reuse', () => {
  it('records a completed session exactly once', async () => {
    const { controller } = createHarness({
      getStatus: async () => stoppedStatus(),
    });
    controller.mount(true);
    await settle();
    await controller.startCapture();
    expect(controller.history).toHaveLength(1);

    controller.applyStatus(stoppedStatus());

    expect(controller.history).toHaveLength(1);
  });

  it('reuseSession restores configuration, device, and status', async () => {
    const { controller } = createHarness();
    controller.mount(true);
    await settle();

    controller.reuseSession(historyItem('Wi-Fi', 'tcp port 80'));

    expect(controller.configuration.captureFilter).toBe('tcp port 80');
    expect(controller.selectedDevice).toBe('wifi0');
    expect(controller.statusMessage).toBe('restored');
  });

  it('reuseSession is a no-op while capturing', async () => {
    const { controller } = createHarness();
    controller.mount(true);
    await settle();
    await controller.startCapture();
    expect(controller.capturing).toBe(true);

    controller.reuseSession(historyItem('Wi-Fi', 'tcp port 80'));

    expect(controller.configuration.captureFilter).toBe('');
  });

  it('clearHistory empties the history', async () => {
    const { controller } = createHarness({
      getStatus: async () => stoppedStatus(),
    });
    controller.mount(true);
    await settle();
    await controller.startCapture();
    expect(controller.history).toHaveLength(1);

    controller.clearHistory();

    expect(controller.history).toHaveLength(0);
  });

  it('clearCurrentSession resets to idle', async () => {
    const { controller, remembered } = createHarness({
      getStatus: async () => stoppedStatus(),
    });
    controller.mount(true);
    await settle();
    await controller.startCapture();

    controller.clearCurrentSession();

    expect(controller.captureId).toBe('');
    expect(controller.captureState).toBe('idle');
    expect(controller.statusMessage).toBe('ready');
    expect(controller.packets).toBe(0);
    expect(remembered[remembered.length - 1]).toBeNull();
  });

  it('clearCurrentSession is a no-op while capturing', async () => {
    const { controller } = createHarness();
    controller.mount(true);
    await settle();
    await controller.startCapture();

    controller.clearCurrentSession();

    expect(controller.captureId).toBe('cap-1');
    expect(controller.captureState).toBe('capturing');
  });
});

describe('packets', () => {
  it('buffers and flushes session packets', () => {
    const { controller } = createHarness();

    controller.enqueueSessionPackets([packet(1), packet(2)]);

    expect(controller.capturedPackets.map((item) => item.sequence)).toEqual([1, 2]);
  });
});

describe('restoreActiveCapture', () => {
  it('re-attaches to a stored capture on mount', async () => {
    const { controller } = createHarness(
      {
        getStatus: async (captureId) =>
          activeStatus({ captureId, deviceName: 'wifi0', packets: 7 }),
      },
      { readActiveCapture: () => 'cap-9' },
    );

    controller.mount(true);
    await settle();

    expect(controller.captureId).toBe('cap-9');
    expect(controller.capturing).toBe(true);
    expect(controller.packets).toBe(7);
  });
});
