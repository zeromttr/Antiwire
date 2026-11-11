import { beforeAll, describe, expect, mock, test } from 'bun:test';
import type { CapturedPacketDto } from '#lib/api/daemon.ts';
import { loadMessages, m } from '#lib/i18n/messages.ts';
import { DEFAULT_CAPTURE_CONFIGURATION, type CaptureConfiguration } from '#lib/models/capture.ts';
import type { CaptureHistoryItem } from './session/capture-session';
import { CaptureWorkspace, type CaptureHost, type CaptureSessionApi } from './capture-workspace';

function packet(overrides: Partial<CapturedPacketDto> = {}): CapturedPacketDto {
  return {
    captureId: 'cap-1',
    sequence: 1,
    timestampUs: 1_000_000,
    capturedLength: 64,
    originalLength: 64,
    linkLayer: 1,
    protocol: 'TCP',
    source: '10.0.0.1',
    destination: '1.1.1.1',
    sourcePort: 443,
    destinationPort: 443,
    info: 'syn',
    data: [],
    ...overrides,
  };
}

function historyItem(overrides: Partial<CaptureHistoryItem> = {}): CaptureHistoryItem {
  return {
    id: 'hist-1',
    startedAt: 1,
    endedAt: 2,
    deviceName: 'Ethernet',
    packets: 4,
    bytes: 128,
    droppedPackets: 0,
    configuration: { ...DEFAULT_CAPTURE_CONFIGURATION },
    outcome: 'completed',
    ...overrides,
  };
}

function fakeSession(overrides: Partial<CaptureSessionApi> = {}): CaptureSessionApi {
  return {
    devices: [{ name: 'eth0', description: 'Ethernet', addresses: ['10.0.0.2'], loopback: false }],
    devicesMessage: '',
    devicesAvailable: true,
    devicesLoaded: true,
    loadingDevices: false,
    selectedDevice: 'eth0',
    configuration: { ...DEFAULT_CAPTURE_CONFIGURATION },
    captureId: '',
    captureState: 'idle',
    capturing: false,
    starting: false,
    stopping: false,
    statusMessage: 'ready',
    statusError: '',
    packets: 0,
    bytes: 0,
    droppedPackets: 0,
    filteredPackets: 0,
    appName: '',
    elapsedSeconds: 0,
    samples: [],
    capturedPackets: [],
    downloading: false,
    history: [],
    loadDevices: mock(async () => undefined),
    startCapture: mock(async () => undefined),
    stopCapture: mock(async () => undefined),
    clearCurrentSession: mock(() => undefined),
    reuseSession: mock(() => undefined),
    clearHistory: mock(() => undefined),
    selectDevice: mock(() => undefined),
    downloadCurrentCapture: mock(async () => undefined),
    onConnectionChange: mock(() => undefined),
    onConfigurationChange: mock(() => undefined),
    mount: mock(() => undefined),
    unmount: mock(() => undefined),
    enqueueSessionPackets: mock(() => undefined),
    reportStreamError: mock(() => undefined),
    ...overrides,
  };
}

function workspace(options?: {
  connected?: boolean;
  connecting?: boolean;
  session?: Partial<CaptureSessionApi>;
  openPacketInspector?: (packet: CapturedPacketDto) => unknown;
  buildFilename?: (now?: Date) => string;
}) {
  const toasts: Array<[string, string, string]> = [];
  const session = fakeSession(options?.session);
  let connected = options?.connected ?? true;
  const host: CaptureHost = {
    get connected() {
      return connected;
    },
    get connecting() {
      return options?.connecting ?? false;
    },
    connect: mock(() => {
      connected = true;
    }),
    toast: (title, body, color) => {
      toasts.push([title, body, color]);
    },
  };
  const openPacketInspector = options?.openPacketInspector ?? mock(async () => undefined);
  const cap = new CaptureWorkspace(host, {
    session,
    openPacketInspector,
    buildFilename: options?.buildFilename ?? (() => 'capture.pcap'),
  });
  return { cap, host, session, toasts, openPacketInspector };
}

beforeAll(async () => {
  await loadMessages('en');
});

describe('CaptureWorkspace chrome', () => {
  test('cannot start while disconnected even with a selected device', () => {
    const { cap } = workspace({ connected: false });
    expect(cap.canStart).toBe(false);
    expect(cap.providerUnavailable).toBe(false);
  });

  test('marks the provider unavailable after a connected empty device load', () => {
    const { cap } = workspace({
      session: { devicesAvailable: false, devicesLoaded: true, selectedDevice: '' },
    });
    expect(cap.providerUnavailable).toBe(true);
    expect(cap.canStart).toBe(false);
    expect(cap.stateLabel).toBe(m.capture_state_provider_required());
  });

  test('shows clear and download only after a finished session has bytes', () => {
    const { cap } = workspace({
      session: {
        capturing: false,
        captureId: 'cap-1',
        captureState: 'completed',
        packets: 12,
        bytes: 240,
      },
    });
    expect(cap.showsClear).toBe(true);
    expect(cap.showsDownload).toBe(true);
    expect(cap.showsStop).toBe(false);
  });

  test('builds device dropdown labels from the session list', () => {
    const { cap } = workspace();
    expect(cap.deviceDropdownOptions).toEqual([{ value: 'eth0', label: 'Ethernet' }]);
  });
});

describe('CaptureWorkspace configuration', () => {
  test('choosePreset writes the filter when idle', () => {
    const { cap, session } = workspace();
    cap.choosePreset('port 53');
    expect(session.configuration.captureFilter).toBe('port 53');
    expect(cap.activePreset).toBe('dns');
  });

  test('choosePreset and reset are ignored while capturing', () => {
    const configuration: CaptureConfiguration = {
      ...DEFAULT_CAPTURE_CONFIGURATION,
      captureFilter: 'tcp',
      snapLength: 256,
    };
    const { cap, session } = workspace({ session: { capturing: true, configuration } });
    cap.choosePreset('port 53');
    cap.chooseSnapLength(96);
    cap.resetConfiguration();
    expect(session.configuration.captureFilter).toBe('tcp');
    expect(session.configuration.snapLength).toBe(256);
  });

  test('chooseApplication stores the path and name, and all applications clears both', () => {
    const { cap, session } = workspace();
    cap.chooseApplication('C:\\Apps\\edge.exe', 'Edge');
    expect(session.configuration.appPath).toBe('C:\\Apps\\edge.exe');
    expect(session.configuration.appName).toBe('Edge');
    cap.chooseApplication('', 'All applications');
    expect(session.configuration.appPath).toBe('');
    expect(session.configuration.appName).toBe('');
  });

  test('chooseApplication is ignored while capturing', () => {
    const { cap, session } = workspace({ session: { capturing: true } });
    cap.chooseApplication('C:\\Apps\\edge.exe', 'Edge');
    expect(session.configuration.appPath).toBe('');
  });

  test('resetConfiguration restores the default setup', () => {
    const { cap, session } = workspace({
      session: {
        configuration: {
          appPath: 'C:\\Apps\\edge.exe',
          appName: 'Edge',
          captureFilter: 'udp',
          promiscuous: true,
          snapLength: 256,
          maxSeconds: 60,
          maxBytes: 10 * 1024 * 1024,
        },
      },
    });
    cap.resetConfiguration();
    expect(session.configuration).toEqual(DEFAULT_CAPTURE_CONFIGURATION);
  });
});

describe('CaptureWorkspace actions', () => {
  test('startCapture is a no-op when the command is disabled', async () => {
    const { cap, session } = workspace({ connected: false });
    cap.startCapture();
    await Promise.resolve();
    expect(session.startCapture).not.toHaveBeenCalled();
  });

  test('startCapture forwards to the session when the command is enabled', async () => {
    const { cap, session } = workspace();
    cap.startCapture();
    await Promise.resolve();
    expect(session.startCapture).toHaveBeenCalledTimes(1);
  });

  test('toasts when startCapture rejects', async () => {
    const { cap, toasts } = workspace({
      session: {
        startCapture: mock(async () => {
          throw new Error('adapter down');
        }),
      },
    });
    cap.startCapture();
    await Promise.resolve();
    await Promise.resolve();
    expect(toasts[0]?.[0]).toBe(m.capture_toast_failed_title());
    expect(toasts[0]?.[1]).toBe('adapter down');
  });

  test('inspectPacket opens the inspector and toasts on failure', async () => {
    const openPacketInspector = mock(async () => {
      throw new Error('no window');
    });
    const { cap, toasts } = workspace({ openPacketInspector });
    const row = packet();
    cap.inspectPacket(row);
    await Promise.resolve();
    await Promise.resolve();
    expect(openPacketInspector).toHaveBeenCalledWith(row);
    expect(toasts[0]?.[0]).toBe(m.capture_toast_save_failed_title());
  });

  test('downloadCurrentCapture skips while capturing or without a capture id', async () => {
    const { cap, session } = workspace({
      session: { capturing: true, captureId: 'cap-1' },
    });
    cap.downloadCurrentCapture();
    await Promise.resolve();
    expect(session.downloadCurrentCapture).not.toHaveBeenCalled();
  });

  test('downloadCurrentCapture uses the injected filename builder', async () => {
    const { cap, session } = workspace({
      session: { captureId: 'cap-1', captureState: 'completed' },
      buildFilename: () => 'antiwire-2026.pcap',
    });
    cap.downloadCurrentCapture();
    await Promise.resolve();
    expect(session.downloadCurrentCapture).toHaveBeenCalledWith('antiwire-2026.pcap');
  });

  test('reuseSession forwards the history row', () => {
    const { cap, session } = workspace();
    const item = historyItem();
    cap.reuseSession(item);
    expect(session.reuseSession).toHaveBeenCalledWith(item);
  });

  test('setTelemetryView switches the explorer tab', () => {
    const { cap } = workspace();
    expect(cap.telemetryView).toBe('packets');
    cap.setTelemetryView('samples');
    expect(cap.telemetryView).toBe('samples');
  });
});

describe('CaptureWorkspace reactivity', () => {
  test('re-notifies session changes and stops on dispose', async () => {
    let listener: (() => void) | null = null;
    const unsubscribe = mock(() => {
      listener = null;
    });
    const { cap, session } = workspace({
      session: {
        subscribe: (next: () => void) => {
          listener = next;
          return unsubscribe;
        },
      },
    });
    let calls = 0;
    cap.subscribe(() => calls++);
    (listener as (() => void) | null)?.();
    await Promise.resolve();
    expect(calls).toBe(1);

    cap.dispose();
    expect(unsubscribe).toHaveBeenCalledTimes(1);
    expect(session.unmount).toHaveBeenCalledTimes(1);
  });

  test('configuration changes replace the object', () => {
    const { cap, session } = workspace();
    const before = session.configuration;
    cap.setMaxSeconds(30);
    expect(session.configuration).not.toBe(before);
    expect(session.configuration.maxSeconds).toBe(30);
    expect(before.maxSeconds).not.toBe(30);
  });
});
