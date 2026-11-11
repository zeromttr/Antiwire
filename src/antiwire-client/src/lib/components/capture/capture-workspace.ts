import type { CapturedPacketDto, CaptureDeviceDto } from '#lib/api/daemon.ts';
import {
  CaptureSessionController,
  type CaptureHistoryItem,
  type CaptureSessionEvents,
  type CaptureSessionTexts,
} from './session/capture-session';
import { buildDefaultCaptureFilename, type CaptureIpc } from './session/capture-ipc';
import { m } from '#lib/i18n/messages.ts';
import {
  DEFAULT_CAPTURE_CONFIGURATION,
  captureLimitProgress,
  capturePresetId,
  normalizeCaptureConfiguration,
  recentCapturedPackets,
  type CaptureConfiguration,
  type CaptureSample,
} from '#lib/models/capture.ts';
import { formatErrorMessage } from '#lib/utils/error.ts';
import { fireUiAction } from '#lib/utils/ui-action.ts';
import { TrackedReactive } from '#lib/state/tracked.ts';
import {
  canStartCapture,
  captureStateLabel,
  chartSampleWindow,
  commandShowsClear,
  commandShowsDownload,
  commandShowsStop,
  deviceDropdownOptions,
  durationDropdownOptions,
  isProviderUnavailable,
  maxChartRate,
  recentSampleWindow,
  sizeDropdownOptions,
} from './view/capture-view';

const CONFIG_STORAGE_KEY = 'antiwire-capture-configuration-v1';
const ACTIVE_CAPTURE_KEY = 'antiwire-active-capture-id';

export type CaptureHost = {
  readonly connected: boolean;
  readonly connecting: boolean;
  connect(): void | Promise<void>;
  toast(title: string, body: string, color: string): void;
};

export type CaptureSessionApi = {
  devices: CaptureDeviceDto[];
  devicesMessage: string;
  devicesAvailable: boolean;
  devicesLoaded: boolean;
  loadingDevices: boolean;
  selectedDevice: string;
  configuration: CaptureConfiguration;
  captureId: string;
  captureState: string;
  capturing: boolean;
  starting: boolean;
  stopping: boolean;
  statusMessage: string;
  statusError: string;
  packets: number;
  bytes: number;
  droppedPackets: number;
  filteredPackets: number;
  appName: string;
  elapsedSeconds: number;
  samples: CaptureSample[];
  capturedPackets: CapturedPacketDto[];
  downloading: boolean;
  history: CaptureHistoryItem[];
  loadDevices(): unknown;
  startCapture(): unknown;
  stopCapture(): unknown;
  clearCurrentSession(): void;
  reuseSession(item: CaptureHistoryItem): void;
  clearHistory(): void;
  selectDevice(name: string): void;
  downloadCurrentCapture(defaultPath: string): unknown;
  onConnectionChange(connected: boolean): void;
  onConfigurationChange(): void;
  mount(connected: boolean): void;
  unmount(): void;
  enqueueSessionPackets(packets: readonly CapturedPacketDto[]): void;
  reportStreamError(message: string): void;
  /** Change listener; `CaptureSessionController` inherits it from `Reactive`. */
  subscribe?: (listener: () => void) => () => void;
};

export type CaptureWorkspaceDeps = {
  session: CaptureSessionApi;
  openPacketInspector: (packet: CapturedPacketDto) => unknown;
  buildFilename?: (now?: Date) => string;
};

export type CaptureTelemetryView = 'packets' | 'samples';

export function createCaptureSessionTexts(): CaptureSessionTexts {
  return {
    ready: () => m.capture_status_ready(),
    opening: () => m.capture_status_opening(),
    closing: () => m.capture_status_closing(),
    receiving: () => m.capture_status_receiving(),
    ended: () => m.capture_status_ended(),
    couldNotStart: () => m.capture_status_could_not_start(),
    completedOutcome: () => m.capture_state_completed(),
    unavailableOutcome: () => m.capture_status_unavailable_outcome(),
    stopWaiting: () => m.capture_status_stop_waiting(),
    installProvider: () => m.capture_status_install_provider(),
    interfacesAvailable: (count, singular) =>
      m.capture_status_interfaces_available({
        count,
        word: singular ? m.capture_status_interface_one() : m.capture_status_interface_other(),
      }),
    interfaceOne: () => m.capture_status_interface_one(),
    interfaceOther: () => m.capture_status_interface_other(),
    streamUnavailable: (error) => m.capture_stream_unavailable({ error }),
    toastStartedTitle: () => m.capture_toast_started_title(),
    toastStartedBody: (device) => m.capture_toast_started_body({ device }),
    toastFailedTitle: () => m.capture_toast_failed_title(),
    toastSavedTitle: () => m.capture_toast_saved_title(),
    toastSaveFailedTitle: () => m.capture_toast_save_failed_title(),
    toastStoppedTitle: () => m.capture_toast_stopped_title(),
    toastStoppedBody: () => m.capture_toast_stopped_body(),
    toastStopRequestedTitle: () => m.capture_toast_stop_requested_title(),
    toastStopRequestedBody: () => m.capture_toast_stop_requested_body(),
    toastStopFailedTitle: () => m.capture_toast_stop_failed_title(),
    restored: () => m.capture_status_restored(),
    saveFilterName: () => m.capture_save_dialog_filter(),
  };
}

export function createBrowserCaptureEvents(toast: CaptureHost['toast']): CaptureSessionEvents {
  return {
    notify: (title, body, color) => toast(title, body, color),
    persistConfiguration: (configuration) => {
      try {
        if (typeof localStorage === 'undefined') return;
        localStorage.setItem(CONFIG_STORAGE_KEY, JSON.stringify(configuration));
      } catch (error) {
        toast(m.capture_toast_save_failed_title(), formatErrorMessage(error), 'var(--bad)');
      }
    },
    readPersistedConfiguration: () => {
      try {
        if (typeof localStorage === 'undefined') return null;
        const stored = localStorage.getItem(CONFIG_STORAGE_KEY);
        return stored ? normalizeCaptureConfiguration(JSON.parse(stored)) : null;
      } catch {
        return { ...DEFAULT_CAPTURE_CONFIGURATION };
      }
    },
    rememberActiveCapture: (captureId) => {
      try {
        if (typeof sessionStorage === 'undefined') return;
        if (captureId) sessionStorage.setItem(ACTIVE_CAPTURE_KEY, captureId);
        else sessionStorage.removeItem(ACTIVE_CAPTURE_KEY);
      } catch (error) {
        toast(m.capture_toast_save_failed_title(), formatErrorMessage(error), 'var(--bad)');
      }
    },
    readActiveCapture: () => {
      try {
        if (typeof sessionStorage === 'undefined') return null;
        return sessionStorage.getItem(ACTIVE_CAPTURE_KEY);
      } catch {
        return null;
      }
    },
  };
}

/**
 * Capture route chrome and user-intent forwarding. The page owns connection
 * / config effects and bridge listeners; this class owns command guards,
 * telemetry view, and toasts so those stay testable without a DOM.
 *
 * Most fields are read through from the session. The workspace re-notifies
 * when the session changes, so the page subscribes to the workspace alone.
 */
export class CaptureWorkspace extends TrackedReactive {
  telemetryView: CaptureTelemetryView = 'packets';

  constructor(
    private readonly host: CaptureHost,
    private readonly deps: CaptureWorkspaceDeps,
  ) {
    super();
    this.track('telemetryView');
    this.#unsubscribeSession = deps.session.subscribe?.(() => this.changed()) ?? null;
  }

  #unsubscribeSession: (() => void) | null;

  get session() {
    return this.deps.session;
  }

  get connected() {
    return this.host.connected;
  }

  get connecting() {
    return this.host.connecting;
  }

  get devices() {
    return this.session.devices;
  }

  get devicesMessage() {
    return this.session.devicesMessage;
  }

  get devicesAvailable() {
    return this.session.devicesAvailable;
  }

  get devicesLoaded() {
    return this.session.devicesLoaded;
  }

  get loadingDevices() {
    return this.session.loadingDevices;
  }

  get selectedDevice() {
    return this.session.selectedDevice;
  }

  get configuration() {
    return this.session.configuration;
  }

  get captureId() {
    return this.session.captureId;
  }

  get captureState() {
    return this.session.captureState;
  }

  get capturing() {
    return this.session.capturing;
  }

  get starting() {
    return this.session.starting;
  }

  get stopping() {
    return this.session.stopping;
  }

  get statusMessage() {
    return this.session.statusMessage;
  }

  get statusError() {
    return this.session.statusError;
  }

  get packets() {
    return this.session.packets;
  }

  get bytes() {
    return this.session.bytes;
  }

  get droppedPackets() {
    return this.session.droppedPackets;
  }

  get filteredPackets() {
    return this.session.filteredPackets;
  }

  get appName() {
    return this.session.appName;
  }

  get elapsedSeconds() {
    return this.session.elapsedSeconds;
  }

  get samples() {
    return this.session.samples;
  }

  get capturedPackets() {
    return this.session.capturedPackets;
  }

  get downloading() {
    return this.session.downloading;
  }

  get history() {
    return this.session.history;
  }

  get providerUnavailable() {
    return isProviderUnavailable(this.connected, this.devicesLoaded, this.devicesAvailable);
  }

  get canStart() {
    return canStartCapture({
      connected: this.connected,
      devicesAvailable: this.devicesAvailable,
      selectedDevice: this.selectedDevice,
      capturing: this.capturing,
      starting: this.starting,
    });
  }

  get stateLabel() {
    return captureStateLabel(this.captureState, this.providerUnavailable);
  }

  get activePreset() {
    return capturePresetId(this.configuration.captureFilter);
  }

  get activeDevice() {
    return this.devices.find((device) => device.name === this.selectedDevice);
  }

  get deviceDropdownOptions() {
    return deviceDropdownOptions(this.devices, m.capture_interface_none());
  }

  get durationDropdownOptions() {
    return durationDropdownOptions();
  }

  get sizeDropdownOptions() {
    return sizeDropdownOptions();
  }

  get latestSample() {
    return this.samples.at(-1);
  }

  get chartSamples() {
    return chartSampleWindow(this.samples);
  }

  get recentSamples() {
    return recentSampleWindow(this.samples);
  }

  get recentPackets() {
    return recentCapturedPackets(this.capturedPackets);
  }

  get maxChartRate() {
    return maxChartRate(this.chartSamples);
  }

  get limitProgress() {
    return captureLimitProgress(
      this.elapsedSeconds,
      this.bytes,
      this.configuration.maxSeconds,
      this.configuration.maxBytes,
    );
  }

  get showsClear() {
    return commandShowsClear(this.capturing, this.packets, this.bytes);
  }

  get showsDownload() {
    return commandShowsDownload(this.capturing, this.captureId, this.captureState);
  }

  get showsStop() {
    return commandShowsStop(this.capturing, this.stopping);
  }

  connect = () => {
    void this.host.connect();
  };

  loadDevices = () => {
    fireUiAction(() => this.session.loadDevices(), {
      onError: (message) => this.host.toast(m.capture_toast_failed_title(), message, 'var(--bad)'),
    });
  };

  choosePreset = (filter: string) => {
    if (this.session.capturing) return;
    this.patchConfiguration({ captureFilter: filter });
  };

  chooseSnapLength = (value: number) => {
    if (this.session.capturing) return;
    this.patchConfiguration({ snapLength: value });
  };

  /** The configuration is replaced, never mutated, so its reference changes with it. */
  private patchConfiguration(patch: Partial<CaptureConfiguration>) {
    this.session.configuration = { ...this.session.configuration, ...patch };
  }

  resetConfiguration = () => {
    if (this.session.capturing) return;
    this.session.configuration = { ...DEFAULT_CAPTURE_CONFIGURATION };
  };

  selectDevice = (name: string) => {
    this.session.selectDevice(name);
  };

  /** An empty `path` means all applications, which carries no name. */
  chooseApplication = (path: string, name: string) => {
    if (this.session.capturing) return;
    this.patchConfiguration({ appPath: path, appName: path ? name : '' });
  };

  setMaxSeconds = (value: number) => {
    this.patchConfiguration({ maxSeconds: value });
  };

  setMaxBytes = (value: number) => {
    this.patchConfiguration({ maxBytes: value });
  };

  setPromiscuous = (value: boolean) => {
    this.patchConfiguration({ promiscuous: value });
  };

  startCapture = () => {
    if (!this.canStart) return;
    fireUiAction(() => this.session.startCapture(), {
      onError: (message) => this.host.toast(m.capture_toast_failed_title(), message, 'var(--bad)'),
    });
  };

  stopCapture = () => {
    fireUiAction(() => this.session.stopCapture(), {
      onError: (message) =>
        this.host.toast(m.capture_toast_stop_failed_title(), message, 'var(--bad)'),
    });
  };

  clearCurrentSession = () => {
    this.session.clearCurrentSession();
  };

  reuseSession = (item: CaptureHistoryItem) => {
    this.session.reuseSession(item);
  };

  clearHistory = () => {
    this.session.clearHistory();
  };

  inspectPacket = (packet: CapturedPacketDto) => {
    fireUiAction(() => this.deps.openPacketInspector(packet), {
      onError: (message) =>
        this.host.toast(m.capture_toast_save_failed_title(), message, 'var(--bad)'),
    });
  };

  downloadCurrentCapture = () => {
    if (!this.captureId || this.capturing || this.downloading) return;
    const filename = (this.deps.buildFilename ?? buildDefaultCaptureFilename)(new Date());
    fireUiAction(() => this.session.downloadCurrentCapture(filename), {
      onError: (message) =>
        this.host.toast(m.capture_toast_save_failed_title(), message, 'var(--bad)'),
    });
  };

  setTelemetryView = (view: CaptureTelemetryView) => {
    this.telemetryView = view;
  };

  onConnectionChange = () => {
    this.session.onConnectionChange(this.connected);
  };

  onConfigurationChange = () => {
    this.session.onConfigurationChange();
  };

  mount = () => {
    this.session.mount(this.connected);
  };

  unmount = () => {
    this.session.unmount();
  };

  /** Unmounts the session (timers, buffered packets) and stops forwarding its changes. */
  dispose = () => {
    this.#unsubscribeSession?.();
    this.#unsubscribeSession = null;
    this.session.unmount();
  };

  enqueueSessionPackets = (packets: readonly CapturedPacketDto[]) => {
    this.session.enqueueSessionPackets(packets);
  };

  reportStreamError = (message: string) => {
    this.session.reportStreamError(message);
  };
}

export function createCaptureWorkspace(host: CaptureHost, ipc: CaptureIpc): CaptureWorkspace {
  const session = new CaptureSessionController(
    ipc,
    createCaptureSessionTexts(),
    createBrowserCaptureEvents(host.toast),
    DEFAULT_CAPTURE_CONFIGURATION,
  );
  return new CaptureWorkspace(host, {
    session,
    openPacketInspector: (packet) => ipc.openPacketInspector(packet),
    buildFilename: (now) => buildDefaultCaptureFilename(now ?? new Date()),
  });
}
