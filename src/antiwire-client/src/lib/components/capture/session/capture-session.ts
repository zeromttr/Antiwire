import {
  appendCapturedPackets,
  deriveCaptureSample,
  enqueueCapturedPackets,
  normalizeCaptureConfiguration,
  type CaptureConfiguration,
  type CaptureSample,
} from '#lib/models/capture.ts';
import type { CapturedPacketDto, CaptureDeviceDto, CaptureStatusDto } from '#lib/api/daemon.ts';
import { formatErrorMessage } from '#lib/utils/error.ts';
import type { CaptureIpc } from './capture-ipc';
import { TrackedReactive } from '#lib/state/tracked.ts';
import {
  buildHistoryEntry,
  buildSessionKey,
  nextPollDelayMs,
  preferredCaptureDeviceName,
  pushHistoryEntry,
  shouldFaultSession,
  type CaptureHistoryEntry,
} from './capture-policy';

export type CaptureHistoryItem = CaptureHistoryEntry;

export type CaptureLifecycle =
  'idle' | 'starting' | 'capturing' | 'stopping' | 'completed' | 'faulted';

/** Localizable strings the controller needs; supplied by the route. */
export interface CaptureSessionTexts {
  ready: () => string;
  opening: () => string;
  closing: () => string;
  receiving: () => string;
  ended: () => string;
  couldNotStart: () => string;
  completedOutcome: () => string;
  unavailableOutcome: () => string;
  stopWaiting: () => string;
  installProvider: () => string;
  interfacesAvailable: (count: number, singular: boolean) => string;
  interfaceOne: () => string;
  interfaceOther: () => string;
  streamUnavailable: (error: string) => string;
  toastStartedTitle: () => string;
  toastStartedBody: (device: string) => string;
  toastFailedTitle: () => string;
  toastSavedTitle: () => string;
  toastSaveFailedTitle: () => string;
  toastStoppedTitle: () => string;
  toastStoppedBody: () => string;
  toastStopRequestedTitle: () => string;
  toastStopRequestedBody: () => string;
  toastStopFailedTitle: () => string;
  restored: () => string;
  saveFilterName: () => string;
}

export interface CaptureSessionEvents {
  notify: (title: string, body: string, color: string) => void;
  persistConfiguration: (configuration: CaptureConfiguration) => void;
  readPersistedConfiguration: () => CaptureConfiguration | null;
  rememberActiveCapture: (captureId: string | null) => void;
  readActiveCapture: () => string | null;
}

const MAX_SAMPLES = 120;
const ACTIVE_FALLBACK_DEVICE = '';

/**
 * Session controller for the capture route: lifecycle, polling, packet
 * buffering, and history. Rendering, i18n wiring, and storage access stay
 * with the caller through `CaptureSessionTexts` / `CaptureSessionEvents`,
 * which keeps every failure path unit-testable without a DOM.
 */
export class CaptureSessionController extends TrackedReactive {
  devices: CaptureDeviceDto[] = [];
  devicesMessage = '';
  devicesAvailable = false;
  devicesLoaded = false;
  loadingDevices = false;
  selectedDevice = '';
  configuration: CaptureConfiguration = {} as CaptureConfiguration;
  captureId = '';
  captureState: CaptureLifecycle | string = 'idle';
  capturing = false;
  starting = false;
  stopping = false;
  statusMessage = '';
  statusError = '';
  packets = 0;
  bytes = 0;
  droppedPackets = 0;
  filteredPackets = 0;
  /** Application the running or last capture was restricted to; empty for all applications. */
  appName = '';
  elapsedSeconds = 0;
  samples: CaptureSample[] = [];
  capturedPackets: CapturedPacketDto[] = [];
  downloading = false;
  history: CaptureHistoryItem[] = [];

  private packetBuffer: CapturedPacketDto[] = [];
  private packetFlushFrame = 0;
  private flushScheduler: (flush: () => void) => number;
  private cancelScheduledFlush: (handle: number) => void;
  private pollTimer: ReturnType<typeof setTimeout> | null = null;
  private pollInFlight = false;
  private pollFailures = 0;
  private sessionStartedAt = 0;
  private recordedSessionKey = '';
  private mounted = false;
  private wasConnected = false;
  private now: () => number;

  constructor(
    private readonly ipc: CaptureIpc,
    private readonly texts: CaptureSessionTexts,
    private readonly events: CaptureSessionEvents,
    initialConfiguration: CaptureConfiguration,
    options?: {
      now?: () => number;
      flushScheduler?: (flush: () => void) => number;
      cancelScheduledFlush?: (handle: number) => void;
    },
  ) {
    super();
    this.configuration = { ...initialConfiguration };
    this.statusMessage = texts.ready();
    this.now = options?.now ?? Date.now;
    this.flushScheduler =
      options?.flushScheduler ?? ((flush) => requestAnimationFrame(flush) as unknown as number);
    this.cancelScheduledFlush =
      options?.cancelScheduledFlush ??
      ((handle) => cancelAnimationFrame(handle as unknown as number));
    this.track(
      'devices',
      'devicesMessage',
      'devicesAvailable',
      'devicesLoaded',
      'loadingDevices',
      'selectedDevice',
      'configuration',
      'captureId',
      'captureState',
      'capturing',
      'starting',
      'stopping',
      'statusMessage',
      'statusError',
      'packets',
      'bytes',
      'droppedPackets',
      'filteredPackets',
      'appName',
      'elapsedSeconds',
      'samples',
      'capturedPackets',
      'downloading',
      'history',
    );
  }

  get connected(): boolean {
    return this.wasConnected;
  }

  get providerUnavailable(): boolean {
    return this.wasConnected && this.devicesLoaded && !this.devicesAvailable;
  }

  get canStart(): boolean {
    return (
      this.wasConnected &&
      this.devicesAvailable &&
      Boolean(this.selectedDevice) &&
      !this.capturing &&
      !this.starting
    );
  }

  get activeDevice(): CaptureDeviceDto | undefined {
    return this.devices.find((device) => device.name === this.selectedDevice);
  }

  mount(connected: boolean): void {
    this.mounted = true;
    const stored = this.events.readPersistedConfiguration();
    if (stored) this.configuration = normalizeCaptureConfiguration(stored);
    if (connected) {
      this.wasConnected = true;
      void this.initializeConnectedPage();
    }
  }

  unmount(): void {
    this.mounted = false;
    this.stopPolling();
    this.resetCapturedPackets();
  }

  /** Same as `unmount`: stops polling and drops buffered packets. */
  dispose(): void {
    this.unmount();
  }

  onConnectionChange(connected: boolean): void {
    if (!this.mounted) return;
    const wasConnected = this.wasConnected;
    this.wasConnected = connected;
    if (connected && !wasConnected) void this.initializeConnectedPage();
    if (!connected) this.stopPolling();
  }

  onConfigurationChange(): void {
    if (!this.mounted) return;
    this.events.persistConfiguration({ ...this.configuration });
  }

  /**
   * Replaces the configuration with `patch` applied and persists it. The
   * configuration is never mutated in place, so a form field calls this
   * rather than assigning into `configuration`.
   */
  updateConfiguration(patch: Partial<CaptureConfiguration>): void {
    this.configuration = { ...this.configuration, ...patch };
    this.onConfigurationChange();
  }

  async loadDevices(): Promise<void> {
    if (!this.wasConnected || this.loadingDevices) return;
    this.loadingDevices = true;
    this.devicesMessage = '';
    try {
      const response = await this.ipc.listDevices();
      this.devicesAvailable = response.available;
      this.devicesMessage = response.message;
      this.devices = response.available ? response.devices : [];
      if (!response.available && this.captureState === 'idle') {
        this.statusMessage = this.texts.installProvider();
      } else if (response.available && this.captureState === 'idle') {
        const singular = response.devices.length === 1;
        this.statusMessage = this.texts.interfacesAvailable(response.devices.length, singular);
      }
      if (!this.devices.some((device) => device.name === this.selectedDevice)) {
        this.selectedDevice = preferredCaptureDeviceName(this.devices) || ACTIVE_FALLBACK_DEVICE;
      }
    } catch (error) {
      this.devicesAvailable = false;
      this.devices = [];
      this.devicesMessage = formatErrorMessage(error);
    } finally {
      this.devicesLoaded = true;
      this.loadingDevices = false;
    }
  }

  async startCapture(): Promise<void> {
    if (!this.canStart) return;
    this.starting = true;
    this.statusError = '';
    this.statusMessage = this.texts.opening();
    this.captureState = 'starting';
    this.packets = 0;
    this.bytes = 0;
    this.droppedPackets = 0;
    this.filteredPackets = 0;
    this.appName = this.configuration.appName;
    this.elapsedSeconds = 0;
    this.samples = [];
    this.resetCapturedPackets();
    this.sessionStartedAt = this.now();
    this.recordedSessionKey = '';
    this.events.persistConfiguration({ ...this.configuration });
    try {
      this.captureId = await this.ipc.startCapture({
        deviceName: this.selectedDevice,
        appPath: this.configuration.appPath,
        appName: this.configuration.appName,
        captureFilter: this.configuration.captureFilter.trim(),
        snapLength: this.configuration.snapLength,
        promiscuous: this.configuration.promiscuous,
        maxSeconds: this.configuration.maxSeconds,
        maxBytes: this.configuration.maxBytes,
      });
      this.captureState = 'capturing';
      this.capturing = true;
      this.events.rememberActiveCapture(this.captureId);
      await this.beginPacketStream();
      const device = this.activeDevice;
      this.events.notify(
        this.texts.toastStartedTitle(),
        this.texts.toastStartedBody(device?.description || this.selectedDevice),
        'var(--acc)',
      );
      await this.pollStatus();
    } catch (error) {
      this.captureState = 'faulted';
      this.capturing = false;
      this.captureId = '';
      this.sessionStartedAt = 0;
      this.events.rememberActiveCapture(null);
      this.statusError = formatErrorMessage(error);
      this.statusMessage = this.texts.couldNotStart();
      this.events.notify(this.texts.toastFailedTitle(), this.statusError, 'var(--bad)');
    } finally {
      this.starting = false;
    }
  }

  async stopCapture(): Promise<void> {
    if (!this.captureId || this.stopping) return;
    this.stopping = true;
    this.captureState = 'stopping';
    this.statusMessage = this.texts.closing();
    try {
      await this.ipc.stopCapture(this.captureId);
      this.stopPolling();
      try {
        const status = await this.ipc.getStatus(this.captureId);
        this.applyStatus(status);
        if (status.active) {
          this.schedulePoll(150);
          this.events.notify(
            this.texts.toastStopRequestedTitle(),
            this.texts.toastStopRequestedBody(),
            'var(--t3)',
          );
        } else {
          this.events.notify(
            this.texts.toastStoppedTitle(),
            this.texts.toastStoppedBody(),
            'var(--t3)',
          );
        }
      } catch {
        this.captureState = 'stopping';
        this.capturing = true;
        this.statusMessage = this.texts.stopWaiting();
        this.schedulePoll(250);
      }
    } catch (error) {
      this.statusError = formatErrorMessage(error);
      this.captureState = 'capturing';
      this.events.notify(this.texts.toastStopFailedTitle(), this.statusError, 'var(--bad)');
    } finally {
      this.stopping = false;
    }
  }

  async downloadCurrentCapture(defaultPath: string): Promise<void> {
    if (!this.captureId || this.capturing || this.downloading) return;
    // The native dialog is part of the guarded action: a dialog failure
    // must surface as user feedback, never as an unhandled rejection.
    let path: string | null;
    try {
      path = await this.ipc.pickSavePath(defaultPath, this.texts.saveFilterName());
    } catch (error) {
      const message = formatErrorMessage(error);
      this.events.notify(this.texts.toastSaveFailedTitle(), message, 'var(--bad)');
      return;
    }
    if (!path) return;
    this.downloading = true;
    try {
      await this.ipc.downloadCapture(this.captureId, path);
      this.events.notify(this.texts.toastSavedTitle(), path, 'var(--ok)');
    } catch (error) {
      this.events.notify(
        this.texts.toastSaveFailedTitle(),
        formatErrorMessage(error),
        'var(--bad)',
      );
    } finally {
      this.downloading = false;
    }
  }

  clearCurrentSession(): void {
    if (this.capturing) return;
    this.captureId = '';
    this.captureState = 'idle';
    this.statusMessage = this.texts.ready();
    this.statusError = '';
    this.packets = 0;
    this.bytes = 0;
    this.droppedPackets = 0;
    this.filteredPackets = 0;
    this.appName = '';
    this.elapsedSeconds = 0;
    this.sessionStartedAt = 0;
    this.samples = [];
    this.resetCapturedPackets();
    this.events.rememberActiveCapture(null);
  }

  reuseSession(item: CaptureHistoryItem): void {
    if (this.capturing) return;
    this.configuration = normalizeCaptureConfiguration(item.configuration);
    const device = this.devices.find(
      (candidate) =>
        candidate.name === item.deviceName || candidate.description === item.deviceName,
    );
    if (device) this.selectedDevice = device.name;
    this.statusMessage = this.texts.restored();
  }

  selectDevice(name: string): void {
    this.selectedDevice = name;
  }

  clearHistory(): void {
    this.history = [];
  }

  enqueueSessionPackets(packets: readonly CapturedPacketDto[]): void {
    enqueueCapturedPackets(this.packetBuffer, packets);
    if (this.packetFlushFrame !== 0) return;
    this.packetFlushFrame = this.flushScheduler(() => this.flushPacketBuffer());
  }

  applyStatus(status: CaptureStatusDto): void {
    const wasCapturing = this.capturing;
    this.captureState = status.state || (status.active ? 'capturing' : 'completed');
    this.packets = Number(status.packets ?? 0);
    this.bytes = Number(status.bytes ?? 0);
    this.droppedPackets = Number(status.droppedPackets ?? 0);
    this.filteredPackets = Number(status.filteredPackets ?? 0);
    this.appName = String(status.appName ?? '');
    this.elapsedSeconds = Number(status.elapsedSeconds ?? 0);
    this.statusMessage =
      status.message || (status.active ? this.texts.receiving() : this.texts.ended());
    this.statusError = '';
    if (status.deviceName && this.devices.some((device) => device.name === status.deviceName)) {
      this.selectedDevice = status.deviceName;
    }
    if (!this.sessionStartedAt && status.active) {
      this.sessionStartedAt = this.now() - this.elapsedSeconds * 1000;
    }
    this.recordSample(status);
    this.capturing = status.active;
    if (!status.active) {
      this.stopPolling();
      this.events.rememberActiveCapture(null);
      if (wasCapturing || this.sessionStartedAt) {
        this.finalizeSession(status.state || this.texts.completedOutcome());
      }
    }
  }

  async pollStatus(): Promise<void> {
    if (!this.mounted || !this.captureId || this.pollInFlight) return;
    this.pollInFlight = true;
    try {
      const status = await this.ipc.getStatus(this.captureId);
      if (!this.mounted) return;
      this.pollFailures = 0;
      this.applyStatus(status);
    } catch (error) {
      if (!this.mounted) return;
      this.pollFailures += 1;
      this.statusError = formatErrorMessage(error);
      if (shouldFaultSession(this.pollFailures)) {
        this.captureState = 'faulted';
        this.capturing = false;
        this.stopPolling();
        this.finalizeSession(this.texts.unavailableOutcome());
      }
    } finally {
      this.pollInFlight = false;
      if (this.mounted) {
        this.schedulePoll(nextPollDelayMs(this.pollFailures));
      }
    }
  }

  reportStreamError(message: string): void {
    this.statusError = message;
  }

  private async initializeConnectedPage(): Promise<void> {
    await this.loadDevices();
    await this.restoreActiveCapture();
  }

  private async restoreActiveCapture(): Promise<void> {
    const storedId = this.events.readActiveCapture();
    if (!storedId) return;
    this.captureId = storedId;
    this.captureState = 'starting';
    this.capturing = true;
    try {
      await this.beginPacketStream();
      await this.pollStatus();
    } catch {
      this.events.rememberActiveCapture(null);
    }
  }

  private async beginPacketStream(): Promise<void> {
    try {
      await this.ipc.startPacketStream(this.captureId);
    } catch (error) {
      this.statusError = this.texts.streamUnavailable(formatErrorMessage(error));
    }
  }

  private recordSample(status: CaptureStatusDto): void {
    const snapshot = {
      timestampMs: this.now(),
      packets: Number(status.packets ?? 0),
      bytes: Number(status.bytes ?? 0),
    };
    const sample = deriveCaptureSample(snapshot, this.samples.at(-1));
    this.samples = [...this.samples, sample].slice(-MAX_SAMPLES);
  }

  private finalizeSession(outcome: string): void {
    if (!this.captureId || !this.sessionStartedAt) return;
    const sessionKey = buildSessionKey(this.captureId, this.sessionStartedAt);
    if (this.recordedSessionKey === sessionKey) return;
    const device = this.activeDevice;
    const entry = buildHistoryEntry({
      captureId: this.captureId,
      startedAt: this.sessionStartedAt,
      endedAt: this.now(),
      deviceName: device?.description || device?.name || this.selectedDevice,
      packets: this.packets,
      bytes: this.bytes,
      droppedPackets: this.droppedPackets,
      configuration: this.configuration,
      outcome,
    });
    const next = pushHistoryEntry(this.history, entry, this.recordedSessionKey);
    this.history = next.history;
    this.recordedSessionKey = next.recordedKey;
  }

  private stopPolling(): void {
    if (this.pollTimer) clearTimeout(this.pollTimer);
    this.pollTimer = null;
  }

  private schedulePoll(delay = 1000): void {
    if (!this.mounted || !this.captureId || !this.capturing || this.pollTimer) return;
    this.pollTimer = setTimeout(() => {
      this.pollTimer = null;
      if (this.mounted) void this.pollStatus();
    }, delay);
  }

  private resetCapturedPackets(): void {
    this.packetBuffer = [];
    if (this.packetFlushFrame !== 0) {
      this.cancelScheduledFlush(this.packetFlushFrame);
      this.packetFlushFrame = 0;
    }
    this.capturedPackets = [];
  }

  private flushPacketBuffer(): void {
    this.packetFlushFrame = 0;
    if (this.packetBuffer.length === 0) return;
    const incoming = this.packetBuffer;
    this.packetBuffer = [];
    this.capturedPackets = appendCapturedPackets(this.capturedPackets, incoming);
  }
}
