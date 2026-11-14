import { api } from '#lib/api/daemon.ts';
import { m } from '#lib/i18n/messages.ts';
import { scanSuggestions, type NetworkScanRange } from '#lib/models/network-scan.ts';
import { sortNetworkDevices, type NetworkDeviceSortKey } from '#lib/models/network-device-sort.ts';
import {
  formatWatchInterval,
  mergeDevicesWithWatches,
  type DeviceWatch,
  type NetworkDeviceRow,
  type WatchInterval,
} from '#lib/models/network-watch.ts';
import {
  DEFAULT_WATCH_INTERVAL,
  activeNetworkSortDir,
  activeNetworkSortKey,
  chooseScanRange,
  createLastSeenCache,
  deviceCountLabel,
  lastSeenLabel,
  lastSeenTitle,
  networkColumnDefs,
  nextNetworkSort,
  pollDelayMs,
  scanRequestRanges,
  watchIntervalOrDefault,
} from './list/network-list';
import { TrackedReactive } from '#lib/state/tracked.ts';

export type NetworkApiClient = Pick<
  typeof api,
  | 'getNetworkMappingState'
  | 'scanNetwork'
  | 'stopNetworkScan'
  | 'clearNetworkDevices'
  | 'saveNetworkDeviceWatch'
  | 'removeNetworkDeviceWatch'
>;

export type NetworkHost = {
  readonly connected: boolean;
  toast(title: string, body: string, color: string): void;
};

/**
 * Network route state and daemon writes. The page owns connect/mount
 * effects; this class owns polling, scan controls, and the watch dialog
 * so those stay testable without a DOM.
 */
export class NetworkWorkspace extends TrackedReactive {
  devices: NetworkDeviceRow[] = [];
  scanRanges: NetworkScanRange[] = [];
  deviceWatches: DeviceWatch[] = [];
  isScanning = false;
  supported = false;
  ready = false;
  message = '';
  customCidr = '';
  watchDialogOpen = false;
  watchDialogMode: 'configure' | 'remove' = 'configure';
  selectedDevice: NetworkDeviceRow | null = null;
  selectedWatch: DeviceWatch | null = null;
  selectedWatchInterval: WatchInterval = DEFAULT_WATCH_INTERVAL;
  watchSubmitting = false;
  sortKey: NetworkDeviceSortKey | null = null;
  sortDir: 1 | -1 = -1;

  private mounted = false;
  private pollTimer: ReturnType<typeof setTimeout> | null = null;
  private pollInFlight = false;
  private readonly lastSeenTimestamp = createLastSeenCache();

  constructor(
    private readonly client: NetworkApiClient,
    private readonly host: NetworkHost,
  ) {
    super();
    this.track(
      'devices',
      'scanRanges',
      'deviceWatches',
      'isScanning',
      'supported',
      'ready',
      'message',
      'customCidr',
      'watchDialogOpen',
      'watchDialogMode',
      'selectedDevice',
      'selectedWatch',
      'selectedWatchInterval',
      'watchSubmitting',
      'sortKey',
      'sortDir',
    );
  }

  get connected() {
    return this.host.connected;
  }

  get suggestedRanges() {
    return scanSuggestions(this.scanRanges);
  }

  get sortedDevices() {
    const { devices, sortKey, sortDir } = this;
    return this.memo('sortedDevices', [devices, sortKey, sortDir], () =>
      sortNetworkDevices(devices, sortKey, sortDir, this.lastSeenTimestamp),
    );
  }

  get colDefs() {
    return networkColumnDefs();
  }

  get activeSortKey() {
    return activeNetworkSortKey(this.sortKey);
  }

  get activeSortDir() {
    return activeNetworkSortDir(this.sortKey, this.sortDir);
  }

  get deviceCountText() {
    return deviceCountLabel(this.devices.length);
  }

  lastSeenLabel = (lastSeen: string) => lastSeenLabel(lastSeen, Date.now(), this.lastSeenTimestamp);

  lastSeenTitle = (lastSeen: string) => lastSeenTitle(lastSeen, this.lastSeenTimestamp);

  mount = () => {
    this.mounted = true;
  };

  unmount = () => {
    this.mounted = false;
    this.stopPolling();
  };

  /** Same as `unmount`: stops the poll timer and ignores late responses. */
  dispose = () => {
    this.unmount();
  };

  onConnectionChange = () => {
    if (!this.connected) {
      this.stopPolling();
      return;
    }
    queueMicrotask(() => {
      if (this.mounted) void this.loadState();
    });
  };

  loadState = async () => {
    if (!this.mounted || !this.connected || this.pollInFlight) return;
    this.pollInFlight = true;
    try {
      const state = await this.client.getNetworkMappingState();
      if (!this.mounted || !this.connected) return;
      this.supported = state.supported;
      this.isScanning = state.isScanning;
      this.message = state.message;
      this.scanRanges = state.scanRanges;
      this.deviceWatches = state.deviceWatches;
      this.devices = mergeDevicesWithWatches(state.devices, state.deviceWatches);
      this.ready = true;
    } catch (error) {
      if (!this.mounted || !this.connected) return;
      this.message = error instanceof Error ? error.message : String(error);
      this.ready = true;
    } finally {
      this.pollInFlight = false;
      if (this.mounted) this.schedulePoll();
    }
  };

  startScan = async () => {
    if (!this.connected) return;
    const ranges = scanRequestRanges(this.customCidr, this.scanRanges);
    try {
      await this.client.scanNetwork(ranges);
      this.isScanning = true;
      this.host.toast(
        m.network_toast_scan_started_title(),
        ranges.length
          ? m.network_toast_scan_started_ranges({ ranges: ranges.join(', ') })
          : m.network_toast_scan_started_all(),
        'var(--acc)',
      );
      await this.loadState();
    } catch (error) {
      this.host.toast(
        m.network_toast_scan_failed_title(),
        error instanceof Error ? error.message : String(error),
        'var(--bad)',
      );
    }
  };

  stopScan = async () => {
    try {
      await this.client.stopNetworkScan();
      this.isScanning = false;
      this.stopPolling();
      await this.loadState();
    } catch (error) {
      this.host.toast(
        m.network_toast_stop_failed_title(),
        error instanceof Error ? error.message : String(error),
        'var(--bad)',
      );
    }
  };

  clearDevices = async () => {
    try {
      await this.client.clearNetworkDevices();
      await this.loadState();
      this.host.toast(
        m.network_toast_devices_cleared_title(),
        m.network_toast_devices_cleared_body(),
        'var(--t3)',
      );
    } catch (error) {
      this.host.toast(
        m.network_toast_clear_failed_title(),
        error instanceof Error ? error.message : String(error),
        'var(--bad)',
      );
    }
  };

  chooseScanRange = (cidr: string) => {
    this.customCidr = chooseScanRange(this.customCidr, cidr);
  };

  openWatchSettings = (device: NetworkDeviceRow) => {
    this.selectedDevice = device;
    this.selectedWatch = null;
    this.selectedWatchInterval = DEFAULT_WATCH_INTERVAL;
    this.watchDialogMode = 'configure';
    this.watchDialogOpen = true;
  };

  openRemoveWatch = (device: NetworkDeviceRow, watch: DeviceWatch) => {
    this.selectedDevice = device;
    this.selectedWatch = watch;
    this.selectedWatchInterval = watchIntervalOrDefault(watch.intervalMinutes);
    this.watchDialogMode = 'remove';
    this.watchDialogOpen = true;
  };

  closeWatchDialog = () => {
    if (this.watchSubmitting) return;
    this.watchDialogOpen = false;
  };

  confirmWatchDialog = async (interval: WatchInterval) => {
    if (!this.selectedDevice || this.watchSubmitting) return;
    this.watchSubmitting = true;
    try {
      if (this.watchDialogMode === 'remove') {
        if (!this.selectedWatch) return;
        await this.client.removeNetworkDeviceWatch(this.selectedWatch);
        this.host.toast(
          m.network_toast_watch_removed_title(),
          m.network_toast_watch_removed_body(),
          'var(--t3)',
        );
      } else {
        await this.client.saveNetworkDeviceWatch({
          ipAddress: this.selectedDevice.ipAddress,
          macAddress: this.selectedDevice.macAddress,
          intervalMinutes: interval,
        });
        this.host.toast(
          m.network_toast_watch_added_title(),
          m.network_toast_watch_added_body({ interval: formatWatchInterval(interval) }),
          'var(--ok)',
        );
      }
      this.watchDialogOpen = false;
      await this.loadState();
    } catch (error) {
      this.host.toast(
        this.watchDialogMode === 'remove'
          ? m.network_toast_remove_failed_title()
          : m.network_toast_watch_failed_title(),
        error instanceof Error ? error.message : String(error),
        'var(--bad)',
      );
    } finally {
      this.watchSubmitting = false;
    }
  };

  toggleSort = (key: NetworkDeviceSortKey) => {
    const next = nextNetworkSort(this.sortKey, this.sortDir, key);
    this.sortKey = next.sortKey;
    this.sortDir = next.sortDir;
  };

  private stopPolling = () => {
    if (this.pollTimer) clearTimeout(this.pollTimer);
    this.pollTimer = null;
  };

  private schedulePoll = () => {
    if (!this.mounted || !this.connected || this.pollTimer) return;
    this.pollTimer = setTimeout(() => {
      this.pollTimer = null;
      void this.loadState();
    }, pollDelayMs(this.isScanning));
  };
}
