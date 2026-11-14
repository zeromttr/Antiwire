import { m } from '#lib/i18n/messages.ts';

export const WATCH_INTERVALS = [1, 5, 10, 30, 60] as const;
export type WatchInterval = (typeof WATCH_INTERVALS)[number];

export interface DeviceWatch {
  id: number;
  ipAddress: string;
  macAddress: string;
  intervalMinutes: number;
  enabled: boolean;
  isPresent: boolean;
  lastChecked: string;
}

export interface NetworkDeviceIdentity {
  ipAddress: string;
  macAddress: string;
}

export interface NetworkDeviceRow extends NetworkDeviceIdentity {
  manufacturer: string;
  mdnsName: string;
  isPresent: boolean;
  lastSeen: string;
  isWatched: boolean;
}

function watchMatchesDevice(watch: DeviceWatch, device: NetworkDeviceIdentity): boolean {
  return (
    (watch.macAddress !== '' &&
      watch.macAddress.toLowerCase() === device.macAddress.toLowerCase()) ||
    (watch.ipAddress !== '' && watch.ipAddress === device.ipAddress)
  );
}

export function matchingDeviceWatch(
  watches: DeviceWatch[],
  device: NetworkDeviceIdentity,
): DeviceWatch | undefined {
  return watches.find((watch) => watchMatchesDevice(watch, device));
}

export function deviceWatchTarget(watch: Pick<DeviceWatch, 'ipAddress' | 'macAddress'>): string {
  if (watch.ipAddress && watch.macAddress) return `${watch.ipAddress} · ${watch.macAddress}`;
  return watch.ipAddress || watch.macAddress;
}

export function formatWatchInterval(minutes: number, compact = false): string {
  if (minutes === 60) {
    return compact ? m.network_watch_interval_compact_hour() : m.network_watch_interval_1_hour();
  }
  if (compact) return m.network_watch_interval_compact_minutes({ count: minutes });
  return minutes === 1
    ? m.network_watch_interval_1_minute()
    : m.network_watch_interval_n_minutes({ count: minutes });
}

export function watchIntervalDescription(minutes: WatchInterval): string {
  if (minutes === 1) return m.network_watch_interval_1_desc();
  if (minutes === 5) return m.network_watch_interval_5_desc();
  if (minutes === 10) return m.network_watch_interval_10_desc();
  if (minutes === 30) return m.network_watch_interval_30_desc();
  return m.network_watch_interval_60_desc();
}

export function mergeDevicesWithWatches(
  devices: NetworkDeviceRow[],
  watches: DeviceWatch[],
): NetworkDeviceRow[] {
  const rows = devices.map((device) => ({
    ...device,
    isWatched: matchingDeviceWatch(watches, device) !== undefined,
  }));

  for (const watch of watches) {
    if (rows.some((device) => watchMatchesDevice(watch, device))) continue;
    rows.push({
      ipAddress: watch.ipAddress,
      macAddress: watch.macAddress,
      manufacturer: '',
      mdnsName: '',
      isPresent: watch.isPresent,
      lastSeen: watch.lastChecked,
      isWatched: true,
    });
  }
  return rows;
}
