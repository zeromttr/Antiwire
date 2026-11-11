import { m } from '#lib/i18n/messages.ts';
import type { NetworkDeviceSortKey } from '#lib/models/network-device-sort.ts';
import { WATCH_INTERVALS, type WatchInterval } from '#lib/models/network-watch.ts';
import { formatDateTime, formatTimeAgo } from '#lib/utils/index.ts';

export const DEVICE_ROW_HEIGHT = 52;
export const POLL_MS_SCANNING = 2000;
export const POLL_MS_IDLE = 10000;
export const LAST_SEEN_CACHE_MAX = 512;
export const DEFAULT_WATCH_INTERVAL: WatchInterval = 5;

export type NetworkColumnDef = {
  key: NetworkDeviceSortKey;
  label: string;
  just: string;
};

export function networkDeviceKey(device: { macAddress: string; ipAddress: string }): string {
  const mac = device.macAddress.trim().toLowerCase();
  return mac ? `mac:${mac}` : `ip:${device.ipAddress}`;
}

export function nextNetworkSort(
  sortKey: NetworkDeviceSortKey | null,
  sortDir: 1 | -1,
  clicked: NetworkDeviceSortKey,
): { sortKey: NetworkDeviceSortKey | null; sortDir: 1 | -1 } {
  if (sortKey !== clicked) return { sortKey: clicked, sortDir: -1 };
  if (sortDir === -1) return { sortKey, sortDir: 1 };
  return { sortKey: null, sortDir: -1 };
}

export function activeNetworkSortKey(sortKey: NetworkDeviceSortKey | null): NetworkDeviceSortKey {
  return sortKey ?? 'lastSeen';
}

export function activeNetworkSortDir(
  sortKey: NetworkDeviceSortKey | null,
  sortDir: 1 | -1,
): 1 | -1 {
  return sortKey ? sortDir : -1;
}

/**
 * Sortable columns in display order. The device's name leads (sorted by
 * `identity`); `device` sorts by address. The MAC column is not sortable and
 * is rendered between IP and status by the list itself.
 */
export function networkColumnDefs(): NetworkColumnDef[] {
  return [
    { key: 'identity', label: m.network_col_device(), just: 'flex-start' },
    { key: 'device', label: m.network_col_ip(), just: 'flex-start' },
    { key: 'status', label: m.network_col_status(), just: 'flex-start' },
    { key: 'lastSeen', label: m.network_col_last_seen(), just: 'flex-start' },
  ];
}

export function parseLastSeenTimestamp(lastSeen: string): number {
  const parsed = Date.parse(lastSeen);
  return Number.isFinite(parsed) ? parsed : 0;
}

export function createLastSeenCache(max = LAST_SEEN_CACHE_MAX): (lastSeen: string) => number {
  const cache = new Map<string, number>();
  return (lastSeen: string): number => {
    const cached = cache.get(lastSeen);
    if (cached !== undefined) return cached;
    const timestamp = parseLastSeenTimestamp(lastSeen);
    if (cache.size >= max) cache.clear();
    cache.set(lastSeen, timestamp);
    return timestamp;
  };
}

export function lastSeenLabel(
  lastSeen: string,
  now = Date.now(),
  parse = parseLastSeenTimestamp,
): string {
  const timestamp = parse(lastSeen);
  if (!timestamp) return m.network_last_seen_never();
  const elapsed = formatTimeAgo(timestamp, now);
  return elapsed === m.common_format_time_ago_s({ count: 0 })
    ? m.network_last_seen_just_now()
    : m.network_last_seen_ago({ elapsed });
}

export function lastSeenTitle(lastSeen: string, parse = parseLastSeenTimestamp): string {
  const timestamp = parse(lastSeen);
  return timestamp ? formatDateTime(timestamp) : m.network_last_seen_none_title();
}

export function scanRequestRanges(
  customCidr: string,
  scanRanges: readonly { cidr: string }[],
): string[] {
  const custom = customCidr.trim();
  return custom ? [custom] : scanRanges.map((range) => range.cidr).filter(Boolean);
}

export function chooseScanRange(current: string, cidr: string): string {
  return current === cidr ? '' : cidr;
}

export function watchIntervalOrDefault(minutes: number): WatchInterval {
  return WATCH_INTERVALS.includes(minutes as WatchInterval)
    ? (minutes as WatchInterval)
    : DEFAULT_WATCH_INTERVAL;
}

export function pollDelayMs(isScanning: boolean): number {
  return isScanning ? POLL_MS_SCANNING : POLL_MS_IDLE;
}

export function rangeHelpText(networkClass: 'A' | 'B' | 'C' | null): string {
  if (networkClass === 'A') return m.network_range_help_a();
  if (networkClass === 'B') return m.network_range_help_b();
  if (networkClass === 'C') return m.network_range_help_c();
  return m.network_range_help_other();
}

export function deviceCountLabel(count: number): string {
  return count === 1
    ? m.network_device_count_one({ count })
    : m.network_device_count_other({ count });
}
