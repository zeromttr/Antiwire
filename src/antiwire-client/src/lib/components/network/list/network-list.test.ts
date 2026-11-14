import { beforeAll, describe, expect, test } from 'bun:test';
import { loadMessages, m } from '#lib/i18n/messages.ts';
import { formatTimeAgo } from '#lib/utils/index.ts';
import {
  DEVICE_ROW_HEIGHT,
  DEFAULT_WATCH_INTERVAL,
  LAST_SEEN_CACHE_MAX,
  POLL_MS_IDLE,
  POLL_MS_SCANNING,
  activeNetworkSortDir,
  activeNetworkSortKey,
  chooseScanRange,
  createLastSeenCache,
  deviceCountLabel,
  lastSeenLabel,
  lastSeenTitle,
  networkColumnDefs,
  networkDeviceKey,
  nextNetworkSort,
  parseLastSeenTimestamp,
  pollDelayMs,
  rangeHelpText,
  scanRequestRanges,
  watchIntervalOrDefault,
} from './network-list';

beforeAll(async () => {
  await loadMessages('en');
});

describe('network list keys and chrome', () => {
  test('keys a device by lowercase MAC when present', () => {
    expect(networkDeviceKey({ ipAddress: '10.0.0.2', macAddress: 'AA:BB:CC:DD:EE:FF' })).toBe(
      'mac:aa:bb:cc:dd:ee:ff',
    );
  });

  test('falls back to IP when MAC is blank', () => {
    expect(networkDeviceKey({ ipAddress: '10.0.0.2', macAddress: '  ' })).toBe('ip:10.0.0.2');
  });

  test('keeps a fixed device row height for the virtual list', () => {
    expect(DEVICE_ROW_HEIGHT).toBe(52);
  });

  test('cycles a column from default desc to asc to unsorted', () => {
    expect(nextNetworkSort(null, -1, 'device')).toEqual({ sortKey: 'device', sortDir: -1 });
    expect(nextNetworkSort('device', -1, 'device')).toEqual({ sortKey: 'device', sortDir: 1 });
    expect(nextNetworkSort('device', 1, 'device')).toEqual({ sortKey: null, sortDir: -1 });
  });

  test('defaults the active sort to last-seen descending', () => {
    expect(activeNetworkSortKey(null)).toBe('lastSeen');
    expect(activeNetworkSortDir(null, 1)).toBe(-1);
    expect(activeNetworkSortKey('status')).toBe('status');
    expect(activeNetworkSortDir('status', 1)).toBe(1);
  });

  test('exposes every sortable column', () => {
    expect(networkColumnDefs().map((col) => col.key)).toEqual([
      'identity',
      'device',
      'status',
      'lastSeen',
    ]);
  });

  test('labels the inventory count', () => {
    expect(deviceCountLabel(1)).toBe(m.network_device_count_one({ count: 1 }));
    expect(deviceCountLabel(4)).toBe(m.network_device_count_other({ count: 4 }));
  });
});

describe('last-seen timestamps', () => {
  test('parses a valid ISO timestamp and treats junk as never', () => {
    expect(parseLastSeenTimestamp('2026-09-05T12:00:00.000Z')).toBe(
      Date.parse('2026-09-05T12:00:00.000Z'),
    );
    expect(parseLastSeenTimestamp('not-a-date')).toBe(0);
  });

  test('caches parsed timestamps and clears when the cap is reached', () => {
    const parse = createLastSeenCache(2);
    const first = '2026-09-05T12:00:00.000Z';
    const second = '2026-09-05T13:00:00.000Z';
    const third = '2026-09-05T14:00:00.000Z';
    expect(parse(first)).toBe(Date.parse(first));
    expect(parse(first)).toBe(Date.parse(first));
    expect(parse(second)).toBe(Date.parse(second));
    expect(parse(third)).toBe(Date.parse(third));
    expect(LAST_SEEN_CACHE_MAX).toBe(512);
  });

  test('labels a missing timestamp as never and a just-seen stamp as now', () => {
    const now = Date.parse('2026-09-05T12:00:00.000Z');
    expect(lastSeenLabel('', now)).toBe(m.network_last_seen_never());
    expect(lastSeenLabel('2026-09-05T12:00:00.000Z', now)).toBe(m.network_last_seen_just_now());
    expect(lastSeenLabel('2026-09-05T11:59:00.000Z', now)).toBe(
      m.network_last_seen_ago({ elapsed: formatTimeAgo(now - 60_000, now) }),
    );
  });

  test('titles a missing timestamp without inventing a clock time', () => {
    expect(lastSeenTitle('')).toBe(m.network_last_seen_none_title());
    expect(lastSeenTitle('2026-09-05T12:00:00.000Z').length).toBeGreaterThan(0);
  });
});

describe('scan and watch helpers', () => {
  test('prefers a custom CIDR and otherwise uses advertised ranges', () => {
    expect(scanRequestRanges(' 10.0.0.0/8 ', [{ cidr: '192.168.1.0/24' }, { cidr: '' }])).toEqual([
      '10.0.0.0/8',
    ]);
    expect(scanRequestRanges('  ', [{ cidr: '192.168.1.0/24' }, { cidr: '' }])).toEqual([
      '192.168.1.0/24',
    ]);
  });

  test('toggles a suggested range on and off', () => {
    expect(chooseScanRange('', '10.0.0.0/8')).toBe('10.0.0.0/8');
    expect(chooseScanRange('10.0.0.0/8', '10.0.0.0/8')).toBe('');
  });

  test('keeps a supported watch interval and falls back to five minutes', () => {
    expect(watchIntervalOrDefault(10)).toBe(10);
    expect(watchIntervalOrDefault(7)).toBe(DEFAULT_WATCH_INTERVAL);
  });

  test('polls faster while a scan is running', () => {
    expect(pollDelayMs(true)).toBe(POLL_MS_SCANNING);
    expect(pollDelayMs(false)).toBe(POLL_MS_IDLE);
  });

  test('explains each private class suggestion', () => {
    expect(rangeHelpText('A')).toBe(m.network_range_help_a());
    expect(rangeHelpText('B')).toBe(m.network_range_help_b());
    expect(rangeHelpText('C')).toBe(m.network_range_help_c());
    expect(rangeHelpText(null)).toBe(m.network_range_help_other());
  });
});
