import { describe, expect, test } from 'bun:test';
import {
  deviceWatchTarget,
  formatWatchInterval,
  matchingDeviceWatch,
  mergeDevicesWithWatches,
  WATCH_INTERVALS,
  type DeviceWatch,
} from './network-watch';

const watch: DeviceWatch = {
  id: 7,
  ipAddress: '192.168.1.7',
  macAddress: '00:1B:63:00:00:07',
  intervalMinutes: 5,
  enabled: true,
  isPresent: true,
  lastChecked: '2026-08-03T12:00:00Z',
};

describe('network presence watches', () => {
  test('offers only the daemon-supported intervals', () => {
    expect(WATCH_INTERVALS).toEqual([1, 5, 10, 30, 60]);
  });

  test('matches a discovered device by IP or case-insensitive MAC', () => {
    expect(
      matchingDeviceWatch([watch], {
        ipAddress: '192.168.1.99',
        macAddress: '00:1b:63:00:00:07',
      }),
    ).toBe(watch);
    expect(
      matchingDeviceWatch([watch], {
        ipAddress: '192.168.1.7',
        macAddress: 'AA:BB:CC:DD:EE:FF',
      }),
    ).toBe(watch);
  });

  test('formats an identity without empty punctuation', () => {
    expect(deviceWatchTarget(watch)).toBe('192.168.1.7 · 00:1B:63:00:00:07');
    expect(deviceWatchTarget({ ipAddress: '192.168.1.7', macAddress: '' })).toBe('192.168.1.7');
  });

  test('formats watch intervals for dialogs and compact row badges', () => {
    expect(formatWatchInterval(1)).toBe('1 minute');
    expect(formatWatchInterval(5)).toBe('5 minutes');
    expect(formatWatchInterval(60)).toBe('1 hour');
    expect(formatWatchInterval(5, true)).toBe('5M');
    expect(formatWatchInterval(60, true)).toBe('1H');
  });

  test('keeps an unmatched saved watch manageable in the main device list', () => {
    const rows = mergeDevicesWithWatches([], [watch]);
    expect(rows).toEqual([
      {
        ipAddress: watch.ipAddress,
        macAddress: watch.macAddress,
        manufacturer: '',
        mdnsName: '',
        isPresent: true,
        lastSeen: watch.lastChecked,
        isWatched: true,
      },
    ]);
  });
});
