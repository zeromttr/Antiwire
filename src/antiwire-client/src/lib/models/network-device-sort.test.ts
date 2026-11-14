import { describe, expect, it } from 'bun:test';
import { sortNetworkDevices } from './network-device-sort';

const devices = [
  {
    ipAddress: '192.168.1.20',
    macAddress: 'aa:bb:cc:dd:ee:01',
    mdnsName: 'printer.local',
    manufacturer: 'HP',
    isPresent: false,
    lastSeen: '2026-01-01T10:00:00.000Z',
  },
  {
    ipAddress: '192.168.1.10',
    macAddress: 'aa:bb:cc:dd:ee:02',
    mdnsName: 'phone.local',
    manufacturer: 'Apple',
    isPresent: true,
    lastSeen: '2026-01-02T10:00:00.000Z',
  },
];

describe('sortNetworkDevices', () => {
  const lastSeenTimestamp = (lastSeen: string) => Date.parse(lastSeen);

  it('defaults to newest last seen first', () => {
    const sorted = sortNetworkDevices(devices, null, -1, lastSeenTimestamp);
    expect(sorted.map((device) => device.ipAddress)).toEqual(['192.168.1.10', '192.168.1.20']);
  });

  it('sorts by device address ascending', () => {
    const sorted = sortNetworkDevices(devices, 'device', 1, lastSeenTimestamp);
    expect(sorted.map((device) => device.ipAddress)).toEqual(['192.168.1.10', '192.168.1.20']);
  });

  it('sorts present devices first when status is descending', () => {
    const sorted = sortNetworkDevices(devices, 'status', -1, lastSeenTimestamp);
    expect(sorted[0]?.isPresent).toBe(true);
  });
});
