import { describe, expect, it } from 'bun:test';
import { DEFAULT_CAPTURE_CONFIGURATION } from '#lib/models/capture.ts';
import {
  buildDefaultCaptureFilename,
  buildHistoryEntry,
  buildSessionKey,
  isClassAbcIpv4,
  MAX_HISTORY_ITEMS,
  nextPollDelayMs,
  POLL_FAULT_THRESHOLD,
  preferredCaptureDeviceName,
  pushHistoryEntry,
  shouldFaultSession,
} from './capture-policy';

function entry(id: string) {
  return buildHistoryEntry({
    captureId: id,
    startedAt: 1000,
    endedAt: 2000,
    deviceName: 'eth0',
    packets: 10,
    bytes: 512,
    droppedPackets: 0,
    configuration: { ...DEFAULT_CAPTURE_CONFIGURATION },
    outcome: 'completed',
  });
}

describe('poll failure policy', () => {
  it('polls every second while healthy and backs off on failures', () => {
    expect(nextPollDelayMs(0)).toBe(1000);
    expect(nextPollDelayMs(1)).toBe(2000);
    expect(nextPollDelayMs(5)).toBe(2000);
  });

  it('faults the session after three consecutive failures', () => {
    expect(POLL_FAULT_THRESHOLD).toBe(3);
    expect(shouldFaultSession(0)).toBe(false);
    expect(shouldFaultSession(1)).toBe(false);
    expect(shouldFaultSession(2)).toBe(false);
    expect(shouldFaultSession(3)).toBe(true);
    expect(shouldFaultSession(4)).toBe(true);
  });
});

describe('session history', () => {
  it('keys sessions by capture id and start time', () => {
    expect(buildSessionKey('abc', 123)).toBe('abc:123');
  });

  it('snapshots the configuration so later edits do not rewrite history', () => {
    const configuration = { ...DEFAULT_CAPTURE_CONFIGURATION, snapLength: 512 };
    const item = buildHistoryEntry({
      captureId: 'abc',
      startedAt: 1,
      endedAt: 2,
      deviceName: 'eth0',
      packets: 1,
      bytes: 1,
      droppedPackets: 0,
      configuration,
      outcome: 'completed',
    });

    configuration.snapLength = 9000;
    expect(item.configuration.snapLength).toBe(512);
  });

  it('prepends new sessions and caps the history length', () => {
    const history = [entry('first')];
    const second = entry('second');

    const next = pushHistoryEntry(history, second, null);

    expect(next.history[0].id).toBe(second.id);
    expect(next.history).toHaveLength(2);
    expect(next.recordedKey).toBe(second.id);
    expect(MAX_HISTORY_ITEMS).toBe(8);
  });

  it('drops the oldest sessions beyond the cap', () => {
    let history: ReturnType<typeof entry>[] = [];
    for (let i = 0; i < MAX_HISTORY_ITEMS + 3; i += 1) {
      const next = pushHistoryEntry(history, entry(`cap-${i}`), null);
      history = next.history;
    }

    expect(history).toHaveLength(MAX_HISTORY_ITEMS);
    expect(history[0].id).toContain(`cap-${MAX_HISTORY_ITEMS + 2}`);
  });

  it('does not duplicate a session recorded twice (status race)', () => {
    const item = entry('same');
    const first = pushHistoryEntry([], item, null);
    const second = pushHistoryEntry(first.history, item, first.recordedKey);

    expect(second.history).toHaveLength(1);
  });
});

describe('class A/B/C interface preference', () => {
  it('accepts classful unicast IPv4 and rejects loopback, multicast, and IPv6', () => {
    expect(isClassAbcIpv4('10.0.0.1')).toBe(true);
    expect(isClassAbcIpv4('172.16.4.2')).toBe(true);
    expect(isClassAbcIpv4('192.168.1.10')).toBe(true);
    expect(isClassAbcIpv4('8.8.8.8')).toBe(true);
    expect(isClassAbcIpv4('127.0.0.1')).toBe(false);
    expect(isClassAbcIpv4('0.0.0.0')).toBe(false);
    expect(isClassAbcIpv4('224.0.0.1')).toBe(false);
    expect(isClassAbcIpv4('::1')).toBe(false);
    expect(isClassAbcIpv4('fe80::1')).toBe(false);
  });

  it('selects the first non-loopback device with a class A, B, or C address', () => {
    expect(
      preferredCaptureDeviceName([
        { name: 'lo', addresses: ['127.0.0.1'], loopback: true },
        { name: 'npcap', addresses: ['fe80::1'], loopback: false },
        { name: 'eth0', addresses: ['192.168.1.20'], loopback: false },
        { name: 'wifi0', addresses: ['10.0.0.5'], loopback: false },
      ]),
    ).toBe('eth0');
  });

  it('falls back to the first listed device when no classful IPv4 is present', () => {
    expect(
      preferredCaptureDeviceName([
        { name: 'lo', addresses: ['127.0.0.1'], loopback: true },
        { name: 'tun0', addresses: ['fe80::2'], loopback: false },
      ]),
    ).toBe('lo');
  });
});

describe('download filename', () => {
  it('builds a filesystem-safe pcap name from a timestamp', () => {
    const name = buildDefaultCaptureFilename(new Date('2026-09-03T10:20:30.400Z'));

    expect(name).toBe('antiwire-capture-2026-09-03T10-20-30-400Z.pcap');
    expect(name.endsWith('.pcap')).toBe(true);
    expect(name.slice(0, -'.pcap'.length)).not.toMatch(/[:.]/);
  });
});
