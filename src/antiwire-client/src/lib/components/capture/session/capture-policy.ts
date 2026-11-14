import type { CaptureConfiguration } from '#lib/models/capture.ts';
import { isValidIpv4 } from '#lib/utils/network-target.ts';

/** Consecutive status-poll failures before a session is marked faulted. */
export const POLL_FAULT_THRESHOLD = 3;

/** Sessions remembered in the capture history panel. */
export const MAX_HISTORY_ITEMS = 8;

export interface CaptureHistoryEntry {
  id: string;
  startedAt: number;
  endedAt: number;
  deviceName: string;
  packets: number;
  bytes: number;
  droppedPackets: number;
  configuration: CaptureConfiguration;
  outcome: string;
}

/** Delay before the next status poll: back off while failures accumulate. */
export function nextPollDelayMs(pollFailures: number): number {
  return pollFailures > 0 ? 2000 : 1000;
}

export function shouldFaultSession(pollFailures: number): boolean {
  return pollFailures >= POLL_FAULT_THRESHOLD;
}

export function buildSessionKey(captureId: string, startedAt: number): string {
  return `${captureId}:${startedAt}`;
}

export function buildHistoryEntry(args: {
  captureId: string;
  startedAt: number;
  endedAt: number;
  deviceName: string;
  packets: number;
  bytes: number;
  droppedPackets: number;
  configuration: CaptureConfiguration;
  outcome: string;
}): CaptureHistoryEntry {
  return {
    id: buildSessionKey(args.captureId, args.startedAt),
    startedAt: args.startedAt,
    endedAt: args.endedAt,
    deviceName: args.deviceName,
    packets: args.packets,
    bytes: args.bytes,
    droppedPackets: args.droppedPackets,
    configuration: { ...args.configuration },
    outcome: args.outcome,
  };
}

/** Prepends a history entry, de-duplicating repeat recordings of one session. */
export function pushHistoryEntry(
  history: readonly CaptureHistoryEntry[],
  entry: CaptureHistoryEntry,
  recordedKey: string | null,
): { history: CaptureHistoryEntry[]; recordedKey: string } {
  if (recordedKey === entry.id) return { history: [...history], recordedKey: entry.id };
  return {
    history: [entry, ...history].slice(0, MAX_HISTORY_ITEMS),
    recordedKey: entry.id,
  };
}

export function buildDefaultCaptureFilename(date: Date = new Date()): string {
  return `antiwire-capture-${date.toISOString().replace(/[:.]/g, '-')}.pcap`;
}

export interface CaptureDeviceChoice {
  name: string;
  addresses: readonly string[];
  loopback?: boolean;
}

/** Class A (1–126), B (128–191), or C (192–223) unicast IPv4. */
export function isClassAbcIpv4(value: string): boolean {
  if (!isValidIpv4(value)) return false;
  const first = Number(value.trim().split('.')[0]);
  return (first >= 1 && first <= 126) || (first >= 128 && first <= 223);
}

/** First non-loopback device with a class A/B/C address, else the first listed device. */
export function preferredCaptureDeviceName(devices: readonly CaptureDeviceChoice[]): string {
  return (
    devices.find((device) => !device.loopback && device.addresses.some(isClassAbcIpv4))?.name ??
    devices[0]?.name ??
    ''
  );
}
