import { m } from '#lib/i18n/messages.ts';

export interface CaptureConfiguration {
  /** Executable path of the application to keep; empty captures every application. */
  appPath: string;
  /** Display name of `appPath`, kept so the choice reads correctly while the app is not live. */
  appName: string;
  captureFilter: string;
  promiscuous: boolean;
  snapLength: number;
  maxSeconds: number;
  maxBytes: number;
}

export interface CaptureCounterSnapshot {
  timestampMs: number;
  packets: number;
  bytes: number;
}

export interface CaptureSample extends CaptureCounterSnapshot {
  packetDelta: number;
  byteDelta: number;
  bytesPerSecond: number;
}

export const BPF_PRESETS = [
  { id: 'all', filter: '' },
  { id: 'web', filter: 'tcp port 80 or tcp port 443' },
  { id: 'dns', filter: 'port 53' },
  { id: 'tcp', filter: 'tcp' },
  { id: 'udp', filter: 'udp' },
  { id: 'icmp', filter: 'icmp or icmp6' },
] as const;

export type BpfPresetId = (typeof BPF_PRESETS)[number]['id'];

const BPF_PRESET_LABELS: Record<BpfPresetId, () => string> = {
  all: () => m.capture_preset_all(),
  web: () => m.capture_preset_web(),
  dns: () => m.capture_preset_dns(),
  tcp: () => m.capture_preset_tcp(),
  udp: () => m.capture_preset_udp(),
  icmp: () => m.capture_preset_icmp(),
};

export function bpfPresetLabel(id: BpfPresetId): string {
  return BPF_PRESET_LABELS[id]();
}

export const SNAP_LENGTH_OPTIONS = [96, 1518, 65535] as const;

export type SnapLengthOption = (typeof SNAP_LENGTH_OPTIONS)[number];

const SNAP_LENGTH_LABELS: Record<SnapLengthOption, () => string> = {
  96: () => m.capture_snap_headers(),
  1518: () => m.capture_snap_standard(),
  65535: () => m.capture_snap_full(),
};

const SNAP_LENGTH_DESCRIPTIONS: Record<SnapLengthOption, () => string> = {
  96: () => m.capture_snap_headers_desc(),
  1518: () => m.capture_snap_standard_desc(),
  65535: () => m.capture_snap_full_desc(),
};

export function snapLengthLabel(value: SnapLengthOption): string {
  return SNAP_LENGTH_LABELS[value]();
}

export function snapLengthDescription(value: SnapLengthOption): string {
  return SNAP_LENGTH_DESCRIPTIONS[value]();
}

export const CAPTURE_DURATION_OPTIONS = [60, 300, 900, 1800, 3600, 0] as const;

export type CaptureDurationOption = (typeof CAPTURE_DURATION_OPTIONS)[number];

const CAPTURE_DURATION_LABELS: Record<CaptureDurationOption, () => string> = {
  60: () => m.capture_duration_1m(),
  300: () => m.capture_duration_5m(),
  900: () => m.capture_duration_15m(),
  1800: () => m.capture_duration_30m(),
  3600: () => m.capture_duration_1h(),
  0: () => m.capture_duration_unlimited(),
};

export function captureDurationLabel(value: CaptureDurationOption): string {
  return CAPTURE_DURATION_LABELS[value]();
}

export const CAPTURE_SIZE_OPTIONS = [
  10 * 1024 * 1024,
  50 * 1024 * 1024,
  100 * 1024 * 1024,
  250 * 1024 * 1024,
  500 * 1024 * 1024,
] as const;

export type CaptureSizeOption = (typeof CAPTURE_SIZE_OPTIONS)[number];

const CAPTURE_SIZE_LABELS: Record<CaptureSizeOption, () => string> = {
  [10 * 1024 * 1024]: () => m.capture_size_10mb(),
  [50 * 1024 * 1024]: () => m.capture_size_50mb(),
  [100 * 1024 * 1024]: () => m.capture_size_100mb(),
  [250 * 1024 * 1024]: () => m.capture_size_250mb(),
  [500 * 1024 * 1024]: () => m.capture_size_500mb(),
};

export function captureSizeLabel(value: CaptureSizeOption): string {
  return CAPTURE_SIZE_LABELS[value as CaptureSizeOption]();
}

export const DEFAULT_CAPTURE_CONFIGURATION: CaptureConfiguration = {
  appPath: '',
  appName: '',
  captureFilter: '',
  promiscuous: false,
  snapLength: 65535,
  maxSeconds: 300,
  maxBytes: 50 * 1024 * 1024,
};

const VALID_DURATIONS = new Set<number>(CAPTURE_DURATION_OPTIONS);
const VALID_SIZES = new Set<number>(CAPTURE_SIZE_OPTIONS);

export function normalizeCaptureConfiguration(
  value: Partial<CaptureConfiguration> | null | undefined,
): CaptureConfiguration {
  const snapLength = Math.round(Number(value?.snapLength));
  const maxSeconds = Number(value?.maxSeconds);
  const maxBytes = Number(value?.maxBytes);
  const appPath = String(value?.appPath ?? '').trim();
  return {
    appPath,
    appName: appPath ? String(value?.appName ?? '').trim() : '',
    captureFilter: String(value?.captureFilter ?? '').trim(),
    promiscuous: value?.promiscuous === true,
    snapLength: Number.isFinite(snapLength)
      ? Math.min(65535, Math.max(64, snapLength))
      : DEFAULT_CAPTURE_CONFIGURATION.snapLength,
    maxSeconds: VALID_DURATIONS.has(maxSeconds)
      ? maxSeconds
      : DEFAULT_CAPTURE_CONFIGURATION.maxSeconds,
    maxBytes: VALID_SIZES.has(maxBytes) ? maxBytes : DEFAULT_CAPTURE_CONFIGURATION.maxBytes,
  };
}

export function capturePresetId(filter: string): string {
  const normalized = filter.trim().replaceAll(/\s+/g, ' ').toLowerCase();
  return (
    BPF_PRESETS.find(
      (preset) => preset.filter.trim().replaceAll(/\s+/g, ' ').toLowerCase() === normalized,
    )?.id ?? 'custom'
  );
}

export function deriveCaptureSample(
  current: CaptureCounterSnapshot,
  previous?: CaptureCounterSnapshot,
): CaptureSample {
  if (!previous) {
    return { ...current, packetDelta: 0, byteDelta: 0, bytesPerSecond: 0 };
  }
  const elapsedSeconds = Math.max((current.timestampMs - previous.timestampMs) / 1000, 0.001);
  const packetDelta = Math.max(0, current.packets - previous.packets);
  const byteDelta = Math.max(0, current.bytes - previous.bytes);
  return {
    ...current,
    packetDelta,
    byteDelta,
    bytesPerSecond: byteDelta / elapsedSeconds,
  };
}

export function captureLimitProgress(
  elapsedSeconds: number,
  bytes: number,
  maxSeconds: number,
  maxBytes: number,
): number {
  const timeProgress = maxSeconds > 0 ? elapsedSeconds / maxSeconds : 0;
  const sizeProgress = maxBytes > 0 ? bytes / maxBytes : 0;
  return Math.min(100, Math.max(0, timeProgress, sizeProgress) * 100);
}

export const MAX_CAPTURED_PACKETS = 500;
export const MAX_RECENT_PACKETS = 250;

/** Appends `incoming` onto a live capture buffer, dropping the oldest items past `cap`. */
export function enqueueCapturedPackets<T>(
  buffer: T[],
  incoming: readonly T[],
  cap = MAX_CAPTURED_PACKETS,
): void {
  if (incoming.length === 0) return;
  buffer.push(...incoming);
  const extra = buffer.length - cap;
  if (extra > 0) buffer.splice(0, extra);
}

/** Replaces a captured-packet store with `existing + incoming`, capped at `cap`. */
export function appendCapturedPackets<T>(
  existing: readonly T[],
  incoming: readonly T[],
  cap = MAX_CAPTURED_PACKETS,
): T[] {
  if (incoming.length === 0) {
    return existing.length <= cap ? (existing as T[]) : existing.slice(existing.length - cap);
  }
  if (incoming.length >= cap) return incoming.slice(incoming.length - cap);
  const keep = cap - incoming.length;
  if (existing.length <= keep) return existing.concat(incoming as T[]);
  return existing.slice(existing.length - keep).concat(incoming as T[]);
}

/** Newest-first window for the capture explorer. Does not mutate `packets`. */
export function recentCapturedPackets<T>(packets: readonly T[], limit = MAX_RECENT_PACKETS): T[] {
  if (packets.length === 0) return [];
  const recent = packets.length <= limit ? packets.slice() : packets.slice(packets.length - limit);
  recent.reverse();
  return recent;
}

export function formatCaptureDuration(seconds: number): string {
  const safeSeconds = Math.max(0, Math.floor(seconds));
  const hours = Math.floor(safeSeconds / 3600);
  const minutes = Math.floor((safeSeconds % 3600) / 60);
  const remainder = safeSeconds % 60;
  return hours > 0
    ? `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}:${remainder.toString().padStart(2, '0')}`
    : `${minutes.toString().padStart(2, '0')}:${remainder.toString().padStart(2, '0')}`;
}
