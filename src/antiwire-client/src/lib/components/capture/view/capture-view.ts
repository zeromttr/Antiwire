import { m } from '#lib/i18n/messages.ts';
import {
  CAPTURE_DURATION_OPTIONS,
  CAPTURE_SIZE_OPTIONS,
  captureDurationLabel,
  captureSizeLabel,
} from '#lib/models/capture.ts';

export const PACKET_ROW_HEIGHT = 33;
export const CHART_SAMPLE_LIMIT = 48;
export const RECENT_SAMPLE_LIMIT = 10;

export type CaptureViewDevice = {
  name: string;
  description?: string;
};

export function capturePacketKey(packet: { captureId: string; sequence: number }): string {
  return `${packet.captureId}:${packet.sequence}`;
}

export function formatCaptureClock(timestampMs: number, locale: string): string {
  return new Date(timestampMs).toLocaleTimeString(locale, {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  });
}

export function formatPacketClock(timestampUs: number, locale: string): string {
  return formatCaptureClock(Math.floor(timestampUs / 1000), locale);
}

export function isProviderUnavailable(
  connected: boolean,
  devicesLoaded: boolean,
  devicesAvailable: boolean,
): boolean {
  return connected && devicesLoaded && !devicesAvailable;
}

export function canStartCapture(input: {
  connected: boolean;
  devicesAvailable: boolean;
  selectedDevice: string;
  capturing: boolean;
  starting: boolean;
}): boolean {
  return (
    input.connected &&
    input.devicesAvailable &&
    Boolean(input.selectedDevice) &&
    !input.capturing &&
    !input.starting
  );
}

export function captureStateLabel(captureState: string, providerUnavailable: boolean): string {
  if (providerUnavailable) return m.capture_state_provider_required();
  if (captureState === 'capturing') return m.capture_state_capturing();
  if (captureState === 'starting') return m.capture_state_starting();
  if (captureState === 'stopping') return m.capture_state_stopping();
  if (captureState === 'completed') return m.capture_state_completed();
  if (captureState === 'faulted') return m.capture_state_attention();
  return m.capture_state_ready();
}

export function commandShowsClear(capturing: boolean, packets: number, bytes: number): boolean {
  return !capturing && (packets > 0 || bytes > 0);
}

export function commandShowsDownload(
  capturing: boolean,
  captureId: string | null | undefined,
  captureState: string,
): boolean {
  return !capturing && Boolean(captureId) && captureState !== 'idle';
}

export function commandShowsStop(capturing: boolean, stopping: boolean): boolean {
  return capturing || stopping;
}

export function deviceDropdownOptions(
  devices: readonly CaptureViewDevice[],
  emptyLabel: string,
): { value: string; label: string }[] {
  if (devices.length === 0) return [{ value: '', label: emptyLabel }];
  return devices.map((device) => ({
    value: device.name,
    label: device.description || device.name,
  }));
}

/**
 * "All applications" first, then live applications sorted by name. The selected
 * application stays listed even when it is not live, so the choice remains visible.
 */
export function applicationDropdownOptions(
  apps: readonly { name: string; path: string }[],
  selected: { path: string; name: string },
  allLabel: string,
): { value: string; label: string }[] {
  const choices = apps
    .filter((app) => app.path)
    .map((app) => ({ value: app.path, label: app.name || app.path }));
  if (selected.path && !choices.some((choice) => choice.value === selected.path)) {
    choices.push({ value: selected.path, label: selected.name || selected.path });
  }
  choices.sort((a, b) => a.label.localeCompare(b.label, undefined, { sensitivity: 'base' }));
  return [{ value: '', label: allLabel }, ...choices];
}

export function durationDropdownOptions(): { value: string; label: string }[] {
  return CAPTURE_DURATION_OPTIONS.map((value) => ({
    value: String(value),
    label: captureDurationLabel(value),
  }));
}

export function sizeDropdownOptions(): { value: string; label: string }[] {
  return CAPTURE_SIZE_OPTIONS.map((value) => ({
    value: String(value),
    label: captureSizeLabel(value),
  }));
}

export function chartSampleWindow<T>(samples: readonly T[], limit = CHART_SAMPLE_LIMIT): T[] {
  return samples.slice(-limit);
}

export function recentSampleWindow<T>(samples: readonly T[], limit = RECENT_SAMPLE_LIMIT): T[] {
  return samples.slice(-limit).reverse();
}

export function maxChartRate(samples: readonly { bytesPerSecond: number }[]): number {
  return Math.max(...samples.map((sample) => sample.bytesPerSecond), 1);
}

export function historyElapsedSeconds(startedAt: number, endedAt: number): number {
  return Math.round((endedAt - startedAt) / 1000);
}
