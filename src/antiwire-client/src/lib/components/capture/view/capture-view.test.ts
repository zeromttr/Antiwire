import { beforeAll, describe, expect, test } from 'bun:test';
import { loadMessages, m } from '#lib/i18n/messages.ts';
import {
  CHART_SAMPLE_LIMIT,
  PACKET_ROW_HEIGHT,
  RECENT_SAMPLE_LIMIT,
  canStartCapture,
  capturePacketKey,
  captureStateLabel,
  chartSampleWindow,
  commandShowsClear,
  commandShowsDownload,
  commandShowsStop,
  applicationDropdownOptions,
  deviceDropdownOptions,
  durationDropdownOptions,
  formatCaptureClock,
  formatPacketClock,
  historyElapsedSeconds,
  isProviderUnavailable,
  maxChartRate,
  recentSampleWindow,
  sizeDropdownOptions,
} from './capture-view';

beforeAll(async () => {
  await loadMessages('en');
});

describe('capture view keys and windows', () => {
  test('keys a packet by capture id and sequence', () => {
    expect(capturePacketKey({ captureId: 'cap-1', sequence: 9 })).toBe('cap-1:9');
  });

  test('keeps a fixed packet row height for the virtual list', () => {
    expect(PACKET_ROW_HEIGHT).toBe(33);
  });

  test('takes the newest chart samples without mutating the store', () => {
    const samples = Array.from({ length: 50 }, (_, index) => index);
    expect(chartSampleWindow(samples)).toEqual(samples.slice(-CHART_SAMPLE_LIMIT));
    expect(chartSampleWindow(samples, 3)).toEqual([47, 48, 49]);
    expect(samples).toHaveLength(50);
  });

  test('reverses the newest samples for the explorer', () => {
    const samples = [1, 2, 3, 4, 5];
    expect(recentSampleWindow(samples, RECENT_SAMPLE_LIMIT)).toEqual([5, 4, 3, 2, 1]);
    expect(recentSampleWindow(samples, 2)).toEqual([5, 4]);
    expect(samples).toEqual([1, 2, 3, 4, 5]);
  });

  test('floors the chart rate at 1 so an empty window still scales', () => {
    expect(maxChartRate([])).toBe(1);
    expect(maxChartRate([{ bytesPerSecond: 0 }, { bytesPerSecond: 40 }])).toBe(40);
  });

  test('rounds history duration to whole seconds', () => {
    expect(historyElapsedSeconds(1_000, 4_400)).toBe(3);
  });
});

describe('capture view clocks', () => {
  test('formats packet timestamps from microseconds', () => {
    const ms = Date.UTC(2024, 5, 1, 12, 30, 45);
    expect(formatPacketClock(ms * 1000, 'en-GB')).toBe(formatCaptureClock(ms, 'en-GB'));
    expect(formatCaptureClock(ms, 'en-GB')).toMatch(/^\d{2}:\d{2}:\d{2}$/);
  });
});

describe('capture command chrome', () => {
  test('treats a connected host with no devices as provider-unavailable', () => {
    expect(isProviderUnavailable(true, true, false)).toBe(true);
    expect(isProviderUnavailable(true, false, false)).toBe(false);
    expect(isProviderUnavailable(false, true, false)).toBe(false);
  });

  test('starts only when connected, a device is chosen, and nothing is in flight', () => {
    expect(
      canStartCapture({
        connected: true,
        devicesAvailable: true,
        selectedDevice: 'eth0',
        capturing: false,
        starting: false,
      }),
    ).toBe(true);
    expect(
      canStartCapture({
        connected: true,
        devicesAvailable: true,
        selectedDevice: '',
        capturing: false,
        starting: false,
      }),
    ).toBe(false);
    expect(
      canStartCapture({
        connected: true,
        devicesAvailable: true,
        selectedDevice: 'eth0',
        capturing: true,
        starting: false,
      }),
    ).toBe(false);
  });

  test('labels the command pill from lifecycle and provider state', () => {
    expect(captureStateLabel('idle', true)).toBe(m.capture_state_provider_required());
    expect(captureStateLabel('capturing', false)).toBe(m.capture_state_capturing());
    expect(captureStateLabel('faulted', false)).toBe(m.capture_state_attention());
    expect(captureStateLabel('idle', false)).toBe(m.capture_state_ready());
  });

  test('shows clear, download, and stop only in the matching session states', () => {
    expect(commandShowsClear(false, 1, 0)).toBe(true);
    expect(commandShowsClear(true, 1, 1)).toBe(false);
    expect(commandShowsClear(false, 0, 0)).toBe(false);
    expect(commandShowsDownload(false, 'cap-1', 'completed')).toBe(true);
    expect(commandShowsDownload(false, 'cap-1', 'idle')).toBe(false);
    expect(commandShowsDownload(true, 'cap-1', 'capturing')).toBe(false);
    expect(commandShowsStop(true, false)).toBe(true);
    expect(commandShowsStop(false, true)).toBe(true);
    expect(commandShowsStop(false, false)).toBe(false);
  });
});

describe('capture dropdowns', () => {
  test('lists all applications first, then live applications by name', () => {
    expect(
      applicationDropdownOptions(
        [
          { name: 'zeta', path: 'C:\\z.exe' },
          { name: 'Alpha', path: 'C:\\a.exe' },
          { name: 'beta', path: '' },
        ],
        { path: '', name: '' },
        'All applications',
      ),
    ).toEqual([
      { value: '', label: 'All applications' },
      { value: 'C:\\a.exe', label: 'Alpha' },
      { value: 'C:\\z.exe', label: 'zeta' },
    ]);
  });

  test('keeps a selected application that is no longer live', () => {
    expect(
      applicationDropdownOptions(
        [{ name: 'Edge', path: 'C:\\edge.exe' }],
        { path: 'C:\\gone.exe', name: 'Gone' },
        'All applications',
      ),
    ).toEqual([
      { value: '', label: 'All applications' },
      { value: 'C:\\edge.exe', label: 'Edge' },
      { value: 'C:\\gone.exe', label: 'Gone' },
    ]);
  });

  test('lists devices and falls back when none are present', () => {
    expect(deviceDropdownOptions([], m.capture_interface_none())).toEqual([
      { value: '', label: m.capture_interface_none() },
    ]);
    expect(
      deviceDropdownOptions(
        [
          { name: 'eth0', description: 'Ethernet' },
          { name: 'lo', description: '' },
        ],
        m.capture_interface_none(),
      ),
    ).toEqual([
      { value: 'eth0', label: 'Ethernet' },
      { value: 'lo', label: 'lo' },
    ]);
  });

  test('exposes every duration and size option', () => {
    expect(durationDropdownOptions().map((option) => option.value)).toEqual([
      '60',
      '300',
      '900',
      '1800',
      '3600',
      '0',
    ]);
    expect(sizeDropdownOptions()).toHaveLength(5);
  });
});
