import { describe, expect, it } from 'bun:test';
import {
  DEFAULT_CAPTURE_CONFIGURATION,
  appendCapturedPackets,
  captureLimitProgress,
  capturePresetId,
  deriveCaptureSample,
  enqueueCapturedPackets,
  formatCaptureDuration,
  normalizeCaptureConfiguration,
  recentCapturedPackets,
} from './capture';

describe('capture configuration', () => {
  it('normalizes persisted values and clamps the snap length', () => {
    expect(
      normalizeCaptureConfiguration({
        captureFilter: '  tcp  ',
        promiscuous: true,
        snapLength: 999_999,
        maxSeconds: 900,
        maxBytes: 10 * 1024 * 1024,
      }),
    ).toMatchObject({
      captureFilter: 'tcp',
      promiscuous: true,
      snapLength: 65535,
      maxSeconds: 900,
      maxBytes: 10 * 1024 * 1024,
    });
  });

  it('defaults to every application and keeps a persisted application choice', () => {
    expect(DEFAULT_CAPTURE_CONFIGURATION).toMatchObject({ appPath: '', appName: '' });
    expect(
      normalizeCaptureConfiguration({ appPath: ' C:\\Apps\\edge.exe ', appName: 'Edge' }),
    ).toMatchObject({
      appPath: 'C:\\Apps\\edge.exe',
      appName: 'Edge',
    });
    expect(normalizeCaptureConfiguration({})).toMatchObject({ appPath: '', appName: '' });
    expect(normalizeCaptureConfiguration({ appName: 'Edge' })).toMatchObject({ appName: '' });
  });

  it('recognizes presets while allowing custom BPF expressions', () => {
    expect(capturePresetId(' TCP   PORT 80 or TCP PORT 443 ')).toBe('web');
    expect(capturePresetId('host 192.168.1.10')).toBe('custom');
  });

  it('replaces legacy unbounded size settings with the safe default', () => {
    expect(normalizeCaptureConfiguration({ maxBytes: 0 }).maxBytes).toBe(50 * 1024 * 1024);
  });
});

describe('capture telemetry', () => {
  it('derives non-negative deltas and a byte rate', () => {
    expect(
      deriveCaptureSample(
        { timestampMs: 3000, packets: 14, bytes: 5000 },
        { timestampMs: 1000, packets: 10, bytes: 1000 },
      ),
    ).toMatchObject({ packetDelta: 4, byteDelta: 4000, bytesPerSecond: 2000 });
    expect(
      deriveCaptureSample(
        { timestampMs: 3000, packets: 1, bytes: 10 },
        { timestampMs: 1000, packets: 10, bytes: 1000 },
      ),
    ).toMatchObject({ packetDelta: 0, byteDelta: 0 });
  });

  it('uses whichever configured limit is closest', () => {
    expect(captureLimitProgress(30, 20, 60, 100)).toBe(50);
    expect(captureLimitProgress(10, 80, 60, 100)).toBe(80);
    expect(captureLimitProgress(10, 80, 0, 0)).toBe(0);
  });

  it('formats durations without locale-dependent output', () => {
    expect(formatCaptureDuration(9)).toBe('00:09');
    expect(formatCaptureDuration(65)).toBe('01:05');
    expect(formatCaptureDuration(3661)).toBe('01:01:01');
  });

  it('appends packet batches and drops the oldest past the cap', () => {
    expect(appendCapturedPackets([1, 2], [3, 4], 10)).toEqual([1, 2, 3, 4]);
    expect(appendCapturedPackets([1, 2, 3, 4], [5, 6], 4)).toEqual([3, 4, 5, 6]);
    expect(appendCapturedPackets([1], [2, 3, 4, 5, 6], 3)).toEqual([4, 5, 6]);
  });

  it('trims an in-place packet queue to the cap', () => {
    const buffer = [1, 2];
    enqueueCapturedPackets(buffer, [3, 4, 5], 4);
    expect(buffer).toEqual([2, 3, 4, 5]);
  });

  it('returns a newest-first window without mutating the store', () => {
    const packets = [1, 2, 3, 4, 5];
    expect(recentCapturedPackets(packets, 3)).toEqual([5, 4, 3]);
    expect(recentCapturedPackets(packets, 10)).toEqual([5, 4, 3, 2, 1]);
    expect(packets).toEqual([1, 2, 3, 4, 5]);
  });
});
