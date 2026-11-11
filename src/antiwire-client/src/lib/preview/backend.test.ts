import { describe, expect, test } from 'bun:test';
import { createPreviewBackend } from './backend';
import { resolvePreviewMode } from './mode';

describe('browser preview boundary', () => {
  test('only development browsers receive fixtures', () => {
    expect(resolvePreviewMode(true, true, false, '')).toBe('sample');
    expect(resolvePreviewMode(true, true, false, '?preview=offline')).toBe('offline');
    expect(resolvePreviewMode(false, true, false, '?preview=sample')).toBe(null);
    expect(resolvePreviewMode(true, true, true, '?preview=sample')).toBe(null);
    expect(resolvePreviewMode(true, false, false, '')).toBe(null);
  });
});

describe('sample backend', () => {
  const now = 1_789_000_000_000;
  test('filters before paginating and reports matching totals', () => {
    const backend = createPreviewBackend(() => now);
    const all = backend.call('get_connection_logs', { actionFilter: 'Blocked' }) as {
      logs: { action: string }[];
      totalCount: number;
    };
    const page = backend.call('get_connection_logs', {
      actionFilter: 'Blocked',
      offset: 1,
      limit: 2,
    }) as typeof all;
    expect(all.totalCount).toBeGreaterThan(2);
    expect(all.logs.every((row) => row.action === 'BLOCK')).toBe(true);
    expect(page.logs).toEqual(all.logs.slice(1, 3));
    expect(page.totalCount).toBe(all.totalCount);
    expect(
      (backend.call('get_connection_logs', { searchQuery: 'no-such-host' }) as typeof all)
        .totalCount,
    ).toBe(0);
  });
  test('country totals cover every record regardless of connection pagination', () => {
    const backend = createPreviewBackend(() => now);
    const page = backend.call('get_connection_logs', { limit: 1 }) as {
      logs: unknown[];
      totalCount: number;
    };
    const summary = backend.call('get_country_statistics') as {
      countryCounts: Record<string, number>;
      totalCount: number;
      unknownCount: number;
    };
    expect(page.logs).toHaveLength(1);
    expect(summary.totalCount).toBe(page.totalCount);
    expect(
      Object.values(summary.countryCounts).reduce(
        (sum, count) => sum + count,
        summary.unknownCount,
      ),
    ).toBe(summary.totalCount);
  });

  test('mutations update only one session and return detached data', () => {
    const backend = createPreviewBackend(() => now);
    const initial = backend.call('get_rules') as { id: number }[];
    backend.call('add_rule', {
      targetType: 'DOMAIN',
      targetValue: 'test.example',
      action: 'BLOCK',
      direction: 'OUTBOUND',
    });
    expect((backend.call('get_rules') as unknown[]).length).toBe(initial.length + 1);
    initial.length = 0;
    expect((backend.call('get_rules') as unknown[]).length).toBeGreaterThan(1);
    expect((createPreviewBackend(() => now).call('get_rules') as unknown[]).length).toBeGreaterThan(
      0,
    );
    backend.call('clear_alerts');
    expect(backend.call('get_alerts')).toEqual([]);
    expect(
      (createPreviewBackend(() => now).call('get_alerts') as unknown[]).length,
    ).toBeGreaterThan(0);
  });
  test('history deletion removes recent rows, then everything', () => {
    const backend = createPreviewBackend(() => now);
    const logs = () =>
      (backend.call('get_connection_logs', { limit: 1000 }) as { logs: { lastSeen: number }[] })
        .logs;
    const total = logs().length;
    const since = Math.floor(now / 1000) - 300;

    expect(backend.call('delete_history', { all: false, since })).toBeGreaterThan(0);
    expect(logs().length).toBeGreaterThan(0);
    expect(logs().length).toBeLessThan(total);
    expect(logs().every((row) => row.lastSeen < since)).toBe(true);
    expect(() => backend.call('delete_history', { all: false })).toThrow();

    backend.call('delete_history', { all: true });
    expect(logs()).toEqual([]);
    expect(backend.call('get_alerts')).toEqual([]);
  });
  test('clock drives byte counters and capture stop freezes totals', () => {
    let clock = now;
    const backend = createPreviewBackend(() => clock);
    const first = backend.call('get_stats') as { bytesReceived: number };
    clock += 1000;
    expect((backend.call('get_stats') as typeof first).bytesReceived).toBeGreaterThan(
      first.bytesReceived,
    );
    const captureId = backend.call('start_capture', { deviceName: 'preview-en0' });
    clock += 2000;
    backend.call('stop_capture', { captureId });
    const stopped = backend.call('get_capture_status', { captureId });
    clock += 2000;
    expect(backend.call('get_capture_status', { captureId })).toEqual(stopped);
  });
  test('an application-restricted capture reports its name and skipped packets', () => {
    let clock = now;
    const backend = createPreviewBackend(() => clock);
    const everyApp = backend.call('start_capture', { deviceName: 'preview-en0', appPath: '' });
    const onlyEdge = backend.call('start_capture', {
      deviceName: 'preview-en0',
      appPath: 'C:\\Apps\\edge.exe',
      appName: 'Edge',
    });
    clock += 2000;
    expect(backend.call('get_capture_status', { captureId: everyApp })).toMatchObject({
      appName: '',
      filteredPackets: 0,
    });
    expect(backend.call('get_capture_status', { captureId: onlyEdge })).toMatchObject({
      appName: 'Edge',
    });
    expect(
      (backend.call('get_capture_status', { captureId: onlyEdge }) as { filteredPackets: number })
        .filteredPackets,
    ).toBeGreaterThan(0);
  });
  test('unknown and native-only operations fail explicitly', () => {
    const backend = createPreviewBackend(() => now);
    expect(() => backend.call('unknown_command')).toThrow('Browser preview');
    expect(() => backend.call('export_logs', { path: 'ignored.csv' })).toThrow('Browser preview');
  });
});
