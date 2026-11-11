import { describe, expect, test } from 'bun:test';
import type { ConnectionLog } from '#lib/types/index.ts';
import type { ActivityBucket } from '#lib/models/activity-heatmap.ts';
import {
  buildFacetOptions,
  buildTimeFilterData,
  customTimeWindow,
  dayTimeWindow,
  facetWindowStart,
  formatTimeWindowShort,
  loadFacetRows,
  rowsInFacetWindow,
  serviceLabel,
} from './records-quick-filters';

function row(overrides: Partial<ConnectionLog>): ConnectionLog {
  return {
    id: 1,
    applicationName: 'Browser',
    applicationPath: '/browser',
    domain: 'example.com',
    sourceIp: '10.0.0.2',
    sourcePort: 0,
    destinationIp: '203.0.113.1',
    port: 443,
    protocol: 'TCP',
    action: 'ALLOW',
    bytesSent: 10,
    bytesReceived: 20,
    timestamp: 1_700_000_000,
    lastSeen: 1_700_000_000,
    closedAt: 0,
    countryCode: 'US',
    blocklistNames: [],
    ...overrides,
  };
}

function activityBucket(
  bucketStart: number,
  bytesSent: number,
  bytesReceived: number,
): ActivityBucket {
  return { bucketStart, eventCount: 1, bytesSent, bytesReceived, blockedCount: 0 };
}

function localSeconds(day: number, hour: number, minute: number): number {
  return Math.floor(new Date(2023, 10, day, hour, minute).getTime() / 1000);
}

describe('record quick filter data', () => {
  test('ranks services, countries and destinations as exact values with shares', () => {
    const data = buildFacetOptions([
      row({ port: 443, protocol: 'TCP', countryCode: 'us', domain: 'a.example' }),
      row({ port: 443, protocol: 'TCP', countryCode: 'US', domain: 'a.example' }),
      row({ port: 53, protocol: 'UDP', countryCode: 'DE', domain: '', destinationIp: '9.9.9.9' }),
      row({ port: 0, countryCode: '', domain: '', destinationIp: '' }),
    ]);
    expect(data.services[0]).toMatchObject({ value: 443, label: 'HTTPS', detail: '443', count: 2 });
    expect(data.services[0].share).toBe(0.5);
    expect(data.services).toHaveLength(2);
    expect(data.countries[0]).toMatchObject({ value: 'US', count: 2 });
    expect(data.destinations.map((d) => d.value)).toEqual(['a.example', '9.9.9.9']);
  });

  test('keeps every distinct value instead of a short top list', () => {
    const rows = Array.from({ length: 8 }, (_, index) =>
      row({
        id: index + 1,
        port: 8000 + index,
        protocol: 'TCP',
        countryCode: ['US', 'DE', 'GB', 'NL', 'JP', 'AU', 'FR', 'CA'][index],
        domain: `host-${index}.example`,
      }),
    );
    const data = buildFacetOptions(rows);
    expect(data.services).toHaveLength(8);
    expect(data.countries).toHaveLength(8);
    expect(data.destinations).toHaveLength(8);
  });

  test('limits suggestions to the rolling day, week, or month', () => {
    const now = new Date('2023-11-14T12:00:00').getTime();
    const recent = row({
      id: 1,
      lastSeen: Math.floor(now / 1000) - 3_600,
      timestamp: Math.floor(now / 1000) - 3_600,
      domain: 'today.example',
      port: 443,
    });
    const lastWeek = row({
      id: 2,
      lastSeen: Math.floor(now / 1000) - 3 * 86_400,
      timestamp: Math.floor(now / 1000) - 3 * 86_400,
      domain: 'week.example',
      port: 53,
    });
    const lastMonth = row({
      id: 3,
      lastSeen: Math.floor(now / 1000) - 20 * 86_400,
      timestamp: Math.floor(now / 1000) - 20 * 86_400,
      domain: 'month.example',
      port: 22,
    });
    const older = row({
      id: 4,
      lastSeen: Math.floor(now / 1000) - 40 * 86_400,
      timestamp: Math.floor(now / 1000) - 40 * 86_400,
      domain: 'old.example',
      port: 21,
    });
    const rows = [recent, lastWeek, lastMonth, older];
    expect(rowsInFacetWindow(rows, 'day', now).map((item) => item.domain)).toEqual([
      'today.example',
    ]);
    expect(rowsInFacetWindow(rows, 'week', now).map((item) => item.domain)).toEqual([
      'today.example',
      'week.example',
    ]);
    expect(rowsInFacetWindow(rows, 'month', now).map((item) => item.domain)).toEqual([
      'today.example',
      'week.example',
      'month.example',
    ]);
    expect(facetWindowStart('day', now)).toBe(Math.floor(now / 1000) - 86_400);
  });

  test('pages facet rows until the window is exhausted and stops on a repeated page', async () => {
    const all = [
      row({ id: 1, domain: 'a.example' }),
      row({ id: 2, domain: 'b.example' }),
      row({ id: 3, domain: 'c.example' }),
    ];
    const loaded = await loadFacetRows(
      async (offset, limit) => ({
        logs: all.slice(offset, offset + limit),
        totalCount: all.length,
      }),
      { pageSize: 2, cap: 10 },
    );
    expect(loaded.map((item) => item.domain)).toEqual(['a.example', 'b.example', 'c.example']);

    const capped = await loadFacetRows(
      async (offset, limit) => ({
        logs: all.slice(offset, offset + limit),
        totalCount: all.length,
      }),
      { pageSize: 1, cap: 2 },
    );
    expect(capped.map((item) => item.id)).toEqual([1, 2]);

    const stuck = await loadFacetRows(
      async () => ({ logs: [row({ id: 1, domain: 'a.example' })], totalCount: 50 }),
      { pageSize: 1, cap: 10 },
    );
    expect(stuck).toHaveLength(1);
  });

  test('labels well-known ports by service and others by number', () => {
    expect(serviceLabel(443, 'TCP')).toEqual({ label: 'HTTPS', detail: '443' });
    expect(serviceLabel(49152, 'TCP')).toEqual({ label: '49152' });
  });

  test('builds whole-day windows and short labels', () => {
    const day = dayTimeWindow('2023-11-14');
    expect(day.end - day.start).toBe(86_400);
    expect(formatTimeWindowShort(day.start, day.end)).not.toContain('–');
    const hour = new Date(2023, 10, 14, 14, 0).getTime() / 1000;
    expect(formatTimeWindowShort(hour, hour + 3600).split('–')).toHaveLength(2);
  });

  test('marks daily and hourly buckets by their dominant byte direction', () => {
    const down = Math.floor(new Date('2023-11-14T10:15:00').getTime() / 1000);
    const up = Math.floor(new Date('2023-11-14T11:15:00').getTime() / 1000);
    const data = buildTimeFilterData(
      [
        row({ timestamp: down, lastSeen: down, bytesSent: 10, bytesReceived: 90 }),
        row({ timestamp: up, lastSeen: up, bytesSent: 80, bytesReceived: 20 }),
      ],
      new Date('2023-11-14T12:00:00'),
    );
    expect(data.days.find((day) => day.key === '2023-11-14')?.direction).toBe('down');
    expect(data.hours[10].direction).toBe('down');
    expect(data.hours[11].direction).toBe('up');
  });

  test('aggregates real activity buckets into daily and hourly traffic', () => {
    const now = new Date(2023, 10, 14, 12, 0);
    const data = buildTimeFilterData([], now, '2023-11-14', [
      activityBucket(localSeconds(14, 10, 0), 100, 300),
      activityBucket(localSeconds(14, 10, 30), 200, 200),
      activityBucket(localSeconds(13, 23, 30), 50, 50),
    ]);

    expect(data.hours[10]).toMatchObject({
      sent: 300,
      received: 500,
      total: 800,
      intensity: 1,
      direction: 'down',
    });
    expect(data.hours[0].total).toBe(0);
    expect(data.days.find((day) => day.key === '2023-11-14')?.total).toBe(800);
    expect(data.days.find((day) => day.key === '2023-11-13')?.total).toBe(100);
  });

  test('prefers real activity buckets over the loaded records page', () => {
    const now = new Date(2023, 10, 14, 12, 0);
    const nine = localSeconds(14, 9, 0);
    const data = buildTimeFilterData(
      [row({ timestamp: nine, lastSeen: nine, bytesSent: 10, bytesReceived: 20 })],
      now,
      '2023-11-14',
      [activityBucket(nine, 500, 0)],
    );

    expect(data.hours[9].total).toBe(500);
  });

  test('builds a valid local time range and rejects inverted ranges', () => {
    expect(customTimeWindow('2023-11-14', '09:30', '11:15')).toEqual({
      start: Math.floor(new Date('2023-11-14T09:30').getTime() / 1000),
      // The end minute is inclusive.
      end: Math.floor(new Date('2023-11-14T11:15').getTime() / 1000) + 60,
    });
    expect(customTimeWindow('2023-11-14', '11:15', '09:30')).toBeNull();
  });
});
