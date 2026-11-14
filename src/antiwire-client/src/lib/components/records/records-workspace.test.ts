import { beforeAll, describe, expect, mock, test } from 'bun:test';
import type { AppSummary, ConnectionLog } from '#lib/types/index.ts';
import type { ActivityBucket } from '#lib/models/activity-heatmap.ts';
import { loadMessages, m } from '#lib/i18n/messages.ts';
import { RecordsWorkspace, type RecordsHost } from './records-workspace';
import { recordsLogItemKey } from './list/records-list';

function summary(overrides: Partial<AppSummary> = {}): AppSummary {
  return {
    applicationId: 1,
    applicationName: 'Chrome',
    applicationPath: 'C:\\Apps\\chrome.exe',
    connectionCount: 4,
    blockedCount: 0,
    totalBytes: 100,
    bytesSent: 40,
    bytesReceived: 60,
    ...overrides,
  };
}

function log(overrides: Partial<ConnectionLog> = {}): ConnectionLog {
  return {
    id: 1,
    applicationName: 'Chrome',
    applicationPath: 'C:\\Apps\\chrome.exe',
    domain: 'example.com',
    sourceIp: '10.0.0.1',
    sourcePort: 0,
    destinationIp: '1.1.1.1',
    port: 443,
    protocol: 'TCP',
    action: 'Allowed',
    bytesSent: 10,
    bytesReceived: 20,
    timestamp: 1,
    lastSeen: 2,
    closedAt: 0,
    countryCode: 'US',
    blocklistNames: [],
    ...overrides,
  };
}

function workspace(options?: {
  connected?: boolean;
  logs?: ConnectionLog[];
  summaries?: AppSummary[];
  logsTotalCount?: number;
  activityBuckets?: ActivityBucket[];
  pathname?: string;
  search?: string;
  refreshRecords?: RecordsHost['refreshRecords'];
  subscribeTraffic?: RecordsHost['subscribeTraffic'];
}) {
  const toasts: Array<[string, string, string]> = [];
  const hrefs: string[] = [];
  let search = options?.search ?? '';
  const host: RecordsHost = {
    get connected() {
      return options?.connected ?? true;
    },
    get logs() {
      return options?.logs ?? [];
    },
    get summaries() {
      return options?.summaries ?? [summary()];
    },
    get logsTotalCount() {
      return options?.logsTotalCount ?? 4;
    },
    get activityBuckets() {
      return options?.activityBuckets ?? [];
    },
    subscribeTraffic: options?.subscribeTraffic ?? (async () => () => {}),
    currentUrl: () => ({ pathname: options?.pathname ?? '/records', search }),
    goto: (href) => {
      hrefs.push(href);
      const q = href.includes('?') ? href.slice(href.indexOf('?')) : '';
      search = q;
    },
    refreshRecords:
      options?.refreshRecords ??
      mock(async () => {
        /* no-op */
      }),
    toast: (title, body, color) => {
      toasts.push([title, body, color]);
    },
  };
  return { rec: new RecordsWorkspace(host), host, toasts, hrefs };
}

beforeAll(async () => {
  await loadMessages('en');
});

describe('RecordsWorkspace.load', () => {
  test('does not call the daemon while disconnected', async () => {
    const refreshRecords = mock(async () => {
      throw new Error('should not run');
    });
    const { rec } = workspace({ connected: false, refreshRecords });
    await rec.load('manual-refresh');
    expect(refreshRecords).not.toHaveBeenCalled();
    expect(rec.recordsLoading).toBe(false);
  });

  test('asks the daemon for a blocked page and clears the loading flag', async () => {
    const refreshRecords = mock(async () => undefined);
    const { rec } = workspace({ refreshRecords });
    rec.verdict = 'blocked';
    rec.selectedApp = 'Chrome';
    await rec.load('verdict-change');
    expect(refreshRecords).toHaveBeenCalledWith(
      expect.objectContaining({
        actionFilter: 'Blocked',
        applicationName: 'Chrome',
        refreshSummaries: false,
      }),
    );
    expect(rec.recordsLoading).toBe(false);
  });

  test('toasts when the daemon refresh fails', async () => {
    const { rec, toasts } = workspace({
      refreshRecords: mock(async () => {
        throw new Error('offline');
      }),
    });
    await rec.load('manual-refresh');
    expect(toasts[0]?.[0]).toBe(m.records_toast_load_failed_title());
    expect(toasts[0]?.[1]).toBe('offline');
  });
});

describe('RecordsWorkspace filters', () => {
  test('selects a time window through the existing URL filter path', () => {
    const { rec, hrefs } = workspace();
    rec.selectTimeWindow(100, 200);
    expect(rec.timeWindowStart).toBe(100);
    expect(rec.timeWindowEnd).toBe(200);
    expect(hrefs.at(-1)).toContain('from=100');
    expect(hrefs.at(-1)).toContain('to=200');
  });

  test('selectApp writes the app into the URL', () => {
    const { rec, hrefs } = workspace();
    rec.selectApp('Chrome');
    expect(rec.selectedApp).toBe('Chrome');
    expect(rec.pageOffset).toBe(0);
    expect(hrefs).toEqual(['/records?app=Chrome']);
  });

  test('selectApp by row key pins the exact install path', () => {
    const { rec, hrefs } = workspace({
      summaries: [
        summary({ applicationId: 2, applicationName: 'Tool', applicationPath: 'C:\\a.exe' }),
        summary({ applicationId: 9, applicationName: 'Tool', applicationPath: 'C:\\b.exe' }),
      ],
    });
    rec.selectApp('Tool::C:\\b.exe');
    expect(rec.selectedApp).toBe('Tool');
    expect(rec.selectedAppId).toBe(9);
    expect(hrefs).toEqual(['/records?app=Tool&appid=9']);
  });

  test('onUrlChange restores an exact application id', () => {
    const refreshRecords = mock(async () => undefined);
    const { rec } = workspace({ refreshRecords });
    rec.onUrlChange('?app=Tool&appid=9');
    expect(rec.selectedApp).toBe('Tool');
    expect(rec.selectedAppId).toBe(9);
    expect(refreshRecords).toHaveBeenCalledWith(
      expect.objectContaining({ applicationName: 'Tool', applicationId: 9 }),
    );
  });

  test('selectVerdict ignores a no-op and otherwise reloads', async () => {
    const refreshRecords = mock(async () => undefined);
    const { rec } = workspace({ refreshRecords });
    rec.recordsLoading = false;
    rec.selectVerdict('all');
    expect(refreshRecords).not.toHaveBeenCalled();
    await rec.selectVerdict('allowed');
    expect(rec.verdict).toBe('allowed');
    expect(refreshRecords).toHaveBeenCalled();
  });

  test('toggleSort cycles the column and resets the page', async () => {
    const refreshRecords = mock(async () => undefined);
    const { rec } = workspace({ refreshRecords });
    rec.toggleSort('port');
    expect(rec.sortKey).toBe('port');
    expect(rec.sortDir).toBe(-1);
    rec.toggleSort('port');
    expect(rec.sortDir).toBe(1);
    rec.toggleSort('port');
    expect(rec.sortKey).toBeNull();
    expect(refreshRecords).toHaveBeenCalledTimes(3);
  });

  test('onUrlChange applies the query and loads once', async () => {
    const refreshRecords = mock(async () => undefined);
    const { rec } = workspace({ refreshRecords, search: '?app=Chrome&from=10&to=20' });
    rec.onUrlChange('?app=Chrome&from=10&to=20');
    expect(rec.selectedApp).toBe('Chrome');
    expect(rec.timeWindowStart).toBe(10);
    rec.onUrlChange('?app=Chrome&from=10&to=20');
    await Promise.resolve();
    expect(refreshRecords).toHaveBeenCalledTimes(1);
  });

  test('inspectRecord opens the detail dialog', () => {
    const { rec } = workspace();
    const row = log();
    rec.inspectRecord(row);
    expect(rec.detailOpen).toBe(true);
    expect(rec.selectedRecord).toBe(row);
  });

  test('goToNextPage advances by the page size', async () => {
    const refreshRecords = mock(async () => undefined);
    const { rec } = workspace({ refreshRecords, logsTotalCount: 400, logs: [log()] });
    rec.recordsLoading = false;
    await rec.goToNextPage();
    expect(rec.pageOffset).toBe(200);
    expect(refreshRecords).toHaveBeenCalled();
  });
});

describe('RecordsWorkspace real-time', () => {
  test('subscribes to the traffic stream and refreshes silently per event', async () => {
    const refreshRecords = mock(async () => undefined);
    let handler = null as (() => void) | null;
    const unlisten = mock(() => {});
    const subscribeTraffic = mock(async (next: () => void) => {
      handler = next;
      return unlisten;
    });
    const { rec, toasts } = workspace({ refreshRecords, subscribeTraffic });
    rec.recordsLoading = false;

    expect(rec.realtime).toBe(false);
    rec.toggleRealtime();
    expect(rec.realtime).toBe(true);
    expect(subscribeTraffic).toHaveBeenCalledTimes(1);
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(handler).toBeTypeOf('function');

    handler?.();
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(refreshRecords).toHaveBeenCalledTimes(1);
    expect(refreshRecords).toHaveBeenCalledWith(
      expect.objectContaining({ refreshSummaries: true }),
    );
    expect(rec.recordsLoading).toBe(false);
    expect(toasts).toEqual([]);

    rec.toggleRealtime();
    expect(rec.realtime).toBe(false);
    expect(unlisten).toHaveBeenCalledTimes(1);
    handler?.();
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(refreshRecords).toHaveBeenCalledTimes(1);

    rec.dispose();
    expect(unlisten).toHaveBeenCalledTimes(1);
  });

  test('real-time refresh failures do not toast', async () => {
    let handler = null as (() => void) | null;
    const { rec, toasts } = workspace({
      refreshRecords: mock(async () => {
        throw new Error('offline');
      }),
      subscribeTraffic: async (next) => {
        handler = next;
        return () => {};
      },
    });
    rec.recordsLoading = false;
    rec.toggleRealtime();
    await new Promise((resolve) => setTimeout(resolve, 0));
    handler?.();
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(rec.realtime).toBe(true);
    expect(toasts).toEqual([]);
    rec.dispose();
  });

  test('marks newly arrived records for the entrance animation', async () => {
    const rows: ConnectionLog[] = [log({ id: 1, domain: 'a.example' })];
    const { rec } = workspace({ logs: rows });
    rec.recordsLoading = false;
    await rec.load('url-change');

    const arrival = log({ id: 2, domain: 'b.example', timestamp: 9, lastSeen: 9 });
    rows.unshift(arrival);
    await rec.load('realtime', undefined, { silent: true });

    expect(rec.newRecordKeys.has(recordsLogItemKey(arrival))).toBe(true);
    expect(rec.newRecordKeys.size).toBe(1);
    rec.dispose();
  });

  test('highlights the newest twin when an identical flow arrives', async () => {
    // Unpersisted realtime rows (id 0) share the content identity, which is
    // the population the dedupe backstop exists for; persisted rows key by id.
    const twin = () =>
      log({
        id: 0,
        applicationName: 'gh.exe',
        applicationPath: 'C:\\Program Files\\GitHub CLI\\gh.exe',
        domain: 'api.github.com',
        sourceIp: '192.168.68.58',
        destinationIp: '172.182.252.137',
        port: 443,
        protocol: 'TCP',
        action: 'ALLOWED',
        timestamp: 1_789_644_578,
      });
    const rows: ConnectionLog[] = [twin(), twin()];
    const { rec } = workspace({ logs: rows });
    rec.recordsLoading = false;
    await rec.load('url-change');
    expect(rec.newRecordKeys.size).toBe(0);

    rows.unshift(twin());
    await rec.load('realtime', undefined, { silent: true });

    // The new row sorts newest-first to the top and keeps the bare base key;
    // a naive Set diff would have flagged the oldest twin instead.
    expect(rec.newRecordKeys.has(recordsLogItemKey(twin()))).toBe(true);
    expect(rec.newRecordKeys.size).toBe(1);
    rec.dispose();
  });
});
