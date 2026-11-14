import { beforeAll, describe, expect, test } from 'bun:test';
import type { AppSummary, ConnectionLog } from '#lib/types/index.ts';
import { loadMessages, m } from '#lib/i18n/messages.ts';
import {
  recordActionLabel,
  RECORDS_PAGE_SIZE,
  appMatchKey,
  buildRecordsAppList,
  liveAppIndex,
  recordsAppFilterCounts,
  shortPath,
  canPageBack,
  canPageForward,
  destinationIpTooltip,
  nextRecordsSort,
  recordsAppItemKey,
  recordsColumnDefs,
  recordsGrandTotal,
  recordsHref,
  recordsLogItemKey,
  recordsLogKeys,
  recordsNoAppMatch,
  recordsRefreshOptions,
  recordsScopeStats,
  recordBlocklistTooltip,
  recordsStateStyle,
  recordsVisibleEnd,
  recordsUrlFilters,
  recordsUrlLoadKey,
  serverActionFilter,
  shouldRefreshSummaries,
} from './records-list';

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
    sourceIp: '192.168.1.10',
    sourcePort: 0,
    destinationIp: '1.1.1.1',
    port: 443,
    protocol: 'TCP',
    action: 'Allowed',
    bytesSent: 10,
    bytesReceived: 20,
    timestamp: 1_700_000_000,
    lastSeen: 1_700_000_100,
    closedAt: 0,
    countryCode: 'US',
    blocklistNames: [],
    ...overrides,
  };
}

beforeAll(async () => {
  await loadMessages('en');
});

describe('recordsUrlFilters', () => {
  test('reads app and a complete time window from the query string', () => {
    expect(recordsUrlFilters('?app=Chrome&from=100&to=200')).toEqual({
      application: 'Chrome',
      applicationId: undefined,
      timeWindowStart: 100,
      timeWindowEnd: 200,
    });
  });

  test('reads an exact application id alongside the name', () => {
    expect(recordsUrlFilters('?app=Chrome&appid=7')).toEqual({
      application: 'Chrome',
      applicationId: 7,
      timeWindowStart: undefined,
      timeWindowEnd: undefined,
    });
  });

  test('ignores a partial time window and an empty app', () => {
    expect(recordsUrlFilters('?app=&from=100')).toEqual({
      application: undefined,
      applicationId: undefined,
      timeWindowStart: undefined,
      timeWindowEnd: undefined,
    });
  });
});

describe('recordsHref', () => {
  test('omits ALL and an incomplete window', () => {
    expect(recordsHref('ALL')).toBe('/records');
    expect(recordsHref('Chrome', 10)).toBe('/records?app=Chrome');
    expect(recordsHref('Chrome', 10, 20)).toBe('/records?app=Chrome&from=10&to=20');
  });

  test('carries the exact application id for a path selection', () => {
    expect(recordsHref('Chrome', undefined, undefined, 7)).toBe('/records?app=Chrome&appid=7');
    expect(recordsHref('ALL', undefined, undefined, undefined)).toBe('/records');
  });
});

describe('recordsUrlLoadKey', () => {
  test('includes the raw search plus normalized filters', () => {
    expect(recordsUrlLoadKey('?app=Chrome&from=1&to=2')).toBe(
      '?app=Chrome&from=1&to=2|Chrome||1|2',
    );
    expect(recordsUrlLoadKey('')).toBe('||||');
  });

  test('distinguishes two install paths sharing one name', () => {
    expect(recordsUrlLoadKey('?app=Chrome&appid=7')).not.toBe(recordsUrlLoadKey('?app=Chrome'));
  });
});

describe('serverActionFilter', () => {
  test('maps the verdict control to the daemon action filter', () => {
    expect(serverActionFilter('all')).toBeUndefined();
    expect(serverActionFilter('allowed')).toBe('Allowed');
    expect(serverActionFilter('blocked')).toBe('Blocked');
  });
});

describe('recordsRefreshOptions', () => {
  test('uses page state when no URL search is supplied', () => {
    expect(
      recordsRefreshOptions({
        verdict: 'blocked',
        pageOffset: 200,
        selectedApp: 'Chrome',
        selectedAppId: 7,
        filter: ' ads ',
        sortKey: 'port',
        sortDir: 1,
        proto: 'tcp',
        timeWindowStart: 10,
        timeWindowEnd: 20,
      }),
    ).toEqual({
      actionFilter: 'Blocked',
      offset: 200,
      limit: RECORDS_PAGE_SIZE,
      applicationName: 'Chrome',
      applicationId: 7,
      searchQuery: 'ads',
      orderBy: 'port',
      sortDescending: false,
      protocolFilter: 'TCP',
      timeWindowStart: 10,
      timeWindowEnd: 20,
      countryFilter: undefined,
      portFilter: undefined,
      hostFilter: undefined,
    });
  });

  test('lets the URL override the selected app and time window', () => {
    const options = recordsRefreshOptions({
      verdict: 'all',
      pageOffset: 0,
      selectedApp: 'Chrome',
      filter: '',
      sortKey: null,
      sortDir: -1,
      proto: 'ALL',
      timeWindowStart: 1,
      timeWindowEnd: 2,
      urlSearch: '?app=Edge&from=8&to=9',
    });
    expect(options.applicationName).toBe('Edge');
    expect(options.timeWindowStart).toBe(8);
    expect(options.timeWindowEnd).toBe(9);
    expect(options.searchQuery).toBeUndefined();
    expect(options.protocolFilter).toBeUndefined();
    expect(options.orderBy).toBe('last_seen');
    expect(options.sortDescending).toBe(true);
  });

  test('drops ALL as an application name', () => {
    expect(
      recordsRefreshOptions({
        verdict: 'all',
        pageOffset: 0,
        selectedApp: 'ALL',
        filter: '',
        sortKey: null,
        sortDir: -1,
        proto: 'ALL',
      }).applicationName,
    ).toBeUndefined();
  });

  test('lets the URL application id override page state', () => {
    const options = recordsRefreshOptions({
      verdict: 'all',
      pageOffset: 0,
      selectedApp: 'Chrome',
      selectedAppId: 3,
      filter: '',
      sortKey: null,
      sortDir: -1,
      proto: 'ALL',
      urlSearch: '?app=Chrome&appid=9',
    });
    expect(options.applicationName).toBe('Chrome');
    expect(options.applicationId).toBe(9);
  });
});

describe('records applications panel', () => {
  const live = liveAppIndex([
    {
      name: 'Edge',
      path: 'C:\\APPS\\edge.exe',
      connections: 3,
      downloadRate: 900,
      uploadRate: 100,
    },
    {
      name: 'Slack',
      path: 'C:\\Apps\\slack.exe',
      connections: 1,
      downloadRate: 5_000,
      uploadRate: 0,
    },
  ]);
  const apps = [
    summary({ applicationName: 'Edge', applicationPath: 'C:\\Apps\\edge.exe', connectionCount: 9 }),
    summary({
      applicationName: 'Slack',
      applicationPath: 'C:\\Apps\\slack.exe',
      connectionCount: 2,
      blockedCount: 1,
    }),
    summary({ applicationName: 'Idle', applicationPath: 'C:\\Apps\\idle.exe', connectionCount: 5 }),
  ];
  const build = (filter: 'all' | 'live' | 'blocked', query = '') =>
    buildRecordsAppList(apps, {
      query,
      selectedApp: 'ALL',
      allLabel: 'All applications',
      grandTotal: 16,
      filter,
      live,
    });

  test('joins live data by install path, ignoring case', () => {
    expect(appMatchKey('C:\\Apps\\Edge.exe', 'Edge')).toBe(appMatchKey('c:\\apps\\edge.exe', 'x'));
    const rows = build('all');
    expect(rows.find((row) => row.name === 'Edge')?.live).toEqual({
      connections: 3,
      downloadRate: 900,
      uploadRate: 100,
    });
    expect(rows.find((row) => row.name === 'Idle')?.live).toBeNull();
    expect(rows.find((row) => row.name === 'Slack')?.blocked).toBe(1);
  });

  test('filters to live or blocked applications and keeps All pinned', () => {
    // Live sorts by open connections: Edge (3) before Slack (1), whatever the rates.
    expect(build('live').map((row) => row.value)).toEqual(['ALL', 'Edge', 'Slack']);
    expect(build('blocked').map((row) => row.value)).toEqual(['ALL', 'Slack']);
    expect(build('all').map((row) => row.value)).toEqual(['ALL', 'Edge', 'Idle', 'Slack']);
    expect(build('live', 'edge').map((row) => row.value)).toEqual(['ALL', 'Edge']);
  });

  test('shortens install paths to their last two segments', () => {
    expect(shortPath('C:\\Program Files\\Cloud Sync\\sync.exe')).toBe('…\\Cloud Sync\\sync.exe');
    expect(shortPath('/usr/lib/firefox/firefox')).toBe('…/firefox/firefox');
    expect(shortPath('C:\\app.exe')).toBe('C:\\app.exe');
  });

  test('counts what each filter would list', () => {
    expect(recordsAppFilterCounts(apps, live)).toEqual({ all: 3, live: 2, blocked: 1 });
    expect(recordsAppFilterCounts(apps)).toEqual({ all: 3, live: 0, blocked: 1 });
  });
});

describe('buildRecordsAppList', () => {
  test('puts All first and sorts apps by connection count', () => {
    const rows = buildRecordsAppList(
      [
        summary({ applicationName: 'Small', connectionCount: 1 }),
        summary({ applicationName: 'Big', connectionCount: 9 }),
      ],
      { query: '', selectedApp: 'ALL', allLabel: 'All applications', grandTotal: 10 },
    );
    expect(rows.map((row) => row.value)).toEqual(['ALL', 'Big', 'Small']);
    expect(rows[0]).toMatchObject({
      name: 'All applications',
      count: 10,
      selected: true,
      isAll: true,
      key: 'ALL',
    });
    expect(rows[1]?.selected).toBe(false);
  });

  test('filters by name or path and marks the selected app', () => {
    const rows = buildRecordsAppList(
      [
        summary({ applicationName: 'Chrome' }),
        summary({
          applicationName: 'Edge',
          applicationPath: 'C:\\Apps\\edge.exe',
          connectionCount: 1,
        }),
      ],
      { query: 'edge', selectedApp: 'Edge', allLabel: 'All applications', grandTotal: 5 },
    );
    expect(rows.map((row) => row.value)).toEqual(['ALL', 'Edge']);
    expect(rows[1]).toMatchObject({ selected: true, path: 'C:\\Apps\\edge.exe' });
  });

  test('carries the row id and highlights only the exact install path', () => {
    const rows = buildRecordsAppList(
      [
        summary({ applicationId: 2, applicationName: 'Tool', applicationPath: 'C:\\a.exe' }),
        summary({ applicationId: 9, applicationName: 'Tool', applicationPath: 'C:\\b.exe' }),
      ],
      {
        query: '',
        selectedApp: 'Tool',
        selectedAppId: 9,
        allLabel: 'All applications',
        grandTotal: 11,
      },
    );
    expect(rows.map((row) => row.appId)).toEqual([0, 2, 9]);
    expect(rows[1]?.selected).toBe(false);
    expect(rows[2]?.selected).toBe(true);
  });
});

describe('recordsGrandTotal', () => {
  test('prefers summary counts and falls back to the log total', () => {
    expect(recordsGrandTotal([summary({ connectionCount: 3 })], 99)).toBe(3);
    expect(recordsGrandTotal([], 99)).toBe(99);
  });
});

describe('records list keys', () => {
  test('app keys use the row key and log keys ignore live counters', () => {
    expect(recordsAppItemKey({ key: 'Chrome::C:\\a.exe' })).toBe('Chrome::C:\\a.exe');
    const a = recordsLogItemKey(log({ id: 0, bytesSent: 1, lastSeen: 10 }));
    const b = recordsLogItemKey(log({ id: 0, bytesSent: 99, lastSeen: 99 }));
    expect(a).toBe(b);
    expect(a).toContain('Chrome');
    expect(a).toContain('1.1.1.1');
  });

  test('deduped log keys stay unique for identical parallel flows', () => {
    // Two gh.exe HTTPS flows to the same destination in the same second share
    // the base identity; the keyed each block crashed on these duplicates.
    // Unpersisted realtime rows (id 0) still use the content identity, so the
    // dedupe backstop covers them; persisted rows key by database id (below).
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
    const keys = recordsLogKeys([twin(), twin(), log({ id: 0 })]);
    expect(new Set(keys).size).toBe(keys.length);
    // The common no-duplicate case keeps the bare base key (stable identity).
    expect(keys[0]).toBe(recordsLogItemKey(twin()));
    expect(keys[2]).toBe(recordsLogItemKey(log({ id: 0 })));
  });

  test('deduped log keys ignore live counters', () => {
    const a = recordsLogKeys([log({ id: 0, bytesSent: 1, lastSeen: 10 })]);
    const b = recordsLogKeys([log({ id: 0, bytesSent: 99, lastSeen: 99 })]);
    expect(a).toEqual(b);
  });

  test('persisted rows key by database id even when every content field matches', () => {
    const a = recordsLogItemKey(log({ id: 8 }));
    const b = recordsLogItemKey(log({ id: 9 }));
    expect(a).not.toBe(b);
    // Repeat sightings of one row keep one key across live updates.
    expect(recordsLogItemKey(log({ id: 8, bytesSent: 1, lastSeen: 10 }))).toBe(a);
    expect(recordsLogItemKey(log({ id: 8, bytesSent: 99, lastSeen: 99 }))).toBe(a);
  });
});

describe('recordsStateStyle', () => {
  test('colors blocked, listen, and allowed actions', () => {
    expect(recordsStateStyle(log({ action: 'BLOCK' })).fg).toBe('var(--bad)');
    expect(recordsStateStyle(log({ action: 'Listen' })).fg).toBe('var(--warn)');
    expect(recordsStateStyle(log({ action: 'Allowed' })).fg).toBe('var(--ok)');
  });
});

describe('destinationIpTooltip', () => {
  test('appends the country when both are present', () => {
    expect(destinationIpTooltip(log())).toBe('1.1.1.1 · US');
    expect(destinationIpTooltip(log({ countryCode: '' }))).toBe('1.1.1.1');
    expect(destinationIpTooltip(log({ destinationIp: '' }))).toBe('');
  });
});

describe('recordBlocklistTooltip', () => {
  test('shows matching lists only on blocked rows', () => {
    expect(recordBlocklistTooltip(log({ blocklistNames: ['hagezi_light'] }))).toBe('');
    expect(
      recordBlocklistTooltip(log({ action: 'Blocked', blocklistNames: ['hagezi_light'] })),
    ).toBe(m.settings_blocklist_hagezi_light_name());
    expect(recordBlocklistTooltip(log({ action: 'Blocked' }))).toBe('');
  });
});

describe('nextRecordsSort', () => {
  test('cycles a column from default desc to asc to unsorted', () => {
    expect(nextRecordsSort(null, -1, 'port')).toEqual({ sortKey: 'port', sortDir: -1 });
    expect(nextRecordsSort('port', -1, 'port')).toEqual({ sortKey: 'port', sortDir: 1 });
    expect(nextRecordsSort('port', 1, 'port')).toEqual({ sortKey: null, sortDir: -1 });
    expect(nextRecordsSort('app', -1, 'port')).toEqual({ sortKey: 'port', sortDir: -1 });
  });
});

describe('records chrome helpers', () => {
  test('totals the selected scope from the application summaries', () => {
    const summaries = [
      summary({ connectionCount: 10, blockedCount: 3, bytesSent: 40, bytesReceived: 60 }),
      summary({
        applicationId: 2,
        applicationName: 'Tool',
        applicationPath: 'C:\\a.exe',
        connectionCount: 5,
        blockedCount: 5,
        bytesSent: 1,
        bytesReceived: 2,
      }),
      summary({
        applicationId: 9,
        applicationName: 'Tool',
        applicationPath: 'C:\\b.exe',
        connectionCount: 7,
        blockedCount: 0,
        bytesSent: 100,
        bytesReceived: 200,
      }),
    ];
    expect(recordsScopeStats(summaries, 'ALL')).toEqual({
      allowed: 14,
      blocked: 8,
      bytesSent: 141,
      bytesReceived: 262,
    });
    // A bare name covers every install path sharing it; an id selects one.
    expect(recordsScopeStats(summaries, 'Tool')).toEqual({
      allowed: 7,
      blocked: 5,
      bytesSent: 101,
      bytesReceived: 202,
    });
    expect(recordsScopeStats(summaries, 'Tool', 9)).toEqual({
      allowed: 7,
      blocked: 0,
      bytesSent: 100,
      bytesReceived: 200,
    });
    expect(recordsScopeStats(summaries, 'Missing')).toEqual({
      allowed: 0,
      blocked: 0,
      bytesSent: 0,
      bytesReceived: 0,
    });
  });

  test('derive empty-search and pager state', () => {
    expect(recordsNoAppMatch('zz', 1)).toBe(true);
    expect(recordsNoAppMatch('', 1)).toBe(false);
    expect(canPageBack(0)).toBe(false);
    expect(canPageBack(200)).toBe(true);
    expect(canPageForward(0, 50)).toBe(false);
    expect(canPageForward(0, 201)).toBe(true);
    expect(recordsVisibleEnd(200, 0)).toBe(0);
    expect(recordsVisibleEnd(200, 12)).toBe(212);
  });

  test('refreshes app summaries only for url, time, and manual loads', () => {
    expect(shouldRefreshSummaries('url-change')).toBe(true);
    expect(shouldRefreshSummaries('manual-refresh')).toBe(true);
    expect(shouldRefreshSummaries('time-clear')).toBe(true);
    expect(shouldRefreshSummaries('filter-change')).toBe(false);
  });

  test('exposes the condensed sortable columns', () => {
    const cols = recordsColumnDefs();
    expect(cols.map((col) => col.key)).toEqual(['app', 'host', 'port', 'up', 'down', 'lastSeen']);
    expect(cols[0]?.label).toBe(m.records_col_application());
    expect(cols.find((col) => col.key === 'up')?.just).toBe('flex-end');
  });

  test('drops the application column while one application is selected', () => {
    expect(recordsColumnDefs(false).map((col) => col.key)).toEqual([
      'host',
      'port',
      'up',
      'down',
      'lastSeen',
    ]);
  });
});

describe('recordActionLabel', () => {
  test('sentence-cases daemon actions', () => {
    expect(recordActionLabel('ALLOW')).toBe('Allow');
    expect(recordActionLabel('BLOCK')).toBe('Block');
    expect(recordActionLabel('listen')).toBe('Listen');
    expect(recordActionLabel('')).toBe('');
  });
});
