import { describe, expect, it } from 'bun:test';
import type { AppSummary, ConnectionLog, Rule, Stats } from '#lib/types/index.ts';
import {
  normalizeAppSummary,
  normalizeConnectionLog,
  normalizeCountryRule,
  normalizeCountryStatistics,
  normalizeRule,
  normalizeStats,
} from './normalize';

describe('normalizeCountryStatistics', () => {
  it('uses database totals including countries outside the recent sample', () => {
    const expected = {
      countryCounts: { US: 301, IN: 1 },
      totalCount: 305,
      unknownCount: 3,
      unknownPct: 1,
    };
    expect(
      normalizeCountryStatistics({
        countryCounts: { US: 301, IN: 1 },
        totalCount: 305,
        unknownCount: 3,
      }),
    ).toEqual(expected);
    expect(
      normalizeCountryStatistics({
        country_counts: { US: '301', IN: '1' },
        total_count: '305',
        unknown_count: '3',
      }),
    ).toEqual(expected);
  });
  it('handles an empty database without invalid percentages', () => {
    expect(
      normalizeCountryStatistics({ countryCounts: {}, totalCount: 0, unknownCount: 0 }),
    ).toEqual({
      countryCounts: {},
      totalCount: 0,
      unknownCount: 0,
      unknownPct: 0,
    });
  });
});

describe('normalizeRule', () => {
  it('accepts camelCase daemon payloads', () => {
    expect(
      normalizeRule({
        id: 1,
        targetType: 'APPLICATION',
        targetValue: 'chrome.exe',
        action: 'BLOCK',
        direction: 'BOTH',
      }),
    ).toEqual({
      id: 1,
      targetType: 'APPLICATION',
      targetValue: 'chrome.exe',
      action: 'BLOCK',
      direction: 'BOTH',
    });
  });

  it('defaults missing or unknown directions to outbound', () => {
    const legacy = normalizeRule({
      id: 3,
      targetType: 'IP',
      targetValue: '10.0.0.1/32',
      action: 'BLOCK',
    } as unknown as unknown as Rule & Record<string, unknown>);
    expect(legacy.direction).toBe('OUTBOUND');

    const bogus = normalizeRule({
      id: 4,
      targetType: 'IP',
      targetValue: '10.0.0.2/32',
      action: 'BLOCK',
      direction: 'sideways',
    } as unknown as unknown as Rule & Record<string, unknown>);
    expect(bogus.direction).toBe('OUTBOUND');
  });

  it('accepts lowercase directions from the daemon', () => {
    const rule = normalizeRule({
      id: 5,
      targetType: 'DNS',
      targetValue: 'ads.example.com',
      action: 'BLOCK',
      direction: 'inbound',
    } as unknown as unknown as Rule & Record<string, unknown>);
    expect(rule.direction).toBe('INBOUND');
  });

  it('accepts snake_case daemon payloads without throwing', () => {
    const rule = normalizeRule({
      id: 2,
      target_type: 'DNS',
      target_value: 'ads.example.com',
      action: 'ALLOW',
    } as unknown as Rule & Record<string, unknown>);

    expect(rule.targetType).toBe('DNS');
    expect(rule.targetValue).toBe('ads.example.com');
    expect(() => rule.targetType.toUpperCase()).not.toThrow();
  });
});

describe('normalizeAppSummary', () => {
  it('accepts snake_case daemon payloads', () => {
    expect(
      normalizeAppSummary({
        application_id: 7,
        application_name: 'Chrome',
        application_path: 'C:\\Chrome\\chrome.exe',
        connection_count: 12,
        blocked_count: 1,
        total_bytes: 4096,
        bytes_sent: 1024,
        bytes_received: 3072,
      } as unknown as AppSummary & Record<string, unknown>),
    ).toEqual({
      applicationId: 7,
      applicationName: 'Chrome',
      applicationPath: 'C:\\Chrome\\chrome.exe',
      connectionCount: 12,
      blockedCount: 1,
      totalBytes: 4096,
      bytesSent: 1024,
      bytesReceived: 3072,
    });
  });
});

describe('normalizeStats collector health', () => {
  const base = {
    bytesSent: 1,
    bytesReceived: 2,
    activeConnections: 3,
    blockedConnections: 4,
  } as Stats & Record<string, unknown>;

  it('treats a daemon that omits the field as healthy', () => {
    // An older daemon cannot report collector health; a version mismatch must not raise a
    // false warning in the UI.
    const stats = normalizeStats({ ...base });
    expect(stats.byteAccountingAvailable).toBe(true);
    expect(stats.collectorStatusDetail).toBe('');
    expect(stats.activeConnectionsAvailable).toBe(true);
    expect(stats.activeConnectionsStale).toBe(false);
  });

  it('treats an old-format stats response as a usable socket count', () => {
    const stats = normalizeStats({
      bytesSent: 1,
      bytesReceived: 2,
      activeConnections: 9,
      blockedConnections: 4,
    } as Stats & Record<string, unknown>);
    expect(stats.activeConnections).toBe(9);
    expect(stats.activeConnectionsAvailable).toBe(true);
    expect(stats.activeConnectionsStale).toBe(false);
    expect(stats.activeApplications).toBeNull();
    expect(stats.databaseSizeBytes).toBeNull();
  });

  it('reads the database size in either casing and rejects junk', () => {
    expect(normalizeStats({ ...base, databaseSizeBytes: 8192 }).databaseSizeBytes).toBe(8192);
    expect(
      normalizeStats({ ...base, database_size_bytes: 512 } as Stats & Record<string, unknown>)
        .databaseSizeBytes,
    ).toBe(512);
    expect(
      normalizeStats({ ...base, databaseSizeBytes: -1 } as Stats & Record<string, unknown>)
        .databaseSizeBytes,
    ).toBeNull();
  });

  it('reads the application count in either casing and rejects junk', () => {
    expect(normalizeStats({ ...base, activeApplications: 6 }).activeApplications).toBe(6);
    expect(
      normalizeStats({ ...base, active_applications: 3 } as Stats & Record<string, unknown>)
        .activeApplications,
    ).toBe(3);
    expect(normalizeStats({ ...base, activeApplications: 0 }).activeApplications).toBe(0);
    expect(
      normalizeStats({ ...base, activeApplications: -1 } as Stats & Record<string, unknown>)
        .activeApplications,
    ).toBeNull();
    expect(
      normalizeStats({ ...base, activeApplications: 'x' } as unknown as Stats &
        Record<string, unknown>).activeApplications,
    ).toBeNull();
  });

  it('carries a degraded collector through with its explanation', () => {
    const stats = normalizeStats({
      ...base,
      byteAccountingAvailable: false,
      collectorStatusDetail: 'Run as Administrator',
    } as Stats & Record<string, unknown>);
    expect(stats.byteAccountingAvailable).toBe(false);
    expect(stats.collectorStatusDetail).toBe('Run as Administrator');
  });

  it('carries an unavailable socket count through instead of inventing a valid zero', () => {
    const stats = normalizeStats({
      ...base,
      activeConnections: 0,
      activeConnectionsAvailable: false,
    } as Stats & Record<string, unknown>);
    expect(stats.activeConnections).toBe(0);
    expect(stats.activeConnectionsAvailable).toBe(false);
    expect(stats.activeConnectionsStale).toBe(false);
  });

  it('marks a retained last-known socket count as stale', () => {
    const stats = normalizeStats({
      ...base,
      activeConnections: 7,
      activeConnectionsAvailable: true,
      activeConnectionsStale: true,
    } as Stats & Record<string, unknown>);
    expect(stats.activeConnections).toBe(7);
    expect(stats.activeConnectionsAvailable).toBe(true);
    expect(stats.activeConnectionsStale).toBe(true);
  });

  it('treats a missing payload as an unavailable collector', () => {
    expect(normalizeStats(null).byteAccountingAvailable).toBe(false);
    expect(normalizeStats(undefined).byteAccountingAvailable).toBe(false);
    expect(
      normalizeStats([] as unknown as Stats & Record<string, unknown>).byteAccountingAvailable,
    ).toBe(false);
    expect(normalizeStats(null).activeConnectionsAvailable).toBe(false);
    expect(normalizeStats(undefined).activeConnectionsAvailable).toBe(false);
  });

  it('accepts snake_case daemon payloads', () => {
    const stats = normalizeStats({
      ...base,
      byte_accounting_available: false,
      collector_status_detail: 'snapshot only',
      active_connections_available: false,
    } as unknown as Stats & Record<string, unknown>);
    expect(stats.byteAccountingAvailable).toBe(false);
    expect(stats.collectorStatusDetail).toBe('snapshot only');
    expect(stats.activeConnectionsAvailable).toBe(false);
  });
});

describe('normalize crash safety on null/undefined payloads', () => {
  it('handles null and undefined gracefully without throwing', () => {
    expect(normalizeRule(null)).toEqual({
      id: 0,
      targetType: '',
      targetValue: '',
      action: '',
      direction: 'OUTBOUND',
    });
    expect(normalizeRule(undefined)).toEqual({
      id: 0,
      targetType: '',
      targetValue: '',
      action: '',
      direction: 'OUTBOUND',
    });

    expect(normalizeCountryRule(null)).toEqual({
      id: 0,
      countryCode: '',
      action: 'BLOCK',
      direction: 'OUTBOUND',
      cidrCount: 0,
    });
    expect(normalizeCountryRule(undefined)).toEqual({
      id: 0,
      countryCode: '',
      action: 'BLOCK',
      direction: 'OUTBOUND',
      cidrCount: 0,
    });

    expect(normalizeAppSummary(null)).toEqual({
      applicationId: 0,
      applicationName: '',
      applicationPath: '',
      connectionCount: 0,
      blockedCount: 0,
      totalBytes: 0,
      bytesSent: 0,
      bytesReceived: 0,
    });
    expect(normalizeAppSummary(undefined)).toEqual({
      applicationId: 0,
      applicationName: '',
      applicationPath: '',
      connectionCount: 0,
      blockedCount: 0,
      totalBytes: 0,
      bytesSent: 0,
      bytesReceived: 0,
    });

    expect(normalizeConnectionLog(null)).toEqual({
      id: 0,
      closedAt: 0,
      isActive: false,
      applicationName: '',
      applicationPath: '',
      domain: '',
      sourceIp: '',
      sourcePort: 0,
      destinationIp: '',
      port: 0,
      protocol: '',
      action: '',
      bytesSent: 0,
      bytesReceived: 0,
      timestamp: 0,
      lastSeen: 0,
      countryCode: '',
      blocklistNames: [],
    });
    expect(normalizeConnectionLog(undefined)).toEqual({
      id: 0,
      closedAt: 0,
      isActive: false,
      applicationName: '',
      applicationPath: '',
      domain: '',
      sourceIp: '',
      sourcePort: 0,
      destinationIp: '',
      port: 0,
      protocol: '',
      action: '',
      bytesSent: 0,
      bytesReceived: 0,
      timestamp: 0,
      lastSeen: 0,
      countryCode: '',
      blocklistNames: [],
    });

    expect(normalizeStats(null)).toEqual({
      bytesSent: 0,
      bytesReceived: 0,
      activeConnections: 0,
      blockedConnections: 0,
      byteAccountingAvailable: false,
      collectorStatusDetail: '',
      activeConnectionsAvailable: false,
      activeConnectionsStale: false,
      activeApplications: null,
      databaseSizeBytes: null,
    });
    expect(normalizeStats(undefined)).toEqual({
      bytesSent: 0,
      bytesReceived: 0,
      activeConnections: 0,
      blockedConnections: 0,
      byteAccountingAvailable: false,
      collectorStatusDetail: '',
      activeConnectionsAvailable: false,
      activeConnectionsStale: false,
      activeApplications: null,
      databaseSizeBytes: null,
    });
  });
});

describe('normalizeConnectionLog blocklist names', () => {
  it('accepts camelCase arrays, snake_case arrays, and newline-separated strings', () => {
    expect(
      normalizeConnectionLog({
        blocklistNames: ['hagezi_light', '  hagezi_tif  ', ''],
      } as unknown as ConnectionLog & Record<string, unknown>).blocklistNames,
    ).toEqual(['hagezi_light', 'hagezi_tif']);

    expect(
      normalizeConnectionLog({
        blocklist_names: ['hagezi_light'],
      } as unknown as ConnectionLog & Record<string, unknown>).blocklistNames,
    ).toEqual(['hagezi_light']);

    expect(
      normalizeConnectionLog({
        blocklist_names: 'hagezi_light\nhagezi_tif\n',
      } as unknown as ConnectionLog & Record<string, unknown>).blocklistNames,
    ).toEqual(['hagezi_light', 'hagezi_tif']);
  });

  it('defaults missing names to an empty list', () => {
    expect(
      normalizeConnectionLog({} as unknown as ConnectionLog & Record<string, unknown>)
        .blocklistNames,
    ).toEqual([]);
  });

  it('maps the close time from either casing and defaults open rows to zero', () => {
    expect(
      normalizeConnectionLog({ closedAt: 42 } as unknown as ConnectionLog & Record<string, unknown>)
        .closedAt,
    ).toBe(42);
    expect(
      normalizeConnectionLog({ closed_at: 43 } as unknown as ConnectionLog &
        Record<string, unknown>).closedAt,
    ).toBe(43);
    expect(
      normalizeConnectionLog({} as unknown as ConnectionLog & Record<string, unknown>).closedAt,
    ).toBe(0);
  });
});
