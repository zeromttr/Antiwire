import { describe, expect, it } from 'bun:test';
import type { ConnectionLog } from '#lib/types/index.ts';
import { aggregateAnalyticsLogs, topCountries } from './analytics-aggregates';
import { computeRegionStats } from './region-stats';
import { formatBytes, formatTimestamp } from './format';

function log(partial: Partial<ConnectionLog>): ConnectionLog {
  return {
    id: 1,
    applicationName: 'app',
    applicationPath: '',
    domain: '',
    sourceIp: '10.0.0.1',
    sourcePort: 0,
    destinationIp: '1.1.1.1',
    port: 443,
    protocol: 'TCP',
    action: 'Allowed',
    bytesSent: 0,
    bytesReceived: 0,
    timestamp: 0,
    lastSeen: 0,
    closedAt: 0,
    countryCode: '',
    blocklistNames: [],
    ...partial,
  };
}

describe('aggregateAnalyticsLogs', () => {
  it('builds hosts, ports, dns, and region stats in one pass', () => {
    const logs = [
      log({
        domain: 'a.example',
        destinationIp: '1.1.1.1',
        port: 443,
        bytesSent: 100,
        bytesReceived: 50,
        timestamp: 1_700_000_000,
        countryCode: 'US',
      }),
      log({
        domain: 'a.example',
        destinationIp: '1.1.1.1',
        port: 443,
        action: 'Blocked',
        bytesSent: 20,
        bytesReceived: 10,
        timestamp: 1_700_000_100,
        countryCode: 'us',
      }),
      log({
        destinationIp: '8.8.8.8',
        port: 53,
        bytesSent: 4,
        bytesReceived: 8,
        timestamp: 1_700_000_200,
        countryCode: 'DE',
      }),
      log({
        domain: 'b.example',
        destinationIp: '9.9.9.9',
        port: 80,
        bytesSent: 1,
        bytesReceived: 1,
        timestamp: 1_700_000_300,
        countryCode: '',
      }),
      log({
        destinationIp: '9.9.9.10',
        port: 80,
        bytesSent: 0,
        bytesReceived: 0,
        timestamp: 1_700_000_400,
        countryCode: '—',
      }),
    ];

    const aggregates = aggregateAnalyticsLogs(logs);

    expect(aggregates.regionStats).toEqual(computeRegionStats(logs));

    expect(aggregates.hosts.map((row) => row.host)).toEqual([
      'a.example',
      '8.8.8.8',
      'b.example',
      '9.9.9.10',
    ]);
    expect(aggregates.hosts[0]).toMatchObject({
      sockets: 2,
      total: 180,
      totalLabel: formatBytes(180),
      pct: 100,
      color: 'var(--acc)',
      seen: formatTimestamp(1_700_000_000),
      geo: 'US',
    });

    expect(aggregates.ports).toEqual([
      { label: '443', count: 2, h: 88, share: 40, service: 'HTTPS' },
      { label: '80', count: 2, h: 88, share: 40, service: 'HTTP' },
      { label: '53', count: 1, h: 44, share: 20, service: 'DNS' },
    ]);

    expect(aggregates.dnsEntries).toEqual([
      {
        name: 'a.example',
        q: 2,
        verdict: 'Blocked',
        color: 'var(--bad)',
      },
      {
        name: 'b.example',
        q: 1,
        verdict: 'Resolved',
        color: 'var(--ok)',
      },
    ]);

    expect(aggregates.dnsSummary).toEqual({ lookups: 3, blocked: 2 });
  });

  it('ranks countries by count with their share of the known total', () => {
    const ranked = topCountries({
      countryCounts: { DE: 2, US: 5, JP: 2, NL: 1 },
      unknownCount: 3,
      totalCount: 13,
      unknownPct: 23,
    });
    expect(ranked).toEqual([
      { code: 'US', count: 5, share: 50 },
      { code: 'DE', count: 2, share: 20 },
      { code: 'JP', count: 2, share: 20 },
      { code: 'NL', count: 1, share: 10 },
    ]);
    expect(
      topCountries({ countryCounts: {}, unknownCount: 0, totalCount: 0, unknownPct: 0 }),
    ).toEqual([]);
  });

  it('includes every country rather than limiting the list to six', () => {
    const stats = {
      countryCounts: { US: 100, DE: 2, GB: 2, FR: 2, CA: 1, AU: 1, JP: 1, IN: 1 },
      unknownCount: 0,
      totalCount: 110,
      unknownPct: 0,
    };
    const countries = topCountries(stats);
    expect(countries).toHaveLength(8);
    expect(countries.find((country) => country.code === 'IN')?.count).toBe(1);
    expect(countries.find((country) => country.code === 'IN')?.share).toBeCloseTo(100 / 110);
  });

  it('returns empty collections for no logs', () => {
    expect(aggregateAnalyticsLogs([])).toEqual({
      hosts: [],
      regionStats: { countryCounts: {}, unknownCount: 0, totalCount: 0, unknownPct: 0 },
      ports: [],
      dnsEntries: [],
      dnsSummary: { lookups: 0, blocked: 0 },
    });
  });
});
