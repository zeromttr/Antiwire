import { describe, expect, it } from 'bun:test';
import type { ConnectionLog } from '#lib/types/index.ts';
import { computeRegionStats } from './region-stats';

function log(countryCode: string): ConnectionLog {
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
    countryCode,
    blocklistNames: [],
  };
}

describe('computeRegionStats', () => {
  it('groups known countries and counts unknown destinations', () => {
    const stats = computeRegionStats([log('US'), log('US'), log('DE'), log(''), log('—')]);

    expect(stats.countryCounts).toEqual({ US: 2, DE: 1 });
    expect(stats.unknownCount).toBe(2);
    expect(stats.totalCount).toBe(5);
    expect(stats.unknownPct).toBe(40);
  });
});
