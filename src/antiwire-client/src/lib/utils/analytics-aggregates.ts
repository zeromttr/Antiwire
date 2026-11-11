import type { ConnectionLog } from '#lib/types/index.ts';
import { formatBytes, formatTimestamp } from './format';
import { m } from '#lib/i18n/messages.ts';
import { isUnknownCountryCode, type RegionStats } from './region-stats';
import { wellKnownPortName } from '#lib/models/well-known-ports.ts';

export interface AnalyticsHostRow {
  host: string;
  org: string;
  geo: string;
  sockets: number;
  total: number;
  totalLabel: string;
  pct: number;
  color: string;
  seen: string;
  rep: string;
  repFg: string;
  repBg: string;
}

export interface AnalyticsPortBar {
  label: string;
  count: number;
  h: number;
  /** Share of all sampled connections, 0–100. */
  share: number;
  /** Well-known service name (HTTPS, DNS…), empty when the port is unassigned. */
  service: string;
}

export interface AnalyticsDnsSummary {
  /** Lookups across every sampled domain, not just the listed top entries. */
  lookups: number;
  blocked: number;
}

export interface AnalyticsCountryShare {
  code: string;
  count: number;
  /** Share of connections with a known country, 0–100. */
  share: number;
}

export interface AnalyticsDnsEntry {
  name: string;
  q: number;
  verdict: string;
  color: string;
}

export interface AnalyticsAggregates {
  hosts: AnalyticsHostRow[];
  regionStats: RegionStats;
  ports: AnalyticsPortBar[];
  dnsEntries: AnalyticsDnsEntry[];
  dnsSummary: AnalyticsDnsSummary;
}

export const PORT_BAR_MAX_HEIGHT = 88;
const PORT_BAR_MIN_HEIGHT = 8;
const MAX_PORT_BARS = 10;
const MAX_DNS_ENTRIES = 8;

export function aggregateAnalyticsLogs(logs: ConnectionLog[]): AnalyticsAggregates {
  const hosts = new Map<string, AnalyticsHostRow>();
  const portCounts = new Map<number, number>();
  const dns = new Map<string, { q: number; blocked: boolean }>();
  const countryCounts: Record<string, number> = {};
  let unknownCount = 0;

  for (const log of logs) {
    const bytes = log.bytesSent + log.bytesReceived;
    const flagged = log.action.toLowerCase().includes('block');
    const hostKey = log.domain || log.destinationIp;
    const existingHost = hosts.get(hostKey);
    if (existingHost) {
      existingHost.sockets += 1;
      existingHost.total += bytes;
    } else {
      hosts.set(hostKey, {
        host: hostKey,
        org: log.domain ? m.analytics_org_resolved() : m.analytics_org_unattributed(),
        geo: log.countryCode || m.common_em_dash(),
        sockets: 1,
        total: bytes,
        totalLabel: '',
        pct: 0,
        color: flagged ? 'var(--bad)' : 'var(--acc)',
        seen: formatTimestamp(log.timestamp),
        rep: flagged ? m.analytics_rep_flagged() : m.analytics_rep_trusted(),
        repFg: flagged ? 'var(--bad)' : 'var(--ok)',
        repBg: flagged
          ? 'color-mix(in oklab, var(--bad) 13%, transparent)'
          : 'color-mix(in oklab, var(--ok) 12%, transparent)',
      });
    }

    portCounts.set(log.port, (portCounts.get(log.port) ?? 0) + 1);

    if (log.domain) {
      const existingDns = dns.get(log.domain);
      if (existingDns) {
        existingDns.q += 1;
        if (flagged) existingDns.blocked = true;
      } else {
        dns.set(log.domain, { q: 1, blocked: flagged });
      }
    }

    if (isUnknownCountryCode(log.countryCode)) {
      unknownCount += 1;
    } else {
      const code = log.countryCode.trim().toUpperCase();
      countryCounts[code] = (countryCounts[code] || 0) + 1;
    }
  }

  const hostRows = [...hosts.values()].sort((a, b) => b.total - a.total);
  const hostMax = Math.max(...hostRows.map((h) => h.total), 1);
  for (const host of hostRows) {
    host.pct = Math.round((host.total / hostMax) * 100);
    host.totalLabel = formatBytes(host.total);
  }

  const portEntries = [...portCounts.entries()].sort((a, b) => b[1] - a[1]).slice(0, MAX_PORT_BARS);
  const portMax = Math.max(...portEntries.map(([, count]) => count), 1);
  const ports = portEntries.map(([port, count]) => ({
    label: String(port),
    count,
    h: Math.max(PORT_BAR_MIN_HEIGHT, Math.round((count / portMax) * PORT_BAR_MAX_HEIGHT)),
    share: logs.length ? Math.round((count / logs.length) * 100) : 0,
    service: wellKnownPortName(port, '') ?? '',
  }));

  let lookups = 0;
  let blockedLookups = 0;
  for (const { q, blocked } of dns.values()) {
    lookups += q;
    if (blocked) blockedLookups += q;
  }

  const dnsEntries = [...dns.entries()]
    .sort((a, b) => b[1].q - a[1].q)
    .slice(0, MAX_DNS_ENTRIES)
    .map(([name, { q, blocked }]) => ({
      name,
      q,
      verdict: blocked ? m.analytics_dns_blocked() : m.analytics_dns_resolved(),
      color: blocked ? 'var(--bad)' : 'var(--ok)',
    }));

  const totalCount = logs.length;
  const regionStats: RegionStats = {
    countryCounts,
    unknownCount,
    totalCount,
    unknownPct: totalCount ? Math.round((unknownCount / totalCount) * 100) : 0,
  };

  return {
    hosts: hostRows,
    regionStats,
    ports,
    dnsEntries,
    dnsSummary: { lookups, blocked: blockedLookups },
  };
}

/** Every country ranked by connection count, with its share of the known total. */
export function topCountries(stats: RegionStats): AnalyticsCountryShare[] {
  const known = stats.totalCount - stats.unknownCount;
  return Object.entries(stats.countryCounts)
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .map(([code, count]) => ({
      code,
      count,
      share: known > 0 ? (count / known) * 100 : 0,
    }));
}
