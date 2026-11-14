import type { ConnectionLog } from '#lib/types/index.ts';

export interface RegionStats {
  countryCounts: Record<string, number>;
  unknownCount: number;
  totalCount: number;
  unknownPct: number;
}

export function isUnknownCountryCode(code: string | undefined | null): boolean {
  const normalized = code?.trim().toUpperCase() ?? '';
  return !normalized || normalized === '—' || normalized === '-' || normalized === 'OTHER';
}

export function computeRegionStats(logs: ConnectionLog[]): RegionStats {
  const countryCounts: Record<string, number> = {};
  let unknownCount = 0;

  for (const log of logs) {
    if (isUnknownCountryCode(log.countryCode)) {
      unknownCount += 1;
      continue;
    }
    const code = log.countryCode.trim().toUpperCase();
    countryCounts[code] = (countryCounts[code] || 0) + 1;
  }

  const totalCount = logs.length;
  const unknownPct = totalCount ? Math.round((unknownCount / totalCount) * 100) : 0;

  return { countryCounts, unknownCount, totalCount, unknownPct };
}
