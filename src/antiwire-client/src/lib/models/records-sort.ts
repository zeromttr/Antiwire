export type RecordsSortKey =
  'app' | 'host' | 'sip' | 'ip' | 'port' | 'proto' | 'state' | 'up' | 'down' | 'lastSeen' | 'geo';

const SORT_KEY_TO_ORDER_BY: Record<RecordsSortKey, string> = {
  app: 'app',
  host: 'domain',
  sip: 'src',
  ip: 'dst',
  port: 'port',
  proto: 'protocol',
  state: 'action',
  up: 'bytes_sent',
  down: 'bytes_received',
  lastSeen: 'last_seen',
  geo: 'country',
};

export function sortKeyToOrderBy(sortKey: RecordsSortKey | null): string {
  if (!sortKey) return 'last_seen';
  return SORT_KEY_TO_ORDER_BY[sortKey];
}

export function sortDirToDescending(sortKey: RecordsSortKey | null, sortDir: 1 | -1): boolean {
  if (!sortKey) return true;
  return sortDir === -1;
}

export function protocolFilterValue(proto: string): string | undefined {
  const normalized = proto.trim().toUpperCase();
  if (!normalized || normalized === 'ALL') return undefined;
  return normalized;
}
