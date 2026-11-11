import { formatBlocklistNames } from '#lib/models/blocklists.ts';
import type { ConnectionLog } from '#lib/types/index.ts';

function firstNonEmpty(...values: string[]): string {
  for (const value of values) {
    const trimmed = value.trim();
    if (trimmed) return trimmed;
  }
  return '';
}

/** Headline for the record popup: domain first, then destination IP, then app. */
export function recordDetailTitle(record: ConnectionLog): string {
  return firstNonEmpty(record.domain, record.destinationIp, record.applicationName);
}

/** File name only, e.g. `brave.exe` from a full application path. */
export function recordExecutableName(record: ConnectionLog): string {
  const path = record.applicationPath.trim();
  if (path && path !== '—') {
    const base = path.replace(/\\/g, '/').split('/').pop();
    if (base) return base;
  }
  return record.applicationName.trim();
}

/** Header line: executable and domain, or IP when the record has no domain. */
export function recordDetailSubtitle(record: ConnectionLog): string {
  const app = recordExecutableName(record);
  const host = firstNonEmpty(record.domain, record.destinationIp);
  if (app && host) return `${app} · ${host}`;
  return app || host;
}

export type RecordStateTone = 'blocked' | 'listen' | 'allowed';

export type RecordConnectionStatus = 'active' | 'unknown' | 'closed';

/**
 * Tri-state liveness for a connection record.
 *
 * Close evidence always wins: a row with `closedAt > 0` is finished even if a
 * stale `isActive` flag survives a reopen. `isActive` is session-scoped
 * (confirmed open by a tracked-flow write in this daemon lifetime); without
 * it a missing close proves nothing and the record stays `unknown`.
 */
export function recordConnectionStatus(record: ConnectionLog): RecordConnectionStatus {
  if (record.closedAt > 0) return 'closed';
  return record.isActive === true ? 'active' : 'unknown';
}

export function recordStateTone(action: string): RecordStateTone {
  const lower = action.toLowerCase();
  if (lower.includes('block') || lower.includes('deny')) return 'blocked';
  if (lower.includes('listen')) return 'listen';
  return 'allowed';
}

/** Localized matching-list names for a blocked record, empty when none were stored. */
export function recordBlockedByText(record: ConnectionLog): string {
  return formatBlocklistNames(record.blocklistNames);
}

export function recordCountryLabel(code: string, locale = 'en'): string {
  const trimmed = code.trim().toUpperCase();
  if (!trimmed) return '';
  try {
    const name = new Intl.DisplayNames([locale], { type: 'region' }).of(trimmed);
    if (name && name !== trimmed && !name.toLowerCase().includes('unknown')) {
      return `${trimmed} · ${name}`;
    }
  } catch {
    // Invalid region codes stay as the raw code.
  }
  return trimmed;
}
