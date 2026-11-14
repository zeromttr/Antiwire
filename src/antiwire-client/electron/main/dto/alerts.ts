import type { NotificationEvent } from '../daemon/messages';

export interface AlertDto {
  id: string;
  title: string;
  body: string;
  severity: string;
  timestamp: string;
  tag: string;
}

/** How a notification id addresses an alert. */
export type AlertId =
  /** A persisted daemon alert, addressed by its database row id. */
  | { kind: 'database'; id: number }
  /**
   * A synthetic client-side notification: the stream lag marker and other
   * unpersisted events arrive as `<timestamp>-<TYPE>` and have no daemon row,
   * so dismissing them is purely local.
   */
  | { kind: 'local' };

const DIGITS = /^\d+$/;

/** Classifies a notification id produced by `eventId`. */
export function parseAlertId(raw: string): AlertId | null {
  if (DIGITS.test(raw)) {
    const id = Number(raw);
    return Number.isSafeInteger(id) ? { kind: 'database', id } : null;
  }
  const dash = raw.indexOf('-');
  if (dash < 0) return null;
  const timestamp = raw.slice(0, dash);
  const tag = raw.slice(dash + 1);
  return tag && DIGITS.test(timestamp) ? { kind: 'local' } : null;
}

export function eventId(event: Pick<NotificationEvent, 'id' | 'timestamp' | 'type'>): string {
  return event.id === 0 ? `${event.timestamp}-${event.type}` : String(event.id);
}

function severity(raw: string): string {
  switch (raw) {
    case 'ERROR':
    case 'CRITICAL':
      return 'bad';
    case 'WARNING':
      return 'warn';
    case 'SUCCESS':
      return 'ok';
    default:
      return 'info';
  }
}

export function eventToDto(event: NotificationEvent): AlertDto {
  return {
    id: eventId(event),
    title: event.title,
    body: event.message,
    severity: severity(event.severity),
    timestamp: String(event.timestamp),
    tag: event.type,
  };
}
