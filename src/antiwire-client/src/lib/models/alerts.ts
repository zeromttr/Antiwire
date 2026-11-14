import { m } from '#lib/i18n/messages.ts';
import type { NotificationEvent } from '#lib/types/index.ts';

const ALERT_TYPE_LABELS: Record<string, () => string> = {
  AI_ALERT: m.alerts_type_ai_alert,
  APP_PATH_CHANGED: m.alerts_type_app_path_changed,
  APP_RULES_NOT_MOVED: m.alerts_type_app_rules_not_moved,
  DNS_UPSTREAM_SKIPPED: m.alerts_type_dns_upstream_skipped,
  FIREWALL_RULE_DRIFT: m.alerts_type_firewall_rule_drift,
  GEOIP_SYNC: m.alerts_type_geoip_sync,
  GEOIP_SYNC_FAIL: m.alerts_type_geoip_sync_fail,
  HOSTS_SYNC: m.alerts_type_hosts_sync,
  HOSTS_SYNC_FAIL: m.alerts_type_hosts_sync_fail,
  MAJOR_ERROR: m.alerts_type_major_error,
  MALICIOUS_FLOW: m.alerts_type_malicious_flow,
  NETWORK_DEVICE_CONNECTED: m.alerts_type_network_device_connected,
  NETWORK_DEVICE_DISCONNECTED: m.alerts_type_network_device_disconnected,
  NEW_APP: m.alerts_type_new_app,
  NEW_DOMAIN: m.alerts_type_new_domain,
};

/** Localized label for a daemon alert type tag. */
export function alertTypeLabel(tag: string): string {
  const normalized = tag.trim().toUpperCase();
  const labelFn = ALERT_TYPE_LABELS[normalized];
  if (labelFn) return labelFn();
  return formatAlertTypeFallback(tag);
}

/** Sentence-case fallback for alert types that do not have a dedicated label yet. */
export function formatAlertTypeFallback(tag: string): string {
  const text = tag
    .trim()
    .split(/[_\s]+/)
    .filter(Boolean)
    .join(' ')
    .toLowerCase();
  return text.charAt(0).toUpperCase() + text.slice(1);
}

export type AlertCategory = 'threats' | 'activity' | 'system';
export type AlertTab = 'all' | AlertCategory;
export const ALERT_TABS: AlertTab[] = ['all', 'threats', 'activity', 'system'];

const CATEGORY_BY_TAG: Record<string, AlertCategory> = {
  MALICIOUS_FLOW: 'threats',
  AI_ALERT: 'threats',
  THREAT: 'threats',
  BLOCKED: 'threats',
  NEW_APP: 'activity',
  NEW_DOMAIN: 'activity',
  APP_PATH_CHANGED: 'activity',
  APP_RULES_NOT_MOVED: 'activity',
  NETWORK_DEVICE_CONNECTED: 'activity',
  NETWORK_DEVICE_DISCONNECTED: 'activity',
};

function normalizeTag(tag: string): string {
  return tag
    .trim()
    .toUpperCase()
    .replace(/[\s-]+/g, '_');
}

/** Which tab an alert belongs to. Anything not a threat or new activity is housekeeping. */
export function alertCategory(tag: string): AlertCategory {
  const normalized = normalizeTag(tag);
  if (CATEGORY_BY_TAG[normalized]) return CATEGORY_BY_TAG[normalized];
  if (normalized === 'NEW_APPLICATION' || normalized.startsWith('NEW_')) return 'activity';
  return 'system';
}

export function filterAlertsByTab(alerts: NotificationEvent[], tab: AlertTab): NotificationEvent[] {
  if (tab === 'all') return alerts;
  return alerts.filter((alert) => alertCategory(alert.tag) === tab);
}

export function alertTabCounts(alerts: NotificationEvent[]): Record<AlertTab, number> {
  const counts: Record<AlertTab, number> = {
    all: alerts.length,
    threats: 0,
    activity: 0,
    system: 0,
  };
  for (const alert of alerts) counts[alertCategory(alert.tag)] += 1;
  return counts;
}

/**
 * The daemon sends Unix seconds as a string; older builds and the browser
 * preview send ready-made text. Returns epoch milliseconds, or null for text.
 */
export function alertTimeMs(timestamp: string): number | null {
  const trimmed = timestamp.trim();
  if (!/^\d+$/.test(trimmed)) return null;
  const value = Number(trimmed);
  if (!Number.isFinite(value) || value <= 0) return null;
  // Tolerate millisecond stamps as well as seconds.
  return value > 1e12 ? value : value * 1000;
}

function startOfDay(ms: number): number {
  const date = new Date(ms);
  return new Date(date.getFullYear(), date.getMonth(), date.getDate()).getTime();
}

export interface AlertDayGroup {
  key: string;
  label: string;
  alerts: NotificationEvent[];
}

const groupDateFmt = new Intl.DateTimeFormat(undefined, {
  weekday: 'long',
  month: 'short',
  day: 'numeric',
});

/** Consecutive runs of alerts on the same local day, newest first as given. */
export function groupAlertsByDay(
  alerts: NotificationEvent[],
  nowMs: number = Date.now(),
): AlertDayGroup[] {
  const today = startOfDay(nowMs);
  const yesterday = today - 86_400_000;
  const groups: AlertDayGroup[] = [];
  for (const alert of alerts) {
    const ms = alertTimeMs(alert.timestamp);
    const day = ms == null ? null : startOfDay(ms);
    const key = day == null ? 'recent' : String(day);
    let group = groups.at(-1);
    if (!group || group.key !== key) {
      const label =
        day == null
          ? m.alerts_group_recent()
          : day === today
            ? m.alerts_group_today()
            : day === yesterday
              ? m.alerts_group_yesterday()
              : groupDateFmt.format(day);
      group = { key, label, alerts: [] };
      groups.push(group);
    }
    group.alerts.push(alert);
  }
  return groups;
}

const clockFmt = new Intl.DateTimeFormat(undefined, { hour: '2-digit', minute: '2-digit' });
const shortDateFmt = new Intl.DateTimeFormat(undefined, { month: 'short', day: 'numeric' });
const fullFmt = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'medium' });

/** Compact time for the list: "now", "12m", "3h", then a clock time or date. */
export function formatAlertAge(timestamp: string, nowMs: number = Date.now()): string {
  const ms = alertTimeMs(timestamp);
  if (ms == null) return timestamp;
  const seconds = Math.max(0, Math.round((nowMs - ms) / 1000));
  if (seconds < 60) return m.alerts_age_now();
  if (seconds < 3600) return m.alerts_age_minutes({ count: Math.floor(seconds / 60) });
  if (seconds < 6 * 3600) return m.alerts_age_hours({ count: Math.floor(seconds / 3600) });
  return startOfDay(ms) === startOfDay(nowMs) ? clockFmt.format(ms) : shortDateFmt.format(ms);
}

/** Full local date and time for the detail pane. */
export function formatAlertTime(timestamp: string): string {
  const ms = alertTimeMs(timestamp);
  return ms == null ? timestamp : fullFmt.format(ms);
}

const SEVERITY_LABELS: Record<NotificationEvent['severity'], () => string> = {
  bad: m.alerts_severity_bad,
  warn: m.alerts_severity_warn,
  ok: m.alerts_severity_ok,
  info: m.alerts_severity_info,
};

export function alertSeverityLabel(severity: NotificationEvent['severity']): string {
  return (SEVERITY_LABELS[severity] ?? SEVERITY_LABELS.info)();
}

/** A window around the alert for "View connections"; null when the time is unknown. */
export function alertRecordsWindow(timestamp: string): { from: number; to: number } | null {
  const ms = alertTimeMs(timestamp);
  if (ms == null) return null;
  const seconds = Math.floor(ms / 1000);
  return { from: seconds - 5 * 60, to: seconds + 5 * 60 };
}
