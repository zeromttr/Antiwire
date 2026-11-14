import { describe, expect, it } from 'bun:test';
import type { NotificationEvent } from '#lib/types/index.ts';
import {
  alertCategory,
  alertRecordsWindow,
  alertSeverityLabel,
  alertTabCounts,
  alertTimeMs,
  alertTypeLabel,
  filterAlertsByTab,
  formatAlertAge,
  formatAlertTime,
  formatAlertTypeFallback,
  groupAlertsByDay,
} from './alerts';

function alert(tag: string, id = tag, timestamp = '1'): NotificationEvent {
  return {
    id,
    title: tag,
    body: '',
    severity: 'info',
    timestamp,
    tag,
  };
}

/** Local noon on 2026-08-05, as epoch milliseconds. */
const NOON = new Date(2026, 7, 5, 12, 0, 0).getTime();
const secondsAgo = (s: number) => String(Math.floor(NOON / 1000) - s);

describe('alerts model', () => {
  it('labels known alert types', () => {
    expect(alertTypeLabel('MALICIOUS_FLOW')).toBe('Malicious flow');
    expect(alertTypeLabel('new_app')).toBe('New application');
  });

  it('title-cases unknown alert types', () => {
    expect(formatAlertTypeFallback('CUSTOM_EVENT')).toBe('Custom event');
  });

  it('sorts alert types into threats, new activity and system', () => {
    expect(alertCategory('MALICIOUS_FLOW')).toBe('threats');
    expect(alertCategory('ai_alert')).toBe('threats');
    expect(alertCategory('NEW_APP')).toBe('activity');
    expect(alertCategory('New app')).toBe('activity');
    expect(alertCategory('NETWORK_DEVICE_DISCONNECTED')).toBe('activity');
    expect(alertCategory('HOSTS_SYNC_FAIL')).toBe('system');
    expect(alertCategory('SOMETHING_ELSE')).toBe('system');
  });

  it('filters and counts by tab', () => {
    const alerts = [
      alert('NEW_APP'),
      alert('MALICIOUS_FLOW'),
      alert('GEOIP_SYNC'),
      alert('NEW_DOMAIN'),
    ];
    expect(filterAlertsByTab(alerts, 'all')).toEqual(alerts);
    expect(filterAlertsByTab(alerts, 'activity').map((a) => a.tag)).toEqual([
      'NEW_APP',
      'NEW_DOMAIN',
    ]);
    expect(alertTabCounts(alerts)).toEqual({ all: 4, threats: 1, activity: 2, system: 1 });
  });

  it('reads Unix seconds and milliseconds, and rejects free text', () => {
    expect(alertTimeMs('1700000000')).toBe(1_700_000_000_000);
    expect(alertTimeMs('1700000000000')).toBe(1_700_000_000_000);
    expect(alertTimeMs('Just now')).toBeNull();
    expect(alertTimeMs('0')).toBeNull();
    expect(alertTimeMs('')).toBeNull();
  });

  it('groups consecutive alerts by local day', () => {
    const groups = groupAlertsByDay(
      [
        alert('A', 'a', secondsAgo(60)),
        alert('B', 'b', secondsAgo(3600)),
        alert('C', 'c', secondsAgo(24 * 3600)),
        alert('D', 'd', secondsAgo(4 * 24 * 3600)),
        alert('E', 'e', 'Just now'),
      ],
      NOON,
    );
    expect(groups.map((g) => g.label.length > 0)).toEqual([true, true, true, true]);
    expect(groups[0]).toMatchObject({ label: 'Today' });
    expect(groups[0].alerts.map((a) => a.id)).toEqual(['a', 'b']);
    expect(groups[1]).toMatchObject({ label: 'Yesterday' });
    expect(groups[3]).toMatchObject({ key: 'recent', label: 'Recent' });
  });

  it('formats compact ages for the list', () => {
    expect(formatAlertAge(secondsAgo(10), NOON)).toBe('now');
    expect(formatAlertAge(secondsAgo(12 * 60), NOON)).toBe('12m');
    expect(formatAlertAge(secondsAgo(3 * 3600), NOON)).toBe('3h');
    expect(formatAlertAge('2 min ago', NOON)).toBe('2 min ago');
    expect(formatAlertTime('2 min ago')).toBe('2 min ago');
  });

  it('labels severities and opens a records window around the alert', () => {
    expect(alertSeverityLabel('bad')).toBe('Critical');
    expect(alertSeverityLabel('info')).toBe('Info');
    expect(alertRecordsWindow('1000')).toEqual({ from: 700, to: 1300 });
    expect(alertRecordsWindow('Just now')).toBeNull();
  });
});
