import {
  AppWindow,
  Ban,
  Check,
  CircleAlert,
  FileCog,
  Globe,
  Info,
  RefreshCw,
  Router,
  Server,
  Shield,
  ShieldAlert,
  Sparkles,
  TriangleAlert,
} from 'lucide-react';
import type { NotificationEvent } from '#lib/types/index.ts';

type Icon = typeof Ban;

const ICON_BY_TAG: Record<string, Icon> = {
  MALICIOUS_FLOW: ShieldAlert,
  THREAT: ShieldAlert,
  AI_ALERT: Sparkles,
  BLOCKED: Ban,
  NEW_APP: AppWindow,
  NEW_APPLICATION: AppWindow,
  NEW_DOMAIN: Globe,
  APP_PATH_CHANGED: FileCog,
  APP_RULES_NOT_MOVED: Shield,
  NETWORK_DEVICE_CONNECTED: Router,
  NETWORK_DEVICE_DISCONNECTED: Router,
  FIREWALL_RULE_DRIFT: Shield,
  DNS_UPSTREAM_SKIPPED: Server,
  GEOIP_SYNC: RefreshCw,
  HOSTS_SYNC: RefreshCw,
  GEOIP_SYNC_FAIL: CircleAlert,
  HOSTS_SYNC_FAIL: CircleAlert,
  MAJOR_ERROR: CircleAlert,
};

const ICON_BY_SEVERITY: Record<NotificationEvent['severity'], Icon> = {
  bad: Ban,
  warn: TriangleAlert,
  ok: Check,
  info: Info,
};

/** The glyph says what happened; the tone (below) says how much it matters. */
export function alertIcon(alert: NotificationEvent): Icon {
  const tag = alert.tag
    .trim()
    .toUpperCase()
    .replace(/[\s-]+/g, '_');
  return ICON_BY_TAG[tag] ?? ICON_BY_SEVERITY[alert.severity] ?? Info;
}

const TONE_BY_SEVERITY: Record<NotificationEvent['severity'], string> = {
  bad: 'var(--bad)',
  warn: 'var(--warn)',
  ok: 'var(--ok)',
  info: 'var(--acc-sub)',
};

export function alertTone(severity: NotificationEvent['severity']): string {
  return TONE_BY_SEVERITY[severity] ?? TONE_BY_SEVERITY.info;
}
