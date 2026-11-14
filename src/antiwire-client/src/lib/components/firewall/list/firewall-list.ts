import type { AppSummary, CountryRule, Rule } from '#lib/types/index.ts';
import { COUNTRY_ENTRIES } from '#lib/models/country-cidrs.ts';
import { formatBytes } from '#lib/utils/format.ts';
import { m } from '#lib/i18n/messages.ts';
import { findApplicationRule } from '../rules/application-rule-match';
import { matchesActionFilter, type ActionFilter } from './action-filter';
import { ruleDirectionLabel } from '../form/rule-form';
import type { FirewallSortKey } from './firewall-sort';

export type FirewallListType = 'Application' | 'Domain' | 'IP' | 'Country';

export type FirewallAppRow = {
  name: string;
  path: string;
  key: string;
  inbound: string;
  outbound: string;
  bytesReceived: number;
  bytesSent: number;
  conns: number;
  ruleLabel: string;
  allow: boolean;
};

export type FirewallColumnDef = {
  key: FirewallSortKey;
  label: string;
};

/** Avatar + name/path; underestimate causes stacked overlap in the virtual list. */
export const APP_ROW_HEIGHT = 60;
export const RULE_ROW_HEIGHT = 53;
export const APP_GRID_COLUMNS = 'minmax(0, 2.2fr) 96px minmax(0, 1.6fr) 150px 32px';
export const RULE_GRID_COLUMNS = '2fr 1fr 1fr 1fr 40px';

const NETWORK_TARGET_TYPE = {
  IP: 'IP',
  Domain: 'DNS',
} as const;

const COUNTRY_NAMES = new Map(COUNTRY_ENTRIES.map((entry) => [entry.code, entry.name]));

export function appSummaryKey(name: string, path: string): string {
  return `${name}::${path}`;
}

export function firewallAppKey(app: Pick<FirewallAppRow, 'key'>): string {
  return app.key;
}

export function firewallRuleKey(rule: Rule): string | number {
  return rule.id !== 0 ? rule.id : `${rule.targetType}\0${rule.targetValue}\0${rule.direction}`;
}

export function firewallCountryRuleKey(rule: CountryRule): string | number {
  return rule.id !== 0 ? rule.id : `${rule.countryCode}\0${rule.direction}`;
}

function ruleTypeOf(rule: Rule): string {
  return (rule.targetType || '').toUpperCase();
}

export function resolveAppRuleAction(
  key: string,
  _name: string,
  path: string,
  rules: readonly Rule[],
  optimistic: Readonly<Record<string, string>>,
): 'allow' | 'block' {
  const pending = optimistic[key];
  if (pending === 'allow' || pending === 'block') return pending;
  const rule = findApplicationRule(rules, path);
  if (!rule) return 'allow';
  return rule.action.toLowerCase().includes('block') ? 'block' : 'allow';
}

export function filterFirewallApps(
  summaries: readonly AppSummary[],
  rules: readonly Rule[],
  options: { query: string; filter: ActionFilter; optimistic: Readonly<Record<string, string>> },
): FirewallAppRow[] {
  const q = options.query.trim().toLowerCase();
  let apps = [...summaries].sort((a, b) => b.totalBytes - a.totalBytes);
  if (q) {
    apps = apps.filter((a) => {
      const name = (a.applicationName ?? '').toLowerCase();
      const path = (a.applicationPath ?? '').toLowerCase();
      return name.includes(q) || path.includes(q);
    });
  }
  if (options.filter === 'allowed' || options.filter === 'blocked') {
    const wanted = options.filter === 'allowed' ? 'allow' : 'block';
    apps = apps.filter((a) => {
      const name = a.applicationName ?? '';
      const path = a.applicationPath ?? '';
      return (
        resolveAppRuleAction(appSummaryKey(name, path), name, path, rules, options.optimistic) ===
        wanted
      );
    });
  }
  return apps.map((a) => {
    const name = a.applicationName || m.firewall_unknown_app();
    const path = a.applicationPath;
    const key = appSummaryKey(name, path);
    const allow = resolveAppRuleAction(key, name, path, rules, options.optimistic) === 'allow';
    return {
      name,
      path,
      key,
      inbound: formatBytes(a.bytesReceived),
      outbound: formatBytes(a.bytesSent),
      bytesReceived: a.bytesReceived,
      bytesSent: a.bytesSent,
      conns: a.connectionCount,
      ruleLabel: allow ? m.firewall_badge_allowed() : m.firewall_badge_blocked(),
      allow,
    };
  });
}

export function filterNetworkRules(
  rules: readonly Rule[],
  listType: FirewallListType,
  filter: ActionFilter,
  query: string,
): Rule[] {
  if (listType !== 'Domain' && listType !== 'IP') return [];
  const wanted = NETWORK_TARGET_TYPE[listType];
  const q = query.trim().toLowerCase();
  return rules.filter((rule) => {
    if (ruleTypeOf(rule) !== wanted) return false;
    if (!matchesActionFilter(rule.action, filter)) return false;
    if (!q) return true;
    return (
      rule.targetValue.toLowerCase().includes(q) ||
      rule.action.toLowerCase().includes(q) ||
      ruleDirectionLabel(rule.direction).toLowerCase().includes(q) ||
      rule.targetType.toLowerCase().includes(q)
    );
  });
}

export function countryLabel(rule: CountryRule): string {
  const name = COUNTRY_NAMES.get(rule.countryCode);
  return name ? `${rule.countryCode} — ${name}` : rule.countryCode;
}

export function filterCountryRules(
  countryRules: readonly CountryRule[],
  filter: ActionFilter,
  query: string,
): CountryRule[] {
  const q = query.trim().toLowerCase();
  return countryRules.filter((rule) => {
    if (!matchesActionFilter(rule.action, filter)) return false;
    if (!q) return true;
    const label = countryLabel(rule).toLowerCase();
    return (
      label.includes(q) ||
      rule.countryCode.toLowerCase().includes(q) ||
      rule.action.toLowerCase().includes(q) ||
      ruleDirectionLabel(rule.direction).toLowerCase().includes(q)
    );
  });
}

export function firewallListEmptyText(input: {
  listType: FirewallListType;
  query: string;
  filter: ActionFilter;
  summaryCount: number;
  summaryWithPathCount: number;
}): string {
  const q = input.query.trim();
  if (input.listType === 'Application') {
    if (input.summaryWithPathCount === 0) {
      return input.summaryCount === 0
        ? m.firewall_empty_no_apps_recorded()
        : m.firewall_empty_no_apps_with_path();
    }
    if (q) return m.firewall_empty_no_app_match({ query: q });
    if (input.filter === 'allowed') return m.firewall_empty_no_allowed_apps();
    if (input.filter === 'blocked') return m.firewall_empty_no_blocked_apps();
    return m.firewall_empty_no_apps_display();
  }
  if (input.listType === 'Country') {
    if (q) return m.firewall_empty_no_countries_match({ query: q });
    if (input.filter === 'allowed')
      return m.firewall_empty_no_rules_configured({ type: 'country' });
    return m.firewall_empty_no_countries_blocked();
  }
  if (q) {
    return m.firewall_empty_no_rules_match({ type: input.listType.toLowerCase(), query: q });
  }
  return m.firewall_empty_no_rules_configured({ type: input.listType.toLowerCase() });
}

/** How many entries each list holds, before search and the allowed/blocked filter. */
export function firewallListCounts(
  apps: readonly unknown[],
  rules: readonly Rule[],
  countryRules: readonly unknown[],
): Record<FirewallListType, number> {
  let domains = 0;
  let ips = 0;
  for (const rule of rules) {
    const type = ruleTypeOf(rule);
    if (type === NETWORK_TARGET_TYPE.Domain) domains += 1;
    else if (type === NETWORK_TARGET_TYPE.IP) ips += 1;
  }
  return { Application: apps.length, Domain: domains, IP: ips, Country: countryRules.length };
}

export function showingApplications(listType: FirewallListType): boolean {
  return listType === 'Application';
}

export function canRemoveFirewallRules(listType: FirewallListType): boolean {
  return listType === 'Domain' || listType === 'IP';
}

export function addTargetInitialType(listType: FirewallListType): 'Domain' | 'IP' {
  return listType === 'Domain' || listType === 'IP' ? listType : 'IP';
}

export function visibleFirewallCount(
  listType: FirewallListType,
  apps: readonly unknown[],
  rules: readonly unknown[],
  countries: readonly unknown[],
): number {
  if (listType === 'Application') return apps.length;
  if (listType === 'Country') return countries.length;
  return rules.length;
}

export function pageAppKeys(summaries: readonly AppSummary[]): Set<string> {
  return new Set(
    summaries.map((summary) => {
      const name = summary.applicationName || m.firewall_unknown_app();
      const path = summary.applicationPath || '';
      return appSummaryKey(name, path);
    }),
  );
}

/** Sortable columns for the active list, in the order the table renders them. */
export function firewallColumnDefs(listType: FirewallListType): FirewallColumnDef[] {
  if (listType === 'Application') {
    return [
      { key: 'app', label: m.firewall_tab_applications() },
      { key: 'conns', label: m.firewall_stat_connections() },
      { key: 'traffic', label: m.firewall_col_traffic() },
      { key: 'action', label: m.firewall_col_access() },
    ];
  }
  if (listType === 'Country') {
    return [
      { key: 'country', label: m.firewall_col_country() },
      { key: 'action', label: m.firewall_col_action() },
      { key: 'direction', label: m.firewall_col_direction() },
      { key: 'networks', label: m.firewall_col_networks() },
    ];
  }
  return [
    { key: 'target', label: m.firewall_col_target() },
    { key: 'action', label: m.firewall_col_action() },
    { key: 'direction', label: m.firewall_col_direction() },
    { key: 'type', label: m.firewall_col_type() },
  ];
}
