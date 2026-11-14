import { beforeAll, describe, expect, test } from 'bun:test';
import type { CountryRule, Rule } from '#lib/types/index.ts';
import { loadMessages } from '#lib/i18n/messages.ts';
import type { FirewallAppRow } from './firewall-list';
import {
  nextFirewallSort,
  sortCountryRules,
  sortFirewallApps,
  sortNetworkRules,
} from './firewall-sort';

function app(overrides: Partial<FirewallAppRow>): FirewallAppRow {
  return {
    name: 'Chrome',
    path: 'C:\\Apps\\chrome.exe',
    key: 'Chrome::C:\\Apps\\chrome.exe',
    inbound: '0 B',
    outbound: '0 B',
    bytesReceived: 0,
    bytesSent: 0,
    conns: 0,
    ruleLabel: 'ALLOWED',
    allow: true,
    ...overrides,
  };
}

function rule(overrides: Partial<Rule>): Rule {
  return {
    id: 1,
    targetType: 'DNS',
    targetValue: 'example.com',
    action: 'BLOCK',
    direction: 'OUTBOUND',
    ...overrides,
  };
}

function country(overrides: Partial<CountryRule>): CountryRule {
  return {
    id: 8,
    countryCode: 'US',
    action: 'BLOCK',
    direction: 'BOTH',
    cidrCount: 12,
    ...overrides,
  };
}

beforeAll(async () => {
  await loadMessages('en');
});

describe('nextFirewallSort', () => {
  test('descends, then ascends, then clears', () => {
    const first = nextFirewallSort(null, -1, 'app');
    expect(first).toEqual({ key: 'app', dir: -1 });
    const second = nextFirewallSort(first.key, first.dir, 'app');
    expect(second).toEqual({ key: 'app', dir: 1 });
    const third = nextFirewallSort(second.key, second.dir, 'app');
    expect(third).toEqual({ key: null, dir: -1 });
  });

  test('switching columns restarts at descending', () => {
    expect(nextFirewallSort('app', 1, 'conns')).toEqual({ key: 'conns', dir: -1 });
  });
});

describe('sortFirewallApps', () => {
  test('leaves natural order unchanged when no column is active', () => {
    const rows = [app({ name: 'B' }), app({ name: 'A' })];
    expect(sortFirewallApps(rows, { key: null, dir: -1 }).map((r) => r.name)).toEqual(['B', 'A']);
  });

  test('sorts by name, numeric traffic, and action in either direction', () => {
    const rows = [
      app({ name: 'Chrome', bytesReceived: 10, bytesSent: 30, conns: 2 }),
      app({ name: 'Edge', bytesReceived: 50, bytesSent: 20, conns: 9, allow: false }),
    ];
    expect(sortFirewallApps(rows, { key: 'app', dir: 1 }).map((r) => r.name)).toEqual([
      'Chrome',
      'Edge',
    ]);
    expect(sortFirewallApps(rows, { key: 'app', dir: -1 }).map((r) => r.name)).toEqual([
      'Edge',
      'Chrome',
    ]);
    // Traffic sorts by both directions together: Chrome 40 B, Edge 70 B.
    expect(sortFirewallApps(rows, { key: 'traffic', dir: 1 }).map((r) => r.name)).toEqual([
      'Chrome',
      'Edge',
    ]);
    expect(sortFirewallApps(rows, { key: 'traffic', dir: -1 }).map((r) => r.name)).toEqual([
      'Edge',
      'Chrome',
    ]);
    expect(sortFirewallApps(rows, { key: 'conns', dir: -1 }).map((r) => r.name)).toEqual([
      'Edge',
      'Chrome',
    ]);
    expect(sortFirewallApps(rows, { key: 'action', dir: 1 }).map((r) => r.name)).toEqual([
      'Chrome',
      'Edge',
    ]);
  });
});

describe('sortNetworkRules', () => {
  test('sorts by target, action, direction, and type', () => {
    const rows = [
      rule({ id: 1, targetValue: 'zeta.example' }),
      rule({ id: 2, targetValue: 'alpha.example', action: 'ALLOW' }),
    ];
    expect(sortNetworkRules(rows, { key: 'target', dir: 1 }).map((r) => r.id)).toEqual([2, 1]);
    expect(sortNetworkRules(rows, { key: 'action', dir: 1 }).map((r) => r.id)).toEqual([2, 1]);
    expect(sortNetworkRules(rows, { key: 'direction', dir: -1 }).map((r) => r.id)).toEqual([1, 2]);
    expect(sortNetworkRules(rows, { key: 'type', dir: 1 }).map((r) => r.id)).toEqual([1, 2]);
  });
});

describe('sortCountryRules', () => {
  test('sorts by country label, action, direction, and network count', () => {
    const rows = [
      country({ id: 1, countryCode: 'US', cidrCount: 3 }),
      country({ id: 2, countryCode: 'DE', action: 'ALLOW', cidrCount: 90 }),
    ];
    expect(sortCountryRules(rows, { key: 'country', dir: 1 }).map((r) => r.id)).toEqual([2, 1]);
    expect(sortCountryRules(rows, { key: 'networks', dir: -1 }).map((r) => r.id)).toEqual([2, 1]);
    expect(sortCountryRules(rows, { key: 'action', dir: 1 }).map((r) => r.id)).toEqual([2, 1]);
  });
});
