import { beforeAll, describe, expect, test } from 'bun:test';
import type { AppSummary, CountryRule, Rule } from '#lib/types/index.ts';
import { loadMessages, m } from '#lib/i18n/messages.ts';
import {
  addTargetInitialType,
  appSummaryKey,
  canRemoveFirewallRules,
  countryLabel,
  filterCountryRules,
  filterFirewallApps,
  filterNetworkRules,
  firewallAppKey,
  firewallColumnDefs,
  firewallCountryRuleKey,
  firewallListEmptyText,
  firewallRuleKey,
  pageAppKeys,
  resolveAppRuleAction,
  showingApplications,
  visibleFirewallCount,
} from './firewall-list';

function summary(overrides: Partial<AppSummary>): AppSummary {
  return {
    applicationId: 1,
    applicationName: 'Chrome',
    applicationPath: 'C:\\Apps\\chrome.exe',
    connectionCount: 2,
    blockedCount: 0,
    totalBytes: 100,
    bytesSent: 40,
    bytesReceived: 60,
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

describe('firewall list keys', () => {
  test('app keys join name and path', () => {
    expect(appSummaryKey('Chrome', 'C:\\Apps\\chrome.exe')).toBe('Chrome::C:\\Apps\\chrome.exe');
    expect(firewallAppKey({ key: 'Chrome::C:\\Apps\\chrome.exe' })).toBe(
      'Chrome::C:\\Apps\\chrome.exe',
    );
  });

  test('rule keys prefer a real id and fall back to type, target, and direction', () => {
    expect(firewallRuleKey(rule({ id: 4 }))).toBe(4);
    expect(firewallRuleKey(rule({ id: 0, targetType: 'IP', targetValue: '1.1.1.1' }))).toBe(
      'IP\u00001.1.1.1\u0000OUTBOUND',
    );
  });

  test('country keys prefer a real id and fall back to code and direction', () => {
    expect(firewallCountryRuleKey(country({ id: 9 }))).toBe(9);
    expect(firewallCountryRuleKey(country({ id: 0, countryCode: 'DE' }))).toBe('DE\0BOTH');
  });
});

describe('resolveAppRuleAction', () => {
  test('defaults to allow and uses the last matching path rule', () => {
    const path = 'C:\\Apps\\chrome.exe';
    expect(resolveAppRuleAction('Chrome::' + path, 'Chrome', path, [], {})).toBe('allow');
    expect(
      resolveAppRuleAction(
        'Chrome::' + path,
        'Chrome',
        path,
        [rule({ targetType: 'APPLICATION', targetValue: path, action: 'BLOCK' })],
        {},
      ),
    ).toBe('block');
  });

  test('optimistic overrides win until the daemon row is refreshed', () => {
    const path = 'C:\\Apps\\chrome.exe';
    const key = appSummaryKey('Chrome', path);
    expect(resolveAppRuleAction(key, 'Chrome', path, [], { [key]: 'block' })).toBe('block');
  });
});

describe('filterFirewallApps', () => {
  test('sorts by total bytes and maps display fields', () => {
    const rows = filterFirewallApps(
      [
        summary({ applicationName: 'Small', totalBytes: 10, bytesReceived: 1536 }),
        summary({ applicationName: 'Big', totalBytes: 50, bytesReceived: 2048 }),
      ],
      [],
      { query: '', filter: 'all', optimistic: {} },
    );
    expect(rows.map((row) => row.name)).toEqual(['Big', 'Small']);
    expect(rows[0]?.allow).toBe(true);
    expect(rows[0]?.ruleLabel).toBe(m.firewall_badge_allowed());
    expect(rows[1]?.inbound).toBe('1.5 KB');
  });

  test('filters by path query and allowed/blocked action', () => {
    const chrome = summary({ applicationName: 'Chrome' });
    const edge = summary({
      applicationName: 'Edge',
      applicationPath: 'C:\\Apps\\edge.exe',
      totalBytes: 10,
    });
    const blocked = [
      rule({
        targetType: 'APPLICATION',
        targetValue: chrome.applicationPath,
        action: 'BLOCK',
      }),
    ];

    expect(
      filterFirewallApps([chrome, edge], blocked, {
        query: 'edge',
        filter: 'all',
        optimistic: {},
      }).map((row) => row.name),
    ).toEqual(['Edge']);

    expect(
      filterFirewallApps([chrome, edge], blocked, {
        query: '',
        filter: 'blocked',
        optimistic: {},
      }).map((row) => row.name),
    ).toEqual(['Chrome']);
  });
});

describe('filterNetworkRules', () => {
  test('keeps only the selected type and action, and matches query text', () => {
    const domainBlock = rule({ id: 1, targetType: 'DNS', targetValue: 'ads.example' });
    const domainAllow = rule({
      id: 2,
      targetType: 'DNS',
      targetValue: 'ok.example',
      action: 'ALLOW',
    });
    const ip = rule({ id: 3, targetType: 'IP', targetValue: '1.1.1.1' });

    expect(filterNetworkRules([domainBlock, domainAllow, ip], 'Application', 'all', '')).toEqual(
      [],
    );
    expect(
      filterNetworkRules([domainBlock, domainAllow, ip], 'Domain', 'blocked', '').map((r) => r.id),
    ).toEqual([1]);
    expect(
      filterNetworkRules([domainBlock, domainAllow, ip], 'IP', 'all', '1.1').map((r) => r.id),
    ).toEqual([3]);
  });
});

describe('filterCountryRules', () => {
  test('filters by action and country label', () => {
    const us = country({ id: 1, countryCode: 'US' });
    const de = country({ id: 2, countryCode: 'DE', action: 'ALLOW' });
    expect(filterCountryRules([us, de], 'blocked', '').map((r) => r.countryCode)).toEqual(['US']);
    expect(filterCountryRules([us, de], 'all', 'germany').map((r) => r.countryCode)).toEqual([
      'DE',
    ]);
  });
});

describe('countryLabel', () => {
  test('includes the country name when the code is known', () => {
    expect(countryLabel(country({ countryCode: 'US' }))).toBe('US — United States');
    expect(countryLabel(country({ countryCode: 'ZZ' }))).toBe('ZZ');
  });
});

describe('firewallListEmptyText', () => {
  test('covers application, country, and network empty states', () => {
    expect(
      firewallListEmptyText({
        listType: 'Application',
        query: '',
        filter: 'all',
        summaryCount: 0,
        summaryWithPathCount: 0,
      }),
    ).toBe(m.firewall_empty_no_apps_recorded());

    expect(
      firewallListEmptyText({
        listType: 'Application',
        query: 'zz',
        filter: 'all',
        summaryCount: 2,
        summaryWithPathCount: 2,
      }),
    ).toBe(m.firewall_empty_no_app_match({ query: 'zz' }));

    expect(
      firewallListEmptyText({
        listType: 'Country',
        query: '',
        filter: 'allowed',
        summaryCount: 0,
        summaryWithPathCount: 0,
      }),
    ).toBe(m.firewall_empty_no_rules_configured({ type: 'country' }));

    expect(
      firewallListEmptyText({
        listType: 'Domain',
        query: 'ads',
        filter: 'all',
        summaryCount: 0,
        summaryWithPathCount: 0,
      }),
    ).toBe(m.firewall_empty_no_rules_match({ type: 'domain', query: 'ads' }));
  });
});

describe('list chrome helpers', () => {
  test('derive toolbar and add-dialog state from the selected list', () => {
    expect(showingApplications('Application')).toBe(true);
    expect(canRemoveFirewallRules('Domain')).toBe(true);
    expect(canRemoveFirewallRules('Country')).toBe(false);
    expect(addTargetInitialType('Domain')).toBe('Domain');
    expect(addTargetInitialType('Country')).toBe('IP');
    expect(visibleFirewallCount('Application', [1, 2], [3], [])).toBe(2);
    expect(visibleFirewallCount('Country', [], [], [1])).toBe(1);
    expect(
      [...pageAppKeys([summary({ applicationName: '', applicationPath: 'C:\\a.exe' })])][0],
    ).toBe(`${m.firewall_unknown_app()}::C:\\a.exe`);
  });

  test('column defs carry the sortable keys for each list', () => {
    expect(firewallColumnDefs('Application').map((col) => col.key)).toEqual([
      'app',
      'conns',
      'traffic',
      'action',
    ]);
    expect(firewallColumnDefs('Country').map((col) => col.key)).toEqual([
      'country',
      'action',
      'direction',
      'networks',
    ]);
    expect(firewallColumnDefs('IP').map((col) => col.key)).toEqual([
      'target',
      'action',
      'direction',
      'type',
    ]);
  });
});
