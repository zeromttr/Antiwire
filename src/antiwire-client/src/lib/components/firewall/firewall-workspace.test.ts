import { beforeAll, describe, expect, mock, test } from 'bun:test';
import type { AppSummary, CountryRule, Rule } from '#lib/types/index.ts';
import { loadMessages, m } from '#lib/i18n/messages.ts';
import { FirewallWorkspace, type FirewallApiClient, type FirewallHost } from './firewall-workspace';

function rule(overrides: Partial<Rule> = {}): Rule {
  return {
    id: 1,
    targetType: 'DNS',
    targetValue: 'example.com',
    action: 'BLOCK',
    direction: 'OUTBOUND',
    ...overrides,
  };
}

function country(overrides: Partial<CountryRule> = {}): CountryRule {
  return {
    id: 8,
    countryCode: 'US',
    action: 'BLOCK',
    direction: 'BOTH',
    cidrCount: 12,
    ...overrides,
  };
}

function summary(overrides: Partial<AppSummary> = {}): AppSummary {
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

function workspace(options?: {
  connected?: boolean;
  rules?: Rule[];
  countryRules?: CountryRule[];
  appSummaries?: AppSummary[];
  applicationRulesSupported?: boolean;
  client?: Partial<FirewallApiClient>;
}) {
  const toasts: Array<[string, string, string]> = [];
  let refreshed = 0;
  const host: FirewallHost = {
    get connected() {
      return options?.connected ?? true;
    },
    get rules() {
      return options?.rules ?? [];
    },
    get countryRules() {
      return options?.countryRules ?? [];
    },
    get appSummaries() {
      return options?.appSummaries ?? [];
    },
    get applicationRulesSupported() {
      return options?.applicationRulesSupported ?? true;
    },
    refreshAll: async () => {
      refreshed += 1;
    },
    toast: (title, body, color) => {
      toasts.push([title, body, color]);
    },
  };
  const client = {
    addRule: mock(async () => true),
    removeRule: mock(async () => undefined),
    addCountryRule: mock(async () => ({ success: true, message: '' })),
    removeCountryRule: mock(async () => ({ success: true, message: '' })),
    getAppSummaries: mock(async () => ({ applications: [] })),
    ...options?.client,
  } as FirewallApiClient;
  return { fw: new FirewallWorkspace(client, host), client, toasts, getRefreshed: () => refreshed };
}

beforeAll(async () => {
  await loadMessages('en');
});

describe('FirewallWorkspace lists', () => {
  test('every list is offered where application rules are enforced', () => {
    const { fw } = workspace();
    expect(fw.listTypes).toEqual(['Application', 'Domain', 'IP', 'Country']);
    expect(fw.listType).toBe('Application');
    expect(fw.showsApplications).toBe(true);
  });

  test('the applications list is not offered where they are not', () => {
    const { fw } = workspace({ applicationRulesSupported: false });
    expect(fw.listTypes).toEqual(['Domain', 'IP', 'Country']);
    // The default pick is not offered, so the first list that is takes its place.
    expect(fw.listType).toBe('Domain');
    expect(fw.showsApplications).toBe(false);
    fw.openAdd();
    expect(fw.addAppRuleOpen).toBe(false);
    expect(fw.addTargetRuleOpen).toBe(true);

    fw.setListType('Country');
    expect(fw.listType).toBe('Country');
  });
});

describe('FirewallWorkspace dialogs', () => {
  test('setListType closes add and remove dialogs', () => {
    const { fw } = workspace();
    fw.addAppRuleOpen = true;
    fw.removeConfirmOpen = true;
    fw.rulePendingRemoval = rule();
    fw.setListType('Domain');
    expect(fw.listType).toBe('Domain');
    expect(fw.addAppRuleOpen).toBe(false);
    expect(fw.removeConfirmOpen).toBe(false);
    expect(fw.rulePendingRemoval).toBeNull();
    expect(fw.addTargetType).toBe('Domain');
  });

  test('openAdd picks the dialog for the current list', () => {
    const { fw } = workspace();
    fw.openAdd();
    expect(fw.addAppRuleOpen).toBe(true);
    expect(fw.addTargetRuleOpen).toBe(false);
    fw.setListType('IP');
    fw.openAdd();
    expect(fw.addAppRuleOpen).toBe(false);
    expect(fw.addTargetRuleOpen).toBe(true);
  });

  test('requestRemoveRule is a no-op while disconnected', () => {
    const { fw } = workspace({ connected: false });
    fw.requestRemoveRule(rule());
    expect(fw.removeConfirmOpen).toBe(false);
  });
});

describe('FirewallWorkspace.createRule', () => {
  test('does not call the daemon while disconnected', async () => {
    const { fw, client } = workspace({ connected: false });
    await fw.createRule({
      kind: 'target',
      targetType: 'DNS',
      targetValue: 'ads.example',
      action: 'BLOCK',
      direction: 'OUTBOUND',
    });
    expect(client.addRule).not.toHaveBeenCalled();
  });

  test('creates a country rule and closes the target dialog', async () => {
    const { fw, client, toasts, getRefreshed } = workspace();
    fw.addTargetRuleOpen = true;
    await fw.createRule({
      kind: 'country',
      countryCode: 'DE',
      countryName: 'Germany',
      cidrs: ['1.0.0.0/8'],
      action: 'BLOCK',
      direction: 'BOTH',
    });
    expect(client.addCountryRule).toHaveBeenCalledWith('DE', ['1.0.0.0/8'], 'BLOCK', 'BOTH');
    expect(getRefreshed()).toBe(1);
    expect(fw.addTargetRuleOpen).toBe(false);
    expect(toasts[0]?.[0]).toBe(m.firewall_toast_country_blocked_title({ country: 'Germany' }));
  });

  test('keeps the dialog open when the daemon rejects the country', async () => {
    const { fw, toasts } = workspace({
      client: {
        addCountryRule: mock(async () => ({ success: false, message: 'busy' })),
      },
    });
    fw.addTargetRuleOpen = true;
    await fw.createRule({
      kind: 'country',
      countryCode: 'DE',
      countryName: 'Germany',
      cidrs: ['1.0.0.0/8'],
      action: 'BLOCK',
      direction: 'BOTH',
    });
    expect(fw.addTargetRuleOpen).toBe(true);
    expect(toasts[0]?.[1]).toBe('busy');
  });
});

describe('FirewallWorkspace.toggleApp', () => {
  test('blocks an allowed app and clears the optimistic override', async () => {
    const path = 'C:\\Apps\\chrome.exe';
    const { fw, client, toasts } = workspace();
    await fw.toggleApp({ key: `Chrome::${path}`, name: 'Chrome', path });
    expect(client.addRule).toHaveBeenCalledWith('APPLICATION', path, 'BLOCK', 'BOTH');
    expect(fw.appRules).toEqual({});
    expect(toasts[0]?.[0]).toBe(m.firewall_toast_traffic_blocked_title());
  });

  test('rolls back the optimistic override when the daemon rejects the block', async () => {
    const path = 'C:\\Apps\\chrome.exe';
    const { fw, client } = workspace({
      client: { addRule: mock(async () => false) },
    });
    await fw.toggleApp({ key: `Chrome::${path}`, name: 'Chrome', path });
    expect(client.addRule).toHaveBeenCalled();
    expect(fw.appRules).toEqual({});
    expect(fw.togglingAppKey).toBeNull();
  });
});

describe('FirewallWorkspace.confirmRemoveRule', () => {
  test('removes the pending network rule', async () => {
    const pending = rule({ id: 4, targetValue: 'ads.example' });
    const { fw, client, toasts } = workspace();
    fw.rulePendingRemoval = pending;
    fw.removeConfirmOpen = true;
    await fw.confirmRemoveRule();
    expect(client.removeRule).toHaveBeenCalledWith(4, 'DNS', 'ads.example', 'BLOCK');
    expect(fw.removeConfirmOpen).toBe(false);
    expect(toasts[0]?.[0]).toBe(m.firewall_toast_rule_removed_title());
  });

  test('unblocks the pending country', async () => {
    const pending = country({ id: 9, countryCode: 'DE' });
    const { fw, client } = workspace();
    fw.countryPendingRemoval = pending;
    fw.removeConfirmOpen = true;
    await fw.confirmRemoveRule();
    expect(client.removeCountryRule).toHaveBeenCalledWith(9, 'DE');
    expect(fw.countryPendingRemoval).toBeNull();
  });
});

describe('FirewallWorkspace lists', () => {
  test('filters visible apps from the summary snapshot', () => {
    const { fw } = workspace({
      appSummaries: [
        summary({ applicationName: 'Chrome', totalBytes: 10 }),
        summary({
          applicationName: 'Edge',
          applicationPath: 'C:\\Apps\\edge.exe',
          totalBytes: 50,
        }),
      ],
    });
    fw.debouncedQuery = 'edge';
    expect(fw.filteredApps.map((row) => row.name)).toEqual(['Edge']);
    expect(fw.visibleCount).toBe(1);
  });

  test('sorts the active list by the clicked column', () => {
    const { fw } = workspace({
      appSummaries: [
        summary({ applicationName: 'Zed', totalBytes: 10 }),
        summary({
          applicationName: 'Alpha',
          applicationPath: 'C:\\Apps\\alpha.exe',
          totalBytes: 50,
        }),
      ],
    });
    expect(fw.filteredApps.map((row) => row.name)).toEqual(['Alpha', 'Zed']);
    fw.toggleSort('app');
    expect(fw.activeSortKey).toBe('app');
    expect(fw.activeSortDir).toBe(-1);
    expect(fw.filteredApps.map((row) => row.name)).toEqual(['Zed', 'Alpha']);
    fw.toggleSort('app');
    expect(fw.filteredApps.map((row) => row.name)).toEqual(['Alpha', 'Zed']);
    fw.toggleSort('app');
    expect(fw.activeSortKey).toBeNull();
    expect(fw.filteredApps.map((row) => row.name)).toEqual(['Alpha', 'Zed']);
  });

  test('keeps a sort per list and exposes the matching column defs', () => {
    const { fw } = workspace({
      rules: [
        rule({ id: 1, targetType: 'DNS', targetValue: 'zeta.example' }),
        rule({ id: 2, targetType: 'DNS', targetValue: 'alpha.example' }),
      ],
    });
    fw.setListType('Domain');
    expect(fw.colDefs.map((col) => col.key)).toEqual(['target', 'action', 'direction', 'type']);
    fw.toggleSort('target');
    expect(fw.filteredRules.map((r) => r.id)).toEqual([1, 2]);
    fw.toggleSort('target');
    expect(fw.filteredRules.map((r) => r.id)).toEqual([2, 1]);
    fw.setListType('Application');
    expect(fw.activeSortKey).toBeNull();
  });
});
