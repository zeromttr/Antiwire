import { api } from '#lib/api/daemon.ts';
import type { AppSummary, CountryRule, Rule } from '#lib/types/index.ts';
import { hasApplicationPath } from '#lib/utils/application-path.ts';
import { m } from '#lib/i18n/messages.ts';
import type { ActionFilter } from './list/action-filter';
import { applicationRuleTarget, findApplicationRule } from './rules/application-rule-match';
import { canMutateFirewallRule } from './rules/app-toggle';
import {
  addTargetInitialType,
  countryLabel,
  filterCountryRules,
  filterFirewallApps,
  filterNetworkRules,
  firewallColumnDefs,
  firewallListCounts,
  firewallListEmptyText,
  pageAppKeys as collectPageAppKeys,
  resolveAppRuleAction,
  visibleFirewallCount,
  type FirewallAppRow,
  type FirewallColumnDef,
  type FirewallListType,
} from './list/firewall-list';
import {
  nextFirewallSort,
  sortCountryRules,
  sortFirewallApps,
  sortNetworkRules,
  type FirewallSortKey,
  type FirewallSortState,
} from './list/firewall-sort';
import type { RuleFormPayload } from './form/rule-form';
import { TrackedReactive } from '#lib/state/tracked.ts';

export type FirewallApiClient = Pick<
  typeof api,
  'addRule' | 'removeRule' | 'addCountryRule' | 'removeCountryRule' | 'getAppSummaries'
>;

export type FirewallHost = {
  readonly connected: boolean;
  readonly rules: readonly Rule[];
  readonly countryRules: readonly CountryRule[];
  readonly appSummaries: readonly AppSummary[];
  refreshAll(): Promise<void>;
  toast(title: string, body: string, color: string): void;
};

/**
 * Firewall route state and daemon writes. The page owns connect/search
 * effects and the presentational lists; this class owns filters, dialogs,
 * and mutations so those stay testable without a DOM.
 */
export class FirewallWorkspace extends TrackedReactive {
  listType: FirewallListType = 'Application';
  query = '';
  debouncedQuery = '';
  filter: ActionFilter = 'all';
  sortStates: Record<FirewallListType, FirewallSortState> = {
    Application: { key: null, dir: -1 },
    Domain: { key: null, dir: -1 },
    IP: { key: null, dir: -1 },
    Country: { key: null, dir: -1 },
  };
  appRules: Record<string, string> = {};
  togglingAppKey: string | null = null;
  addAppRuleOpen = false;
  addTargetRuleOpen = false;
  addRuleSubmitting = false;
  removingRuleId: number | null = null;
  removeConfirmOpen = false;
  rulePendingRemoval: Rule | null = null;
  countryPendingRemoval: CountryRule | null = null;
  fwAppSummaries: AppSummary[] | null = null;

  get connected() {
    return this.host.connected;
  }

  get summaries() {
    return this.fwAppSummaries ?? this.host.appSummaries;
  }

  get summariesWithPath() {
    const summaries = this.summaries;
    return this.memo('summariesWithPath', [summaries], () =>
      summaries.filter((summary) => hasApplicationPath(summary.applicationPath ?? '')),
    );
  }

  get rules() {
    return this.host.rules;
  }

  get countryRules() {
    return this.host.countryRules;
  }

  // The lists below are read several times per render (the list, its count,
  // the tab badges), so each is memoized on the values it is computed from.
  get filteredApps() {
    const { summariesWithPath, rules, debouncedQuery: query, filter, appRules: optimistic } = this;
    const sort = this.sortStates.Application;
    return this.memo(
      'filteredApps',
      [summariesWithPath, rules, query, filter, optimistic, sort],
      () =>
        sortFirewallApps(
          filterFirewallApps(summariesWithPath, rules, { query, filter, optimistic }),
          sort,
        ),
    );
  }

  get filteredRules() {
    const { rules, listType, filter, debouncedQuery } = this;
    const sort = this.sortStates[listType];
    return this.memo('filteredRules', [rules, listType, filter, debouncedQuery, sort], () =>
      sortNetworkRules(filterNetworkRules(rules, listType, filter, debouncedQuery), sort),
    );
  }

  get filteredCountryRules() {
    const { countryRules, filter, debouncedQuery } = this;
    const sort = this.sortStates.Country;
    return this.memo('filteredCountryRules', [countryRules, filter, debouncedQuery, sort], () =>
      sortCountryRules(filterCountryRules(countryRules, filter, debouncedQuery), sort),
    );
  }

  /** Every application with its access resolved, ignoring search and filter. */
  get allApps() {
    const { summariesWithPath, rules, appRules: optimistic } = this;
    return this.memo('allApps', [summariesWithPath, rules, optimistic], () =>
      filterFirewallApps(summariesWithPath, rules, { query: '', filter: 'all', optimistic }),
    );
  }

  get listCounts() {
    return firewallListCounts(this.allApps, this.rules, this.countryRules);
  }

  get blockedAppCount() {
    return this.allApps.filter((app) => !app.allow).length;
  }

  get colDefs(): FirewallColumnDef[] {
    return firewallColumnDefs(this.listType);
  }

  get activeSortKey(): FirewallSortKey | null {
    return this.sortStates[this.listType].key;
  }

  get activeSortDir(): 1 | -1 {
    return this.sortStates[this.listType].dir;
  }

  get listEmptyText() {
    return firewallListEmptyText({
      listType: this.listType,
      query: this.debouncedQuery,
      filter: this.filter,
      summaryCount: this.summaries.length,
      summaryWithPathCount: this.summariesWithPath.length,
    });
  }

  get visibleCount() {
    return visibleFirewallCount(
      this.listType,
      this.filteredApps,
      this.filteredRules,
      this.filteredCountryRules,
    );
  }

  get addTargetType() {
    return addTargetInitialType(this.listType);
  }

  get pageAppKeys() {
    return collectPageAppKeys(this.summariesWithPath);
  }

  get addAppOptions() {
    return this.summariesWithPath.map((summary) => ({
      name: summary.applicationName || m.firewall_unknown_app(),
      path: summary.applicationPath,
    }));
  }

  get countryPendingLabel() {
    return this.countryPendingRemoval ? countryLabel(this.countryPendingRemoval) : '';
  }

  get removeSubmitting() {
    return this.removingRuleId !== null;
  }

  constructor(
    private readonly client: FirewallApiClient,
    private readonly host: FirewallHost,
  ) {
    super();
    this.track(
      'listType',
      'query',
      'debouncedQuery',
      'filter',
      'sortStates',
      'appRules',
      'togglingAppKey',
      'addAppRuleOpen',
      'addTargetRuleOpen',
      'addRuleSubmitting',
      'removingRuleId',
      'removeConfirmOpen',
      'rulePendingRemoval',
      'countryPendingRemoval',
      'fwAppSummaries',
    );
  }

  /** Nothing to release: the page owns the search debounce. */
  dispose = () => {};

  setListType = (next: FirewallListType) => {
    if (next === this.listType) return;
    this.addAppRuleOpen = false;
    this.addTargetRuleOpen = false;
    this.removeConfirmOpen = false;
    this.rulePendingRemoval = null;
    this.countryPendingRemoval = null;
    this.listType = next;
  };

  setFilter = (next: ActionFilter) => {
    this.filter = next;
  };

  toggleSort = (key: FirewallSortKey) => {
    const current = this.sortStates[this.listType];
    this.sortStates = {
      ...this.sortStates,
      [this.listType]: nextFirewallSort(current.key, current.dir, key),
    };
  };

  openAdd = () => {
    if (this.listType === 'Application') {
      this.addTargetRuleOpen = false;
      this.addAppRuleOpen = true;
      return;
    }
    this.addAppRuleOpen = false;
    this.addTargetRuleOpen = true;
  };

  creationFailed = (message: string) => {
    this.host.toast(m.firewall_toast_rule_creation_failed_title(), message, 'var(--bad)');
  };

  clearPendingRemoval = () => {
    this.rulePendingRemoval = null;
    this.countryPendingRemoval = null;
  };

  requestRemoveCountry = (rule: CountryRule) => {
    if (!this.connected || this.removingRuleId !== null) return;
    this.rulePendingRemoval = null;
    this.countryPendingRemoval = rule;
    this.removeConfirmOpen = true;
  };

  requestRemoveRule = (rule: Rule) => {
    if (!this.connected || this.removingRuleId !== null) return;
    this.countryPendingRemoval = null;
    this.rulePendingRemoval = rule;
    this.removeConfirmOpen = true;
  };

  cancelRemoveRule = () => {
    this.clearPendingRemoval();
  };

  confirmRemoveRule = async () => {
    if (this.countryPendingRemoval) {
      await this.removeCountryRule(this.countryPendingRemoval);
    } else if (this.rulePendingRemoval) {
      await this.removeNetworkRule(this.rulePendingRemoval);
    }
    this.removeConfirmOpen = false;
    this.clearPendingRemoval();
  };

  createRule = async (payload: RuleFormPayload) => {
    if (!this.connected || this.addRuleSubmitting) return;

    this.addRuleSubmitting = true;
    try {
      if (payload.kind === 'country') {
        const result = await this.client.addCountryRule(
          payload.countryCode,
          payload.cidrs,
          payload.action,
          payload.direction,
        );
        if (!result.success) {
          this.host.toast(
            m.firewall_toast_country_not_blocked_title(),
            result.message || m.firewall_toast_daemon_rejected_rule(),
            'var(--bad)',
          );
          return;
        }

        await this.host.refreshAll();
        this.addTargetRuleOpen = false;
        this.host.toast(
          m.firewall_toast_country_blocked_title({ country: payload.countryName }),
          m.firewall_toast_country_blocked_body({
            action: payload.action,
            direction: payload.direction.toLowerCase(),
            count: payload.cidrs.length.toLocaleString(),
          }),
          payload.action === 'BLOCK' ? 'var(--bad)' : 'var(--ok)',
        );
        return;
      }

      const ok = await this.client.addRule(
        payload.targetType,
        payload.targetValue,
        payload.action,
        payload.direction,
      );
      if (!ok) {
        this.host.toast(
          m.firewall_toast_rule_not_created_title(),
          m.firewall_toast_daemon_rejected_rule(),
          'var(--bad)',
        );
        return;
      }

      await this.host.refreshAll();
      this.addAppRuleOpen = false;
      this.addTargetRuleOpen = false;
      this.host.toast(
        m.firewall_toast_rule_created_title(),
        m.firewall_toast_rule_created_body({
          action: payload.action,
          direction: payload.direction.toLowerCase(),
          type: payload.targetType.toLowerCase(),
          target: payload.targetValue,
        }),
        payload.action === 'BLOCK' ? 'var(--bad)' : 'var(--ok)',
      );
    } catch {
      this.host.toast(
        m.firewall_toast_rule_creation_failed_title(),
        m.firewall_toast_could_not_sync(),
        'var(--bad)',
      );
    } finally {
      this.addRuleSubmitting = false;
    }
  };

  toggleApp = async (app: Pick<FirewallAppRow, 'key' | 'name' | 'path'>) => {
    if (!canMutateFirewallRule(this.connected, this.togglingAppKey)) return;

    const targetValue = applicationRuleTarget(app.path);
    if (!targetValue) return;

    const current = resolveAppRuleAction(app.key, app.name, app.path, this.rules, this.appRules);
    const next = current === 'allow' ? 'block' : 'allow';

    this.appRules = { ...this.appRules, [app.key]: next };
    this.togglingAppKey = app.key;

    try {
      if (next === 'block') {
        const ok = await this.client.addRule('APPLICATION', targetValue, 'BLOCK', 'BOTH');
        if (!ok) {
          throw new Error('daemon rejected rule');
        }
      } else {
        const existing = findApplicationRule(this.rules, app.path);
        if (existing) {
          await this.client.removeRule(
            existing.id,
            existing.targetType,
            existing.targetValue,
            existing.action,
          );
        } else {
          void this.host.refreshAll();
          throw new Error('Active firewall rule not found; state resynchronized from daemon');
        }
      }

      await this.host.refreshAll();
      await this.refreshSummaries();
      const { [app.key]: _, ...rest } = this.appRules;
      this.appRules = rest;
      this.host.toast(
        next === 'block'
          ? m.firewall_toast_traffic_blocked_title()
          : m.firewall_toast_traffic_allowed_title(),
        m.firewall_toast_rule_updated_body({ name: app.name }),
        next === 'block' ? 'var(--bad)' : 'var(--ok)',
      );
    } catch {
      const { [app.key]: _, ...rest } = this.appRules;
      this.appRules = rest;
      this.host.toast(
        m.firewall_toast_rule_update_failed_title(),
        m.firewall_toast_could_not_sync(),
        'var(--bad)',
      );
    } finally {
      this.togglingAppKey = null;
    }
  };

  refreshSummaries = async () => {
    if (!this.connected) return;
    try {
      // No time window: a rule can target any application ever seen, not just
      // the ones active recently, and this must match the Records app list.
      const page = await this.client.getAppSummaries();
      this.fwAppSummaries = page.applications ?? [];
    } catch {
      // Keep the last loaded snapshot on transient failures.
    }
  };

  private removeCountryRule = async (rule: CountryRule) => {
    if (!this.connected || this.removingRuleId !== null) return;
    this.removingRuleId = rule.id;
    try {
      const result = await this.client.removeCountryRule(rule.id, rule.countryCode);
      if (!result.success) {
        this.host.toast(
          m.firewall_toast_country_not_unblocked_title(),
          result.message || m.firewall_toast_daemon_rejected_removal(),
          'var(--bad)',
        );
        return;
      }
      await this.host.refreshAll();
      this.host.toast(m.firewall_toast_country_unblocked_title(), countryLabel(rule), 'var(--t2)');
    } catch {
      this.host.toast(
        m.firewall_toast_removal_failed_title(),
        m.firewall_toast_could_not_sync(),
        'var(--bad)',
      );
    } finally {
      this.removingRuleId = null;
    }
  };

  private removeNetworkRule = async (rule: Rule) => {
    if (!this.connected || this.removingRuleId !== null) return;
    this.removingRuleId = rule.id;
    try {
      await this.client.removeRule(rule.id, rule.targetType, rule.targetValue, rule.action);
      await this.host.refreshAll();
      this.host.toast(m.firewall_toast_rule_removed_title(), rule.targetValue, 'var(--t2)');
    } catch {
      this.host.toast(
        m.firewall_toast_rule_removal_failed_title(),
        m.firewall_toast_could_not_sync(),
        'var(--bad)',
      );
    } finally {
      this.removingRuleId = null;
    }
  };
}
