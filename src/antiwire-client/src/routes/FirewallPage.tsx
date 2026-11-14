// Reads a mutable workspace while rendering, so React Compiler must not
// cache it (see src/lib/state/compiler-opt-out.test.ts).
'use no memo';

import { Plus } from 'lucide-react';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import DaemonOffline from '#lib/components/shell/DaemonOffline.tsx';
import Button from '#lib/components/ui/Button.tsx';
import UnderlineTabs from '#lib/components/ui/UnderlineTabs.tsx';
import {
  pageAppKeys as collectPageAppKeys,
  type FirewallAppRow,
  type FirewallListType,
} from '#lib/components/firewall/list/firewall-list.ts';
import AddApplicationRuleModal from '#lib/components/firewall/dialogs/AddApplicationRuleModal.tsx';
import AddTargetRuleModal from '#lib/components/firewall/dialogs/AddTargetRuleModal.tsx';
import RemoveRuleDialog from '#lib/components/firewall/dialogs/RemoveRuleDialog.tsx';
import FirewallToolbar from '#lib/components/firewall/FirewallToolbar.tsx';
import FirewallLists from '#lib/components/firewall/FirewallLists.tsx';
import {
  FirewallWorkspace,
  type FirewallHost,
} from '#lib/components/firewall/firewall-workspace.ts';
import { shallowEqual, useReactive, useSelector } from '#lib/state/reactive.ts';
import { daemon } from '#lib/stores/daemon.ts';
import { api } from '#lib/api/daemon.ts';
import { m } from '#lib/i18n/messages.ts';
import styles from './FirewallPage.module.css';

const FW_SEARCH_DEBOUNCE_MS = 150;

const LIST_TAB_LABELS: Record<FirewallListType, () => string> = {
  Application: () => m.firewall_tab_applications(),
  Domain: () => m.firewall_tab_domains(),
  IP: () => m.firewall_tab_ips(),
  Country: () => m.firewall_tab_countries(),
};

/**
 * Writes a tracked workspace field (the former `bind:` target). The field's
 * setter notifies subscribers; a helper keeps the write out of render code.
 */
function setField<T extends object, K extends keyof T>(target: T, key: K, value: T[K]): void {
  target[key] = value;
}

// The host reads the daemon store directly, so it is stable for the page's
// lifetime; the page subscribes to the same slice below to re-render.
const firewallHost: FirewallHost = {
  get connected() {
    return daemon.state.connected;
  },
  get rules() {
    return daemon.state.rules ?? [];
  },
  get countryRules() {
    return daemon.state.countryRules ?? [];
  },
  get appSummaries() {
    return daemon.state.appSummaries ?? [];
  },
  get applicationRulesSupported() {
    return daemon.state.applicationRulesSupported;
  },
  refreshAll: () => daemon.refreshAll(),
  toast: (title, body, color) => daemon.addToast(title, body, color),
};

export default function FirewallPage() {
  const [fw] = useState(() => new FirewallWorkspace(api, firewallHost));
  useReactive(fw);
  const { connected } = useSelector(
    daemon,
    (d) => ({
      connected: d.state.connected,
      rules: d.state.rules,
      countryRules: d.state.countryRules,
      appSummaries: d.state.appSummaries,
      applicationRulesSupported: d.state.applicationRulesSupported,
    }),
    shallowEqual,
  );

  useEffect(() => () => fw.dispose(), [fw]);

  const query = fw.query;
  useEffect(() => {
    const timer = setTimeout(() => {
      setField(fw, 'debouncedQuery', query);
    }, FW_SEARCH_DEBOUNCE_MS);
    return () => clearTimeout(timer);
  }, [fw, query]);

  const { removeConfirmOpen, removingRuleId } = fw;
  useEffect(() => {
    if (!removeConfirmOpen && removingRuleId === null) {
      fw.clearPendingRemoval();
    }
  }, [fw, removeConfirmOpen, removingRuleId]);

  const loadedWhileConnected = useRef(false);
  useEffect(() => {
    if (!connected) {
      loadedWhileConnected.current = false;
      return;
    }
    if (loadedWhileConnected.current) return;
    loadedWhileConnected.current = true;
    void daemon.refreshAll();
    void fw.refreshSummaries();
  }, [fw, connected]);

  const onQueryChange = useCallback((next: string) => setField(fw, 'query', next), [fw]);
  const onToggleApp = useCallback(
    (app: Pick<FirewallAppRow, 'key' | 'name' | 'path'>) => void fw.toggleApp(app),
    [fw],
  );
  const onAddAppOpenChange = useCallback(
    (open: boolean) => setField(fw, 'addAppRuleOpen', open),
    [fw],
  );
  const onAddTargetOpenChange = useCallback(
    (open: boolean) => setField(fw, 'addTargetRuleOpen', open),
    [fw],
  );
  const onRemoveOpenChange = useCallback(
    (open: boolean) => setField(fw, 'removeConfirmOpen', open),
    [fw],
  );

  const listCounts = fw.listCounts;
  // Both are rebuilt on every read; keep their identity while the apps are unchanged.
  const summariesWithPath = fw.summariesWithPath;
  const addAppOptions = useMemo(
    () =>
      summariesWithPath.map((summary) => ({
        name: summary.applicationName || m.firewall_unknown_app(),
        path: summary.applicationPath,
      })),
    [summariesWithPath],
  );
  const pageAppKeys = useMemo(() => collectPageAppKeys(summariesWithPath), [summariesWithPath]);

  return (
    <>
      <div className={styles.page} data-testid="page-firewall" data-page-motion="firewall">
        <header className={styles['page-head']}>
          <h1>{m.nav_firewall()}</h1>
          {fw.connected && (
            <>
              {fw.showsApplications && (
                <p className={styles.sub}>
                  {m.firewall_page_sub({
                    apps: listCounts.Application,
                    blocked: fw.blockedAppCount,
                  })}
                </p>
              )}
              <div className={styles['head-actions']}>
                <Button variant="primary" onClick={fw.openAdd}>
                  <Plus size={14} strokeWidth={2} />
                  {fw.listType === 'Application'
                    ? m.firewall_add_application()
                    : m.firewall_add_rule()}
                </Button>
              </div>
            </>
          )}
        </header>

        {!fw.connected ? (
          <DaemonOffline text={m.firewall_empty_disconnected()} />
        ) : (
          <>
            <div className={styles.tabs} data-motion-stage="1">
              <UnderlineTabs
                tabs={fw.listTypes.map((type) => ({
                  value: type,
                  label: LIST_TAB_LABELS[type](),
                  count: listCounts[type],
                }))}
                value={fw.listType}
                ariaLabel={m.firewall_tabs_aria()}
                onChange={(next) => fw.setListType(next as FirewallListType)}
              />
            </div>
            <div className={styles['rules-section']} data-motion-stage="2">
              <FirewallToolbar
                query={fw.query}
                onQueryChange={onQueryChange}
                listType={fw.listType}
                filter={fw.filter}
                visibleCount={fw.visibleCount}
                onFilterChange={fw.setFilter}
              />
              <div key={fw.listType} className={styles['fw-view']}>
                <FirewallLists
                  listType={fw.listType}
                  apps={fw.filteredApps}
                  rules={fw.filteredRules}
                  countryRules={fw.filteredCountryRules}
                  emptyText={fw.listEmptyText}
                  connected={fw.connected}
                  togglingAppKey={fw.togglingAppKey}
                  removingRuleId={fw.removingRuleId}
                  colDefs={fw.colDefs}
                  sortKey={fw.activeSortKey}
                  sortDir={fw.activeSortDir}
                  onToggleSort={fw.toggleSort}
                  onToggleApp={onToggleApp}
                  onRemoveCountry={fw.requestRemoveCountry}
                  onRemoveRule={fw.requestRemoveRule}
                />
                {fw.listType === 'Application' && fw.filteredApps.length > 0 && (
                  <p className={styles.hint}>{m.firewall_apps_hint()}</p>
                )}
              </div>
            </div>
          </>
        )}
      </div>

      <AddApplicationRuleModal
        open={fw.addAppRuleOpen}
        onOpenChange={onAddAppOpenChange}
        applications={addAppOptions}
        excludedKeys={pageAppKeys}
        submitting={fw.addRuleSubmitting}
        onSubmit={fw.createRule}
        onError={fw.creationFailed}
      />

      <AddTargetRuleModal
        open={fw.addTargetRuleOpen}
        onOpenChange={onAddTargetOpenChange}
        initialRuleType={fw.addTargetType}
        submitting={fw.addRuleSubmitting}
        onSubmit={fw.createRule}
      />

      <RemoveRuleDialog
        open={fw.removeConfirmOpen}
        onOpenChange={onRemoveOpenChange}
        rule={fw.rulePendingRemoval}
        countryRule={fw.countryPendingRemoval}
        countryDisplay={fw.countryPendingLabel}
        submitting={fw.removeSubmitting}
        onConfirm={fw.confirmRemoveRule}
        onCancel={fw.cancelRemoveRule}
      />
    </>
  );
}
