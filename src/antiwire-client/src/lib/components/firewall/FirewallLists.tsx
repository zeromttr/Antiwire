import clsx from 'clsx';
import { ArrowUpRight, Trash2 } from 'lucide-react';
import { memo, useCallback, useMemo, type MouseEvent } from 'react';
import Status from '#lib/components/ui/Status.tsx';
import Button from '#lib/components/ui/Button.tsx';
import Tooltip from '#lib/components/ui/Tooltip.tsx';
import VirtualScrollList from '#lib/components/ui/VirtualScrollList.tsx';
import AppAvatar from '#lib/components/ui/AppAvatar.tsx';
import EmptyState from '#lib/components/ui/EmptyState.tsx';
import Toggle from '#lib/components/ui/Toggle.tsx';
import { displayText } from '#lib/utils/index.ts';
import { recordsApplicationUrl } from '#lib/utils/records-url.ts';
import { navigate } from '#lib/navigation.ts';
import { m } from '#lib/i18n/messages.ts';
import type { CountryRule, Rule } from '#lib/types/index.ts';
import { hasExecutablePath } from './rules/application-rule-match';
import { ruleDirectionLabel } from './form/rule-form';
import {
  APP_GRID_COLUMNS,
  APP_ROW_HEIGHT,
  RULE_GRID_COLUMNS,
  RULE_ROW_HEIGHT,
  canRemoveFirewallRules,
  countryLabel,
  firewallAppKey,
  firewallCountryRuleKey,
  firewallRuleKey,
  type FirewallAppRow,
  type FirewallColumnDef,
  type FirewallListType,
} from './list/firewall-list';
import type { FirewallSortKey } from './list/firewall-sort';
import styles from './FirewallLists.module.css';

type ToggleableApp = Pick<FirewallAppRow, 'key' | 'name' | 'path'>;

interface Props {
  listType: FirewallListType;
  apps: readonly FirewallAppRow[];
  rules: readonly Rule[];
  countryRules: readonly CountryRule[];
  emptyText: string;
  connected: boolean;
  togglingAppKey: string | null;
  removingRuleId: number | null;
  colDefs: FirewallColumnDef[];
  sortKey: FirewallSortKey | null;
  sortDir: 1 | -1;
  onToggleSort: (key: FirewallSortKey) => void;
  onToggleApp: (app: ToggleableApp) => void;
  onRemoveCountry: (rule: CountryRule) => void;
  onRemoveRule: (rule: Rule) => void;
}

const APP_GRID = { gridTemplateColumns: APP_GRID_COLUMNS };
const RULE_GRID = { gridTemplateColumns: RULE_GRID_COLUMNS };

function isBlock(action: string): boolean {
  return action.toLowerCase().includes('block');
}

function actionLabel(action: string): string {
  return isBlock(action) ? m.firewall_badge_blocked() : m.firewall_badge_allowed();
}

/** In-app link: route through the router instead of reloading the document. */
function followLink(event: MouseEvent<HTMLAnchorElement>) {
  if (event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) {
    return;
  }
  event.preventDefault();
  navigate(event.currentTarget.getAttribute('href') ?? '/');
}

const AppRow = memo(function AppRow({
  app,
  maxTraffic,
  connected,
  toggling,
  onToggleApp,
}: {
  app: FirewallAppRow;
  maxTraffic: number;
  connected: boolean;
  toggling: boolean;
  onToggleApp: (app: ToggleableApp) => void;
}) {
  const name = displayText(app.name);
  return (
    <div className={clsx(styles['rules-row'], styles['app-row'])} style={APP_GRID}>
      <div className={styles['app-identity']}>
        <span className={styles['fw-avatar']}>
          <AppAvatar name={app.name} path={app.path} size={28} className={styles.avatar} />
        </span>
        <div className={styles['app-meta']}>
          <div className={styles['app-name']}>{name}</div>
          {app.path && (
            <div className={clsx('mono', styles['app-path'])}>
              <Tooltip text={displayText(app.path)} label={m.firewall_tooltip_application_path()}>
                {displayText(app.path)}
              </Tooltip>
            </div>
          )}
        </div>
      </div>
      <span className={clsx('num', styles.conns)}>{app.conns.toLocaleString()}</span>
      <div className={clsx(styles.traffic, !app.allow && styles.muted)}>
        <span
          className={styles['traffic-bar']}
          style={{ width: `${((app.bytesReceived + app.bytesSent) / maxTraffic) * 100}%` }}
          aria-hidden="true"
        >
          <span className={styles.in} style={{ flexGrow: app.bytesReceived }}></span>
          <span className={styles.out} style={{ flexGrow: app.bytesSent }}></span>
        </span>
        <span className={styles['traffic-text']}>
          {m.firewall_traffic_in_out({ in: app.inbound, out: app.outbound })}
        </span>
      </div>
      <div className={styles.access}>
        {app.allow ? (
          <Status tone="ok" quiet>
            {app.ruleLabel}
          </Status>
        ) : (
          <Status tone="bad">{app.ruleLabel}</Status>
        )}
        <Toggle
          checked={app.allow}
          disabled={!connected || toggling || !hasExecutablePath(app.path)}
          ariaLabel={m.firewall_toggle_app_aria({ name })}
          onCheckedChange={() => onToggleApp({ key: app.key, name: app.name, path: app.path })}
        />
      </div>
      <span className={styles['row-action']}>
        <Button
          variant="ghost"
          size="sm"
          iconOnly
          href={recordsApplicationUrl(app.name)}
          onClick={followLink}
          aria-label={m.firewall_view_connections_aria({ name })}
          title={m.firewall_view_connections_aria({ name })}
        >
          <ArrowUpRight size={15} strokeWidth={1.9} />
        </Button>
      </span>
    </div>
  );
});

const CountryRuleRow = memo(function CountryRuleRow({
  rule,
  removing,
  onRemoveCountry,
}: {
  rule: CountryRule;
  removing: boolean;
  onRemoveCountry: (rule: CountryRule) => void;
}) {
  return (
    <div className={styles['rules-row']} style={RULE_GRID}>
      <span className={styles.target}>{countryLabel(rule)}</span>
      <span>
        <Status tone={isBlock(rule.action) ? 'bad' : 'ok'}>{actionLabel(rule.action)}</Status>
      </span>
      <span className={styles.dim}>{ruleDirectionLabel(rule.direction)}</span>
      <span className={styles.dim}>{rule.cidrCount.toLocaleString()}</span>
      <Button
        variant="ghost"
        size="sm"
        iconOnly
        aria-label={m.firewall_unblock_country_aria({ label: countryLabel(rule) })}
        disabled={removing}
        onClick={() => onRemoveCountry(rule)}
      >
        <Trash2 size={14} strokeWidth={1.75} />
      </Button>
    </div>
  );
});

const NetworkRuleRow = memo(function NetworkRuleRow({
  rule,
  removing,
  canRemove,
  onRemoveRule,
}: {
  rule: Rule;
  removing: boolean;
  canRemove: boolean;
  onRemoveRule: (rule: Rule) => void;
}) {
  return (
    <div className={styles['rules-row']} style={RULE_GRID}>
      <span className={clsx('mono', styles.target)}>{displayText(rule.targetValue)}</span>
      <span>
        <Status tone={isBlock(rule.action) ? 'bad' : 'ok'}>{actionLabel(rule.action)}</Status>
      </span>
      <span className={styles.dim}>{ruleDirectionLabel(rule.direction)}</span>
      <span className={styles.dim}>{rule.targetType}</span>
      {canRemove && (
        <Button
          variant="ghost"
          size="sm"
          iconOnly
          aria-label={m.firewall_remove_rule_aria({ target: displayText(rule.targetValue) })}
          disabled={removing}
          onClick={() => onRemoveRule(rule)}
        >
          <Trash2 size={14} strokeWidth={1.75} />
        </Button>
      )}
    </div>
  );
});

export function FirewallLists({
  listType,
  apps,
  rules,
  countryRules,
  emptyText,
  connected,
  togglingAppKey,
  removingRuleId,
  colDefs,
  sortKey,
  sortDir,
  onToggleSort,
  onToggleApp,
  onRemoveCountry,
  onRemoveRule,
}: Props) {
  const canRemoveRules = canRemoveFirewallRules(listType);
  /** Traffic bars share one scale: the busiest application fills the column. */
  const maxTraffic = useMemo(
    () => Math.max(1, ...apps.map((app) => app.bytesReceived + app.bytesSent)),
    [apps],
  );

  const appRow = useCallback(
    ({ item }: { item: FirewallAppRow }) => (
      <AppRow
        app={item}
        maxTraffic={maxTraffic}
        connected={connected}
        toggling={togglingAppKey === item.key}
        onToggleApp={onToggleApp}
      />
    ),
    [maxTraffic, connected, togglingAppKey, onToggleApp],
  );

  const countryRuleRow = useCallback(
    ({ item }: { item: CountryRule }) => (
      <CountryRuleRow
        rule={item}
        removing={removingRuleId === item.id}
        onRemoveCountry={onRemoveCountry}
      />
    ),
    [removingRuleId, onRemoveCountry],
  );

  const networkRuleRow = useCallback(
    ({ item }: { item: Rule }) => (
      <NetworkRuleRow
        rule={item}
        removing={removingRuleId === item.id}
        canRemove={canRemoveRules}
        onRemoveRule={onRemoveRule}
      />
    ),
    [removingRuleId, canRemoveRules, onRemoveRule],
  );

  const listEmpty = <EmptyState text={emptyText} compact />;

  const sortHeaders = colDefs.map((col) => (
    <button
      key={col.key}
      type="button"
      className={styles.th}
      style={{ color: sortKey === col.key ? 'var(--t1)' : 'var(--t3)' }}
      onClick={() => onToggleSort(col.key)}
    >
      {col.label}
      <span className={styles.arrow}>{sortKey === col.key ? (sortDir === 1 ? '▲' : '▼') : ''}</span>
    </button>
  ));

  if (listType === 'Application') {
    return (
      <div className={clsx(styles['rules-table'], 'panel')}>
        <div className={styles['rules-thead']} style={APP_GRID}>
          {sortHeaders}
          <span className={styles['sr-only']}>
            {m.firewall_toggle_app_aria({ name: m.firewall_tab_applications() })}
          </span>
        </div>
        <VirtualScrollList
          items={apps}
          estimateSize={APP_ROW_HEIGHT}
          getItemKey={firewallAppKey}
          row={appRow}
          empty={listEmpty}
        />
      </div>
    );
  }

  if (listType === 'Country') {
    return (
      <div className={clsx(styles['rules-table'], 'panel')}>
        <div className={styles['rules-thead']} style={RULE_GRID}>
          {sortHeaders}
          <span className={styles['sr-only']}>{m.firewall_col_remove_sr()}</span>
        </div>
        {/* One row per country, never one per network: a large
            country covers tens of thousands of them. */}
        <VirtualScrollList
          items={countryRules}
          estimateSize={RULE_ROW_HEIGHT}
          getItemKey={firewallCountryRuleKey}
          row={countryRuleRow}
          empty={listEmpty}
        />
      </div>
    );
  }

  return (
    <div className={clsx(styles['rules-table'], 'panel')}>
      <div className={styles['rules-thead']} style={RULE_GRID}>
        {sortHeaders}
        {canRemoveRules && <span className={styles['sr-only']}>{m.firewall_col_remove_sr()}</span>}
      </div>
      <VirtualScrollList
        items={rules}
        estimateSize={RULE_ROW_HEIGHT}
        getItemKey={firewallRuleKey}
        row={networkRuleRow}
        empty={listEmpty}
      />
    </div>
  );
}

export default FirewallLists;
