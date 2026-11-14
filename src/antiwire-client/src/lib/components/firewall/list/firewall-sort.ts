import type { CountryRule, Rule } from '#lib/types/index.ts';
import { countryLabel, type FirewallAppRow } from './firewall-list';
import { ruleDirectionLabel } from '../form/rule-form';

export type FirewallSortKey =
  'app' | 'conns' | 'traffic' | 'action' | 'target' | 'direction' | 'type' | 'country' | 'networks';

export type FirewallSortState = {
  key: FirewallSortKey | null;
  dir: 1 | -1;
};

/**
 * Cycles a column like the records table: first click descending, second
 * ascending, third clears back to the list's natural order.
 */
export function nextFirewallSort(
  key: FirewallSortKey | null,
  dir: 1 | -1,
  clicked: FirewallSortKey,
): FirewallSortState {
  if (key !== clicked) return { key: clicked, dir: -1 };
  if (dir === -1) return { key, dir: 1 };
  return { key: null, dir: -1 };
}

function compareText(a: string, b: string): number {
  return a.localeCompare(b, undefined, { numeric: true, sensitivity: 'base' });
}

function compareNumber(a: number, b: number): number {
  return a - b;
}

function applySort<T>(
  rows: readonly T[],
  state: FirewallSortState,
  compare: (a: T, b: T, key: FirewallSortKey) => number,
): T[] {
  if (!state.key) return [...rows];
  const key = state.key;
  return [...rows].sort((a, b) => compare(a, b, key) * state.dir);
}

export function sortFirewallApps(
  rows: readonly FirewallAppRow[],
  state: FirewallSortState,
): FirewallAppRow[] {
  return applySort(rows, state, (a, b, key) => {
    switch (key) {
      case 'app':
        return compareText(a.name, b.name);
      case 'conns':
        return compareNumber(a.conns, b.conns);
      case 'traffic':
        return compareNumber(a.bytesReceived + a.bytesSent, b.bytesReceived + b.bytesSent);
      case 'action':
        return compareNumber(a.allow ? 0 : 1, b.allow ? 0 : 1);
      default:
        return 0;
    }
  });
}

export function sortNetworkRules(rules: readonly Rule[], state: FirewallSortState): Rule[] {
  return applySort(rules, state, (a, b, key) => {
    switch (key) {
      case 'target':
        return compareText(a.targetValue, b.targetValue);
      case 'action':
        return compareText(a.action, b.action);
      case 'direction':
        return compareText(ruleDirectionLabel(a.direction), ruleDirectionLabel(b.direction));
      case 'type':
        return compareText(a.targetType, b.targetType);
      default:
        return 0;
    }
  });
}

export function sortCountryRules(
  rules: readonly CountryRule[],
  state: FirewallSortState,
): CountryRule[] {
  return applySort(rules, state, (a, b, key) => {
    switch (key) {
      case 'country':
        return compareText(countryLabel(a), countryLabel(b));
      case 'action':
        return compareText(a.action, b.action);
      case 'direction':
        return compareText(ruleDirectionLabel(a.direction), ruleDirectionLabel(b.direction));
      case 'networks':
        return compareNumber(a.cidrCount, b.cidrCount);
      default:
        return 0;
    }
  });
}
