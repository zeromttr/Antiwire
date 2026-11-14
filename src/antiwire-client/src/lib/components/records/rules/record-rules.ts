import {
  applicationRuleTarget,
  findApplicationRule,
  hasExecutablePath,
} from '#lib/components/firewall/rules/application-rule-match.ts';
import { isValidDomain, isValidIp } from '#lib/utils/network-target.ts';
import type { ConnectionLog, Rule, RuleDirection } from '#lib/types/index.ts';

export { applicationRuleTarget, findApplicationRule, hasExecutablePath };

export type RecordRuleKind = 'application' | 'domain' | 'ip';

export type RecordRulePlan =
  | {
      op: 'add';
      kind: RecordRuleKind;
      targetType: 'APPLICATION' | 'DNS' | 'IP';
      targetValue: string;
      action: 'BLOCK';
      direction: RuleDirection;
    }
  | {
      op: 'remove';
      kind: RecordRuleKind;
      rule: Rule;
    };

function ruleTypeOf(rule: Rule): string {
  return (rule.targetType || '').toUpperCase();
}

export function normalizeDomainTarget(value: string): string {
  return value.trim().replace(/\.+$/, '').toLowerCase();
}

export function normalizeIpTarget(value: string): string {
  return value
    .trim()
    .toLowerCase()
    .replace(/\/32$/, '')
    .replace(/\/128$/, '');
}

export function recordRuleTarget(kind: RecordRuleKind, record: ConnectionLog): string {
  if (kind === 'application') {
    return applicationRuleTarget(record.applicationPath) ?? '';
  }
  if (kind === 'domain') return normalizeDomainTarget(record.domain);
  return normalizeIpTarget(record.destinationIp);
}

export function canTargetRecordRule(kind: RecordRuleKind, record: ConnectionLog): boolean {
  if (kind === 'application') return hasExecutablePath(record.applicationPath);
  const target = recordRuleTarget(kind, record);
  if (!target) return false;
  if (kind === 'domain') return isValidDomain(target);
  if (kind === 'ip') return isValidIp(target);
  return true;
}

export function isBlockingRule(rule: Rule | undefined): boolean {
  return Boolean(rule && rule.action.toLowerCase().includes('block'));
}

function lastMatchingRule(
  rules: readonly Rule[],
  type: 'DNS' | 'IP',
  matches: (value: string) => boolean,
): Rule | undefined {
  for (let index = rules.length - 1; index >= 0; index -= 1) {
    const rule = rules[index];
    if (!rule || ruleTypeOf(rule) !== type) continue;
    if (matches(rule.targetValue)) return rule;
  }
  return undefined;
}

export function findDomainRule(rules: readonly Rule[], domain: string): Rule | undefined {
  const wanted = normalizeDomainTarget(domain);
  if (!wanted) return undefined;
  return lastMatchingRule(rules, 'DNS', (value) => normalizeDomainTarget(value) === wanted);
}

export function findIpRule(rules: readonly Rule[], ip: string): Rule | undefined {
  const wanted = normalizeIpTarget(ip);
  if (!wanted) return undefined;
  return lastMatchingRule(rules, 'IP', (value) => normalizeIpTarget(value) === wanted);
}

export function findRecordRule(
  kind: RecordRuleKind,
  record: ConnectionLog,
  rules: readonly Rule[],
): Rule | undefined {
  if (kind === 'application') {
    return findApplicationRule(rules, record.applicationPath);
  }
  if (kind === 'domain') return findDomainRule(rules, record.domain);
  return findIpRule(rules, record.destinationIp);
}

export function planRecordRuleToggle(
  kind: RecordRuleKind,
  record: ConnectionLog,
  rules: readonly Rule[],
): RecordRulePlan | null {
  if (!canTargetRecordRule(kind, record)) return null;

  const existing = findRecordRule(kind, record, rules);
  if (isBlockingRule(existing) && existing) {
    return { op: 'remove', kind, rule: existing };
  }

  const targetValue = recordRuleTarget(kind, record);
  if (kind === 'application') {
    return {
      op: 'add',
      kind,
      targetType: 'APPLICATION',
      targetValue,
      action: 'BLOCK',
      direction: 'BOTH',
    };
  }
  if (kind === 'domain') {
    return {
      op: 'add',
      kind,
      targetType: 'DNS',
      targetValue,
      action: 'BLOCK',
      direction: 'OUTBOUND',
    };
  }
  return {
    op: 'add',
    kind,
    targetType: 'IP',
    targetValue,
    action: 'BLOCK',
    direction: 'OUTBOUND',
  };
}
