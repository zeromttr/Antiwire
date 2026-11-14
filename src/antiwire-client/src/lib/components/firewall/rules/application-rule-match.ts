import type { Rule } from '#lib/types/index.ts';
import { hasApplicationPath } from '#lib/utils/application-path.ts';

/** True when a record/summary has a filesystem path the daemon can enforce. */
export function hasExecutablePath(path: string): boolean {
  return hasApplicationPath(path);
}

/** Canonical APPLICATION target: the executable path, or null if unusable. */
export function applicationRuleTarget(path: string): string | null {
  if (!hasExecutablePath(path)) return null;
  return path.trim();
}

function ruleTypeOf(rule: Rule): string {
  return (rule.targetType || '').toUpperCase();
}

function normalizeApplicationTarget(value: string): string {
  return value.trim().toLowerCase();
}

/** Last APPLICATION rule whose target equals the path. Matches daemon last-wins. */
export function findApplicationRule(rules: readonly Rule[], path: string): Rule | undefined {
  const wanted = applicationRuleTarget(path);
  if (!wanted) return undefined;
  const wantedLower = normalizeApplicationTarget(wanted);

  for (let index = rules.length - 1; index >= 0; index -= 1) {
    const rule = rules[index];
    if (!rule || ruleTypeOf(rule) !== 'APPLICATION') continue;
    if (normalizeApplicationTarget(rule.targetValue) === wantedLower) return rule;
  }
  return undefined;
}
