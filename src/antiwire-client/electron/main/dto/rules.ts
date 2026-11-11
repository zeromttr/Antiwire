import type { RulesResponse } from '../daemon/messages';
import { pick } from './pick';

export function rulesToDto(r: RulesResponse) {
  return r.rules.map((rule) =>
    pick(rule, ['id', 'targetType', 'targetValue', 'action', 'direction'] as const),
  );
}

/** A country block as the UI sees it: one row, with a count rather than the networks themselves. */
export function countryRulesToDto(r: RulesResponse) {
  return r.countryRules.map((rule) =>
    pick(rule, ['id', 'countryCode', 'action', 'direction', 'cidrCount'] as const),
  );
}
