import { m } from '#lib/i18n/messages.ts';
import type { RuleDirection } from '#lib/types/index.ts';

export type RuleFormAction = 'ALLOW' | 'BLOCK';

export const ruleActions: RuleFormAction[] = ['BLOCK', 'ALLOW'];

export function ruleActionLabel(action: RuleFormAction): string {
  return action === 'BLOCK' ? m.firewall_action_block() : m.firewall_action_allow();
}

export function ruleActionDescription(action: RuleFormAction): string {
  return action === 'BLOCK' ? m.firewall_action_block_desc() : m.firewall_action_allow_desc();
}

/**
 * A rule the user submitted.
 *
 * Discriminated so a country block can carry its code — the old shape flattened
 * countries into a plain IP rule plus a `bulkTargets` array, which meant the
 * daemon never learned which country the networks belonged to and could not
 * group, list, or remove them as one thing.
 */
export type RuleFormPayload =
  | {
      kind: 'target';
      targetType: string;
      targetValue: string;
      action: RuleFormAction;
      direction: RuleDirection;
    }
  | {
      kind: 'country';
      countryCode: string;
      countryName: string;
      cidrs: string[];
      action: RuleFormAction;
      direction: RuleDirection;
    };

export const ruleDirections: RuleDirection[] = ['OUTBOUND', 'INBOUND', 'BOTH'];

export function ruleDirectionLabel(direction: RuleDirection): string {
  switch (direction) {
    case 'OUTBOUND':
      return m.firewall_direction_outbound();
    case 'INBOUND':
      return m.firewall_direction_inbound();
    case 'BOTH':
      return m.firewall_direction_both();
  }
}

export function ruleDirectionDescription(direction: RuleDirection): string {
  switch (direction) {
    case 'OUTBOUND':
      return m.firewall_direction_outbound_desc();
    case 'INBOUND':
      return m.firewall_direction_inbound_desc();
    case 'BOTH':
      return m.firewall_direction_both_desc();
  }
}

export type NetworkRuleKind = 'Domain' | 'IP' | 'CIDR' | 'Country';

export type RuleFormType = 'App' | 'Domain' | 'IP';

export function networkRuleKindLabel(kind: NetworkRuleKind): string {
  switch (kind) {
    case 'Domain':
      return m.firewall_kind_domain();
    case 'IP':
      return m.firewall_kind_ip();
    case 'CIDR':
      return m.firewall_kind_cidr();
    case 'Country':
      return m.firewall_kind_country();
  }
}

export function networkRulePlaceholder(kind: Exclude<NetworkRuleKind, 'Country'>): string {
  switch (kind) {
    case 'Domain':
      return m.firewall_placeholder_domain();
    case 'IP':
      return m.firewall_placeholder_ip();
    case 'CIDR':
      return m.firewall_placeholder_cidr();
  }
}

export function pageRuleTypeToNetworkKind(ruleType: RuleFormType): NetworkRuleKind {
  if (ruleType === 'Domain') return 'Domain';
  if (ruleType === 'IP') return 'IP';
  return 'Domain';
}
