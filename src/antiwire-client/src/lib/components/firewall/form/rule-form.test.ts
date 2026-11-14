import { describe, expect, it } from 'bun:test';
import { pageRuleTypeToNetworkKind, ruleActions, ruleDirections } from './rule-form';

describe('rule form helpers', () => {
  it('exposes only the actions the daemon accepts', () => {
    expect(ruleActions).toEqual(['BLOCK', 'ALLOW']);
  });

  it('exposes every persisted direction', () => {
    expect(ruleDirections).toEqual(['OUTBOUND', 'INBOUND', 'BOTH']);
  });

  it('maps the page type picker to a network kind without inventing countries', () => {
    expect(pageRuleTypeToNetworkKind('Domain')).toBe('Domain');
    expect(pageRuleTypeToNetworkKind('IP')).toBe('IP');
    expect(pageRuleTypeToNetworkKind('App')).toBe('Domain');
  });
});
