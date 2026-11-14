import { describe, expect, it } from 'bun:test';
import { canMutateFirewallRule } from './app-toggle';

describe('canMutateFirewallRule', () => {
  it('allows a toggle only when the daemon is connected and no change is in flight', () => {
    expect(canMutateFirewallRule(true, null)).toBe(true);
    expect(canMutateFirewallRule(false, null)).toBe(false);
    expect(canMutateFirewallRule(true, 'app::path')).toBe(false);
    expect(canMutateFirewallRule(false, 'app::path')).toBe(false);
  });
});
