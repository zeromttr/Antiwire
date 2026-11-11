/** Firewall app toggles must not apply optimistic state while offline or in-flight. */
export function canMutateFirewallRule(connected: boolean, inFlightKey: string | null): boolean {
  return connected && inFlightKey === null;
}
