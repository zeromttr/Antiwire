export type ActionFilter = 'all' | 'allowed' | 'blocked';

/** True when a stored rule action matches the All / Allowed / Blocked control. */
export function matchesActionFilter(action: string, filter: ActionFilter): boolean {
  if (filter === 'all') return true;
  const blocked = action.toLowerCase().includes('block');
  return filter === 'blocked' ? blocked : !blocked;
}
