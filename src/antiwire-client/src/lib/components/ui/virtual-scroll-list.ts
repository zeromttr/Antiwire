export type VirtualItemKey = string | number;

export type VirtualItemKeyFn<T> = (item: T, index: number) => VirtualItemKey;

/**
 * Resolves the React key for a TanStack virtual row.
 * Falls back to index when the item is gone or the caller did not supply a key.
 * `0` is a valid key (rule ids); only nullish / empty-string results are rejected.
 */
export function resolveVirtualItemKey<T>(
  index: number,
  items: readonly T[],
  getItemKey?: VirtualItemKeyFn<T>,
): VirtualItemKey {
  const item = items[index];
  if (item === undefined || !getItemKey) return index;
  const key = getItemKey(item, index);
  if (typeof key === 'number') return key;
  if (typeof key === 'string' && key.length > 0) return key;
  return index;
}
