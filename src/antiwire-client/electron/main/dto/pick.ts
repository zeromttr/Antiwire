/**
 * Copies `keys` from `source`, in that order. For messages whose fields keep
 * the same camelCase name in the DTO, so a field the daemon adds later is not
 * forwarded until the client chooses to.
 */
export function pick<T extends object, K extends keyof T>(
  source: T,
  keys: readonly K[],
): Pick<T, K> {
  const out = {} as Pick<T, K>;
  for (const key of keys) out[key] = source[key];
  return out;
}
