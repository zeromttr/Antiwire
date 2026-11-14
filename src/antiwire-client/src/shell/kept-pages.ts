/**
 * Bookkeeping for the pages the shell keeps mounted (hidden) after the user
 * leaves them, so returning to one is instant and keeps its state. Pure, so the
 * eviction rules are testable without React.
 */

/** Pages kept mounted at once, including the visible one. */
export const MAX_KEPT_PAGES = 4;

export interface KeptPages<E> {
  /** In first-visit order. Never reordered, so React never moves their DOM. */
  readonly pages: readonly { readonly key: string; readonly element: E }[];
  /** Keys, most recently shown first. Decides which page is evicted. */
  readonly recency: readonly string[];
  /** Pages whose error boundary caught; dropped once the user leaves them. */
  readonly failed: ReadonlySet<string>;
}

export function emptyKeptPages<E>(): KeptPages<E> {
  return { pages: [], recency: [], failed: new Set() };
}

/**
 * The cache after showing `key`. Returns `state` itself when nothing changed,
 * so a caller that sets it as React state during render does not loop.
 *
 * `element` is stored on the first visit only: kept pages render their stored
 * element while hidden, so they bail out of re-rendering.
 */
export function showKeptPage<E>(
  state: KeptPages<E>,
  key: string,
  element: E,
  max: number = MAX_KEPT_PAGES,
): KeptPages<E> {
  const leftFailed = [...state.failed].filter((failed) => failed !== key);
  const alreadyFront = state.recency[0] === key;
  if (alreadyFront && leftFailed.length === 0) return state;

  const dropped = new Set(leftFailed);
  const recency = [key, ...state.recency.filter((k) => k !== key && !dropped.has(k))];
  for (const evicted of recency.splice(max)) dropped.add(evicted);

  let pages = state.pages.filter((page) => !dropped.has(page.key));
  if (!pages.some((page) => page.key === key)) pages = [...pages, { key, element }];

  const failed = new Set([...state.failed].filter((k) => !dropped.has(k)));
  return { pages, recency, failed };
}

/** Marks `key` as failed; it is dropped the next time another page is shown. */
export function markKeptPageFailed<E>(state: KeptPages<E>, key: string): KeptPages<E> {
  if (state.failed.has(key)) return state;
  return { ...state, failed: new Set([...state.failed, key]) };
}
