import { describe, expect, test } from 'bun:test';
import { emptyKeptPages, markKeptPageFailed, showKeptPage, type KeptPages } from './kept-pages.ts';

const keys = (state: KeptPages<string>) => state.pages.map((page) => page.key);

function visit(...path: string[]): KeptPages<string> {
  let state = emptyKeptPages<string>();
  for (const key of path) state = showKeptPage(state, key, `<${key}>`, 3);
  return state;
}

describe('showKeptPage', () => {
  test('keeps pages in first-visit order and tracks recency separately', () => {
    const state = visit('/', '/records', '/');
    expect(keys(state)).toEqual(['/', '/records']);
    expect(state.recency).toEqual(['/', '/records']);
  });

  test('returns the same state when the front page is shown again', () => {
    const state = visit('/', '/records');
    expect(showKeptPage(state, '/records', 'other', 3)).toBe(state);
  });

  test('keeps the element from the first visit', () => {
    const state = showKeptPage(visit('/', '/records'), '/', 'new element', 3);
    expect(state.pages[0]).toEqual({ key: '/', element: '</>' });
  });

  test('evicts the least recently shown page past the limit', () => {
    const state = visit('/', '/records', '/firewall', '/', '/alerts');
    expect(keys(state)).toEqual(['/', '/firewall', '/alerts']);
    expect(state.recency).toEqual(['/alerts', '/', '/firewall']);
  });

  test('drops a failed page once another page is shown', () => {
    let state = markKeptPageFailed(visit('/', '/records'), '/records');
    // Still on the failed page: it stays, showing its fallback.
    expect(showKeptPage(state, '/records', '<x>', 3)).toBe(state);
    state = showKeptPage(state, '/', '</>', 3);
    expect(keys(state)).toEqual(['/']);
    expect(state.failed.size).toBe(0);
    // A revisit mounts it afresh.
    state = showKeptPage(state, '/records', '<records again>', 3);
    expect(state.pages[1]).toEqual({ key: '/records', element: '<records again>' });
  });

  test('marking the same page twice is a no-op', () => {
    const state = markKeptPageFailed(visit('/'), '/');
    expect(markKeptPageFailed(state, '/')).toBe(state);
  });
});
