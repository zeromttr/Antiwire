import { invoke, isNative } from '#lib/bridge.ts';
import { Reactive } from '#lib/state/reactive.ts';
import {
  APP_ICON_CACHE_MAX,
  APP_ICON_MISSING_CACHE_MAX,
  IconSrcLru,
  isIconDataUrl,
} from './app-icon-cache';

export type AppIconStatus = 'idle' | 'loading' | 'ready' | 'missing';

export interface AppIconEntry {
  status: AppIconStatus;
  src?: string;
}

export { APP_ICON_CACHE_MAX, APP_ICON_MISSING_CACHE_MAX };

const PLACEHOLDER_PATHS = new Set([
  '',
  '—',
  '-',
  'unknown (exited)',
  'unknown (no owner)',
  'unknown (access denied)',
  'unknown',
  'unknown.exe',
  'system',
  'system / elevated process',
  'path unavailable',
]);

export function normalizeIconPath(path: string | undefined): string | null {
  const trimmed = (path ?? '').trim();
  if (!trimmed || PLACEHOLDER_PATHS.has(trimmed.toLowerCase())) {
    return null;
  }

  const exePath = trimmed.split('::')[0]?.trim() ?? '';
  if (!exePath || PLACEHOLDER_PATHS.has(exePath.toLowerCase())) {
    return null;
  }

  if (!exePath.includes('\\') && !exePath.includes('/')) {
    return null;
  }

  return exePath;
}

export function appIconCacheKey(path: string | undefined, name: string): string {
  const normalizedPath = normalizeIconPath(path);
  if (normalizedPath) {
    return `path:${normalizedPath.toLowerCase()}`;
  }
  return `name:${name.trim().toLowerCase()}`;
}

function canFetchIcon(path: string | undefined): path is string {
  return normalizeIconPath(path) !== null;
}

const IDLE: AppIconEntry = Object.freeze({ status: 'idle' });

/**
 * Icons by `appIconCacheKey`. Every change stores a new entry object and
 * notifies, and `get` returns the same object until that key changes, so
 * `useSelector(appIcons, (s) => s.get(key))` re-renders one row only.
 */
export class AppIconStore extends Reactive {
  #entries = new Map<string, AppIconEntry>();
  #inflight = new Map<string, Promise<void>>();
  #readyLru: IconSrcLru;
  #missingLru: IconSrcLru;

  constructor(readyMax = APP_ICON_CACHE_MAX, missingMax = APP_ICON_MISSING_CACHE_MAX) {
    super();
    this.#readyLru = new IconSrcLru(readyMax);
    this.#missingLru = new IconSrcLru(missingMax);
  }

  readonly get = (key: string): AppIconEntry => this.#entries.get(key) ?? IDLE;

  #set(key: string, entry: AppIconEntry) {
    this.#entries.set(key, entry);
    this.changed();
  }

  #delete(key: string) {
    if (this.#entries.delete(key)) this.changed();
  }

  #dropReady(key: string) {
    this.#readyLru.remove(key);
    this.#delete(key);
  }

  #dropMissing(key: string) {
    this.#missingLru.remove(key);
    if (this.#entries.get(key)?.status === 'missing') this.#delete(key);
  }

  #rememberReady(key: string, src: string) {
    this.#missingLru.remove(key);
    this.#set(key, { status: 'ready', src });
    this.#readyLru.touch(key);
    for (const evicted of this.#readyLru.evict()) this.#dropReady(evicted);
  }

  #rememberMissing(key: string) {
    this.#readyLru.remove(key);
    this.#set(key, { status: 'missing' });
    this.#missingLru.touch(key);
    for (const evicted of this.#missingLru.evict()) this.#dropMissing(evicted);
  }

  async #fetchIcon(path: string, key: string) {
    if (!isNative()) {
      this.#rememberMissing(key);
      return;
    }

    this.#set(key, { status: 'loading' });
    try {
      const resolvedPath = normalizeIconPath(path);
      if (!resolvedPath) {
        this.#rememberMissing(key);
        return;
      }

      // The main process extracts, caches and encodes the icon; the answer is
      // a PNG data URL or null.
      const src = await invoke<string | null>('get_app_icon', { path: resolvedPath });
      if (!isIconDataUrl(src)) {
        this.#rememberMissing(key);
        return;
      }

      this.#rememberReady(key, src);
    } catch {
      this.#rememberMissing(key);
    }
  }

  readonly markBroken = (key: string) => {
    this.#rememberMissing(key);
  };

  readonly ensure = (path: string | undefined, name: string) => {
    const key = appIconCacheKey(path, name);
    const current = this.get(key);
    if (current.status === 'ready') {
      this.#readyLru.touch(key);
      return;
    }
    if (current.status === 'missing') {
      this.#missingLru.touch(key);
      return;
    }
    if (current.status === 'loading') {
      return;
    }
    if (!canFetchIcon(path)) {
      this.#rememberMissing(key);
      return;
    }

    if (this.#inflight.has(key)) return;

    const promise = this.#fetchIcon(path, key).finally(() => {
      this.#inflight.delete(key);
    });
    this.#inflight.set(key, promise);
  };
}

export const appIcons = new AppIconStore();
