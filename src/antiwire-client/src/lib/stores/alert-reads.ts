import { Reactive } from '#lib/state/reactive.ts';

/**
 * Which alerts the user has looked at. The daemon has no read state, so this
 * lives on the client: a small id set persisted to localStorage. Storage can
 * be unavailable (private windows, tests), in which case reads simply do not
 * survive a reload.
 */
const STORAGE_KEY = 'antiwire.alerts.read';
/** The feed holds at most 100 alerts; keep headroom for ones cleared meanwhile. */
const MAX_REMEMBERED = 400;

function load(): string[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    const parsed: unknown = raw ? JSON.parse(raw) : [];
    return Array.isArray(parsed) ? parsed.filter((id): id is string => typeof id === 'string') : [];
  } catch {
    return [];
  }
}

function save(ids: string[]) {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(ids.slice(-MAX_REMEMBERED)));
  } catch {
    // Read state is a convenience; losing it is harmless.
  }
}

class AlertReads extends Reactive {
  #ids: string[] = typeof localStorage === 'undefined' ? [] : load();
  #set = new Set(this.#ids);

  #commit(next: string[]) {
    this.#ids = next.slice(-MAX_REMEMBERED);
    this.#set = new Set(this.#ids);
    save(this.#ids);
    this.changed();
  }

  readonly has = (id: string): boolean => {
    return this.#set.has(id);
  };

  readonly markRead = (id: string) => {
    if (this.#set.has(id)) return;
    this.#commit([...this.#ids, id]);
  };

  readonly markAllRead = (alertIds: string[]) => {
    const fresh = alertIds.filter((id) => !this.#set.has(id));
    if (fresh.length) this.#commit([...this.#ids, ...fresh]);
  };
}

export const alertReads = new AlertReads();
