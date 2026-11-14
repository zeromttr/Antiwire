/**
 * Resolved icons by key, including "this file has no icon". Concurrent
 * requests for one key share a single load, so a page of rows for the same
 * executable extracts once. Missing icons expire so they are tried again;
 * errors are never cached. Bounded with least-recently-used eviction.
 */
export class IconCache {
  #entries = new Map<string, { value: string | null; expires: number }>();
  #inflight = new Map<string, Promise<string | null>>();

  constructor(
    private readonly maxEntries = 512,
    private readonly missingTtlMs = 300_000,
    private readonly now: () => number = Date.now,
  ) {}

  get size(): number {
    return this.#entries.size;
  }

  async get(key: string, load: () => Promise<string | null>): Promise<string | null> {
    const hit = this.#entries.get(key);
    if (hit && hit.expires > this.now()) {
      // Re-insert to mark it most recently used.
      this.#entries.delete(key);
      this.#entries.set(key, hit);
      return hit.value;
    }
    this.#entries.delete(key);

    const pending = this.#inflight.get(key);
    if (pending) return pending;
    const loading = load()
      .then((value) => {
        this.#remember(key, value);
        return value;
      })
      .finally(() => this.#inflight.delete(key));
    this.#inflight.set(key, loading);
    return loading;
  }

  #remember(key: string, value: string | null): void {
    // An icon is keyed by the file's mtime, so it stays valid; a miss may not.
    const expires = value === null ? this.now() + this.missingTtlMs : Number.POSITIVE_INFINITY;
    this.#entries.set(key, { value, expires });
    while (this.#entries.size > this.maxEntries) {
      const oldest = this.#entries.keys().next().value;
      if (oldest === undefined) break;
      this.#entries.delete(oldest);
    }
  }
}
