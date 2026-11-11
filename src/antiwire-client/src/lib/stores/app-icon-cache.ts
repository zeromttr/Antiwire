/** Max decoded icons kept in the in-memory store. Disk cache is not evicted. */
export const APP_ICON_CACHE_MAX = 64;
/** Max missing icon keys kept in the in-memory store to prevent unbounded memory growth. */
export const APP_ICON_MISSING_CACHE_MAX = 256;

export class IconSrcLru {
  #order: string[] = [];

  constructor(private readonly max: number = APP_ICON_CACHE_MAX) {}

  get size(): number {
    return this.#order.length;
  }

  keys(): string[] {
    return [...this.#order];
  }

  touch(key: string) {
    const index = this.#order.indexOf(key);
    if (index >= 0) this.#order.splice(index, 1);
    this.#order.push(key);
  }

  remove(key: string) {
    const index = this.#order.indexOf(key);
    if (index >= 0) this.#order.splice(index, 1);
  }

  evict(): string[] {
    const evicted: string[] = [];
    while (this.#order.length > this.max) {
      const key = this.#order.shift();
      if (key) evicted.push(key);
    }
    return evicted;
  }
}

const PNG_DATA_URL_PREFIX = 'data:image/png;base64,';

/**
 * Whether `value` is what the main process's `get_app_icon` returns for a
 * found icon: a base64 PNG data URL. Anything else (a file path, another
 * scheme, an empty payload) is treated as no icon, so the webview never loads
 * a URL it did not expect.
 */
export function isIconDataUrl(value: unknown): value is string {
  if (typeof value !== 'string' || !value.startsWith(PNG_DATA_URL_PREFIX)) return false;
  const payload = value.slice(PNG_DATA_URL_PREFIX.length);
  return payload.length > 0 && /^[A-Za-z0-9+/]+={0,2}$/.test(payload);
}
