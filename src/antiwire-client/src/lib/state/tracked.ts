import { Reactive } from './reactive.ts';

/**
 * A `Reactive` whose listed fields notify listeners on assignment. Page-local workspaces have dozens of plain fields that
 * both their own methods and the UI (former `bind:` targets) assign; turning
 * each into an accessor keeps `ws.query = next` working and removes the need
 * for a `changed()` call after every write.
 *
 * Only assignment is observed. Arrays and objects must still be replaced, not
 * mutated in place.
 *
 * Call `track(...)` at the end of the subclass constructor, once the field
 * initializers have run:
 *
 * ```ts
 * class Workspace extends TrackedReactive {
 *   query = '';
 *   constructor() { super(); this.track('query'); }
 * }
 * ```
 */
export abstract class TrackedReactive extends Reactive {
  #memos = new Map<string, { deps: readonly unknown[]; value: unknown }>();

  /**
   * Memoizes a derived value: returns the cached result of `compute`
   * while every entry of `deps` is identical (`Object.is`) to the last call's.
   * For getters that filter or sort and are read several times per render.
   */
  protected memo<T>(key: string, deps: readonly unknown[], compute: () => T): T {
    const cached = this.#memos.get(key);
    if (
      cached &&
      cached.deps.length === deps.length &&
      cached.deps.every((dep, index) => Object.is(dep, deps[index]))
    ) {
      return cached.value as T;
    }
    const value = compute();
    this.#memos.set(key, { deps, value });
    return value;
  }

  protected track<K extends keyof this & string>(...keys: K[]): void {
    for (const key of keys) {
      let value = this[key];
      Object.defineProperty(this, key, {
        configurable: true,
        enumerable: true,
        get: () => value,
        set: (next: this[K]) => {
          if (Object.is(next, value)) return;
          value = next;
          this.changed();
        },
      });
    }
  }
}
