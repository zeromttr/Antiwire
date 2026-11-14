import { useRef, useSyncExternalStore } from 'react';

/**
 * The one reactivity primitive in the renderer. A store is a plain class that
 * extends `Reactive`, mutates its own fields, and calls `changed()` afterwards.
 * Components read it through `useSelector` (re-render only when the selected
 * value changes) or `useReactive` (re-render on any change).
 *
 * Stores must replace arrays and objects rather than mutate them in place, so
 * a selector returning `store.rows` sees a new reference when rows change.
 * Notifications are coalesced into one per microtask, so a burst of field
 * writes costs one render.
 */
export class Reactive {
  #listeners = new Set<() => void>();
  #version = 0;
  #scheduled = false;

  /** Call after mutating fields. Cheap to call repeatedly. */
  protected changed(): void {
    this.#version++;
    if (this.#scheduled) return;
    this.#scheduled = true;
    queueMicrotask(() => {
      this.#scheduled = false;
      for (const listener of [...this.#listeners]) listener();
    });
  }

  readonly subscribe = (listener: () => void): (() => void) => {
    this.#listeners.add(listener);
    return () => {
      this.#listeners.delete(listener);
    };
  };

  /** Monotonic change counter; differs after every `changed()`. */
  readonly version = (): number => this.#version;
}

export function shallowEqual(a: unknown, b: unknown): boolean {
  if (Object.is(a, b)) return true;
  if (typeof a !== 'object' || typeof b !== 'object' || a === null || b === null) return false;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  const keysA = Object.keys(a);
  if (keysA.length !== Object.keys(b).length) return false;
  for (const key of keysA) {
    if (!Object.is((a as Record<string, unknown>)[key], (b as Record<string, unknown>)[key])) {
      return false;
    }
  }
  return true;
}

/**
 * Subscribes to the part of `store` that `select` returns. The component
 * re-renders only when that value changes under `isEqual` (default
 * `Object.is`; pass `shallowEqual` when the selector builds an object).
 */
export function useSelector<S extends Reactive, T>(
  store: S,
  select: (store: S) => T,
  isEqual: (a: T, b: T) => boolean = Object.is,
): T {
  // The cache keeps the previous value while the store's version is unchanged,
  // and keeps its identity when `isEqual` says a recomputed value is the same,
  // so useSyncExternalStore sees a stable snapshot. A new `select` each render
  // is fine: it only runs when the version moved.
  const cache = useRef<{ version: number; value: T } | null>(null);
  const getSnapshot = () => {
    const version = store.version();
    const cached = cache.current;
    if (cached && cached.version === version) return cached.value;
    const next = select(store);
    if (cached && isEqual(cached.value, next)) {
      cache.current = { version, value: cached.value };
      return cached.value;
    }
    cache.current = { version, value: next };
    return next;
  };
  return useSyncExternalStore(store.subscribe, getSnapshot, getSnapshot);
}

/**
 * Re-renders on every change of `store` and returns it. For page-local stores.
 *
 * The store keeps its identity across changes, so React Compiler would keep
 * serving the first render's output. A file that calls this, or that reads a
 * workspace while rendering, must start with `'use no memo'`;
 * `compiler-opt-out.test.ts` enforces it.
 */
export function useReactive<S extends Reactive>(store: S): S {
  useSyncExternalStore(store.subscribe, store.version, store.version);
  return store;
}
