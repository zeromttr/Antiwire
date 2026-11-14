import type { Plugin } from 'vite';

/** The modules that hold the app's one copy of some state: `export const x = new XStore()`. */
const STORE_MODULE = /[\\/]src[\\/]lib[\\/]stores[\\/][^\\/]+\.ts$/;

/** The part of Vite's module graph this needs; a test supplies plain objects. */
export interface GraphModule {
  id: string | null;
  /** True for a module that takes its own hot updates, as every component module does. */
  isSelfAccepting?: boolean;
  importers: Iterable<GraphModule>;
}

/**
 * Whether hot-updating `changed` would evaluate a store module again.
 *
 * A hot update re-evaluates the changed module and everything that imports it, up to the
 * first module that accepts updates (a component). A store on that path is created a
 * second time. The components move to the new store, which never connects, because the
 * app shell's start-up effect does not run again (under StrictMode React keeps a mount
 * effect across a hot update). The old store keeps polling and feeding the shared
 * charts, so the page shows "not connected" beside a chart that still moves.
 */
export function replacesStore(changed: Iterable<GraphModule>): boolean {
  const seen = new Set<GraphModule>();
  const queue = [...changed];
  for (let module = queue.pop(); module; module = queue.pop()) {
    if (seen.has(module)) continue;
    seen.add(module);
    if (module.id && STORE_MODULE.test(module.id)) return true;
    if (module.isSelfAccepting) continue;
    queue.push(...module.importers);
  }
  return false;
}

/**
 * Reloads the page instead of hot-updating it when the update would replace a store
 * (`replacesStore`). Edits to components, styles and anything only components import
 * still update in place.
 */
export function reloadWhenStoresChange(): Plugin {
  return {
    name: 'antiwire:reload-when-stores-change',
    apply: 'serve',
    hotUpdate({ modules }) {
      if (this.environment.name !== 'client' || !replacesStore(modules)) return;
      this.environment.hot.send({ type: 'full-reload' });
      return [];
    },
  };
}
