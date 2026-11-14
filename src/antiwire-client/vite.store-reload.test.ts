import { expect, test } from 'bun:test';
import { replacesStore, type GraphModule } from './vite.store-reload.ts';

function module(id: string, importers: GraphModule[] = [], isSelfAccepting = false): GraphModule {
  return { id, isSelfAccepting, importers };
}

const ROOT = 'C:/app/src';
const component = (name: string) => module(`${ROOT}/lib/components/${name}.tsx`, [], true);

test('a change to a store replaces it', () => {
  expect(replacesStore([module(`${ROOT}/lib/stores/daemon.ts`, [component('StatusBar')])])).toBe(
    true,
  );
});

test('a change to something a store imports replaces the store', () => {
  const store = module(`${ROOT}/lib/stores/daemon.ts`, [component('StatusBar')]);
  const api = module(`${ROOT}/lib/api/daemon.ts`, [store, component('RecordInspector')]);
  const normalize = module(`${ROOT}/lib/api/normalize.ts`, [api]);
  expect(replacesStore([normalize])).toBe(true);
});

test('Windows paths are recognised', () => {
  expect(replacesStore([module('C:\\app\\src\\lib\\stores\\client.ts')])).toBe(true);
});

test('a component, and what only components import, updates in place', () => {
  const panel = component('RecordsAppsPanel');
  expect(replacesStore([panel])).toBe(false);
  expect(replacesStore([module(`${ROOT}/lib/utils/only-ui.ts`, [panel])])).toBe(false);
  expect(replacesStore([module(`${ROOT}/lib/components/Panel.module.css`, [panel])])).toBe(false);
});

// The update stops at the component, so a store that imports it is not evaluated again.
test('the walk stops at a module that accepts its own updates', () => {
  const store = module(`${ROOT}/lib/stores/daemon.ts`);
  const accepting = module(`${ROOT}/lib/components/Odd.tsx`, [store], true);
  expect(replacesStore([accepting])).toBe(false);
});

test('an import cycle ends', () => {
  const a: GraphModule = { id: `${ROOT}/lib/a.ts`, importers: [] };
  const b: GraphModule = { id: `${ROOT}/lib/b.ts`, importers: [a] };
  a.importers = [b];
  expect(replacesStore([a])).toBe(false);
});
