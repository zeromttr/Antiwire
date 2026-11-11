import { afterEach, beforeEach, describe, expect, mock, spyOn, test } from 'bun:test';
import { api } from '#lib/api/daemon.ts';
import type { Rule, Stats } from '#lib/types/index.ts';
import { DaemonStore } from './daemon.ts';

const globals = globalThis as { window?: unknown };

function stats(overrides: Partial<Stats> = {}): Stats {
  return {
    bytesSent: 100,
    bytesReceived: 200,
    activeConnections: 3,
    blockedConnections: 1,
    byteAccountingAvailable: true,
    collectorStatusDetail: '',
    activeConnectionsAvailable: true,
    activeConnectionsStale: false,
    activeApplications: 2,
    databaseSizeBytes: 4096,
    ...overrides,
  };
}

const rule = { id: 1, targetType: 'DOMAIN', targetValue: 'example.com' } as unknown as Rule;

let currentStats = stats();
const spies: Array<{ mockRestore(): void }> = [];

function stub<K extends keyof typeof api>(key: K, impl: (typeof api)[K]) {
  spies.push(spyOn(api, key).mockImplementation(impl as never));
}

/** Waits for pending promises and the coalesced notification. */
const settle = () => new Promise((resolve) => setTimeout(resolve, 0));

let store: DaemonStore;

beforeEach(() => {
  // `connect` only runs inside the app, which is detected by the preload bridge.
  globals.window = { antiwire: { invoke: mock(), on: () => () => {}, platform: 'win32' } };
  currentStats = stats();
  stub('connectDaemon', async () => true);
  stub('getConnectionStatus', async () => ({ connected: true }));
  stub('getStats', async () => currentStats);
  stub('getRules', async () => [rule]);
  stub('getAppSummaries', async () => ({ applications: [], totalCount: 0, blockedCount: 0 }));
  stub('getCountryRules', async () => []);
  stub('getActivityBuckets', async () => []);
  stub('getAlerts', async () => []);
  store = new DaemonStore();
});

afterEach(() => {
  store.dispose();
  for (const spy of spies.splice(0)) spy.mockRestore();
  delete globals.window;
});

describe('DaemonStore', () => {
  test('connect loads a snapshot and replaces state instead of mutating it', async () => {
    const before = store.state;
    await store.connect();
    expect(store.state).not.toBe(before);
    expect(before.connected).toBe(false);
    expect(store.state.connected).toBe(true);
    expect(store.state.connecting).toBe(false);
    expect(store.state.rules).toEqual([rule]);
    expect(store.state.socketCount).toBe(3);
  });

  test('a poll that sees new numbers notifies once; an identical one does not notify', async () => {
    await store.connect();
    await settle();
    let calls = 0;
    store.subscribe(() => calls++);
    const rules = store.state.rules;

    // Hidden then visible polls at once instead of waiting for the timer.
    store.setWindowVisible(false);
    currentStats = stats({ bytesReceived: 5000, activeConnections: 4 });
    store.setWindowVisible(true);
    await settle();
    expect(calls).toBe(1);
    expect(store.state.stats.bytesReceived).toBe(5000);
    expect(store.state.socketCount).toBe(4);
    // Members the poll does not touch keep their identity.
    expect(store.state.rules).toBe(rules);

    // The same counters again: the computed rate is zero, which differs from
    // the last push once, then the following identical sample is skipped.
    store.setWindowVisible(false);
    store.setWindowVisible(true);
    await settle();
    calls = 0;
    const snapshot = store.state;
    store.setWindowVisible(false);
    store.setWindowVisible(true);
    await settle();
    expect(calls).toBe(0);
    expect(store.state).toBe(snapshot);
  });

  test('toasts are replaced arrays, capped, and dismissable', async () => {
    const empty = store.state.toasts;
    for (let i = 0; i < 7; i++) store.addToast(`t${i}`, 'body', 'var(--ok)');
    expect(empty).toEqual([]);
    expect(store.state.toasts.map((t) => t.title)).toEqual(['t2', 't3', 't4', 't5', 't6']);
    const id = store.state.toasts[0].id;
    store.dismissToast(id);
    expect(store.state.toasts.some((t) => t.id === id)).toBe(false);
    expect(store.state.toasts).toHaveLength(4);
  });

  test('notifications keep the alert count in step', () => {
    store.addNotification({ id: 'a', severity: 'bad', timestamp: 2 } as never);
    store.addNotification({ id: 'b', severity: 'info', timestamp: 1 } as never);
    store.addNotification({ id: 'a', severity: 'bad', timestamp: 2 } as never);
    expect(store.state.notifications.map((n) => n.id)).toEqual(['b', 'a']);
    expect(store.state.alertCount).toBe(1);
  });

  test('dispose stops the poll timer', async () => {
    await store.connect();
    const calls = (api.getStats as unknown as { mock: { calls: unknown[] } }).mock.calls.length;
    store.dispose();
    await new Promise((resolve) => setTimeout(resolve, 1100));
    expect((api.getStats as unknown as { mock: { calls: unknown[] } }).mock.calls.length).toBe(
      calls,
    );
  });
});
