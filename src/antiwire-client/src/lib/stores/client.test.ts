import { afterEach, beforeEach, describe, expect, test } from 'bun:test';
import { ClientStore } from './client.ts';

const globals = globalThis as { localStorage?: Storage };
const original = globals.localStorage;

/** The browser-preview store reads `antiwire-client-settings` from localStorage. */
function memoryStorage(initial: Record<string, string>): Storage {
  const data = new Map(Object.entries(initial));
  return {
    get length() {
      return data.size;
    },
    clear: () => data.clear(),
    getItem: (key) => data.get(key) ?? null,
    key: (index) => [...data.keys()][index] ?? null,
    removeItem: (key) => void data.delete(key),
    setItem: (key, value) => void data.set(key, String(value)),
  };
}

describe('ClientStore.init', () => {
  beforeEach(() => {
    globals.localStorage = memoryStorage({
      'antiwire-client-settings': JSON.stringify({ onboardingDone: true, theme: 'dark' }),
    });
  });

  afterEach(() => {
    globals.localStorage = original;
  });

  // StrictMode runs the start-up effect twice in dev. The second call used to
  // return before the stored settings loaded, so onboarding reopened every run.
  test('a second caller waits for the load already in flight', async () => {
    const store = new ClientStore();
    let firstSettled = false;
    const first = store.init().then(() => {
      firstSettled = true;
    });
    await store.init();
    expect(firstSettled).toBe(true);
    expect(store.state.onboardingDone).toBe(true);
    expect(store.state.theme).toBe('dark');
    await first;
  });

  test('loads once', async () => {
    const store = new ClientStore();
    expect(store.init()).toBe(store.init());
    await store.init();
  });
});
