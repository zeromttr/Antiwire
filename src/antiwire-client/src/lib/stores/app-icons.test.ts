import { afterEach, beforeEach, describe, expect, mock, test } from 'bun:test';
import { AppIconStore, appIconCacheKey, normalizeIconPath } from './app-icons.ts';

const PNG = 'data:image/png;base64,iVBORw0KGgo=';
const invoke = mock(
  async (_command: string, _args?: Record<string, unknown>): Promise<unknown> => PNG,
);
const globals = globalThis as { window?: unknown };

// A stand-in for the Electron preload bridge (`window.antiwire`); `#lib/bridge.ts`
// reads it on every call, so tests can install and remove it.
beforeEach(() => {
  globals.window = { antiwire: { invoke, on: () => () => {}, platform: 'win32' } };
});

afterEach(() => {
  delete globals.window;
  invoke.mockReset();
  invoke.mockImplementation(async () => PNG);
});

/** Lets the store's async fetch settle. */
const settle = () => new Promise((resolve) => setTimeout(resolve, 0));

describe('normalizeIconPath', () => {
  test('strips svchost service suffixes', () => {
    expect(normalizeIconPath('C:\\Windows\\System32\\svchost.exe::DnsCache')).toBe(
      'C:\\Windows\\System32\\svchost.exe',
    );
  });

  test('rejects placeholders and bare executable names', () => {
    expect(normalizeIconPath(undefined)).toBeNull();
    expect(normalizeIconPath('')).toBeNull();
    expect(normalizeIconPath('unknown')).toBeNull();
    expect(normalizeIconPath('chrome.exe')).toBeNull();
    expect(normalizeIconPath('System / Elevated Process')).toBeNull();
    expect(normalizeIconPath('Path unavailable')).toBeNull();
  });

  test('accepts absolute Windows and Unix paths', () => {
    expect(normalizeIconPath('C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe')).toBe(
      'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
    );
    expect(normalizeIconPath('/usr/bin/firefox')).toBe('/usr/bin/firefox');
  });

  test('keeps extended-length prefixes so the backend can strip them', () => {
    expect(normalizeIconPath('\\\\?\\C:\\Apps\\tool.exe')).toBe('\\\\?\\C:\\Apps\\tool.exe');
  });
});

describe('appIconCacheKey', () => {
  test('keys by normalized path when one exists', () => {
    expect(appIconCacheKey('C:\\Apps\\Chrome.exe::unused', 'Chrome')).toBe(
      'path:c:\\apps\\chrome.exe',
    );
  });

  test('falls back to name when the path cannot be fetched', () => {
    expect(appIconCacheKey('chrome.exe', 'Chrome')).toBe('name:chrome');
  });
});

describe('AppIconStore', () => {
  const chrome = '/opt/apps/chrome.exe';
  const key = appIconCacheKey(chrome, 'Chrome');

  test('stores the data URL the main process returns', async () => {
    const store = new AppIconStore();
    store.ensure(`${chrome}::svc`, 'Chrome');
    expect(store.get(key).status).toBe('loading');
    await settle();
    expect(store.get(key)).toEqual({ status: 'ready', src: PNG });
    expect(invoke).toHaveBeenCalledWith('get_app_icon', { path: chrome });
  });

  test('a null or unexpected answer is missing, not loaded', async () => {
    const store = new AppIconStore();
    invoke.mockImplementationOnce(async () => null);
    store.ensure(chrome, 'Chrome');
    invoke.mockImplementationOnce(async () => '/var/cache/app-icons/icon.png');
    store.ensure('/opt/apps/edge.exe', 'Edge');
    await settle();
    expect(store.get(key).status).toBe('missing');
    expect(store.get(appIconCacheKey('/opt/apps/edge.exe', 'Edge')).status).toBe('missing');
  });

  test('a failed command is missing', async () => {
    const store = new AppIconStore();
    invoke.mockImplementationOnce(async () => {
      throw new Error('no icon');
    });
    store.ensure(chrome, 'Chrome');
    await settle();
    expect(store.get(key).status).toBe('missing');
  });

  test('outside the app nothing is fetched', async () => {
    delete globals.window;
    const store = new AppIconStore();
    store.ensure(chrome, 'Chrome');
    await settle();
    expect(invoke).not.toHaveBeenCalled();
    expect(store.get(key).status).toBe('missing');
  });

  test('fetches each key once and keeps entry identity until it changes', async () => {
    const store = new AppIconStore();
    store.ensure(chrome, 'Chrome');
    store.ensure(chrome, 'Chrome');
    await settle();
    store.ensure(chrome, 'Chrome');
    expect(invoke).toHaveBeenCalledTimes(1);
    expect(store.get(key)).toBe(store.get(key));
    expect(store.get('name:unknown')).toBe(store.get('name:other'));
  });

  test('evicts the least recently used ready icon past the cap', async () => {
    const store = new AppIconStore(1);
    store.ensure('/opt/apps/a.exe', 'A');
    await settle();
    store.ensure('/opt/apps/b.exe', 'B');
    await settle();
    expect(store.get(appIconCacheKey('/opt/apps/a.exe', 'A')).status).toBe('idle');
    expect(store.get(appIconCacheKey('/opt/apps/b.exe', 'B')).status).toBe('ready');
  });

  test('markBroken turns a ready icon into missing and notifies', async () => {
    const store = new AppIconStore();
    store.ensure(chrome, 'Chrome');
    await settle();
    let calls = 0;
    store.subscribe(() => calls++);
    store.markBroken(key);
    await Promise.resolve();
    expect(store.get(key).status).toBe('missing');
    expect(calls).toBe(1);
  });
});
