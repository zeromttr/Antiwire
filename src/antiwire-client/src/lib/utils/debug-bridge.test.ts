import { describe, expect, it } from 'bun:test';
import { buildDebugBridge, publishDebugBridge } from './debug-bridge';

const source = {
  connected: true,
  connecting: false,
  error: null,
  rulesCount: 12,
  countryRulesCount: 3,
  notificationsCount: 5,
  toastsCount: 1,
  socketCount: 42,
};

const actions = {
  openDevtools: async () => {},
};

describe('buildDebugBridge', () => {
  it('exposes only toggles in a production build without debug mode', () => {
    const bridge = buildDebugBridge(() => source, actions, { dev: false, debugEnabled: false });

    expect(Object.keys(bridge).sort()).toEqual(['disable', 'enable', 'isEnabled']);
    expect('daemon' in bridge).toBe(false);
    expect('openDevtools' in bridge).toBe(false);
  });

  it('exposes the full bridge when debug mode is enabled', () => {
    const bridge = buildDebugBridge(() => source, actions, { dev: false, debugEnabled: true });

    expect('daemon' in bridge).toBe(true);
    expect('openDevtools' in bridge).toBe(true);
  });

  it('exposes the full bridge in dev builds', () => {
    const bridge = buildDebugBridge(() => source, actions, { dev: true, debugEnabled: false });

    expect('daemon' in bridge).toBe(true);
  });

  it('reads a fresh snapshot on every call instead of caching mount-time values', () => {
    let current = { ...source, rulesCount: 12 };
    const bridge = buildDebugBridge(() => current, actions, {
      dev: false,
      debugEnabled: true,
    });
    if (!('daemon' in bridge)) throw new Error('expected full bridge');

    expect(bridge.daemon()).toMatchObject({ rulesCount: 12 });

    current = { ...current, rulesCount: 48, connected: false };

    expect(bridge.daemon()).toMatchObject({ rulesCount: 48, connected: false });
  });

  it('reports disconnected when the source is gone', () => {
    const bridge = buildDebugBridge(() => null, actions, { dev: false, debugEnabled: true });
    if (!('daemon' in bridge)) throw new Error('expected full bridge');

    expect(bridge.daemon()).toEqual({ connected: false });
  });

  it('publishes a redacted snapshot without rules, logs, or packets', () => {
    const bridge = buildDebugBridge(() => source, actions, { dev: false, debugEnabled: true });
    if (!('daemon' in bridge)) throw new Error('expected full bridge');

    const snapshot = bridge.daemon() as Record<string, unknown>;
    const serialized = JSON.stringify(snapshot);

    expect(snapshot).toMatchObject({
      connected: true,
      connecting: false,
      hasError: false,
      rulesCount: 12,
      countryRulesCount: 3,
      notificationsCount: 5,
      toastsCount: 1,
      socketCount: 42,
    });
    // No rule bodies, messages, payloads, or byte counters leak through.
    expect(serialized).not.toContain('targetValue');
    expect(snapshot).not.toHaveProperty('rules');
    expect(snapshot).not.toHaveProperty('logs');
    expect(snapshot).not.toHaveProperty('error');
  });

  it('surfaces connection errors as a boolean flag only', () => {
    const bridge = buildDebugBridge(
      () => ({ ...source, error: 'daemon socket refused (secret-path)' }),
      actions,
      { dev: false, debugEnabled: true },
    );
    if (!('daemon' in bridge)) throw new Error('expected full bridge');

    const snapshot = bridge.daemon() as Record<string, unknown>;
    expect(snapshot.hasError).toBe(true);
    expect(JSON.stringify(snapshot)).not.toContain('secret-path');
  });

  it('rethrows devtools failures instead of swallowing them', async () => {
    const bridge = buildDebugBridge(
      () => source,
      {
        openDevtools: async () => {
          throw new Error('invoke failed');
        },
      },
      { dev: true, debugEnabled: false },
    );
    if (!('openDevtools' in bridge)) throw new Error('expected full bridge');

    await expect(bridge.openDevtools()).rejects.toThrow('invoke failed');
  });
});

describe('publishDebugBridge', () => {
  it('assigns the bridge on the target window object', () => {
    const target: Record<string, unknown> = {};
    const bridge = buildDebugBridge(() => null, actions, { dev: false, debugEnabled: false });

    publishDebugBridge(target, bridge);

    expect(target.__antiwireDebug).toBe(bridge);
  });
});
