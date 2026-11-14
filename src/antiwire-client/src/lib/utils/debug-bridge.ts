import { isDebugEnabled, setDebugEnabled } from './debug';

export interface DebugBridge {
  enable: () => void;
  disable: () => void;
  isEnabled: () => boolean;
}

export interface FullDebugBridge extends DebugBridge {
  /** Redacted daemon snapshot — counts and flags, never rules/logs/packets. */
  daemon: () => Record<string, unknown>;
  openDevtools: () => Promise<void>;
}

export interface DebugSnapshotSource {
  connected: boolean;
  connecting: boolean;
  error: string | null;
  rulesCount: number;
  countryRulesCount: number;
  notificationsCount: number;
  toastsCount: number;
  socketCount: number;
}

/**
 * Builds the object published on `window.__antiwireDebug`.
 *
 * The full bridge (redacted daemon snapshot + `openDevtools`) is only
 * included when debug mode is enabled or in a dev build. Otherwise only
 * the `enable`/`disable`/`isEnabled` toggles are exposed so a stray
 * WebView script cannot harvest daemon telemetry or open devtools.
 */
export function buildDebugBridge(
  readSource: () => DebugSnapshotSource | null,
  actions: { openDevtools: () => Promise<void> },
  env: { dev: boolean; debugEnabled: boolean },
): DebugBridge | FullDebugBridge {
  const base: DebugBridge = {
    enable: () => {
      setDebugEnabled(true);
    },
    disable: () => setDebugEnabled(false),
    isEnabled: () => isDebugEnabled(),
  };

  if (!env.debugEnabled && !env.dev) return base;

  const readSnapshot = () => {
    const source = readSource();
    return source
      ? {
          connected: source.connected,
          connecting: source.connecting,
          hasError: source.error !== null,
          rulesCount: source.rulesCount,
          countryRulesCount: source.countryRulesCount,
          notificationsCount: source.notificationsCount,
          toastsCount: source.toastsCount,
          socketCount: source.socketCount,
        }
      : { connected: false };
  };

  return {
    ...base,
    daemon: () => ({ ...readSnapshot() }),
    openDevtools: async () => {
      try {
        await actions.openDevtools();
      } catch (error) {
        console.error('[antiwire] open_devtools failed', error);
        throw error;
      }
    },
  };
}

export function publishDebugBridge(
  target: Record<string, unknown>,
  bridge: DebugBridge | FullDebugBridge,
): void {
  target.__antiwireDebug = bridge;
}
