import type { AntiwireBridge, CommandName, EventName, EventPayloads } from '#shared/ipc';

declare global {
  interface Window {
    /** Exposed by the Electron preload; absent in the browser preview. */
    antiwire?: AntiwireBridge;
  }
}

function bridge(): AntiwireBridge | undefined {
  return typeof window === 'undefined' ? undefined : window.antiwire;
}

/** True inside the Electron app, where the preload bridge exists. */
export function isNative(): boolean {
  return bridge() !== undefined;
}

/** Host platform reported by the main process, or the browser's best guess. */
export function hostPlatform(): string {
  const native = bridge()?.platform;
  if (native) return native;
  if (typeof navigator === 'undefined') return '';
  const ua = navigator.userAgent;
  if (/Windows/i.test(ua)) return 'win32';
  if (/Mac/i.test(ua)) return 'darwin';
  return /Linux/i.test(ua) ? 'linux' : '';
}

/** Invokes a main-process command. Rejects outside the Electron app. */
export function invoke<T>(command: CommandName, args?: Record<string, unknown>): Promise<T> {
  const native = bridge();
  if (!native) return Promise.reject(new Error('Native bridge not available'));
  return native.invoke(command, args) as Promise<T>;
}

/**
 * Subscribes to a main-process event and returns the unsubscribe function.
 * A no-op outside the Electron app, so callers need no guard.
 */
export function listen<E extends EventName>(
  event: E,
  handler: (payload: EventPayloads[E]) => void,
): () => void {
  const native = bridge();
  if (!native) return () => {};
  return native.on(event, handler);
}
