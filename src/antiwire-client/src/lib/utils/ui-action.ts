import { formatErrorMessage } from './error';

export interface UiActionOptions {
  onError?: (message: string, error: unknown) => void;
}

function isPromiseLike(value: unknown): value is PromiseLike<unknown> {
  return (
    value !== null &&
    (typeof value === 'object' || typeof value === 'function') &&
    typeof (value as { then?: unknown }).then === 'function'
  );
}

/**
 * Runs a user-triggered action and routes any sync/async failure to `onError`
 * instead of letting it escape as an unhandled rejection.
 *
 * Returns the action result, or `undefined` when the action failed or
 * returned nothing. Never throws — `onError` itself is guarded.
 */
export async function runUiAction<T>(
  action: () => T | Promise<T>,
  options?: UiActionOptions,
): Promise<T | undefined> {
  try {
    const result = action();
    if (isPromiseLike(result)) {
      return (await result) as T;
    }
    return result;
  } catch (error) {
    try {
      options?.onError?.(formatErrorMessage(error), error);
    } catch {
      // Error reporting must never break the UI action path.
    }
    return undefined;
  }
}

/** Fire-and-forget wrapper for `onclick`-style handlers. */
export function fireUiAction(action: () => unknown, options?: UiActionOptions): void {
  void runUiAction(action, options);
}

/**
 * Safely invokes a shared-control callback (Toggle/Dropdown/SegmentedControl)
 * whose implementation may be async. Sync throws and async rejections are
 * both routed to `onError`.
 */
export function invokeUiCallback(
  callback: ((value: never) => unknown) | undefined,
  value: never,
  options?: UiActionOptions,
): void {
  if (!callback) return;
  fireUiAction(() => callback(value) as unknown, options);
}
