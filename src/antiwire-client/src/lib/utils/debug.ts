const DEBUG_KEY = 'antiwire:debug';

export function isDebugEnabled(): boolean {
  if (typeof window === 'undefined') return false;
  try {
    return window.localStorage.getItem(DEBUG_KEY) === '1';
  } catch {
    return false;
  }
}

export function setDebugEnabled(enabled: boolean) {
  if (typeof window === 'undefined') return;
  try {
    if (enabled) window.localStorage.setItem(DEBUG_KEY, '1');
    else window.localStorage.removeItem(DEBUG_KEY);
  } catch {
    // ignore storage errors
  }
}

export function debugLog(scope: string, message: string, data?: unknown) {
  if (!isDebugEnabled()) return;
  if (data === undefined) {
    console.log(`[antiwire:${scope}] ${message}`);
    return;
  }
  console.log(`[antiwire:${scope}] ${message}`, data);
}

export function debugWarn(scope: string, message: string, data?: unknown) {
  if (!isDebugEnabled()) return;
  if (data === undefined) {
    console.warn(`[antiwire:${scope}] ${message}`);
    return;
  }
  console.warn(`[antiwire:${scope}] ${message}`, data);
}

export function debugError(scope: string, message: string, data?: unknown) {
  if (!isDebugEnabled()) return;
  if (data === undefined) {
    console.error(`[antiwire:${scope}] ${message}`);
    return;
  }
  console.error(`[antiwire:${scope}] ${message}`, data);
}
