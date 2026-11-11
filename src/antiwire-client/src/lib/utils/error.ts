const GENERIC_ERROR = 'An unexpected error occurred.';

/** Observe fire-and-forget work without allowing a rejection to escape globally. */
export async function catchAsyncError(
  task: Promise<unknown>,
  report: (error: unknown) => void,
): Promise<void> {
  try {
    await task;
  } catch (error) {
    report(error);
  }
}

/**
 * Turns an unknown throw value into a short, user-visible string.
 * Never throws — error UI has to keep rendering even when the payload is garbage.
 */
export function formatErrorMessage(error: unknown, fallback = GENERIC_ERROR): string {
  if (typeof error === 'string') {
    const trimmed = error.trim();
    return trimmed || fallback;
  }

  try {
    if (error instanceof Error) {
      const message = error.message;
      return typeof message === 'string' ? message.trim() || fallback : fallback;
    }

    const message = error && typeof error === 'object' ? Reflect.get(error, 'message') : undefined;
    if (typeof message === 'string') {
      const trimmed = message.trim();
      if (trimmed) return trimmed;
    }
  } catch {
    // Ignore hostile proxies and throwing message accessors.
  }

  try {
    const text = String(error ?? '');
    if (text && text !== '[object Object]') return text;
  } catch {
    // ignore exotic toString failures
  }

  return fallback;
}

/**
 * The message inside a daemon error. The main process forwards a tonic
 * `Status` as text (`gRPC error: status: …, message: "…", details: …`); the
 * quoted message is the part meant for people. Other text comes back as is.
 */
export function daemonErrorMessage(text: string): string {
  const match = /message: "((?:[^"\\]|\\.)*)"/.exec(text);
  if (!match) return text;
  const message = match[1].replace(/\\(.)/g, '$1').trim();
  return message || text;
}

/** Reads an i18n string, falling back if the catalog is missing or the lookup throws. */
export function tryMessage(read: () => string, fallback: string): string {
  try {
    const value = read();
    return typeof value === 'string' && value.trim() ? value : fallback;
  } catch {
    return fallback;
  }
}
