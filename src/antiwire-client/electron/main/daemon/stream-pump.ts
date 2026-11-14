/** How often batched stream items are sent to the renderer. */
export const BATCH_INTERVAL_MS = 100;

export interface BatchedPumpOptions<M, T> {
  /** The stream to read; iteration ends when it ends or fails. */
  source: AsyncIterable<M>;
  /** Aborted when the task is replaced or stopped. */
  signal: AbortSignal;
  map: (message: M) => T;
  /** Sends one batch; returning `false` (no window to receive it) stops the pump. */
  emit: (batch: T[]) => boolean;
  /** Items held between ticks; the oldest are dropped beyond this. */
  maxPending: number;
  /** The stream ended normally. `flush` sends what is still pending. */
  onEnd?: (flush: () => void) => void;
  /** The stream failed (not called after `signal` was aborted). */
  onError?: (error: unknown) => void;
  intervalMs?: number;
}

/**
 * Forwards a server stream to the renderer, coalescing bursts into one IPC
 * event per tick. When the renderer cannot keep up the newest items win:
 * beyond `maxPending` the oldest pending item is dropped. Shared by the live
 * traffic and captured-packet streams.
 */
export async function pumpBatched<M, T>(options: BatchedPumpOptions<M, T>): Promise<void> {
  const { source, signal, map, emit, maxPending } = options;
  let pending: T[] = [];
  let stopped = false;
  let stopSource: (() => void) | null = null;

  const flush = () => {
    if (pending.length === 0) return;
    const batch = pending;
    pending = [];
    if (!emit(batch)) stop();
  };
  const stop = () => {
    stopped = true;
    stopSource?.();
  };
  const timer = setInterval(flush, options.intervalMs ?? BATCH_INTERVAL_MS);

  try {
    const iterator = source[Symbol.asyncIterator]();
    stopSource = () => void iterator.return?.();
    while (!stopped && !signal.aborted) {
      const next = await iterator.next();
      if (next.done) {
        if (!signal.aborted && !stopped) options.onEnd?.(flush);
        break;
      }
      if (pending.length >= maxPending) pending.shift();
      pending.push(map(next.value));
    }
  } catch (error) {
    if (!signal.aborted && !stopped) options.onError?.(error);
  } finally {
    clearInterval(timer);
  }
}
