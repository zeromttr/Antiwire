import { describe, expect, it } from 'bun:test';
import { pumpBatched } from './stream-pump';

/** A source the test feeds by hand. */
function channel<T>() {
  const queue: IteratorResult<T>[] = [];
  let wake: (() => void) | null = null;
  let failure: unknown = null;
  const notify = () => {
    wake?.();
    wake = null;
  };
  return {
    push(value: T) {
      queue.push({ value, done: false });
      notify();
    },
    end() {
      queue.push({ value: undefined, done: true });
      notify();
    },
    fail(error: unknown) {
      failure = error;
      notify();
    },
    source: {
      [Symbol.asyncIterator]: () => ({
        async next(): Promise<IteratorResult<T>> {
          for (;;) {
            if (failure) throw failure;
            const item = queue.shift();
            if (item) return item;
            await new Promise<void>((resolve) => (wake = resolve));
          }
        },
        async return(): Promise<IteratorResult<T>> {
          return { value: undefined, done: true };
        },
      }),
    } satisfies AsyncIterable<T>,
  };
}

const tick = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

describe('pumpBatched', () => {
  it('coalesces items into one batch per tick and keeps the newest', async () => {
    const input = channel<number>();
    const batches: number[][] = [];
    const done = pumpBatched({
      source: input.source,
      signal: new AbortController().signal,
      map: (n) => n * 10,
      emit: (batch) => (batches.push(batch), true),
      maxPending: 3,
      intervalMs: 20,
    });
    for (const n of [1, 2, 3, 4, 5]) input.push(n);
    await tick(50);
    expect(batches).toEqual([[30, 40, 50]]);
    input.end();
    await done;
  });

  it('flushes the tail on a normal end when asked', async () => {
    const input = channel<number>();
    const batches: number[][] = [];
    const done = pumpBatched({
      source: input.source,
      signal: new AbortController().signal,
      map: (n) => n,
      emit: (batch) => (batches.push(batch), true),
      maxPending: 10,
      intervalMs: 10_000,
      onEnd: (flush) => flush(),
    });
    input.push(1);
    input.push(2);
    input.end();
    await done;
    expect(batches).toEqual([[1, 2]]);
  });

  it('reports a failure, but not one caused by aborting', async () => {
    const errors: unknown[] = [];
    const failing = channel<number>();
    const run = (signal: AbortSignal, source = failing.source) =>
      pumpBatched({
        source,
        signal,
        map: (n) => n,
        emit: () => true,
        maxPending: 1,
        onError: (error) => errors.push(error),
      });

    const first = run(new AbortController().signal);
    failing.fail(new Error('broken'));
    await first;
    expect(errors).toHaveLength(1);

    const aborted = new AbortController();
    const quiet = channel<number>();
    const second = run(aborted.signal, quiet.source);
    aborted.abort();
    quiet.fail(new Error('cancelled'));
    await second;
    expect(errors).toHaveLength(1);
  });

  it('stops when there is no window to receive a batch', async () => {
    const input = channel<number>();
    let emits = 0;
    const done = pumpBatched({
      source: input.source,
      signal: new AbortController().signal,
      map: (n) => n,
      emit: () => (emits++, false),
      maxPending: 10,
      intervalMs: 10,
    });
    input.push(1);
    await tick(30);
    input.push(2);
    await done;
    expect(emits).toBe(1);
  });
});
