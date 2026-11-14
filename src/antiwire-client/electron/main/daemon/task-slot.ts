/**
 * Holds at most one background task, identified by an `AbortSignal`.
 * Starting a new one aborts the previous task, so a restart can never leave a
 * stream running untracked.
 */
export class TaskSlot {
  #current: { key: string; controller: AbortController } | null = null;

  /** Starts a task under `key`, aborting whatever was there; returns its signal. */
  replace(key = ''): AbortSignal {
    this.abort();
    const controller = new AbortController();
    this.#current = { key, controller };
    return controller.signal;
  }

  abort(): void {
    const current = this.#current;
    this.#current = null;
    current?.controller.abort();
  }

  /** Aborts the task only if it was stored under `key`. */
  abortIf(key: string): void {
    if (this.#current?.key === key) this.abort();
  }

  /**
   * Called by a task when it ends on its own: aborts its signal (cancelling a
   * call it left open) and frees the slot. A newer task in the slot is left alone.
   */
  finish(signal: AbortSignal): void {
    if (this.#current?.controller.signal === signal) this.abort();
  }
}
