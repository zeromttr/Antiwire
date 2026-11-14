import path from 'node:path';

/**
 * Destinations the user picked in a native save dialog, each usable once.
 *
 * Commands that write files (`download_capture`, `export_logs`) only accept a
 * destination that came from a dialog, so a compromised renderer cannot make
 * the app overwrite an arbitrary file: a person has to choose the path.
 * Bounded so a renderer that keeps opening dialogs cannot grow it without limit.
 */
export class ApprovedPaths {
  static readonly MAX = 8;
  #paths: string[] = [];

  approve(file: string): void {
    const key = path.resolve(file);
    this.#paths = this.#paths.filter((existing) => existing !== key);
    if (this.#paths.length === ApprovedPaths.MAX) this.#paths.shift();
    this.#paths.push(key);
  }

  /** Removes `file` and returns whether it had been approved. */
  take(file: string): boolean {
    const index = this.#paths.indexOf(path.resolve(file));
    if (index < 0) return false;
    this.#paths.splice(index, 1);
    return true;
  }

  /** Consumes the approval for `file`, failing when no dialog produced it. */
  require(file: string): void {
    if (!this.take(file)) throw new Error('the destination was not chosen in a save dialog');
  }
}

export const approvedSavePaths = new ApprovedPaths();
