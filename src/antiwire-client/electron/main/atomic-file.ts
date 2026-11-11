import { randomBytes } from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';

/**
 * A file written beside its destination and renamed over it on `commit`, so
 * a reader never sees a partial file and a failed write leaves the old one.
 */
export class AtomicFile {
  private constructor(
    readonly destination: string,
    private readonly temporary: string,
    private readonly handle: fs.FileHandle,
  ) {}

  static async create(destination: string): Promise<AtomicFile> {
    const parent = path.dirname(destination);
    if (!parent || parent === destination) {
      throw new Error('destination has no parent directory');
    }
    const temporary = path.join(
      parent,
      `.${path.basename(destination)}.${randomBytes(6).toString('hex')}.tmp`,
    );
    const handle = await fs.open(temporary, 'wx', 0o600);
    return new AtomicFile(destination, temporary, handle);
  }

  async write(data: Uint8Array | string): Promise<void> {
    // `writeFile` loops until every byte is written; `write` may stop short.
    await this.handle.writeFile(data);
  }

  async commit(): Promise<void> {
    await this.handle.sync();
    await this.handle.close();
    await fs.rename(this.temporary, this.destination);
  }

  /** Discards the partial file. Safe to call after `commit` failed. */
  async discard(): Promise<void> {
    await this.handle.close().catch(() => {});
    await fs.rm(this.temporary, { force: true }).catch(() => {});
  }
}

/** Writes `data` to `destination` atomically. */
export async function writeFileAtomic(
  destination: string,
  data: Uint8Array | string,
): Promise<void> {
  const file = await AtomicFile.create(destination);
  try {
    await file.write(data);
    await file.commit();
  } catch (error) {
    await file.discard();
    throw error;
  }
}
