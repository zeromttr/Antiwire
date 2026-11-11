import fs from 'node:fs/promises';
import path from 'node:path';
import { z } from 'zod';
import { writeFileAtomic } from './atomic-file';

/**
 * Client-only preferences (theme, accent, locale, onboarding), formerly
 * Tauri's plugin-store. Only these keys are kept; the renderer normalizes the
 * values further (`src/lib/models/client-settings.ts`).
 */
export const clientSettingsSchema = z.strictObject({
  /** A preset id or a custom `#rrggbb` accent. */
  accentColorId: z.string().regex(/^(#[0-9a-fA-F]{6}|[a-z0-9-]{1,32})$/),
  theme: z.enum(['light', 'dark', 'system']),
  onboardingDone: z.boolean(),
  /** A BCP 47 tag such as `en` or `pt-BR`. */
  locale: z.string().regex(/^[A-Za-z]{2,3}(-[A-Za-z0-9]{2,8}){0,3}$/),
});

export const clientSettingsPatchSchema = clientSettingsSchema.partial();

export type ClientSettingsPatch = z.infer<typeof clientSettingsPatchSchema>;

const FIELDS = Object.keys(clientSettingsSchema.shape) as (keyof ClientSettingsPatch)[];

/** Keeps each known key whose value is valid; anything else in the file is ignored. */
export function sanitizeClientSettings(raw: unknown): ClientSettingsPatch {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return {};
  const source = raw as Record<string, unknown>;
  const out: Record<string, unknown> = {};
  for (const field of FIELDS) {
    const parsed = clientSettingsSchema.shape[field].safeParse(source[field]);
    if (parsed.success) out[field] = parsed.data;
  }
  return out as ClientSettingsPatch;
}

async function readSettingsFile(file: string): Promise<ClientSettingsPatch> {
  try {
    return sanitizeClientSettings(JSON.parse(await fs.readFile(file, 'utf8')));
  } catch {
    return {};
  }
}

/** The settings file, read and written by the main process only. Writes are serialized. */
export class ClientSettingsStore {
  #queue: Promise<unknown> = Promise.resolve();

  /**
   * `legacyFile` is read only while `file` does not exist yet (the first run
   * after upgrading); the next write then copies its values into `file`.
   */
  constructor(
    private readonly file: string,
    private readonly legacyFile?: string,
  ) {}

  async read(): Promise<ClientSettingsPatch> {
    try {
      return sanitizeClientSettings(JSON.parse(await fs.readFile(this.file, 'utf8')));
    } catch (error) {
      const missing = (error as NodeJS.ErrnoException).code === 'ENOENT';
      if (missing && this.legacyFile) return readSettingsFile(this.legacyFile);
      // Corrupt: start from the renderer's defaults.
      return {};
    }
  }

  /** Applies `patch` over the stored settings and returns the merged result. */
  update(patch: ClientSettingsPatch): Promise<ClientSettingsPatch> {
    const next = this.#queue.then(async () => {
      const merged = { ...(await this.read()), ...sanitizeClientSettings(patch) };
      await fs.mkdir(path.dirname(this.file), { recursive: true });
      await writeFileAtomic(this.file, JSON.stringify(merged, null, 2));
      return merged;
    });
    this.#queue = next.catch(() => {});
    return next;
  }
}
