import { app } from 'electron';
import fs from 'node:fs/promises';
import { IconCache } from '../icons/icon-cache';
import { normalizeIconPath } from '../icons/icon-path';
import { arg, command, type CommandTable } from './define';

const icons = new IconCache();

/** A file, or on macOS an `.app` bundle (a directory the shell draws an icon for). */
async function iconSourceStat(source: string) {
  try {
    const stat = await fs.stat(source);
    const bundle = process.platform === 'darwin' && stat.isDirectory() && source.endsWith('.app');
    return stat.isFile() || bundle ? stat : null;
  } catch {
    return null;
  }
}

async function loadIcon(source: string): Promise<string | null> {
  // `large` is 48px on Windows and 32px elsewhere; rows draw it at 16-24px.
  const image = await app.getFileIcon(source, { size: 'large' });
  return image.isEmpty() ? null : image.toDataURL();
}

export const iconCommands = {
  /**
   * The icon of the application at `path` as a `data:image/png;base64,…` URL,
   * or `null` when there is none (placeholders, bare names, network paths,
   * missing files). Keyed by path and mtime, so an updated executable gets a
   * fresh icon.
   */
  get_app_icon: command({ path: arg.text(4096) }, async ({ path }) => {
    const source = normalizeIconPath(path);
    if (!source) return null;
    const stat = await iconSourceStat(source);
    if (!stat) return null;
    const key = `${process.platform === 'win32' ? source.toLowerCase() : source}\0${stat.mtimeMs}`;
    return icons.get(key, () => loadIcon(source));
  }),
} satisfies Partial<CommandTable>;
