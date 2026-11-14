import { app, nativeImage, type NativeImage } from 'electron';
import fs from 'node:fs/promises';
import os from 'node:os';
import { IconCache } from '../icons/icon-cache';
import { normalizeIconPath } from '../icons/icon-path';
import { LinuxAppIcons, gsettings, nodeIconFs } from '../icons/linux-icons';
import { arg, command, type CommandTable } from './define';

const icons = new IconCache();
const linuxIcons = new LinuxAppIcons(nodeIconFs, process.env, os.homedir(), gsettings);

/**
 * The side, in points, of the icon asked of Quick Look. Rows draw icons at up to 30px, and
 * Electron multiplies this by the display's scale factor.
 */
const BUNDLE_ICON_SIZE = 32;

/** Icon themes carry PNGs up to 512px. Rows draw at up to 30px, twice that on a dense display. */
const MAX_ICON_PIXELS = 64;

/** An application icon drawn as SVG is a few kilobytes. Larger is not an icon. */
const MAX_SVG_BYTES = 256 * 1024;

/**
 * When the icon source last changed, or `null` when no icon can come from it.
 *
 * The source is a file on Windows and Linux and an application bundle, a directory, on
 * macOS. On Linux one that cannot be seen still counts: an executable inside a Flatpak
 * sandbox, or one only root may read, is matched to its desktop entry by name.
 */
async function sourceModified(source: string): Promise<number | null> {
  try {
    const stat = await fs.stat(source);
    const usable = process.platform === 'darwin' ? stat.isDirectory() : stat.isFile();
    return usable ? stat.mtimeMs : null;
  } catch {
    return process.platform === 'linux' ? 0 : null;
  }
}

/**
 * The icon of the application bundle at `bundle`, from Quick Look.
 *
 * `app.getFileIcon` cannot do this on macOS: there it "returns the icon for the file type of
 * that file rather than the file itself" (electron/electron#15809), so every application got
 * the same stock picture. `createThumbnailFromPath` asks `QLThumbnailGenerator` for the best
 * representation of the file itself, which for a bundle is its icon.
 */
async function bundleIcon(bundle: string): Promise<NativeImage | null> {
  try {
    return await nativeImage.createThumbnailFromPath(bundle, {
      width: BUNDLE_ICON_SIZE,
      height: BUNDLE_ICON_SIZE,
    });
  } catch {
    // Quick Look could not draw this one. That does not change on a retry, so it is a miss.
    return null;
  }
}

function pngUrl(image: NativeImage | null): string | null {
  return !image || image.isEmpty() ? null : image.toDataURL();
}

/**
 * The icon of the Linux application `exe` belongs to, found through its desktop entry and
 * the icon themes; see `linux-icons.ts` for why `app.getFileIcon` is not used here either.
 * A PNG is scaled down to what the app draws. An SVG is passed on as it is: Electron has no
 * decoder for it, and the renderer shows it in an `<img>`, where it cannot run scripts or
 * load anything.
 */
async function linuxIcon(exe: string): Promise<string | null> {
  const file = await linuxIcons.iconFile(exe);
  if (!file) return null;
  if (file.toLowerCase().endsWith('.svg')) {
    const svg = await fs.readFile(file);
    if (svg.length === 0 || svg.length > MAX_SVG_BYTES) return null;
    return `data:image/svg+xml;base64,${svg.toString('base64')}`;
  }
  const image = nativeImage.createFromPath(file);
  const { width, height } = image.getSize();
  const oversized = Math.max(width, height) > MAX_ICON_PIXELS;
  return pngUrl(
    oversized
      ? image.resize(
          width >= height
            ? { width: MAX_ICON_PIXELS, quality: 'best' }
            : { height: MAX_ICON_PIXELS, quality: 'best' },
        )
      : image,
  );
}

async function loadIcon(source: string): Promise<string | null> {
  switch (process.platform) {
    case 'darwin':
      return pngUrl(await bundleIcon(source));
    case 'linux':
      return linuxIcon(source);
    default:
      // Windows reads the icon out of the executable. `large` is 32px, the biggest it has.
      return pngUrl(await app.getFileIcon(source, { size: 'large' }));
  }
}

export const iconCommands = {
  /**
   * The icon of the application at `path` as a base64 `data:` URL (PNG, or SVG for a Linux
   * application whose icon is one), or `null` when there is none (placeholders, bare names,
   * network paths, missing files, programs with no icon of their own). Keyed by path and
   * mtime, so an updated executable gets a fresh icon.
   */
  get_app_icon: command({ path: arg.text(4096) }, async ({ path }) => {
    const source = normalizeIconPath(path);
    if (!source) return null;
    const modified = await sourceModified(source);
    if (modified === null) return null;
    const key = `${process.platform === 'win32' ? source.toLowerCase() : source}\0${modified}`;
    return icons.get(key, () => loadIcon(source));
  }),
} satisfies Partial<CommandTable>;
