/**
 * Finds the icon of a Linux application from the path of its executable.
 *
 * Linux has no icon inside an executable. An application says what its icon is in a desktop
 * entry (freedesktop.org Desktop Entry Specification, the `Icon` key), and the name there is
 * looked up in the icon themes (Icon Theme Specification). `app.getFileIcon` does neither: it
 * asks for the icon of the file's MIME type (Chromium's `icon_loader_auralinux.cc`), which is
 * one picture for every program.
 *
 * So: find the desktop entry that starts the executable, then find the file its `Icon` names.
 */
import { execFile } from 'node:child_process';
import fs from 'node:fs/promises';
import path from 'node:path';

const p = path.posix;

/** The file system as this module uses it, so tests can supply one. */
export interface IconFs {
  /** The names in `dir`, or none when it cannot be read. */
  list(dir: string): Promise<string[]>;
  /** The text of `file`, or `null` when it cannot be read or is implausibly large. */
  read(file: string): Promise<string | null>;
  isFile(file: string): Promise<boolean>;
  isDirectory(file: string): Promise<boolean>;
  /** `file` with every symbolic link followed, or `null` when it does not exist. */
  realpath(file: string): Promise<string | null>;
}

/** Desktop entries and `index.theme` files are a few kilobytes; the largest themes reach 100. */
const MAX_TEXT_BYTES = 1024 * 1024;

export const nodeIconFs: IconFs = {
  list: (dir) => fs.readdir(dir).catch(() => []),
  read: async (file) => {
    try {
      if ((await fs.stat(file)).size > MAX_TEXT_BYTES) return null;
      return await fs.readFile(file, 'utf8');
    } catch {
      return null;
    }
  },
  isFile: (file) =>
    fs.stat(file).then(
      (stat) => stat.isFile(),
      () => false,
    ),
  isDirectory: (file) =>
    fs.stat(file).then(
      (stat) => stat.isDirectory(),
      () => false,
    ),
  realpath: (file) => fs.realpath(file).catch(() => null),
};

type KeyFile = Map<string, Map<string, string>>;

/** Parses the `[Group]` / `Key=Value` format desktop entries and `index.theme` share. */
export function parseKeyFile(text: string): KeyFile {
  const groups: KeyFile = new Map();
  let group: Map<string, string> | undefined;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    if (line.startsWith('[') && line.endsWith(']')) {
      const name = line.slice(1, -1);
      // A repeated group is invalid; the first one stands.
      group = groups.get(name) ?? new Map<string, string>();
      if (!groups.has(name)) groups.set(name, group);
      continue;
    }
    const equals = line.indexOf('=');
    if (!group || equals <= 0) continue;
    const key = line.slice(0, equals).trim();
    if (!group.has(key)) group.set(key, line.slice(equals + 1).trim());
  }
  return groups;
}

function unique(values: string[]): string[] {
  return [...new Set(values)];
}

function absoluteDirs(list: string | undefined): string[] {
  return (list ?? '')
    .split(':')
    .map((dir) => (dir.length > 1 ? dir.replace(/\/+$/, '') : dir))
    .filter((dir) => p.isAbsolute(dir));
}

function dataHome(env: NodeJS.ProcessEnv, home: string): string {
  return absoluteDirs(env.XDG_DATA_HOME)[0] ?? p.join(home, '.local/share');
}

/**
 * The data directories, most important first (XDG Base Directory Specification). The places
 * Flatpak and Snap export desktop entries and icons to follow, since a session started
 * without their profile scripts leaves them out of `XDG_DATA_DIRS`.
 */
export function dataDirs(env: NodeJS.ProcessEnv, home: string): string[] {
  const userData = dataHome(env, home);
  const system = absoluteDirs(env.XDG_DATA_DIRS);
  return unique([
    userData,
    ...(system.length > 0 ? system : ['/usr/local/share', '/usr/share']),
    p.join(userData, 'flatpak/exports/share'),
    '/var/lib/flatpak/exports/share',
    '/var/lib/snapd/desktop',
    '/usr/local/share',
    '/usr/share',
  ]);
}

/** Where a program named without a path is looked for. */
export function programDirs(env: NodeJS.ProcessEnv): string[] {
  return unique([
    ...absoluteDirs(env.PATH),
    '/usr/local/bin',
    '/usr/bin',
    '/bin',
    '/usr/games',
    '/snap/bin',
  ]);
}

/**
 * Splits an `Exec` value into its arguments. An argument may be quoted in whole with double
 * quotes, inside which a backslash escapes the next character (Desktop Entry Specification,
 * "The Exec key").
 */
export function execWords(exec: string): string[] {
  const words: string[] = [];
  let word = '';
  let started = false;
  let quoted = false;
  for (let i = 0; i < exec.length; i++) {
    const char = exec[i];
    if (quoted) {
      if (char === '\\' && i + 1 < exec.length) word += exec[++i];
      else if (char === '"') quoted = false;
      else word += char;
    } else if (char === '"') {
      quoted = true;
      started = true;
    } else if (char === ' ' || char === '\t') {
      if (started) words.push(word);
      word = '';
      started = false;
    } else {
      word += char;
      started = true;
    }
  }
  if (started) words.push(word);
  return words;
}

/** One application's desktop entry, reduced to what finding its icon needs. */
export interface DesktopEntry {
  /** The desktop file ID without `.desktop`, such as `org.mozilla.firefox`. */
  id: string;
  /** The program `Exec` starts, as written: a path or a bare name. Empty when there is none. */
  program: string;
  /** `program` as a path with links followed, or `null` when it was not found. */
  target: string | null;
  /** How many arguments `Exec` passes besides field codes. The plain launcher passes fewest. */
  args: number;
  /** The `Icon` value: an absolute path or a name for the icon theme. */
  icon: string;
}

/** `env NAME=value program args` and `program args` both start `program`. */
function programAndArgs(exec: string): { program: string; args: number } {
  const words = execWords(exec);
  let start = 0;
  if (words[0] !== undefined && p.basename(words[0]) === 'env') {
    start = 1;
    while (start < words.length && (words[start].startsWith('-') || words[start].includes('='))) {
      start++;
    }
  }
  const rest = words.slice(start + 1).filter((word) => !/^%[a-zA-Z]$/.test(word));
  return { program: words[start] ?? '', args: rest.length };
}

async function resolveProgram(
  files: IconFs,
  program: string,
  searchDirs: string[],
): Promise<string | null> {
  if (!program) return null;
  if (p.isAbsolute(program)) return files.realpath(program);
  if (program.includes('/')) return null;
  for (const dir of searchDirs) {
    const found = await files.realpath(p.join(dir, program));
    if (found) return found;
  }
  return null;
}

/** Desktop entries sit at most this deep under `applications`; vendors use one level. */
const MAX_DESKTOP_DEPTH = 2;
/** More entries than any real system has; a bound on a directory that is not what it seems. */
const MAX_DESKTOP_ENTRIES = 4000;

async function desktopFiles(
  files: IconFs,
  dir: string,
  prefix = '',
  depth = 0,
): Promise<{ id: string; file: string }[]> {
  const found: { id: string; file: string }[] = [];
  for (const name of (await files.list(dir)).sort()) {
    const file = p.join(dir, name);
    if (name.endsWith('.desktop')) {
      // `applications/foo/bar.desktop` has the ID `foo-bar.desktop`.
      found.push({ id: prefix + name.slice(0, -'.desktop'.length), file });
    } else if (depth < MAX_DESKTOP_DEPTH && (await files.isDirectory(file))) {
      found.push(...(await desktopFiles(files, file, `${prefix}${name}-`, depth + 1)));
    }
  }
  return found;
}

/**
 * Every application desktop entry that names an icon, from `dirs` in order. Where an ID
 * appears twice the first stands, and one marked `Hidden` counts as deleted, as the
 * specification says.
 */
export async function readDesktopEntries(
  files: IconFs,
  dirs: string[],
  searchDirs: string[],
): Promise<DesktopEntry[]> {
  const entries: DesktopEntry[] = [];
  const seen = new Set<string>();
  for (const dir of dirs) {
    for (const { id, file } of await desktopFiles(files, p.join(dir, 'applications'))) {
      if (seen.has(id) || seen.size >= MAX_DESKTOP_ENTRIES) continue;
      const text = await files.read(file);
      if (text === null) continue;
      seen.add(id);
      const entry = parseKeyFile(text).get('Desktop Entry');
      const icon = entry?.get('Icon') ?? '';
      if (!entry || !icon) continue;
      if (entry.get('Type') !== 'Application' || entry.get('Hidden') === 'true') continue;
      const { program, args } = programAndArgs(entry.get('Exec') ?? '');
      entries.push({
        id,
        program,
        target: await resolveProgram(files, program, searchDirs),
        args,
        icon,
      });
    }
  }
  return entries;
}

/**
 * Programs that start other applications. An entry whose `Exec` begins with one says nothing
 * about which executable the application is, and one of them running is not that application.
 */
const LAUNCHERS = new Set([
  'bash',
  'dash',
  'env',
  'flatpak',
  'gtk-launch',
  'sh',
  'snap',
  'xdg-open',
  'zsh',
]);

/** Directories many unrelated programs share, so being in one together means nothing. */
function isSharedDir(dir: string): boolean {
  const name = p.basename(dir);
  return (
    dir === '/' ||
    name.includes('-linux-gnu') ||
    /^(s?bin|games|libexec|lib|lib32|lib64|share|opt|local|usr)$/.test(name)
  );
}

function executableNames(exe: string): string[] {
  const name = p.basename(exe).toLowerCase();
  // `firefox-bin` and `soffice.bin` are what `firefox` and `soffice` end up running.
  return unique([name, name.replace(/[-.]bin$/, '')]);
}

function entryNames(entry: DesktopEntry, launcher: boolean): string[] {
  const id = entry.id.toLowerCase();
  const names = [id, id.slice(id.lastIndexOf('.') + 1)];
  if (!launcher && entry.program) names.push(p.basename(entry.program).toLowerCase());
  return names;
}

/** How sure it is that `entry` starts `exe`: 0 is not at all. */
function matchStrength(entry: DesktopEntry, exe: string): number {
  const launcher = LAUNCHERS.has(p.basename(entry.target ?? entry.program));
  if (!launcher && entry.target === exe) return 3;
  const names = entryNames(entry, launcher);
  if (executableNames(exe).some((name) => names.includes(name))) return 2;
  // A launcher script and the binary it runs, side by side in the application's own folder:
  // `/opt/google/chrome/google-chrome` and `/opt/google/chrome/chrome`.
  const dir = p.dirname(exe);
  if (!launcher && entry.target && p.dirname(entry.target) === dir && !isSharedDir(dir)) return 1;
  return 0;
}

/** A Snap's files are under `/snap/<name>/<revision>`, and its entries are `<name>_<app>`. */
function snapEntry(entries: DesktopEntry[], exe: string): DesktopEntry | null {
  const snap = /^\/snap\/([^/]+)\//.exec(exe)?.[1];
  if (!snap) return null;
  const own = entries.filter((entry) => entry.id.startsWith(`${snap}_`));
  return (
    own.find((entry) => entry.id === `${snap}_${snap}`) ??
    own.find((entry) => entry.id === `${snap}_${p.basename(exe)}`) ??
    own[0] ??
    null
  );
}

/**
 * The desktop entry of the application `exe` belongs to, or `null`.
 *
 * `exe` is what the daemon reads from `/proc/<pid>/exe`, so links are already followed. The
 * strongest evidence wins; between equals, the entry passing the fewest arguments, which is
 * the application's plain launcher rather than one of its modes.
 */
export function matchDesktopEntry(entries: DesktopEntry[], exe: string): DesktopEntry | null {
  const snap = snapEntry(entries, exe);
  if (snap) return snap;
  let best: DesktopEntry | null = null;
  let bestStrength = 0;
  for (const entry of entries) {
    const strength = matchStrength(entry, exe);
    if (strength === 0) continue;
    if (strength > bestStrength || (strength === bestStrength && best && entry.args < best.args)) {
      best = entry;
      bestStrength = strength;
    }
  }
  return best;
}

/** The side, in pixels, the app draws icons at on a high-density display. */
const WANTED_SIZE = 48;
/** What the app can show. The specification's third format, XPM, it cannot. */
const ICON_EXTENSIONS = ['png', 'svg'];
/** Used when `hicolor` has no `index.theme`, which the `hicolor-icon-theme` package supplies. */
const HICOLOR_FALLBACK = [
  '48x48',
  '64x64',
  '96x96',
  '128x128',
  '256x256',
  '512x512',
  'scalable',
  '32x32',
].map((size) => `${size}/apps`);

interface Theme {
  /** The theme's icon directories, the best size for `WANTED_SIZE` first. */
  dirs: string[];
  inherits: string[];
}

/** How far a theme directory's icons are from the wanted size. Enlarging is worst. */
function sizeDistance(section: Map<string, string>): number {
  const size = Number(section.get('Size'));
  if (!Number.isFinite(size) || size <= 0) return Number.POSITIVE_INFINITY;
  if (section.get('Type') === 'Scalable') {
    const min = Number(section.get('MinSize') ?? size);
    const max = Number(section.get('MaxSize') ?? size);
    if (WANTED_SIZE >= min && WANTED_SIZE <= max) return 0;
    return WANTED_SIZE < min ? min - WANTED_SIZE : 10_000 + WANTED_SIZE - max;
  }
  return size >= WANTED_SIZE ? size - WANTED_SIZE : 10_000 + WANTED_SIZE - size;
}

/**
 * Reads what a theme's `index.theme` says about its icon directories. Every context counts,
 * not only `Applications`: an entry may name a stock icon, as `info` does with
 * `dialog-information`, and the specification's lookup does not tell contexts apart.
 */
export function parseTheme(text: string): Theme {
  const groups = parseKeyFile(text);
  const head = groups.get('Icon Theme');
  const list = (value: string | undefined) =>
    (value ?? '')
      .split(',')
      .map((item) => item.trim())
      .filter(Boolean);
  const ranked: { dir: string; distance: number }[] = [];
  for (const dir of list(head?.get('Directories'))) {
    const section = groups.get(dir);
    // Reject a directory that would step outside the theme.
    if (!section || p.isAbsolute(dir) || dir.split('/').includes('..')) continue;
    if (Number(section.get('Scale') ?? 1) !== 1) continue;
    const distance = sizeDistance(section);
    if (Number.isFinite(distance)) ranked.push({ dir, distance });
  }
  ranked.sort((a, b) => a.distance - b.distance);
  return { dirs: ranked.map((entry) => entry.dir), inherits: list(head?.get('Inherits')) };
}

/** A theme name is one directory name; anything else is not followed. */
function isThemeName(name: string): boolean {
  return name !== '' && name !== '.' && name !== '..' && !name.includes('/');
}

/** Reads one string setting of a GSettings schema, or `null` when it cannot be read. */
export type ReadSetting = (schema: string, key: string) => Promise<string | null>;

/** `gsettings get` prints a string as serialized GVariant text: `'Yaru'`. */
export function parseSettingString(output: string): string | null {
  const match = /^'(.*)'$/.exec(output.trim());
  return match ? match[1].replace(/\\(.)/g, '$1') : null;
}

/**
 * Asks `gsettings` (`gsettings(1)`), which answers with the user's value or, when they never
 * changed it, the default the distribution ships. The value itself is in dconf's database,
 * which is not a file to parse. Both arguments are constants of this module.
 */
export const gsettings: ReadSetting = (schema, key) =>
  new Promise((resolve) => {
    execFile('gsettings', ['get', schema, key], { timeout: 2000 }, (error, stdout) => {
      resolve(error ? null : parseSettingString(stdout));
    });
  });

/**
 * The schema with the `icon-theme` key, by a name in `$XDG_CURRENT_DESKTOP`. Budgie and
 * Ubuntu sessions list `GNOME` beside their own name.
 */
const INTERFACE_SCHEMAS: Record<string, string> = {
  GNOME: 'org.gnome.desktop.interface',
  'GNOME-Classic': 'org.gnome.desktop.interface',
  'GNOME-Flashback': 'org.gnome.desktop.interface',
  Unity: 'org.gnome.desktop.interface',
  Pantheon: 'org.gnome.desktop.interface',
  Cinnamon: 'org.cinnamon.desktop.interface',
  'X-Cinnamon': 'org.cinnamon.desktop.interface',
};

/** What Plasma uses when `kdeglobals` names no theme (`KIconTheme::current`). */
const KDE_DEFAULT_THEME = 'breeze';

async function keyFileValue(
  files: IconFs,
  file: string,
  group: string,
  key: string,
): Promise<string | undefined> {
  const text = await files.read(file);
  return text === null ? undefined : parseKeyFile(text).get(group)?.get(key);
}

/**
 * Plasma's icon theme: `[Icons] Theme` in `kdeglobals`. The user's file wins, then the
 * defaults Plasma writes for the chosen global theme (`kdedefaults`, which `startplasma`
 * puts first in `$XDG_CONFIG_DIRS`), then the system's.
 */
async function kdeIconTheme(files: IconFs, env: NodeJS.ProcessEnv, config: string) {
  const dirs = unique([
    config,
    ...absoluteDirs(env.XDG_CONFIG_DIRS),
    p.join(config, 'kdedefaults'),
    '/etc/xdg',
  ]);
  for (const dir of dirs) {
    const theme = await keyFileValue(files, p.join(dir, 'kdeglobals'), 'Icons', 'Theme');
    if (theme) return theme;
  }
  return KDE_DEFAULT_THEME;
}

/**
 * The icon themes the user's desktop draws with, the chosen one first.
 *
 * Plasma keeps the choice in `kdeglobals`; GNOME and the desktops built on it keep it in
 * GSettings. The GTK settings files follow as what other desktops have to go by.
 */
export async function userIconThemes(
  files: IconFs,
  env: NodeJS.ProcessEnv,
  home: string,
  readSetting: ReadSetting,
): Promise<string[]> {
  const config = absoluteDirs(env.XDG_CONFIG_HOME)[0] ?? p.join(home, '.config');
  const desktops = (env.XDG_CURRENT_DESKTOP ?? '').split(':');
  const schema = desktops.map((name) => INTERFACE_SCHEMAS[name]).find(Boolean);
  const themes: (string | null | undefined)[] = [];
  if (desktops.includes('KDE')) themes.push(await kdeIconTheme(files, env, config));
  else if (schema) themes.push(await readSetting(schema, 'icon-theme'));
  for (const gtk of ['gtk-4.0', 'gtk-3.0']) {
    const file = p.join(config, gtk, 'settings.ini');
    themes.push(await keyFileValue(files, file, 'Settings', 'gtk-icon-theme-name'));
  }
  return unique(
    themes.filter((theme): theme is string => typeof theme === 'string' && isThemeName(theme)),
  );
}

/** Finds icon files by name, following the Icon Theme Specification's lookup. */
export class IconThemes {
  #themes = new Map<string, Promise<Theme>>();
  /** Whether each theme directory exists. Most are in one base directory and not the others. */
  #dirs = new Map<string, Promise<boolean>>();
  /** `$HOME/.icons`, each data directory's `icons`, in the specification's order. */
  readonly #bases: string[];

  constructor(
    private readonly files: IconFs,
    dirs: string[],
    home: string,
    /** The themes to look in before `hicolor`. */
    private readonly preferred: string[],
  ) {
    this.#bases = unique([p.join(home, '.icons'), ...dirs.map((dir) => p.join(dir, 'icons'))]);
  }

  #hasDir(dir: string): Promise<boolean> {
    let exists = this.#dirs.get(dir);
    if (!exists) {
      exists = this.files.isDirectory(dir);
      this.#dirs.set(dir, exists);
    }
    return exists;
  }

  #theme(name: string): Promise<Theme> {
    let theme = this.#themes.get(name);
    if (!theme) {
      theme = this.#readTheme(name);
      this.#themes.set(name, theme);
    }
    return theme;
  }

  async #readTheme(name: string): Promise<Theme> {
    for (const base of this.#bases) {
      const text = await this.files.read(p.join(base, name, 'index.theme'));
      if (text !== null) return parseTheme(text);
    }
    return { dirs: name === 'hicolor' ? HICOLOR_FALLBACK : [], inherits: [] };
  }

  /** The preferred themes, then what they inherit from, then `hicolor`, each once. */
  async #themeOrder(): Promise<string[]> {
    const order: string[] = [];
    const queue = [...this.preferred];
    while (queue.length > 0 && order.length < 16) {
      const name = queue.shift();
      if (!name || name === 'hicolor' || order.includes(name) || !isThemeName(name)) continue;
      order.push(name);
      queue.push(...(await this.#theme(name)).inherits);
    }
    return [...order, 'hicolor'];
  }

  /**
   * The file for `icon`, the value of a desktop entry's `Icon` key: the file itself when it
   * is an absolute path, otherwise the closest size the themes have, otherwise a file of
   * that name directly in an icon directory or `/usr/share/pixmaps`.
   */
  async find(icon: string): Promise<string | null> {
    if (p.isAbsolute(icon)) {
      const usable = ICON_EXTENSIONS.includes(p.extname(icon).slice(1).toLowerCase());
      return usable && (await this.files.isFile(icon)) ? icon : null;
    }
    // A name is one file name. Some entries add an extension, which the lookup adds itself.
    const name = icon.replace(/\.(png|svg|xpm)$/i, '');
    if (!name || name.includes('/')) return null;

    for (const theme of await this.#themeOrder()) {
      for (const dir of (await this.#theme(theme)).dirs) {
        for (const base of this.#bases) {
          const folder = p.join(base, theme, dir);
          if (!(await this.#hasDir(folder))) continue;
          for (const extension of ICON_EXTENSIONS) {
            const file = p.join(folder, `${name}.${extension}`);
            if (await this.files.isFile(file)) return file;
          }
        }
      }
    }
    for (const base of [...this.#bases, '/usr/share/pixmaps']) {
      for (const extension of ICON_EXTENSIONS) {
        const file = p.join(base, `${name}.${extension}`);
        if (await this.files.isFile(file)) return file;
      }
    }
    return null;
  }
}

/** How long the desktop entries read from disk are used before they are read again. */
const INDEX_TTL_MS = 60_000;

interface Index {
  entries: DesktopEntry[];
  themes: IconThemes;
}

/** Finds application icon files, reading the installed desktop entries once a minute at most. */
export class LinuxAppIcons {
  #index: Promise<Index> | undefined;
  #expires = 0;

  constructor(
    private readonly files: IconFs,
    private readonly env: NodeJS.ProcessEnv,
    private readonly home: string,
    private readonly readSetting: ReadSetting,
    private readonly now: () => number = Date.now,
  ) {}

  async #build(): Promise<Index> {
    const dirs = dataDirs(this.env, this.home);
    const [entries, preferred] = await Promise.all([
      readDesktopEntries(this.files, dirs, programDirs(this.env)),
      userIconThemes(this.files, this.env, this.home, this.readSetting),
    ]);
    return { entries, themes: new IconThemes(this.files, dirs, this.home, preferred) };
  }

  /** Concurrent callers share one read. A failed read is not kept. */
  #current(): Promise<Index> {
    if (this.#index && this.#expires > this.now()) return this.#index;
    const building = this.#build();
    this.#index = building;
    this.#expires = this.now() + INDEX_TTL_MS;
    building.catch(() => {
      if (this.#index === building) this.#index = undefined;
    });
    return building;
  }

  /** The icon file of the application the executable at `exe` belongs to, or `null`. */
  async iconFile(exe: string): Promise<string | null> {
    const index = await this.#current();
    const entry = matchDesktopEntry(index.entries, exe);
    return entry ? index.themes.find(entry.icon) : null;
  }
}
