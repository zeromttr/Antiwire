import path from 'node:path';

/** Owner labels the daemon uses when it could not resolve a process image. */
const PLACEHOLDERS = new Set([
  'unknown (exited)',
  'unknown (no owner)',
  'unknown (access denied)',
  'unknown',
  'unknown.exe',
  'system',
  'system / elevated process',
  'path unavailable',
]);

function isIconCandidate(value: string): boolean {
  const trimmed = value.trim();
  if (!trimmed || trimmed === '—' || trimmed === '-') return false;
  return !PLACEHOLDERS.has(trimmed.toLowerCase());
}

/** Strips `\\?\` / `\??\` prefixes so the shell can open the file. */
export function stripNtPathPrefix(value: string): string {
  const trimmed = value.trim();
  const lower = trimmed.toLowerCase();
  if (lower.startsWith('\\\\?\\unc\\')) return '\\\\' + trimmed.slice('\\\\?\\unc\\'.length);
  for (const prefix of ['\\\\?\\', '\\??\\']) {
    if (lower.startsWith(prefix)) return trimmed.slice(prefix.length);
  }
  return trimmed;
}

/**
 * True for `\\server\share` paths in any spelling. Opening one makes Windows
 * contact that server and offer the user's credentials, and the path comes
 * from the renderer, so network locations are never used as an icon source.
 */
function isNetworkPath(value: string): boolean {
  const local = stripNtPathPrefix(value);
  return (
    local.startsWith('\\\\') ||
    local.startsWith('//') ||
    value.trim().toLowerCase().startsWith('\\??\\unc\\')
  );
}

/**
 * The executable to take an icon from, or `null` when `raw` cannot name one. On macOS it is
 * the application bundle the executable is in; see `macosIconSource`.
 *
 * Disambiguated hosts arrive as `C:\...\svchost.exe::ServiceName` and
 * `C:\...\rundll32.exe::module.dll,EntryPoint`: the suffix is identity, the
 * prefix is the icon source. Bare executable names do not resolve reliably,
 * so only absolute paths are accepted.
 */
export function normalizeIconPath(
  raw: string,
  platform: NodeJS.Platform = process.platform,
): string | null {
  if (!isIconCandidate(raw)) return null;
  const exe = raw.trim().split('::')[0].trim();
  if (!isIconCandidate(exe) || isNetworkPath(exe)) return null;
  if (!exe.includes('\\') && !exe.includes('/')) return null;
  const local = stripNtPathPrefix(exe);
  const p = platform === 'win32' ? path.win32 : path.posix;
  if (!p.isAbsolute(local)) return null;
  // Windows also treats a rooted path without a drive (`\Windows\x.exe`) as absolute; require one.
  if (platform === 'win32' && !/^[a-zA-Z]:[\\/]/.test(local)) return null;
  if (platform === 'darwin') return macosIconSource(local);
  // The kernel adds this to the path of an executable that was replaced while it runs.
  return platform === 'linux' ? local.replace(/ \(deleted\)$/, '') : local;
}

/**
 * The application bundle `file` belongs to, or `null` when it is in none.
 *
 * On macOS only a bundle has an icon of its own. A bare binary, as most system daemons are,
 * has none: the system would draw the same stock picture for every one of them, so they get
 * no icon and the app shows their initials.
 *
 * The outermost bundle is the application the user knows. The ones nested in it are its
 * helpers (`Foo.app/Contents/Frameworks/Foo Helper.app`), which do much of an application's
 * networking and have no icon of their own.
 */
export function macosIconSource(file: string): string | null {
  let bundle: string | null = null;
  let current = file;
  for (;;) {
    if (path.posix.extname(current).toLowerCase() === '.app') bundle = current;
    const parent = path.posix.dirname(current);
    if (parent === current) return bundle;
    current = parent;
  }
}
