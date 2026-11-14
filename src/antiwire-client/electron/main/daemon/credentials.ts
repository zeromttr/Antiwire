import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

/** How long a cached token is trusted before the file's mtime is checked again. */
export const TOKEN_RECHECK_INTERVAL_MS = 2_000;

/** Where to look for the daemon's credentials. Injectable so tests need not touch real paths. */
export interface CredentialHost {
  env: NodeJS.ProcessEnv;
  platform: NodeJS.Platform;
  homedir: string;
}

export function defaultHost(): CredentialHost {
  return { env: process.env, platform: process.platform, homedir: os.homedir() };
}

function pathsFor(platform: NodeJS.Platform): typeof path.posix {
  return platform === 'win32' ? path.win32 : path.posix;
}

function modifiedTime(file: string): number | null {
  try {
    return fs.statSync(file).mtimeMs;
  } catch {
    return null;
  }
}

/**
 * Token files to try, newest first. `ANTIWIRE_IPC_TOKEN` replaces the search.
 * Only files that exist are returned; one this account cannot read still
 * counts, so `connect` can tell "not in the group" from "no daemon".
 */
export function candidateTokenPaths(host: CredentialHost = defaultHost()): string[] {
  const override = host.env.ANTIWIRE_IPC_TOKEN;
  if (override) return [override];

  const p = pathsFor(host.platform);
  const paths: string[] = [];
  if (host.platform === 'win32') {
    const local = host.env.LOCALAPPDATA || p.join(host.homedir, 'AppData', 'Local');
    paths.push(p.join(local, 'Antiwire', 'Antiwire', 'data', 'ipc.token'));
    paths.push(p.join(local, 'Antiwire', 'ipc.token'));
    if (host.env.PROGRAMDATA) paths.push(p.join(host.env.PROGRAMDATA, 'Antiwire', 'ipc.token'));
  } else {
    paths.push(p.join(host.homedir, '.antiwire', 'ipc.token'));
    paths.push('/var/lib/antiwire/ipc.token');
  }

  return paths
    .map((file) => ({ file, mtime: modifiedTime(file) }))
    .filter((entry): entry is { file: string; mtime: number } => entry.mtime !== null)
    .sort((a, b) => b.mtime - a.mtime)
    .map((entry) => entry.file);
}

/** The pinned TLS certificate beside `tokenPath`, or `ANTIWIRE_IPC_CERT`. */
export function certPathFor(tokenPath: string, host: CredentialHost = defaultHost()): string {
  const override = host.env.ANTIWIRE_IPC_CERT;
  if (override) return override;
  return pathsFor(host.platform).join(pathsFor(host.platform).dirname(tokenPath), 'ipc.crt');
}

/** Reads `file`, warning about failures other than the file simply not existing yet. */
function readOrWarn<T>(file: string, read: (file: string) => T): T | null {
  try {
    return read(file);
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code !== 'ENOENT')
      console.warn(`[antiwire] cannot read IPC credential file ${file}: ${code}`);
    return null;
  }
}

/** The token at `file`, trimmed; empty when it cannot be read. */
export function readTokenAt(file: string): string {
  return readOrWarn(file, (f) => fs.readFileSync(f, 'utf8'))?.trim() ?? '';
}

export function readCertAt(file: string): Buffer {
  return readOrWarn(file, (f) => fs.readFileSync(f)) ?? Buffer.alloc(0);
}

/** Whether the token at `file` exists but this account may not read it. */
export function isAccessDenied(file: string): boolean {
  try {
    fs.closeSync(fs.openSync(file, 'r'));
    return false;
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    // Windows reports ERROR_ACCESS_DENIED as EPERM; unix uses EACCES.
    return code === 'EACCES' || code === 'EPERM';
  }
}

/**
 * Tracks the token file a connection succeeded with. The token itself never
 * leaves the main process and is never logged.
 */
export class IpcCredentialResolver {
  #path: string | null = null;
  #token = '';
  #modified: number | null = null;
  #checked = 0;

  constructor(
    private readonly host: CredentialHost = defaultHost(),
    private readonly now: () => number = Date.now,
  ) {}

  candidateTokenPaths(): string[] {
    return candidateTokenPaths(this.host);
  }

  certPathFor(tokenPath: string): string {
    return certPathFor(tokenPath, this.host);
  }

  /** Remembers the token file a connection succeeded with, and its contents. */
  resolve(file: string, token: string): void {
    this.#path = file;
    this.#token = token;
    this.#modified = modifiedTime(file);
    this.#checked = this.now();
  }

  /**
   * The token to send with a request.
   *
   * Served from memory: the file is only stat'd every `TOKEN_RECHECK_INTERVAL_MS`
   * and re-read when it changed, so a rotated token is still picked up without
   * reading disk on every RPC.
   */
  currentBestToken(): string {
    if (this.#path !== null) {
      if (this.now() - this.#checked < TOKEN_RECHECK_INTERVAL_MS) return this.#token;
      const modified = modifiedTime(this.#path);
      this.#checked = this.now();
      if (modified === this.#modified && this.#token) return this.#token;
      const token = readTokenAt(this.#path);
      if (token) {
        this.#token = token;
        this.#modified = modified;
        return token;
      }
    }
    const first = this.candidateTokenPaths()[0];
    return first ? readTokenAt(first) : '';
  }
}
