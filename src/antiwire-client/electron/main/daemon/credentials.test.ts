import { afterEach, beforeEach, describe, expect, it } from 'bun:test';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  candidateTokenPaths,
  certPathFor,
  IpcCredentialResolver,
  readTokenAt,
  TOKEN_RECHECK_INTERVAL_MS,
  type CredentialHost,
} from './credentials';

let root: string;

beforeEach(() => {
  root = fs.mkdtempSync(path.join(os.tmpdir(), 'antiwire-creds-'));
});
afterEach(() => {
  fs.rmSync(root, { recursive: true, force: true });
});

function write(file: string, contents: string, mtimeSeconds: number) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, contents);
  fs.utimesSync(file, mtimeSeconds, mtimeSeconds);
}

function windowsHost(): CredentialHost {
  return {
    platform: 'win32',
    homedir: root,
    env: { LOCALAPPDATA: path.join(root, 'local'), PROGRAMDATA: path.join(root, 'programdata') },
  };
}

describe('candidateTokenPaths', () => {
  it.skipIf(process.platform !== 'win32')('lists existing Windows tokens newest first', () => {
    const host = windowsHost();
    const service = path.join(root, 'programdata', 'Antiwire', 'ipc.token');
    const dev = path.join(root, 'local', 'Antiwire', 'ipc.token');
    const data = path.join(root, 'local', 'Antiwire', 'Antiwire', 'data', 'ipc.token');
    write(service, 'a', 1_000);
    write(dev, 'b', 3_000);
    write(data, 'c', 2_000);
    expect(candidateTokenPaths(host)).toEqual([dev, data, service]);
  });

  it.skipIf(process.platform === 'win32')('lists the home token on unix', () => {
    const token = path.join(root, '.antiwire', 'ipc.token');
    write(token, 't', 1_000);
    const host: CredentialHost = { platform: 'linux', homedir: root, env: {} };
    expect(candidateTokenPaths(host)[0]).toBe(token);
  });

  it('skips files that do not exist', () => {
    expect(candidateTokenPaths(windowsHost())).toEqual([]);
  });

  it('uses ANTIWIRE_IPC_TOKEN alone when set', () => {
    const host = { ...windowsHost(), env: { ...windowsHost().env, ANTIWIRE_IPC_TOKEN: 'X:\\t' } };
    expect(candidateTokenPaths(host)).toEqual(['X:\\t']);
  });

  it('ignores an empty override', () => {
    const host = { ...windowsHost(), env: { ...windowsHost().env, ANTIWIRE_IPC_TOKEN: '' } };
    expect(candidateTokenPaths(host)).toEqual([]);
  });
});

describe('certPathFor', () => {
  it('is derived from the token directory', () => {
    const host = windowsHost();
    expect(certPathFor('C:\\Users\\test\\AppData\\Local\\Antiwire\\ipc.token', host)).toBe(
      'C:\\Users\\test\\AppData\\Local\\Antiwire\\ipc.crt',
    );
  });

  it('honours ANTIWIRE_IPC_CERT', () => {
    const host = { ...windowsHost(), env: { ANTIWIRE_IPC_CERT: 'C:\\x.crt' } };
    expect(certPathFor('C:\\a\\ipc.token', host)).toBe('C:\\x.crt');
  });
});

describe('IpcCredentialResolver', () => {
  it('trims the token and treats a missing file as empty', () => {
    const token = path.join(root, 'ipc.token');
    write(token, '  secret\n', 1_000);
    expect(readTokenAt(token)).toBe('secret');
    expect(readTokenAt(path.join(root, 'missing'))).toBe('');
  });

  it('serves the cached token until the recheck interval, then picks up a rotation', () => {
    const token = path.join(root, 'ipc.token');
    write(token, 'first', 1_000);
    let now = 0;
    const resolver = new IpcCredentialResolver(
      { platform: process.platform, homedir: root, env: { ANTIWIRE_IPC_TOKEN: token } },
      () => now,
    );
    resolver.resolve(token, 'first');

    write(token, 'second', 2_000);
    now = TOKEN_RECHECK_INTERVAL_MS - 1;
    expect(resolver.currentBestToken()).toBe('first');
    now = TOKEN_RECHECK_INTERVAL_MS + 1;
    expect(resolver.currentBestToken()).toBe('second');
  });

  it('falls back to the newest candidate before any connection', () => {
    const token = path.join(root, 'ipc.token');
    write(token, 'fresh', 1_000);
    const resolver = new IpcCredentialResolver({
      platform: process.platform,
      homedir: root,
      env: { ANTIWIRE_IPC_TOKEN: token },
    });
    expect(resolver.currentBestToken()).toBe('fresh');
  });
});
