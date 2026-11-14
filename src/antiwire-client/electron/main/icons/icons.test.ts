import { describe, expect, it } from 'bun:test';
import { IconCache } from './icon-cache';
import { macosIconSource, normalizeIconPath, stripNtPathPrefix } from './icon-path';

describe('normalizeIconPath', () => {
  it('strips the svchost service and rundll32 module suffixes', () => {
    expect(normalizeIconPath('C:\\Windows\\System32\\svchost.exe::DnsCache', 'win32')).toBe(
      'C:\\Windows\\System32\\svchost.exe',
    );
    expect(
      normalizeIconPath('C:\\Windows\\System32\\rundll32.exe::shell32.dll,Control_RunDLL', 'win32'),
    ).toBe('C:\\Windows\\System32\\rundll32.exe');
  });

  it('rejects network paths', () => {
    for (const p of [
      '\\\\server\\share\\app.exe',
      '\\\\?\\UNC\\server\\share\\app.exe',
      '\\??\\UNC\\server\\share\\app.exe',
      '//server/share/app.exe',
      '\\\\server\\share\\svchost.exe::Service',
    ]) {
      expect([p, normalizeIconPath(p, 'win32')]).toEqual([p, null]);
    }
    expect(normalizeIconPath('\\\\?\\C:\\Windows\\System32\\cmd.exe', 'win32')).toBe(
      'C:\\Windows\\System32\\cmd.exe',
    );
  });

  it('rejects placeholders, bare names and relative paths', () => {
    for (const p of [
      'unknown',
      'Path unavailable',
      'System / Elevated Process',
      'notepad.exe',
      'a\\b.exe',
      '\\Windows\\x.exe',
    ]) {
      expect([p, normalizeIconPath(p, 'win32')]).toEqual([p, null]);
    }
  });

  it('uses the enclosing app bundle on macOS', () => {
    expect(normalizeIconPath('/Applications/Safari.app/Contents/MacOS/Safari', 'darwin')).toBe(
      '/Applications/Safari.app',
    );
    expect(macosIconSource('/Applications/Utilities/Terminal.app')).toBe(
      '/Applications/Utilities/Terminal.app',
    );
    expect(normalizeIconPath('/usr/bin/curl', 'darwin')).toBe('/usr/bin/curl');
  });

  it('strips extended and NT prefixes', () => {
    expect(stripNtPathPrefix('\\\\?\\C:\\Apps\\tool.exe')).toBe('C:\\Apps\\tool.exe');
    expect(stripNtPathPrefix('\\??\\C:\\Apps\\tool.exe')).toBe('C:\\Apps\\tool.exe');
    expect(stripNtPathPrefix('\\\\?\\UNC\\server\\share\\app.exe')).toBe(
      '\\\\server\\share\\app.exe',
    );
    expect(stripNtPathPrefix('C:\\Apps\\tool.exe')).toBe('C:\\Apps\\tool.exe');
  });
});

describe('IconCache', () => {
  it('loads once for concurrent requests', async () => {
    const cache = new IconCache();
    let loads = 0;
    const load = async () => {
      loads++;
      await new Promise((resolve) => setTimeout(resolve, 20));
      return 'data:image/png;base64,AA==';
    };
    const results = await Promise.all(Array.from({ length: 8 }, () => cache.get('k', load)));
    expect(new Set(results)).toEqual(new Set(['data:image/png;base64,AA==']));
    expect(loads).toBe(1);
  });

  it('remembers missing icons for a while but never errors', async () => {
    let now = 0;
    const cache = new IconCache(16, 1_000, () => now);
    let loads = 0;
    const none = async () => (loads++, null);
    await cache.get('none', none);
    await cache.get('none', none);
    expect(loads).toBe(1);
    now = 2_000;
    await cache.get('none', none);
    expect(loads).toBe(2);

    let failures = 0;
    const fail = async (): Promise<string | null> => {
      failures++;
      throw new Error('disk full');
    };
    await expect(cache.get('bad', fail)).rejects.toThrow('disk full');
    await expect(cache.get('bad', fail)).rejects.toThrow('disk full');
    expect(failures).toBe(2);
  });

  it('evicts the least recently used entry', async () => {
    const cache = new IconCache(2);
    await cache.get('a', async () => 'A');
    await cache.get('b', async () => 'B');
    await cache.get('a', async () => 'A2'); // touch a
    await cache.get('c', async () => 'C');
    expect(cache.size).toBe(2);
    expect(await cache.get('a', async () => 'reloaded')).toBe('A');
    expect(await cache.get('b', async () => 'reloaded')).toBe('reloaded');
  });
});
