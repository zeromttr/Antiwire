import { describe, expect, test } from 'bun:test';
import { resolveWindowPlatform } from './window-platform';

describe('window platform', () => {
  test('the native build target takes precedence over the webview identity', () => {
    expect(resolveWindowPlatform('darwin', 'Windows')).toBe('macos');
    expect(resolveWindowPlatform('windows', 'MacIntel')).toBe('windows');
    expect(resolveWindowPlatform('linux', 'MacIntel')).toBe('linux');
  });

  test('browser previews follow the host and unknown hosts use neutral controls', () => {
    expect(resolveWindowPlatform('', 'MacIntel')).toBe('macos');
    expect(resolveWindowPlatform('', 'Win32')).toBe('windows');
    expect(resolveWindowPlatform('', 'Linux x86_64')).toBe('linux');
    expect(resolveWindowPlatform('', '')).toBe('linux');
  });
});
