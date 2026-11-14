import { describe, expect, it } from 'bun:test';
import { hasApplicationPath } from './application-path';

describe('hasApplicationPath', () => {
  it('rejects empty and placeholder paths', () => {
    expect(hasApplicationPath('')).toBe(false);
    expect(hasApplicationPath('   ')).toBe(false);
    expect(hasApplicationPath('—')).toBe(false);
  });

  it('rejects bare executable names', () => {
    expect(hasApplicationPath('steam.exe')).toBe(false);
    expect(hasApplicationPath('brave.exe')).toBe(false);
  });

  it('accepts absolute filesystem paths', () => {
    expect(hasApplicationPath('C:\\Program Files\\Steam\\steam.exe')).toBe(true);
    expect(hasApplicationPath('/usr/bin/curl')).toBe(true);
    expect(hasApplicationPath('C:\\Windows\\System32\\svchost.exe::DoSvc')).toBe(true);
  });
});
