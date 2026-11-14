import { describe, expect, it } from 'bun:test';
import { REPUTATION_SERVICES, reputationUrl } from './reputation';

describe('reputationUrl', () => {
  it('builds each report URL', () => {
    expect(reputationUrl('virustotal', 'Example.COM.')).toBe(
      'https://www.virustotal.com/gui/domain/example.com',
    );
    expect(reputationUrl('alienvault', ' cdn.xn--bcher-kva.example ')).toBe(
      'https://otx.alienvault.com/indicator/domain/cdn.xn--bcher-kva.example',
    );
    for (const [id, prefix] of REPUTATION_SERVICES) {
      expect(prefix.startsWith('https://')).toBe(true);
      expect(reputationUrl(id, 'example.com')).toBe(`${prefix}example.com`);
    }
  });

  it('refuses unknown services', () => {
    expect(reputationUrl('', 'example.com')).toBeNull();
    expect(reputationUrl('https://evil.test/', 'example.com')).toBeNull();
  });

  it('refuses anything but a hostname', () => {
    for (const bad of [
      '',
      'localhost',
      '1.2.3.4',
      'example.com/path',
      'example.com?x=1',
      'evil.com#frag',
      'user@example.com',
      'example.com:443',
      'a.com&x=1',
      '-bad.com',
      'a..com',
      'exa mple.com',
      '"&calc.exe',
      '::1',
      `${'a'.repeat(64)}.com`,
    ]) {
      expect([bad, reputationUrl('virustotal', bad)]).toEqual([bad, null]);
    }
  });
});
