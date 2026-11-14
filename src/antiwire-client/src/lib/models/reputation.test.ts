import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { REPUTATION_SERVICES, reputationService } from './reputation';

describe('reputation services', () => {
  test('ids are unique and resolvable', () => {
    const ids = REPUTATION_SERVICES.map((service) => service.id);
    expect(new Set(ids).size).toBe(ids.length);
    for (const id of ids) expect(reputationService(id)?.id).toBe(id);
    expect(reputationService('nope')).toBeUndefined();
  });

  test('match the native command in the same order', () => {
    // Read as text: the renderer does not import main-process modules.
    const source = readFileSync(
      new URL('../../../electron/main/reputation.ts', import.meta.url),
      'utf8',
    );
    const table = source.slice(source.indexOf('REPUTATION_SERVICES:'));
    const native = [...table.slice(0, table.indexOf('];')).matchAll(/\[\s*'(\w+)',/g)].map(
      (match) => match[1],
    );
    expect(native).toEqual(REPUTATION_SERVICES.map((service) => service.id));
  });

  test('preview URLs are https and keep the domain', () => {
    for (const service of REPUTATION_SERVICES) {
      const url = new URL(service.previewUrl('example.com'));
      expect(url.protocol).toBe('https:');
      expect(url.href).toContain('example.com');
    }
  });
});
