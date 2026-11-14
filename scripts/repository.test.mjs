import { describe, expect, test } from 'bun:test';
import { tomlTableValue } from './check-versions.mjs';
import { parseRepository, readRepository, sameRepository } from './repository.mjs';

describe('repository', () => {
  test('reads a key from its own TOML table only', () => {
    const toml = [
      '[workspace.package]',
      'version = "0.1.0"',
      'repository = "https://github.com/example/antiwire"',
      '',
      '[workspace.dependencies]',
      'repository = "https://example.com/elsewhere"',
    ].join('\n');
    expect(tomlTableValue(toml, 'workspace.package', 'repository')).toBe(
      'https://github.com/example/antiwire',
    );
    expect(tomlTableValue(toml, 'workspace.package', 'license')).toBeNull();
  });

  test('accepts only a plain GitHub repository URL', () => {
    expect(parseRepository('https://github.com/example/antiwire').slug).toBe(
      'example/antiwire',
    );
    for (const url of [
      'https://github.com/example/antiwire/',
      'https://github.com/example/antiwire.git',
      'http://github.com/example/antiwire',
      'https://gitlab.com/example/antiwire',
      'https://github.com/example',
      null,
    ]) {
      expect(() => parseRepository(url)).toThrow('https://github.com/owner/name');
    }
  });

  test('compares owner and name without case, as GitHub does', () => {
    const repository = parseRepository('https://github.com/example/antiwire');
    expect(sameRepository(repository, 'Example/Antiwire')).toBe(true);
    expect(sameRepository(repository, 'antiwire/antiwire')).toBe(false);
  });

  test('the workspace states a valid repository', async () => {
    const repository = await readRepository();
    expect(repository.url).toBe(`https://github.com/${repository.slug}`);
  });
});
