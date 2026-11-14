import { describe, expect, test } from 'bun:test';
import { releaseUrl, REPOSITORY_URL } from './project';

describe('project', () => {
  test('builds the release page of a version from the repository', () => {
    expect(releaseUrl('0.3.0', 'https://github.com/example/antiwire')).toBe(
      'https://github.com/example/antiwire/releases/tag/v0.3.0',
    );
    expect(releaseUrl('0.3.1-nightly.20261102.4', 'https://github.com/example/antiwire')).toBe(
      'https://github.com/example/antiwire/releases/tag/v0.3.1-nightly.20261102.4',
    );
  });

  test('leaves links out where the build did not define the repository', () => {
    // Unit tests run without Vite, so nothing defines it here.
    expect(REPOSITORY_URL).toBe('');
    expect(releaseUrl('0.3.0')).toBe('');
    expect(releaseUrl('', 'https://github.com/example/antiwire')).toBe('');
  });
});
