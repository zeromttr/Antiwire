import { describe, expect, test } from 'bun:test';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import {
  readSources,
  tomlTableVersion,
  versionProblems,
  workflowEnvVersion,
} from './check-versions.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

describe('check-versions', () => {
  test('reads a version from the named TOML table only', () => {
    const toml = `
[package]
name = "antiwire-client"
version = "1.2.3"

[dependencies]
version = "9.9.9"
`;
    expect(tomlTableVersion(toml, 'package')).toBe('1.2.3');
    expect(tomlTableVersion(toml, 'workspace.package')).toBeNull();
  });

  test('reads workspace.package from a workspace manifest', () => {
    const toml = `[workspace]\nmembers = []\n\n[workspace.package]\nversion = "0.4.0"\nedition = "2021"\n`;
    expect(tomlTableVersion(toml, 'workspace.package')).toBe('0.4.0');
  });

  test('reads ANTIWIRE_VERSION from the top-level env block only', () => {
    const yaml = `name: Packages
env:
  ANTIWIRE_VERSION: 0.3.1
  RUST_BACKTRACE: "1"

jobs:
  linux-packages:
    steps:
      - name: Build
        env:
          ANTIWIRE_VERSION: \${{ env.ANTIWIRE_VERSION }}
`;
    expect(workflowEnvVersion(yaml)).toBe('0.3.1');
    expect(workflowEnvVersion('env:\n  ANTIWIRE_VERSION: "0.3.2"  # quoted\n')).toBe('0.3.2');
  });

  test('reports missing values and disagreements', () => {
    const sources = [
      { label: 'a', version: '0.1.0' },
      { label: 'b', version: '0.1.0' },
    ];
    expect(versionProblems(sources)).toEqual([]);
    expect(versionProblems([...sources, { label: 'c', version: '0.2.0' }])).toEqual([
      'the sources disagree',
    ]);
    expect(versionProblems([...sources, { label: 'c', version: null }])).toEqual([
      'c: no version found',
      'the sources disagree',
    ]);
  });

  test('requires every source to equal the expected tag version', () => {
    const sources = [
      { label: 'a', version: '0.1.0' },
      { label: 'b', version: '0.1.0' },
    ];
    expect(versionProblems(sources, '0.1.0')).toEqual([]);
    expect(versionProblems(sources, '0.2.0')).toEqual([
      'a: 0.1.0 does not match expected 0.2.0',
      'b: 0.1.0 does not match expected 0.2.0',
    ]);
  });

  test('the repository versions agree', async () => {
    const sources = await readSources(ROOT);
    expect(sources.every((source) => source.version)).toBe(true);
    expect(versionProblems(sources)).toEqual([]);
  });
});
