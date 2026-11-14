import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { cp, mkdir, mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { readSources, versionProblems } from './check-versions.mjs';
import {
  setJsonVersion,
  setTomlTableVersion,
  setVersion,
  setWorkflowEnvVersion,
} from './set-version.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const SOURCES = [
  'src/antiwire-rs/Cargo.toml',
  'src/antiwire-client/package.json',
  '.github/workflows/packages.yml',
];

describe('set-version', () => {
  let dir;

  beforeAll(async () => {
    dir = await mkdtemp(join(tmpdir(), 'antiwire-set-version-'));
    for (const path of SOURCES) {
      await mkdir(dirname(join(dir, path)), { recursive: true });
      await cp(join(ROOT, path), join(dir, path));
    }
  });

  afterAll(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  test('changes only the table version in Cargo.toml', () => {
    const toml = [
      '[workspace]',
      'members = ["a"]',
      '',
      '[workspace.package]',
      'version = "0.1.0"',
      'edition = "2021"',
      '',
      '[workspace.dependencies]',
      'serde = { version = "1.0" }',
      '',
    ].join('\n');
    const updated = setTomlTableVersion(toml, 'workspace.package', '0.2.0-beta.1');
    expect(updated).toContain('version = "0.2.0-beta.1"\nedition');
    expect(updated).toContain('serde = { version = "1.0" }');
    expect(() => setTomlTableVersion('[package]\nname = "x"\n', 'package', '1.0.0')).toThrow();
  });

  test('changes only the top-level version in package.json and the workflow env', () => {
    const json = '{\n  "name": "x",\n  "version": "0.1.0",\n  "dependencies": {}\n}\n';
    expect(setJsonVersion(json, '0.2.0')).toBe(json.replace('0.1.0', '0.2.0'));
    const yaml = 'env:\n  ANTIWIRE_VERSION: 0.1.0\n  RUST_BACKTRACE: "1"\n';
    expect(setWorkflowEnvVersion(yaml, '0.2.0-rc.1')).toBe(yaml.replace('0.1.0', '0.2.0-rc.1'));
  });

  test('writes one version into every source check-versions reads', async () => {
    await setVersion(dir, '0.3.1-nightly.20261102.41');
    const sources = await readSources(dir);
    expect(versionProblems(sources, '0.3.1-nightly.20261102.41')).toEqual([]);
    const json = JSON.parse(await readFile(join(dir, SOURCES[1]), 'utf8'));
    expect(json.version).toBe('0.3.1-nightly.20261102.41');
  });

  test('refuses a version that is not semver', async () => {
    await expect(setVersion(dir, 'nightly')).rejects.toThrow('semantic version');
  });
});
