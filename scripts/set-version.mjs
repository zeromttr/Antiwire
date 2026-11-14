#!/usr/bin/env node
/**
 * Writes one version into every source check-versions.mjs reads, so a build states it
 * everywhere: the Rust workspace, the client's package.json, and packages.yml.
 *
 *   node scripts/set-version.mjs 0.3.1-nightly.20261102.41
 *
 * The nightly workflow runs it on a commit that only its tag points at; main keeps the
 * version a person chose. Cargo.lock is not touched: the release builds run without
 * --locked and update it.
 */

import { readFile, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { readSources, versionProblems } from './check-versions.mjs';
import { parseVersion } from './release-channel.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

/** `toml` with the `version` key of `[table]` set to `version`. Throws when there is none. */
export function setTomlTableVersion(toml, table, version) {
  const lines = toml.split(/(?<=\n)/u);
  let inTable = false;
  for (let i = 0; i < lines.length; i++) {
    const header = lines[i].match(/^\s*\[([^\]]+)\]\s*$/u);
    if (header) {
      inTable = header[1].trim() === table;
      continue;
    }
    if (inTable && /^\s*version\s*=\s*"[^"]+"/u.test(lines[i])) {
      lines[i] = lines[i].replace(/"[^"]+"/u, `"${version}"`);
      return lines.join('');
    }
  }
  throw new Error(`no version in [${table}]`);
}

/** `json` with its top-level `"version"` set, keeping the file's formatting. */
export function setJsonVersion(json, version) {
  const pattern = /^(\s*"version"\s*:\s*)"[^"]*"/mu;
  if (!pattern.test(json)) {
    throw new Error('no top-level "version" key');
  }
  return json.replace(pattern, `$1"${version}"`);
}

/** `yaml` with the top-level `env: ANTIWIRE_VERSION` set. */
export function setWorkflowEnvVersion(yaml, version) {
  const pattern = /^( {2}ANTIWIRE_VERSION:\s*)["']?[^"'\s#]+["']?/mu;
  if (!pattern.test(yaml)) {
    throw new Error('no ANTIWIRE_VERSION in env');
  }
  return yaml.replace(pattern, `$1${version}`);
}

export async function setVersion(root, version) {
  parseVersion(version);
  const edit = async (path, change) => {
    const file = resolve(root, path);
    await writeFile(file, change(await readFile(file, 'utf8')));
  };
  await edit('src/antiwire-rs/Cargo.toml', (toml) =>
    setTomlTableVersion(toml, 'workspace.package', version),
  );
  await edit('src/antiwire-client/package.json', (json) => setJsonVersion(json, version));
  await edit('.github/workflows/packages.yml', (yaml) => setWorkflowEnvVersion(yaml, version));

  const problems = versionProblems(await readSources(root), version);
  if (problems.length > 0) {
    throw new Error(`version not written everywhere: ${problems.join('; ')}`);
  }
}

const invokedDirectly =
  process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1]);
if (invokedDirectly) {
  const args = process.argv.slice(2);
  if (args.length !== 1) {
    console.error('usage: set-version.mjs <version>');
    process.exitCode = 2;
  } else {
    setVersion(ROOT, args[0]).then(
      () => console.log(`Set every version source to ${args[0]}.`),
      (error) => {
        console.error(error instanceof Error ? error.message : error);
        process.exitCode = 1;
      },
    );
  }
}
