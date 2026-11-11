#!/usr/bin/env node
/**
 * Checks that every place that states the product version agrees.
 *
 *   node scripts/check-versions.mjs                  every source must agree
 *   node scripts/check-versions.mjs --expect 0.2.0   and must equal 0.2.0 (the release tag)
 *
 * Prints each version it reads and exits 1 when any is missing or they differ.
 */

import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

/**
 * The string value of `key` in a TOML table, or null. Only the table's own keys are read, and
 * only `key = "value"` on one line, which is how the files this repository reads write them.
 */
export function tomlTableValue(toml, table, key) {
  let inTable = false;
  for (const line of toml.split(/\r?\n/u)) {
    const header = line.match(/^\s*\[([^\]]+)\]\s*$/u);
    if (header) {
      inTable = header[1].trim() === table;
      continue;
    }
    if (inTable) {
      const match = line.match(/^\s*([A-Za-z0-9_-]+)\s*=\s*"([^"]+)"/u);
      if (match && match[1] === key) {
        return match[2];
      }
    }
  }
  return null;
}

/** The `version` key of a TOML table, or null. */
export function tomlTableVersion(toml, table) {
  return tomlTableValue(toml, table, 'version');
}

/** `ANTIWIRE_VERSION` from the top-level `env:` block of a workflow file, or null. */
export function workflowEnvVersion(yaml) {
  const match = yaml.match(/^ {2}ANTIWIRE_VERSION:\s*["']?([^"'\s#]+)/mu);
  return match ? match[1] : null;
}

/**
 * Problems with the versions read from each source: a missing value, values that differ,
 * or (with `expect`) a value other than the expected one.
 */
export function versionProblems(sources, expect = null) {
  const problems = [];
  for (const { label, version } of sources) {
    if (!version) {
      problems.push(`${label}: no version found`);
    } else if (expect !== null && version !== expect) {
      problems.push(`${label}: ${version} does not match expected ${expect}`);
    }
  }
  const distinct = new Set(sources.map((source) => source.version));
  if (distinct.size > 1) {
    problems.push('the sources disagree');
  }
  return problems;
}

export async function readSources(root) {
  const read = (path) => readFile(resolve(root, path), 'utf8');
  const json = async (path) => JSON.parse(await read(path)).version ?? null;
  return [
    {
      label: 'src/antiwire-rs/Cargo.toml [workspace.package]',
      version: tomlTableVersion(await read('src/antiwire-rs/Cargo.toml'), 'workspace.package'),
    },
    {
      label: 'src/antiwire-client/package.json',
      version: await json('src/antiwire-client/package.json'),
    },
    {
      label: '.github/workflows/packages.yml ANTIWIRE_VERSION',
      version: workflowEnvVersion(await read('.github/workflows/packages.yml')),
    },
  ];
}

async function main(args) {
  let expect = null;
  if (args.length === 2 && args[0] === '--expect') {
    expect = args[1];
  } else if (args.length !== 0) {
    throw new Error('usage: check-versions.mjs [--expect <version>]');
  }

  const sources = await readSources(ROOT);
  for (const { label, version } of sources) {
    console.log(`${label}: ${version ?? '(missing)'}`);
  }

  const problems = versionProblems(sources, expect);
  if (problems.length > 0) {
    throw new Error(`version check failed: ${problems.join('; ')}`);
  }
  console.log(`All versions agree${expect === null ? '' : ` with ${expect}`}.`);
}

const invokedDirectly =
  process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1]);
if (invokedDirectly) {
  main(process.argv.slice(2)).catch((error) => {
    console.error(error instanceof Error ? error.message : error);
    process.exitCode = 1;
  });
}
