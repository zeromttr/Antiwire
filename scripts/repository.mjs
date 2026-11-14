#!/usr/bin/env node
/**
 * The project's GitHub repository, stated once: `[workspace.package] repository` in
 * src/antiwire-rs/Cargo.toml. The daemon compiles it in (CARGO_PKG_REPOSITORY, trust.rs), the
 * client's build defines it (vite.shared.ts), and the workflows read it here.
 *
 *   node scripts/repository.mjs                 prints owner/name
 *   node scripts/repository.mjs url             prints https://github.com/owner/name
 *   node scripts/repository.mjs check <owner/name>
 *       exits 1 unless the repository is <owner/name>, such as ${{ github.repository }}
 *
 * Moving the project means changing that one line. `release.yml` runs `check` first, so a
 * release from the new location cannot ship daemons that look for updates at the old one.
 */

import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { tomlTableValue } from './check-versions.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const GITHUB_URL = /^https:\/\/github\.com\/([A-Za-z0-9-]+)\/([A-Za-z0-9._-]+)$/u;

/** `{ url, slug }` for a repository URL, or throws for anything but a plain GitHub URL. */
export function parseRepository(url) {
  const match = GITHUB_URL.exec(url ?? '');
  if (!match || match[2].endsWith('.git')) {
    throw new Error(`repository must look like https://github.com/owner/name, not ${url}`);
  }
  return { url, slug: `${match[1]}/${match[2]}` };
}

/** The repository src/antiwire-rs/Cargo.toml states. */
export async function readRepository(root = ROOT) {
  const toml = await readFile(resolve(root, 'src/antiwire-rs/Cargo.toml'), 'utf8');
  return parseRepository(tomlTableValue(toml, 'workspace.package', 'repository'));
}

/** Whether `slug` names the same repository. GitHub ignores case in owner and name. */
export function sameRepository(repository, slug) {
  return repository.slug.toLowerCase() === slug.trim().toLowerCase();
}

async function main(argv) {
  const repository = await readRepository();
  const [command, ...rest] = argv;
  if (command === undefined) {
    console.log(repository.slug);
  } else if (command === 'url' && rest.length === 0) {
    console.log(repository.url);
  } else if (command === 'check' && rest.length === 1) {
    if (!sameRepository(repository, rest[0])) {
      throw new Error(
        `src/antiwire-rs/Cargo.toml names ${repository.slug}, but this runs in ${rest[0]}. ` +
          'Update [workspace.package] repository before releasing from here.',
      );
    }
    console.log(`Repository ${repository.slug} matches.`);
  } else {
    throw new Error('usage: repository.mjs [url | check <owner/name>]');
  }
}

const invokedDirectly =
  process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1]);
if (invokedDirectly) {
  main(process.argv.slice(2)).catch((error) => {
    console.error(error instanceof Error ? error.message : error);
    process.exitCode = 1;
  });
}
