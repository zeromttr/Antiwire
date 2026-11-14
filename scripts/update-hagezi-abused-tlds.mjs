#!/usr/bin/env node
/**
 * Builds data/hagezi-abused-tlds.txt from HaGeZi's Most Abused TLDs list.
 *
 * Downloads the Adblock syntax feed, writes bare names, and always appends
 * .christmas, .mov, and .zip. Legacy infrastructure zones are never written.
 */

import { createHash } from 'node:crypto';
import { writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { readRepository } from './repository.mjs';

export const SOURCE_URLS = [
  'https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/spam-tlds-adblock.txt',
  'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/spam-tlds-adblock.txt',
  'https://gitlab.com/hagezi/mirror/-/raw/main/dns-blocklists/adblock/spam-tlds-adblock.txt',
];

/** Always written, even when HaGeZi omits them. */
export const ALWAYS_INCLUDE = ['christmas', 'mov', 'zip'];

/** Bare names that are too widely used to block. */
export const NEVER_BLOCK = new Set([
  'com',
  'net',
  'org',
  'edu',
  'gov',
  'mil',
  'int',
  'arpa',
]);

const NAME_PATTERN = /^(?:xn--[a-z0-9-]+|[a-z0-9]+)(?:\.(?:xn--[a-z0-9-]+|[a-z0-9]+))*$/u;

export function normalizeName(name) {
  if (typeof name !== 'string') {
    return null;
  }
  const value = name.trim().replace(/^\.+|\.+$/gu, '').toLowerCase();
  if (!value || NEVER_BLOCK.has(value) || !NAME_PATTERN.test(value)) {
    return null;
  }
  return value;
}

export function parseHageziList(text) {
  const names = [];
  for (const rawLine of text.split(/\r?\n/u)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('!') || line.startsWith('[') || line.startsWith('#')) {
      continue;
    }
    const rule = line.startsWith('||') && line.endsWith('^') ? line.slice(2, -1) : line;
    const name = normalizeName(rule);
    if (name !== null) {
      names.push(name);
    }
  }
  return [...new Set(names)];
}

export function mergeAlwaysInclude(names) {
  const extra = ALWAYS_INCLUDE.map((name) => normalizeName(name)).filter((name) => name !== null);
  return [...new Set([...names, ...extra])];
}

/** `homepage` is the project's repository URL (scripts/repository.mjs). */
export function renderList({ names, homepage }) {
  const unique = [...new Set(names)].sort((left, right) => left.localeCompare(right));
  const lines = [
    "# Title: Antiwire HaGeZi abused TLDs",
    "# Description: HaGeZi's The World's Most Abused TLDs, normalized to bare names, plus pinned .christmas/.mov/.zip.",
    '# Source: https://github.com/hagezi/dns-blocklists',
    '# License: https://github.com/hagezi/dns-blocklists/blob/main/LICENSE',
    `# Homepage: ${homepage}`,
    '# Syntax: Domains',
    '#',
    ...unique,
    '',
  ];
  return lines.join('\n');
}

export function fileHash(body) {
  return createHash('sha256').update(body, 'utf8').digest('hex');
}

export function renderHashFile(hex, filename = 'hagezi-abused-tlds.txt') {
  return `${hex}  ${filename}\n`;
}

export function parseHashFile(text) {
  if (typeof text !== 'string') {
    return null;
  }
  for (const rawLine of text.split(/\r?\n/u)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) {
      continue;
    }
    const token = line.split(/\s+/u)[0]?.toLowerCase();
    if (token && /^[0-9a-f]{64}$/u.test(token)) {
      return token;
    }
  }
  return null;
}

async function fetchHageziList() {
  const errors = [];
  for (const url of SOURCE_URLS) {
    try {
      const response = await fetch(url);
      if (!response.ok) {
        errors.push(`${url}: ${response.status} ${response.statusText}`);
        continue;
      }
      const text = await response.text();
      const names = parseHageziList(text);
      if (names.length === 0) {
        errors.push(`${url}: no eligible names`);
        continue;
      }
      return names;
    } catch (error) {
      errors.push(`${url}: ${error instanceof Error ? error.message : error}`);
    }
  }
  throw new Error(`HaGeZi TLD list download failed (${errors.join('; ')})`);
}

async function main() {
  const names = mergeAlwaysInclude(await fetchHageziList());
  if (names.length === 0) {
    throw new Error('HaGeZi returned no eligible names');
  }

  const body = renderList({ names, homepage: (await readRepository()).url });
  const hex = fileHash(body);
  const dataDir = resolve(dirname(fileURLToPath(import.meta.url)), '..', 'data');
  const output = resolve(dataDir, 'hagezi-abused-tlds.txt');
  const hashOutput = resolve(dataDir, 'hagezi-abused-tlds.sha256');
  await writeFile(output, body, 'utf8');
  await writeFile(hashOutput, renderHashFile(hex), 'utf8');
  console.log(`Wrote ${names.length} names to ${output}`);
  console.log(`Wrote SHA-256 ${hex} to ${hashOutput}`);
}

const invokedDirectly =
  process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1]);
if (invokedDirectly) {
  main().catch((error) => {
    console.error(error instanceof Error ? error.message : error);
    process.exitCode = 1;
  });
}
