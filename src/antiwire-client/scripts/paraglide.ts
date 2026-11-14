/**
 * Compiles the message catalogs for `typecheck` and `test`, which do not go through Vite.
 * Skips the compile when the catalogs, the project settings, the options and the Paraglide
 * version are unchanged since the last one and its output is still there, as the Vite plugin
 * does. A compile takes several seconds; a skip takes milliseconds.
 *
 *   bun scripts/paraglide.ts          compile if anything changed
 *   bun scripts/paraglide.ts --force  compile regardless
 */

import { compile } from '@inlang/paraglide-js';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { PARAGLIDE_OPTIONS } from '../paraglide.options.ts';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
// Outside the output directory, which each compile empties of files it did not write.
const STAMP = path.join(ROOT, 'node_modules/.cache/paraglide-inputs.sha256');

function inputsDigest(): string {
  const hash = createHash('sha256');
  const add = (name: string, contents: string | Buffer) => {
    hash.update(name).update('\0').update(contents).update('\0');
  };
  add('options', JSON.stringify(PARAGLIDE_OPTIONS));
  add('version', readFileSync(path.join(ROOT, 'node_modules/@inlang/paraglide-js/package.json')));
  const project = path.join(ROOT, PARAGLIDE_OPTIONS.project);
  add('settings', readFileSync(path.join(project, 'settings.json')));
  const settings = JSON.parse(readFileSync(path.join(project, 'settings.json'), 'utf8')) as {
    'plugin.inlang.messageFormat'?: { pathPattern?: string };
  };
  const pattern =
    settings['plugin.inlang.messageFormat']?.pathPattern ?? './messages/{locale}.json';
  const catalogs = path.resolve(ROOT, path.dirname(pattern));
  for (const file of readdirSync(catalogs)
    .filter((name) => name.endsWith('.json'))
    .sort()) {
    add(`catalog:${file}`, readFileSync(path.join(catalogs, file)));
  }
  return hash.digest('hex');
}

function outputPresent(): boolean {
  const outdir = path.join(ROOT, PARAGLIDE_OPTIONS.outdir);
  return (
    existsSync(path.join(outdir, 'runtime.js')) &&
    existsSync(path.join(outdir, 'messages/_index.js'))
  );
}

const force = process.argv.includes('--force');
const digest = inputsDigest();
const stamp = existsSync(STAMP) ? readFileSync(STAMP, 'utf8').trim() : '';

if (!force && stamp === digest && outputPresent()) {
  console.log('[paraglide] catalogs unchanged, compile skipped');
} else {
  const started = performance.now();
  await compile({ ...PARAGLIDE_OPTIONS, strategy: [...PARAGLIDE_OPTIONS.strategy] });
  mkdirSync(path.dirname(STAMP), { recursive: true });
  writeFileSync(STAMP, `${digest}\n`);
  console.log(`[paraglide] compiled in ${Math.round(performance.now() - started)} ms`);
}
