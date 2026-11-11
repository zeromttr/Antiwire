import { describe, expect, test } from 'bun:test';
import { readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';

/**
 * React Compiler caches a component's output on the identity of its inputs.
 * Workspaces (`TrackedReactive`) are mutated in place and keep their identity,
 * so a compiled component that reads `ws.field` while rendering keeps showing
 * the first render's output: `useReactive` re-renders it, but every cached
 * value still matches. That is how the Scan page rendered blank.
 *
 * Any component that reads a workspace while rendering must therefore opt out
 * with a `'use no memo'` directive. This test finds them: a .tsx file that
 * calls `useReactive` or imports a workspace module (a component handed a
 * workspace imports its type) must carry the directive.
 */

const SRC = path.resolve(import.meta.dir, '../..');

/** `*-workspace.ts` and the capture session controller, which is one too. */
const WORKSPACE_IMPORT = /from\s+'[^']*(?:-workspace|\/capture-session)(?:\.ts)?'/;
const USE_REACTIVE_CALL = /\buseReactive\(/;
/** The directive must be the module's first statement; comments may precede it. */
const OPT_OUT = /^(?:\s*\/\/[^\n]*\n|\s*\/\*[\s\S]*?\*\/)*\s*'use no memo';/;

function tsxFiles(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) return entry.name === 'paraglide' ? [] : tsxFiles(full);
    return entry.name.endsWith('.tsx') ? [full] : [];
  });
}

const files = tsxFiles(SRC).map((file) => ({
  name: path.relative(SRC, file).replaceAll('\\', '/'),
  source: readFileSync(file, 'utf8'),
}));

const readsWorkspace = files.filter(
  ({ source }) => WORKSPACE_IMPORT.test(source) || USE_REACTIVE_CALL.test(source),
);

describe('React Compiler opt-out', () => {
  test('finds the workspace-driven components', () => {
    // Guards the patterns above: if they stop matching, the check below passes vacuously.
    expect(readsWorkspace.map((file) => file.name)).toContain('routes/NetworkPage.tsx');
  });

  test("every component that reads a workspace starts with 'use no memo'", () => {
    const missing = readsWorkspace.filter(({ source }) => !OPT_OUT.test(source));
    expect(missing.map((file) => file.name)).toEqual([]);
  });
});
