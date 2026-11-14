import { expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { compileReact } from './vite.react-compiler.ts';

const ROOT = import.meta.dirname;

function compile(file: string, production = false) {
  const absolute = path.join(ROOT, file);
  return compileReact(absolute, readFileSync(absolute, 'utf8'), production);
}

// A compiled component or hook starts by asking the compiler runtime for its cache.
const USES_COMPILER = /from "react\/compiler-runtime"/;

test('compiles a component', async () => {
  const { code, map } = await compile('src/lib/components/ui/Button.tsx');
  expect(code).toMatch(USES_COMPILER);
  expect(JSON.parse(map!).sources).toHaveLength(1);
});

// Bun's compiler skips `.ts` files unless they are parsed as TSX. Without that these hooks,
// which every component reads the stores through, would lose their memoization and
// nothing would fail.
test.each(['src/lib/state/reactive.ts', 'src/lib/use-presence.ts'])(
  'compiles the hooks in %s',
  async (file) => {
    expect((await compile(file)).code).toMatch(USES_COMPILER);
  },
);

test('leaves imports for Vite to resolve', async () => {
  const { code } = await compile('src/lib/components/ui/Button.tsx');
  expect(code).toContain('from "./Button.module.css"');
});

// React's development JSX runtime exports nothing in a production build of React.
test('uses the JSX runtime that matches the build', async () => {
  const file = 'src/lib/components/ui/Button.tsx';
  expect((await compile(file, false)).code).toContain('from "react/jsx-dev-runtime"');
  const production = (await compile(file, true)).code;
  expect(production).toContain('from "react/jsx-runtime"');
  expect(production).not.toContain('jsx-dev-runtime');
});

test('compiles what Vite read, not what is on disk', async () => {
  const file = path.join(ROOT, 'src/lib/components/ui/Button.tsx');
  const { code } = await compileReact(file, 'export const marker = "from-vite";', false);
  expect(code).toContain('from-vite');
});
