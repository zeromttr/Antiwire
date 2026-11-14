import type { Plugin } from 'vite';

/**
 * Which modules the React Compiler can change: ones with JSX, a React import, or a hook
 * definition. Vite checks this before calling the plugin, so the rest are never handed
 * over (most modules: stores, models, formatting).
 */
const REACT_CODE = /\bfrom ['"]react['"]|\/>|<\/[A-Za-z]|\b(?:function|const)\s+use[A-Z]/;

export interface CompiledModule {
  code: string;
  map: string | null;
}

/**
 * Runs Bun's React Compiler over one module and returns it as JavaScript, with its
 * imports as written. The compiler memoizes components and hook values, so re-renders
 * driven by the once-a-second daemon store stay narrow without hand-written
 * memo/useMemo/useCallback.
 *
 * Bun has the compiler in its bundler only (`Bun.build`), not in a single-file transform,
 * so this is a bundle of one file with every import left external. The bundle also
 * strips the types and turns JSX into calls; `production` picks React's production JSX
 * runtime, whose development one does not work in a production build of React.
 */
export async function compileReact(
  file: string,
  code: string,
  production: boolean,
): Promise<CompiledModule> {
  if (typeof Bun === 'undefined') {
    throw new Error(
      'The React Compiler is the one built into Bun: run Vite with `bun --bun`, as the scripts in package.json do.',
    );
  }
  const result = await Bun.build({
    entrypoints: [file],
    // What Vite read, which is the file unless an earlier plugin changed it.
    files: { [file]: code },
    target: 'browser',
    reactCompiler: true,
    // Bun runs the compiler only on files it parses as JSX. Parsing `.ts` as TSX brings
    // in the hooks defined there (`useSelector`, `usePresence`). TSX rejects `<T>value`
    // casts and `<T>(x) =>` arrows; write `value as T` and `<T,>(x) =>`.
    loader: { '.ts': 'tsx' },
    define: { 'process.env.NODE_ENV': JSON.stringify(production ? 'production' : 'development') },
    sourcemap: 'external',
    throw: false,
    plugins: [
      {
        name: 'leave-imports',
        setup(build) {
          build.onResolve({ filter: /.*/ }, (args) =>
            args.importer ? { path: args.path, external: true } : undefined,
          );
        },
      },
    ],
  });
  if (!result.success) {
    throw new Error(result.logs.map((log) => String(log)).join('\n') || `cannot compile ${file}`);
  }
  const script = result.outputs.find((output) => output.kind === 'entry-point');
  const map = result.outputs.find((output) => output.kind === 'sourcemap');
  if (!script) throw new Error(`Bun wrote no module for ${file}`);
  return { code: await script.text(), map: map ? await map.text() : null };
}

/**
 * The Vite plugin for `compileReact`. It runs before Vite's own transforms, which then
 * see plain JavaScript and add what they always add (React Fast Refresh in dev).
 */
export function bunReactCompiler(): Plugin {
  let production = false;
  return {
    name: 'antiwire:bun-react-compiler',
    enforce: 'pre',
    configResolved(config) {
      production = config.isProduction;
    },
    transform: {
      filter: {
        // No query string: `?inline`, `?url` and the like are not modules to compile.
        id: { include: /\.tsx?$/, exclude: [/node_modules/, /[\\/]lib[\\/]paraglide[\\/]/] },
        code: REACT_CODE,
      },
      handler(code, id) {
        return compileReact(id, code, production);
      },
    },
  };
}
