import { paraglideVitePlugin } from '@inlang/paraglide-js';
import react from '@vitejs/plugin-react';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import type { Plugin, UserConfig } from 'vite';
import { PARAGLIDE_OPTIONS } from './paraglide.options.ts';
import { bunReactCompiler } from './vite.react-compiler.ts';
import { reloadWhenStoresChange } from './vite.store-reload.ts';

const GITHUB_REPOSITORY = /^https:\/\/github\.com\/[A-Za-z0-9-]+\/[A-Za-z0-9._-]+$/;

/**
 * The project's GitHub repository URL, from `[workspace.package] repository` in the Rust
 * workspace, which is the one place it is named (see scripts/repository.mjs). The daemon
 * compiles in the same value, so the client and the daemon cannot point at different repos.
 */
export function projectRepository(root: string): string {
  const toml = readFileSync(path.resolve(root, '../antiwire-rs/Cargo.toml'), 'utf8');
  let inTable = false;
  for (const line of toml.split(/\r?\n/)) {
    const header = /^\s*\[([^\]]+)\]\s*$/.exec(line);
    if (header) {
      inTable = header[1].trim() === 'workspace.package';
      continue;
    }
    const value = inTable ? /^\s*repository\s*=\s*"([^"]+)"/.exec(line) : null;
    if (value) {
      if (!GITHUB_REPOSITORY.test(value[1]) || value[1].endsWith('.git')) {
        throw new Error(`repository must look like https://github.com/owner/name: ${value[1]}`);
      }
      return value[1];
    }
  }
  throw new Error('src/antiwire-rs/Cargo.toml has no [workspace.package] repository');
}

/** Build-time constants for code under `shared/` and the renderer (see shared/project.ts). */
export function projectDefines(root: string): Record<string, string> {
  return { __ANTIWIRE_REPOSITORY__: JSON.stringify(projectRepository(root)) };
}

/**
 * Re-serializes emitted `.json` assets without whitespace. The sources stay
 * pretty-printed so regenerating them gives readable diffs; the country CIDR
 * table, fetched at runtime, shrinks by about a third.
 */
function compactJsonAssets(): Plugin {
  return {
    name: 'antiwire:compact-json-assets',
    apply: 'build',
    generateBundle(_options, bundle) {
      for (const file of Object.values(bundle)) {
        if (file.type !== 'asset' || !file.fileName.endsWith('.json')) continue;
        const text =
          typeof file.source === 'string' ? file.source : new TextDecoder().decode(file.source);
        file.source = JSON.stringify(JSON.parse(text));
      }
    },
  };
}

/**
 * Drops the `.woff` fallback from `@font-face` rules. Fontsource lists each face as
 * `.woff2` then `.woff`; Chromium always takes the `.woff2`, so the `.woff` files (about
 * 400 KB) were shipped and never read. Runs after `@import` inlining, so it sees the
 * Fontsource rules app.css pulls in.
 */
const woff2Only = {
  postcssPlugin: 'antiwire:woff2-only',
  AtRule: {
    'font-face'(rule: { walkDecls(prop: string, visit: (decl: { value: string }) => void): void }) {
      rule.walkDecls('src', (decl) => {
        const sources = decl.value.split(/,(?![^(]*\))/);
        const kept = sources.filter((source) => !/format\(\s*['"]?woff['"]?\s*\)/.test(source));
        if (kept.length > 0 && kept.length < sources.length) decl.value = kept.join(',').trim();
      });
    },
  },
};

/**
 * Keeps some assets as separate files that Vite would otherwise inline as `data:` URLs
 * (it inlines anything under 4 KB):
 * - the per-country CIDR files, which put 144 small countries inside the firewall
 *   page's JavaScript;
 * - fonts, so the CSP's `font-src` can stay `'self'` (electron/main/app-url.ts).
 */
export function assetsInlineLimit(file: string): boolean | undefined {
  if (/\.woff2?$/.test(file)) return false;
  return /[\\/]country-cidrs[\\/][A-Z]{2}\.json$/.test(file) ? false : undefined;
}

/**
 * Renderer settings shared by the Electron build and the browser-only preview
 * (`vite.web.config.ts`), so the two cannot drift.
 */
export function rendererConfig(root: string) {
  const messagesEntry = path.resolve(root, 'src/lib/i18n/messages.ts');
  return {
    root,
    publicDir: path.resolve(root, 'static'),
    resolve: {
      alias: [
        // Steer `import { m }` to the single-locale loader. The generated index pulls in all 24.
        { find: /^#lib\/paraglide\/messages(\.js)?$/, replacement: messagesEntry },
        { find: /^#lib\/(.*)$/, replacement: path.resolve(root, 'src/lib') + '/$1' },
        { find: /^#shared\/(.*)$/, replacement: path.resolve(root, 'shared') + '/$1' },
      ],
    },
    plugins: [
      // Bun's React Compiler, ahead of Vite's own transforms (vite.react-compiler.ts).
      bunReactCompiler(),
      react(),
      reloadWhenStoresChange(),
      compactJsonAssets(),
      paraglideVitePlugin({ ...PARAGLIDE_OPTIONS, strategy: [...PARAGLIDE_OPTIONS.strategy] }),
    ],
    // `styles.fooBar` and `styles['foo-bar']` both resolve, so CSS module
    // class names can stay kebab-case.
    css: {
      modules: { localsConvention: 'camelCase' as const },
      postcss: { plugins: [woff2Only] },
    },
    build: { assetsInlineLimit },
    define: projectDefines(root),
    server: { port: 1420, strictPort: true },
    clearScreen: false,
  } satisfies UserConfig;
}
