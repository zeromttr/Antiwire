import { defineConfig } from 'electron-vite';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import type { Plugin } from 'vite';
import { assetsInlineLimit, projectDefines, rendererConfig } from './vite.shared.ts';

const root = path.dirname(fileURLToPath(import.meta.url));
const alias = { '#shared': path.resolve(root, 'shared') };
const DAEMON_PROTO = path.resolve(
  root,
  '../antiwire-rs/crates/antiwire-proto/proto/antiwire.proto',
);

/**
 * Copies the daemon's proto next to the main bundle (`out/main/antiwire.proto`), so a
 * packaged build reads it from inside `app.asar`, where the asar integrity fuse covers
 * it. See `protoPath()` in electron/main/daemon/connection.ts.
 */
function bundleDaemonProto(): Plugin {
  return {
    name: 'antiwire:bundle-daemon-proto',
    apply: 'build',
    buildStart() {
      this.addWatchFile(DAEMON_PROTO);
    },
    generateBundle() {
      this.emitFile({
        type: 'asset',
        fileName: 'antiwire.proto',
        source: readFileSync(DAEMON_PROTO, 'utf8'),
      });
    },
  };
}
// electron-vite turns minification off for all three builds unless a config asks for it.
const minify = true;

export default defineConfig({
  main: {
    resolve: { alias },
    define: projectDefines(root),
    plugins: [bundleDaemonProto()],
    build: {
      outDir: 'out/main',
      minify,
      // Bundle grpc-js and proto-loader instead of requiring them from node_modules:
      // one file loads in about a third of the time of their ~100 separate modules,
      // and the packaged app then ships no node_modules at all. They are imported
      // lazily (daemon/runtime.ts), so they land in their own chunk.
      externalizeDeps: false,
      // Their notices no longer arrive with node_modules; ship them with the bundle.
      license: { fileName: 'THIRD_PARTY_LICENSES.md' },
      rollupOptions: { input: { index: path.resolve(root, 'electron/main/index.ts') } },
    },
  },
  preload: {
    resolve: { alias },
    build: {
      outDir: 'out/preload',
      minify,
      rollupOptions: {
        input: { index: path.resolve(root, 'electron/preload/index.ts') },
        // A sandboxed preload cannot `require` sibling files, so emit one CommonJS file.
        output: { format: 'cjs', entryFileNames: '[name].cjs', codeSplitting: false },
      },
    },
  },
  renderer: {
    ...rendererConfig(root),
    build: {
      outDir: 'out/renderer',
      minify,
      // Electron 45 ships Chromium 142; no need to transpile for older engines.
      target: 'chrome140',
      assetsInlineLimit,
      rollupOptions: { input: path.resolve(root, 'index.html') },
    },
  },
});
