import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vite';
import { rendererConfig } from './vite.shared.ts';

/**
 * Browser-only dev server for UI work and agents: no Electron, no daemon.
 * The renderer detects the missing bridge and serves synthetic preview data.
 */
export default defineConfig(rendererConfig(path.dirname(fileURLToPath(import.meta.url))));
