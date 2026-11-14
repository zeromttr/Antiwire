import { protocol } from 'electron';
import { randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { resolveInside, withStyleNonce } from './app-url';
import { APP_HOST, APP_SCHEME, contentSecurityPolicy } from './security';

export { resolveInside };

/** Everything the renderer build emits; anything else is served as opaque bytes. */
const MIME_TYPES: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
  '.json': 'application/json',
};

/** Must run before `app` is ready: privileges cannot be granted later. */
export function registerAppScheme(): void {
  protocol.registerSchemesAsPrivileged([
    {
      scheme: APP_SCHEME,
      privileges: { standard: true, secure: true, supportFetchAPI: true, codeCache: true },
    },
  ]);
}

/** Client-side routes have no extension; they all load the SPA shell. */
function isRoutePath(requestPath: string): boolean {
  return path.posix.extname(requestPath) === '';
}

/**
 * Serves the built renderer from `root` on `app://antiwire/`. Unknown routes
 * fall back to `index.html`; anything outside `root`, or another host, is a 404.
 */
export function serveRenderer(root: string): void {
  protocol.handle(APP_SCHEME, async (request) => {
    const url = new URL(request.url);
    if (url.host !== APP_HOST || request.method !== 'GET') {
      return new Response('Not found', { status: 404 });
    }
    const target = isRoutePath(url.pathname)
      ? path.join(root, 'index.html')
      : resolveInside(root, url.pathname);
    if (!target) return new Response('Not found', { status: 404 });

    // Read the file directly rather than through `net.fetch('file://…')`: the
    // session's request filter cancels every non-app URL, `file:` included.
    let body: Buffer;
    try {
      body = await readFile(target);
    } catch {
      return new Response('Not found', { status: 404 });
    }
    // Each document gets a fresh nonce for the `<style>` elements it may carry or inject.
    let nonce: string | undefined;
    if (path.basename(target) === 'index.html') {
      nonce = randomBytes(16).toString('base64');
      body = Buffer.from(withStyleNonce(body.toString('utf8'), nonce), 'utf8');
    }
    const headers = new Headers({
      'Content-Type': MIME_TYPES[path.extname(target).toLowerCase()] ?? 'application/octet-stream',
    });
    headers.set('Content-Security-Policy', contentSecurityPolicy(false, nonce));
    headers.set('X-Content-Type-Options', 'nosniff');
    headers.set('Cross-Origin-Opener-Policy', 'same-origin');
    headers.set('Cross-Origin-Resource-Policy', 'same-origin');
    return new Response(new Uint8Array(body), { status: 200, headers });
  });
}
