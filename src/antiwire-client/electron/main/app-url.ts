import path from 'node:path';

/**
 * Electron-free halves of `security.ts` and `protocol.ts`, so the allow-lists
 * can be tested without an Electron runtime.
 */

/** The privileged scheme the renderer is served from in packaged builds. */
export const APP_SCHEME = 'app';
export const APP_HOST = 'antiwire';
export const APP_ORIGIN = `${APP_SCHEME}://${APP_HOST}`;

/**
 * True when `url` is one of the app's own documents: the `app://` origin, or
 * the dev server (`devServerUrl`, only ever set in unpackaged runs).
 * Everything else is foreign content and must never load in a window that
 * holds the preload bridge.
 */
export function isAppUrlFor(url: string, devServerUrl: string | undefined): boolean {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return false;
  }
  if (parsed.protocol === `${APP_SCHEME}:` && parsed.host === APP_HOST) return true;
  if (devServerUrl) {
    try {
      return parsed.origin === new URL(devServerUrl).origin;
    } catch {
      return false;
    }
  }
  return false;
}

/**
 * Content Security Policy for every app document. No inline script, no eval,
 * no remote content: the renderer talks to the world only through the preload
 * bridge.
 *
 * Packaged builds also refuse inline styles, except `<style>` elements that carry
 * the document's `nonce` (see `withStyleNonce`): React `style` props go through
 * the CSSOM, which CSP does not govern, but Radix's scroll lock injects a
 * `<style>`. They also enforce Trusted Types with no policies, so no string can
 * reach `innerHTML` or another DOM injection sink.
 *
 * Dev keeps `'unsafe-inline'` for both: Vite's React refresh preamble is an inline
 * script, it injects CSS as `<style>` elements, and its error overlay uses `innerHTML`.
 */
export function contentSecurityPolicyFor(
  dev: boolean,
  devServerUrl: string | undefined,
  nonce?: string,
): string {
  const devConnect = dev && devServerUrl ? ` ${new URL(devServerUrl).origin} ws:` : '';
  const scriptSrc = dev ? "'self' 'unsafe-inline'" : "'self'";
  const styleSrc = dev ? "'self' 'unsafe-inline'" : nonce ? `'self' 'nonce-${nonce}'` : "'self'";
  return [
    "default-src 'self'",
    `script-src ${scriptSrc}`,
    `style-src ${styleSrc}`,
    "img-src 'self' data: blob:",
    "font-src 'self'",
    `connect-src 'self'${devConnect}`,
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'none'",
    "frame-src 'none'",
    "frame-ancestors 'none'",
    "worker-src 'none'",
    ...(dev ? [] : ["require-trusted-types-for 'script'", "trusted-types 'none'"]),
  ].join('; ');
}

/** Nonces are base64; anything else would break out of the attribute or the header. */
const NONCE = /^[A-Za-z0-9+/]{16,}={0,2}$/;

/**
 * Stamps `nonce` on the document's own `<style>` elements and publishes it in a
 * `<meta property="csp-nonce">`, where the renderer picks it up for styles it
 * injects later (`src/lib/csp-nonce.ts`). Only for the app's own `index.html`.
 */
export function withStyleNonce(html: string, nonce: string): string {
  if (!NONCE.test(nonce)) throw new Error('invalid CSP nonce');
  const stamped = html.replace(/<style(?=[\s>])/g, `<style nonce="${nonce}"`);
  const head = stamped.indexOf('<head>');
  if (head < 0) throw new Error('index.html has no <head>');
  const at = head + '<head>'.length;
  const meta = `<meta property="csp-nonce" nonce="${nonce}" />`;
  return `${stamped.slice(0, at)}\n    ${meta}${stamped.slice(at)}`;
}

/** Resolves a request path inside `root`, or `null` when it would escape it. */
export function resolveInside(root: string, requestPath: string): string | null {
  let decoded: string;
  try {
    decoded = decodeURIComponent(requestPath);
  } catch {
    return null;
  }
  if (decoded.includes('\0')) return null;
  const resolved = path.resolve(root, '.' + path.posix.normalize('/' + decoded));
  const relative = path.relative(root, resolved);
  if (relative.startsWith('..') || path.isAbsolute(relative)) return null;
  return resolved;
}
