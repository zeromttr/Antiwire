import { app, session, shell, type WebContents } from 'electron';
import { APP_HOST, APP_ORIGIN, APP_SCHEME, contentSecurityPolicyFor, isAppUrlFor } from './app-url';

export { APP_HOST, APP_ORIGIN, APP_SCHEME };

/** Vite dev server URL, set by electron-vite. Only honoured in unpackaged runs. */
export const DEV_SERVER_URL = !app.isPackaged ? process.env.ELECTRON_RENDERER_URL : undefined;

/** See `contentSecurityPolicyFor`. */
export function contentSecurityPolicy(dev: boolean, nonce?: string): string {
  return contentSecurityPolicyFor(dev, DEV_SERVER_URL, nonce);
}

/** True when `url` is one of the app's own documents; see `isAppUrlFor`. */
export function isAppUrl(url: string): boolean {
  return isAppUrlFor(url, DEV_SERVER_URL);
}

/** Only these schemes may leave the app for the system browser. */
const EXTERNAL_SCHEMES = new Set(['https:', 'http:', 'mailto:']);

export function openExternalSafely(url: string): void {
  try {
    if (EXTERNAL_SCHEMES.has(new URL(url).protocol)) void shell.openExternal(url);
  } catch {
    /* not a URL: ignore */
  }
}

/**
 * Locks a webContents to the app: no navigation away, no new windows (links
 * go to the system browser), no webviews, no permission prompts.
 */
export function hardenWebContents(contents: WebContents): void {
  contents.on('will-navigate', (event, url) => {
    if (!isAppUrl(url)) event.preventDefault();
  });
  contents.on('will-redirect', (event, url) => {
    if (!isAppUrl(url)) event.preventDefault();
  });
  contents.on('will-attach-webview', (event) => event.preventDefault());
  contents.setWindowOpenHandler(({ url }) => {
    openExternalSafely(url);
    return { action: 'deny' };
  });
}

/** Permissions the UI actually uses. Everything else (camera, geolocation, …) is refused. */
const ALLOWED_PERMISSIONS = new Set(['clipboard-sanitized-write', 'notifications']);

/** Session-wide defences. Call once, after `app` is ready. */
export function hardenSession(): void {
  const ses = session.defaultSession;
  ses.setPermissionRequestHandler((contents, permission, callback) => {
    callback(ALLOWED_PERMISSIONS.has(permission) && isAppUrl(contents.getURL()));
  });
  ses.setPermissionCheckHandler((_contents, permission, origin) => {
    return ALLOWED_PERMISSIONS.has(permission) && isAppUrl(origin);
  });
  // Nothing in the app downloads through Chromium; native saves go through dialogs.
  ses.on('will-download', (event) => event.preventDefault());
  // The renderer makes no network requests of its own. Anything but app
  // resources (and the dev server) is cancelled before it leaves the machine.
  ses.webRequest.onBeforeRequest((details, callback) => {
    const url = details.url;
    const allowed =
      isAppUrl(url) ||
      url.startsWith('data:') ||
      url.startsWith('blob:') ||
      url.startsWith('devtools:') ||
      (DEV_SERVER_URL !== undefined && url.startsWith('ws:'));
    callback({ cancel: !allowed });
  });
  if (DEV_SERVER_URL) {
    // The packaged app sets CSP from the protocol handler; the dev server needs it injected.
    ses.webRequest.onHeadersReceived((details, callback) => {
      callback({
        responseHeaders: {
          ...details.responseHeaders,
          'Content-Security-Policy': [contentSecurityPolicy(true)],
        },
      });
    });
  }
}

/** Hardening that must happen before `app` is ready. */
export function hardenApp(): void {
  app.enableSandbox();
  app.on('web-contents-created', (_event, contents) => hardenWebContents(contents));
}
