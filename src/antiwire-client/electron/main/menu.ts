import { app, Menu } from 'electron';

/**
 * Packaged builds ship no default application menu. Electron's default menu
 * carries shortcuts the app has no use for (reload, force reload, zoom, the
 * DevTools toggle), and Electron's performance guide recommends skipping it.
 * Windows and Linux copy and paste without a menu; macOS routes those
 * shortcuts through the Edit menu, so it gets a minimal one.
 *
 * Unpackaged runs keep Electron's default menu for its reload and DevTools
 * shortcuts.
 */

/** Must run before `app` is ready, or Electron has already built its default menu. */
export function suppressDefaultMenu(): void {
  if (app.isPackaged) Menu.setApplicationMenu(null);
}

/** Call once `app` is ready. */
export function installApplicationMenu(): void {
  if (!app.isPackaged || process.platform !== 'darwin') return;
  Menu.setApplicationMenu(
    Menu.buildFromTemplate([{ role: 'appMenu' }, { role: 'editMenu' }, { role: 'windowMenu' }]),
  );
}
