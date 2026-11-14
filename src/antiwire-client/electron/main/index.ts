import { app } from 'electron';
import path from 'node:path';
import { commandTable } from './commands';
import { registerIpcRouter } from './ipc-router';
import { installApplicationMenu, suppressDefaultMenu } from './menu';
import { registerAppScheme, serveRenderer } from './protocol';
import { DEV_SERVER_URL, hardenApp, hardenSession } from './security';
import { createMainWindow, showMainWindow } from './windows';
import { setupTray } from './tray';
import { daemon, shutdownDaemon } from './daemon/connection';

// One client per account: a second launch focuses the running one.
if (!app.requestSingleInstanceLock()) {
  app.quit();
} else {
  // Matches the installer's Start Menu shortcut. Dev runs (electron.exe) use their own ID:
  // Windows lists one Start entry per ID, and a dev shortcut under the shared ID would
  // replace the installed "Antiwire" entry with one named "Electron".
  app.setAppUserModelId(app.isPackaged ? 'com.antiwire.client' : 'com.antiwire.client.dev');
  hardenApp();
  registerAppScheme();
  suppressDefaultMenu();

  app.on('second-instance', () => showMainWindow());

  void app.whenReady().then(() => {
    hardenSession();
    installApplicationMenu();
    if (!DEV_SERVER_URL) serveRenderer(path.join(import.meta.dirname, '../renderer'));
    registerIpcRouter(commandTable);
    createMainWindow();
    setupTray();
    // Load gRPC while the renderer starts, not before the window exists. A
    // failure here resurfaces from the first `connect`, which reports it.
    void daemon.prepare().catch(() => {});
  });

  // The tray keeps the app alive with no windows; quitting goes through the tray menu.
  app.on('window-all-closed', () => {});
  app.on('activate', () => showMainWindow());
  app.on('will-quit', () => shutdownDaemon());
}
