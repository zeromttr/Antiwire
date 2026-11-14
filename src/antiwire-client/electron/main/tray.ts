import { app, Menu, nativeImage, Tray } from 'electron';
import { daemon } from './daemon/connection';
import { showDesktopNotification } from './notifications';
import { errorMessage } from './errors';
import { appIconPath } from './resources';
import { showMainWindow } from './windows';

/** Held so the tray icon is not garbage-collected away. */
let tray: Tray | null = null;

async function syncBlocklist(): Promise<void> {
  try {
    const { success } = await daemon.unary('SyncHostsBlocklist', {});
    if (success) {
      showDesktopNotification('Antiwire', 'Blocklist sync triggered successfully.');
    } else {
      showDesktopNotification('Blocklist sync', 'The daemon did not accept the sync request.');
    }
  } catch (error) {
    showDesktopNotification('Blocklist sync failed', errorMessage(error));
  }
}

export function setupTray(): void {
  if (tray) return;
  let icon = nativeImage.createFromPath(appIconPath('32x32.png'));
  // The macOS menu bar wants an 18pt glyph; a 32px image would be drawn oversized.
  if (process.platform === 'darwin') icon = icon.resize({ width: 18, height: 18 });

  tray = new Tray(icon);
  tray.setToolTip('Antiwire');
  tray.setContextMenu(
    Menu.buildFromTemplate([
      { label: 'Show Antiwire', click: () => showMainWindow() },
      { label: 'Sync Blocklist', click: () => void syncBlocklist() },
      { label: 'Exit', click: () => app.quit() },
    ]),
  );
  // Windows opens the window on double-click, as its tray convention is;
  // elsewhere a single click does.
  if (process.platform === 'win32') {
    tray.on('double-click', () => showMainWindow());
  } else {
    tray.on('click', () => showMainWindow());
  }
}
