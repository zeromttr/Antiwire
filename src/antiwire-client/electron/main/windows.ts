import { app, BrowserWindow, nativeTheme, type WebContents } from 'electron';
import path from 'node:path';
import { EVENT_CHANNEL, type EventName, type EventPayloads, type WindowRole } from '#shared/ipc';
import { TRAFFIC_LIGHT_POSITION, usesNativeWindowFrame } from '#shared/window-frame';
import { APP_ORIGIN, DEV_SERVER_URL } from './security';

const roles = new Map<number, WindowRole>();
let mainWindow: BrowserWindow | null = null;
let inspectorWindow: BrowserWindow | null = null;
/** Set while quitting so close-to-tray does not swallow the real close. */
let quitting = false;

app.on('before-quit', () => {
  quitting = true;
});

export function roleOf(contents: WebContents): WindowRole | undefined {
  return roles.get(contents.id);
}

export function getMainWindow(): BrowserWindow | null {
  return mainWindow && !mainWindow.isDestroyed() ? mainWindow : null;
}

export function getInspectorWindow(): BrowserWindow | null {
  return inspectorWindow && !inspectorWindow.isDestroyed() ? inspectorWindow : null;
}

/** Sends `event` to one window. */
export function emitTo<E extends EventName>(
  window: BrowserWindow | null,
  event: E,
  payload: EventPayloads[E],
): boolean {
  if (!window || window.isDestroyed() || window.webContents.isDestroyed()) return false;
  window.webContents.send(EVENT_CHANNEL, event, payload);
  return true;
}

/** Sends `event` to the main window. Daemon data never goes to the inspector. */
export function emitToMain<E extends EventName>(event: E, payload: EventPayloads[E]): boolean {
  return emitTo(getMainWindow(), event, payload);
}

function appUrl(route: string): string {
  const base = DEV_SERVER_URL ?? `${APP_ORIGIN}/`;
  return new URL(route.replace(/^\//, ''), base.endsWith('/') ? base : base + '/').toString();
}

const NATIVE_WINDOW_FRAME = usesNativeWindowFrame(process.platform);

/** Painted before the renderer loads; matches `--bg` in app.css. */
function windowBackground(): string {
  if (!NATIVE_WINDOW_FRAME) return '#00000000';
  return resolvedTheme() === 'dark' ? '#0c0d0f' : '#eeede9';
}

/** See `usesNativeWindowFrame` for why each platform gets the frame it does. */
function frameOptions(): Electron.BrowserWindowConstructorOptions {
  if (process.platform === 'darwin') {
    // Keep the native frame but hide its title bar: the real traffic lights
    // sit over the custom title bar, and AppKit draws corners and shadow.
    return {
      titleBarStyle: 'hidden',
      trafficLightPosition: TRAFFIC_LIGHT_POSITION,
      backgroundColor: windowBackground(),
    };
  }
  return {
    frame: false,
    transparent: !NATIVE_WINDOW_FRAME,
    hasShadow: NATIVE_WINDOW_FRAME,
    backgroundColor: windowBackground(),
  };
}

function createWindow(role: WindowRole, options: Electron.BrowserWindowConstructorOptions) {
  const window = new BrowserWindow({
    show: false,
    ...frameOptions(),
    autoHideMenuBar: true,
    icon: path.join(app.getAppPath(), 'resources/icons/128x128.png'),
    ...options,
    webPreferences: {
      preload: path.join(import.meta.dirname, '../preload/index.cjs'),
      contextIsolation: true,
      sandbox: true,
      nodeIntegration: false,
      nodeIntegrationInWorker: false,
      webSecurity: true,
      allowRunningInsecureContent: false,
      webviewTag: false,
      spellcheck: false,
      navigateOnDragDrop: false,
      // Hidden windows stop animating; polling slows itself via window://visibility.
      backgroundThrottling: true,
      devTools: !app.isPackaged,
    },
  });
  const id = window.webContents.id;
  roles.set(id, role);
  window.on('closed', () => roles.delete(id));
  window.once('ready-to-show', () => window.show());
  // macOS hides the traffic lights in full screen; the title bar drops their inset.
  window.on('enter-full-screen', () => emitTo(window, 'window://fullscreen', true));
  window.on('leave-full-screen', () => emitTo(window, 'window://fullscreen', false));
  return window;
}

export function createMainWindow(): BrowserWindow {
  const window = createWindow('main', {
    title: 'Antiwire',
    width: 1280,
    height: 800,
    minWidth: 1100,
    minHeight: 650,
  });
  mainWindow = window;
  window.on('close', (event) => {
    if (quitting) return;
    // Closing hides to the tray; the firewall UI keeps receiving alerts.
    event.preventDefault();
    hideMainWindow();
  });
  window.on('maximize', () => emitTo(window, 'window://maximized', true));
  window.on('unmaximize', () => emitTo(window, 'window://maximized', false));
  window.on('closed', () => {
    if (mainWindow === window) mainWindow = null;
  });
  void window.loadURL(appUrl('/'));
  return window;
}

export function showMainWindow(): void {
  const window = getMainWindow() ?? createMainWindow();
  if (window.isMinimized()) window.restore();
  window.show();
  window.focus();
  emitTo(window, 'window://visibility', true);
}

export function hideMainWindow(): void {
  const window = getMainWindow();
  if (!window) return;
  window.hide();
  emitTo(window, 'window://visibility', false);
}

/** Opens the packet inspector, or focuses it if already open. */
export function openInspectorWindow(): BrowserWindow {
  const existing = getInspectorWindow();
  if (existing) {
    if (existing.isMinimized()) existing.restore();
    existing.focus();
    return existing;
  }
  const parent = getMainWindow() ?? undefined;
  const window = createWindow('inspector', {
    title: 'Packet Inspector',
    width: 900,
    height: 640,
    minWidth: 520,
    minHeight: 360,
    maximizable: false,
    // Otherwise macOS's green button would still offer full screen.
    fullscreenable: false,
    parent,
  });
  inspectorWindow = window;
  window.on('closed', () => {
    if (inspectorWindow === window) inspectorWindow = null;
  });
  void window.loadURL(appUrl('/inspector'));
  return window;
}

export function resolvedTheme(): 'light' | 'dark' {
  return nativeTheme.shouldUseDarkColors ? 'dark' : 'light';
}
