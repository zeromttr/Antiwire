import { app } from 'electron';
import { clearInspectorState } from '../inspector-state';
import { hideMainWindow } from '../windows';
import { noArgs, type CommandContext, type CommandTable } from './define';

function senderWindow(ctx: CommandContext) {
  if (!ctx.window || ctx.window.isDestroyed()) throw new Error('the window is gone');
  return ctx.window;
}

export const windowCommands = {
  minimize_window: noArgs((ctx) => senderWindow(ctx).minimize()),

  toggle_maximize_window: noArgs((ctx) => {
    const window = senderWindow(ctx);
    if (window.isMaximized()) window.unmaximize();
    else window.maximize();
  }),

  /** The main window hides to the tray; the inspector really closes and forgets its packet. */
  close_window: noArgs((ctx) => {
    if (ctx.role === 'main') {
      hideMainWindow();
      return;
    }
    clearInspectorState();
    senderWindow(ctx).close();
  }),

  hide_window: noArgs(() => hideMainWindow()),

  is_debug_build: noArgs(() => !app.isPackaged),

  open_devtools: noArgs((ctx) => {
    if (app.isPackaged) throw new Error('DevTools are only available in debug builds');
    senderWindow(ctx).webContents.openDevTools();
  }),
} satisfies Partial<CommandTable>;
