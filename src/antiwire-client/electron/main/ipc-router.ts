import { BrowserWindow, ipcMain, type IpcMainInvokeEvent } from 'electron';
import { INVOKE_CHANNEL, isCommandName, roleMayInvoke, type InvokeResult } from '#shared/ipc';
import type { CommandTable } from './commands/define';
import { isAppUrl } from './security';
import { roleOf } from './windows';
import { errorMessage } from './errors';

/**
 * Routes every renderer command. A call is refused unless it comes from the
 * top frame of one of the app's own windows, showing an app document, and the
 * window's role is allowed that command. Arguments are validated by the
 * handler itself (see `command()`).
 */
export function registerIpcRouter(table: CommandTable): void {
  ipcMain.handle(
    INVOKE_CHANNEL,
    async (event: IpcMainInvokeEvent, name: unknown, args: unknown): Promise<InvokeResult> => {
      try {
        const frame = event.senderFrame;
        if (!frame || frame !== event.sender.mainFrame || !isAppUrl(frame.url)) {
          return { ok: false, error: 'Refused: call from an untrusted frame' };
        }
        const role = roleOf(event.sender);
        if (!role) return { ok: false, error: 'Refused: unknown window' };
        if (!isCommandName(name)) return { ok: false, error: `Unknown command '${String(name)}'` };
        if (!roleMayInvoke(role, name)) {
          return { ok: false, error: `Refused: '${name}' is not available in this window` };
        }
        const value = await table[name](args, {
          sender: event.sender,
          role,
          window: BrowserWindow.fromWebContents(event.sender),
        });
        return { ok: true, value: value ?? null };
      } catch (error) {
        return { ok: false, error: errorMessage(error) };
      }
    },
  );
}
