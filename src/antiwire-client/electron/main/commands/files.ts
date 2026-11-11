import { dialog, type BrowserWindow, type FileFilter } from 'electron';
import path from 'node:path';
import { z } from 'zod';
import { approvedSavePaths } from '../approved-paths';
import { arg, command, type CommandTable } from './define';

const extension = z.string().regex(/^(\*|[A-Za-z0-9]{1,16})$/);
const extensions = z.array(extension).max(32);
const filters = z.array(z.strictObject({ name: arg.text(128), extensions })).max(16);

/** Dialogs are modal to the calling window when there is one. */
function withParent<T>(
  window: BrowserWindow | null,
  show: (parent: BrowserWindow) => Promise<T>,
  showFree: () => Promise<T>,
): Promise<T> {
  return window && !window.isDestroyed() ? show(window) : showFree();
}

export const fileCommands = {
  /**
   * Shows a native save dialog and remembers the path the user picked.
   * `download_capture` and `export_logs` only accept a destination that came
   * from here (see `ApprovedPaths`).
   */
  pick_save_path: command(
    { defaultName: arg.text(255), filterName: arg.text(128), extensions },
    async (a, ctx) => {
      const options = {
        // Only the file name is honoured; a directory in it is the renderer's to choose, not ours.
        defaultPath: path.basename(a.defaultName) || undefined,
        filters: [{ name: a.filterName, extensions: a.extensions }] satisfies FileFilter[],
      };
      const result = await withParent(
        ctx.window,
        (parent) => dialog.showSaveDialog(parent, options),
        () => dialog.showSaveDialog(options),
      );
      if (result.canceled || !result.filePath) return null;
      approvedSavePaths.approve(result.filePath);
      return result.filePath;
    },
  ),

  /** Native open dialog for one existing file; `null` when cancelled. Replaces plugin-dialog `open`. */
  pick_open_path: command(
    { title: arg.text(256), defaultPath: arg.text(4096), filters },
    async (a, ctx) => {
      const options: Electron.OpenDialogOptions = {
        title: a.title || undefined,
        defaultPath: a.defaultPath || undefined,
        filters: a.filters,
        properties: ['openFile'],
      };
      const result = await withParent(
        ctx.window,
        (parent) => dialog.showOpenDialog(parent, options),
        () => dialog.showOpenDialog(options),
      );
      return result.canceled ? null : (result.filePaths[0] ?? null);
    },
  ),
} satisfies Partial<CommandTable>;
