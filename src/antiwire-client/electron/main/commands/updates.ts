import { app } from 'electron';
import { daemon } from '../daemon/connection';
import { updateStatusToDto } from '../dto/updates';
import { arg, command, noArgs, type CommandTable } from './define';

export const updateCommands = {
  get_update_status: noArgs(async () =>
    updateStatusToDto(await daemon.unary('GetUpdateStatus', {}), app.getVersion()),
  ),

  /**
   * Reads the release feeds now. The daemon fetches only the signed manifests, from
   * GitHub, so this gets the slow deadline.
   */
  check_for_updates: noArgs(async () =>
    updateStatusToDto(await daemon.unary('CheckForUpdates', {}, 'slow'), app.getVersion()),
  ),

  /**
   * Starts the update the user confirmed. The daemon downloads and applies it;
   * the filtering service restarts, so the user has to reopen Antiwire after.
   */
  install_update: command({ version: arg.text(64) }, async ({ version }) => {
    const { success, message } = await daemon.unary('InstallUpdate', { version });
    return { success, message };
  }),
} satisfies Partial<CommandTable>;
