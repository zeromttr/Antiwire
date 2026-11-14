import { api, type UpdateActionResult } from '#lib/api/daemon.ts';
import { Reactive } from '#lib/state/reactive.ts';
import type { UpdateStatus } from '#lib/types/index.ts';
import { daemonErrorMessage, debugError, formatErrorMessage } from '#lib/utils/index.ts';

/** The daemon calls the store makes; a fake in tests. */
export interface UpdatesClient {
  getUpdateStatus(): Promise<UpdateStatus>;
  checkForUpdates(): Promise<UpdateStatus>;
  installUpdate(version: string): Promise<UpdateActionResult>;
}

/**
 * The update status the footer and the Updates settings section share, and the install
 * dialog either of them can open. Only a click starts a check outside the daemon's own
 * schedule, and only the dialog's Install button starts an install.
 */
export class UpdatesStore extends Reactive {
  status: UpdateStatus | null = null;
  /** A manual check is running. */
  checking = false;
  /** Why the last manual check could not reach the daemon; empty otherwise. */
  checkFailure = '';
  installDialogOpen = false;
  installSubmitting = false;
  /** Why the daemon refused the last Install click, shown until the dialog is reopened. */
  installError = '';

  constructor(private readonly client: UpdatesClient) {
    super();
  }

  /** Keeps the last status on failure: the daemon is usually restarting while an update installs. */
  refresh = async (): Promise<void> => {
    try {
      this.status = await this.client.getUpdateStatus();
      this.changed();
    } catch (error) {
      debugError('updates', 'status-failed', error);
    }
  };

  /** Asks the daemon to read the release feeds now. A second click waits for the first. */
  check = async (): Promise<void> => {
    if (this.checking) return;
    this.checking = true;
    this.checkFailure = '';
    this.changed();
    try {
      this.status = await this.client.checkForUpdates();
    } catch (error) {
      debugError('updates', 'check-failed', error);
      this.checkFailure = daemonErrorMessage(formatErrorMessage(error));
    } finally {
      this.checking = false;
      this.changed();
    }
  };

  setInstallDialogOpen = (open: boolean): void => {
    if (open) this.installError = '';
    this.installDialogOpen = open;
    this.changed();
  };

  /** Starts the install the user confirmed in the dialog. */
  install = async (): Promise<void> => {
    const version = this.status?.availableVersion ?? '';
    if (!version || this.installSubmitting) return;
    this.installSubmitting = true;
    this.installError = '';
    this.changed();
    try {
      const result = await this.client.installUpdate(version);
      if (result.success) {
        this.installDialogOpen = false;
      } else {
        this.installError = result.message;
      }
    } catch (error) {
      debugError('updates', 'install-failed', error);
      this.installError = daemonErrorMessage(formatErrorMessage(error));
    } finally {
      this.installSubmitting = false;
      this.changed();
    }
    await this.refresh();
  };
}

export const updates = new UpdatesStore(api);
