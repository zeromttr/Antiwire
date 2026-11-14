import { app } from 'electron';
import path from 'node:path';
import { ClientSettingsStore, clientSettingsPatchSchema } from '../client-settings-store';
import { daemon, setDesktopNotificationsEnabled } from '../daemon/connection';
import { rejected } from '../daemon/errors';
import { settingsSchema, settingsToDto, settingsToRequest } from '../dto/settings';
import { command, noArgs, type CommandTable } from './define';

const SETTINGS_FILE = 'client-settings.json';

/**
 * Where the Tauri client kept the same file: its app data directory, named
 * after the bundle identifier. Linux used the XDG data directory, not config.
 */
function legacySettingsFile(): string {
  const base =
    process.platform === 'linux'
      ? (process.env.XDG_DATA_HOME ?? path.join(app.getPath('home'), '.local', 'share'))
      : app.getPath('appData');
  return path.join(base, 'com.antiwire.client', SETTINGS_FILE);
}

let clientSettings: ClientSettingsStore | null = null;
function clientSettingsStore(): ClientSettingsStore {
  clientSettings ??= new ClientSettingsStore(
    path.join(app.getPath('userData'), SETTINGS_FILE),
    legacySettingsFile(),
  );
  return clientSettings;
}

export const settingsCommands = {
  get_settings: noArgs(async () => {
    const settings = settingsToDto(await daemon.unary('GetSettings', {}));
    setDesktopNotificationsEnabled(settings.notifyEveryConnection);
    return settings;
  }),

  /**
   * The daemon answers once the change is in effect, or after its own 30s limit
   * (`SETTINGS_APPLY_DEADLINE`), so this gets the slow deadline.
   */
  update_settings: command({ settings: settingsSchema }, async ({ settings }) => {
    const response = await daemon.unary('UpdateSettings', settingsToRequest(settings), 'slow');
    if (response.success) setDesktopNotificationsEnabled(settings.notifyEveryConnection);
    // `notApplied`: saved settings the daemon could not put into effect, each with the reason.
    return { success: response.success, notApplied: response.notApplied };
  }),

  /** Downloads every enabled blocklist before the daemon answers, so it gets the slow deadline. */
  sync_hosts_blocklist: noArgs(async () => {
    const response = await daemon.unary('SyncHostsBlocklist', {}, 'slow');
    if (!response.success) throw rejected(response.message);
    return true;
  }),

  /** Downloads the GeoLite2-City database now, bypassing the quarterly scheduler. */
  refresh_geo_database: noArgs(async () => {
    const response = await daemon.unary('RefreshGeoDatabase', {}, 'slow');
    if (!response.success) throw rejected(response.message);
    return true;
  }),

  get_client_settings: noArgs(() => clientSettingsStore().read()),

  set_client_settings: command({ patch: clientSettingsPatchSchema }, ({ patch }) =>
    clientSettingsStore().update(patch),
  ),
} satisfies Partial<CommandTable>;
