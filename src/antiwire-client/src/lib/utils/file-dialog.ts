import { invoke, isNative } from '#lib/bridge.ts';
import { m } from '#lib/i18n/messages.ts';

/** Native open dialog for an executable; `null` when cancelled or outside the app. */
export async function pickExecutable(defaultPath?: string): Promise<string | null> {
  if (!isNative()) return null;
  return invoke<string | null>('pick_open_path', {
    title: m.firewall_pick_executable_title(),
    defaultPath: defaultPath ?? '',
    filters: [
      {
        name: m.firewall_pick_executable_filter(),
        extensions: ['exe', 'msi', 'bat', 'cmd', 'com'],
      },
      { name: m.firewall_pick_all_files_filter(), extensions: ['*'] },
    ],
  });
}
