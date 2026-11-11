import { isNative } from '../bridge.ts';
import { navigate } from '../navigation.ts';
import { resolvePreviewMode } from './mode';

// Choose once per document: client-side route changes retain the chosen scenario.
// DEV is replaced by Vite, so production and every native runtime keep real IPC.
export const browserPreviewMode = resolvePreviewMode(
  import.meta.env?.DEV === true,
  typeof window !== 'undefined',
  isNative(),
  typeof window === 'undefined' ? '' : window.location.search,
);

export async function callBrowserPreview(
  command: string,
  args?: Record<string, unknown>,
): Promise<unknown> {
  if (!browserPreviewMode) throw new Error('Browser preview is disabled');
  if (browserPreviewMode === 'offline') {
    if (command === 'connect_daemon') return false;
    if (command === 'get_connection_status') return { connected: false };
    throw new Error('Browser preview: offline scenario');
  }
  const { previewBackend } = await import('./backend');
  if (command === 'close_window') {
    navigate('/capture');
    return;
  }
  const result = previewBackend.call(command, args);
  if (command === 'open_packet_inspector') {
    navigate('/inspector');
  }
  return result;
}
