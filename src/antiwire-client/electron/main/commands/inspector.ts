import {
  capturedPacketSchema,
  clearInspectorState,
  inspectorPacket,
  inspectorTheme,
  rememberInspector,
  themeSnapshotSchema,
} from '../inspector-state';
import { emitTo, getInspectorWindow, openInspectorWindow } from '../windows';
import { command, noArgs, type CommandTable } from './define';

export const inspectorCommands = {
  open_packet_inspector: command(
    { packet: capturedPacketSchema, themeSnapshot: themeSnapshotSchema.nullish() },
    ({ packet, themeSnapshot }) => {
      rememberInspector(packet, themeSnapshot ?? null);
      const existing = getInspectorWindow();
      const window = openInspectorWindow();
      if (existing) {
        // Already mounted: push the new packet. A new window reads the stored
        // state after it mounts instead, since an event now would race its listener.
        if (themeSnapshot) emitTo(window, 'packet-inspector://theme', themeSnapshot);
        emitTo(window, 'packet-inspector://packet', packet);
        return;
      }
      // Also covers closing from the OS, which never reaches `close_window`.
      window.once('closed', clearInspectorState);
    },
  ),

  get_packet_inspector_packet: noArgs(() => inspectorPacket()),
  get_packet_inspector_theme: noArgs(() => inspectorTheme()),
} satisfies Partial<CommandTable>;
