import { z } from 'zod';
import { arg } from './commands/define';

/** Largest packet a capture can hold (the maximum snap length). */
const MAX_PACKET_BYTES = 262_144;

/**
 * A captured packet as the renderer received it from `capture://packets`.
 * Extra keys the renderer attached are dropped, as serde ignored them.
 */
export const capturedPacketSchema = z.object({
  captureId: arg.text(128),
  sequence: arg.u64(),
  timestampUs: arg.u64(),
  capturedLength: arg.u32(),
  originalLength: arg.u32(),
  linkLayer: arg.u32(),
  protocol: arg.text(64),
  source: arg.text(256),
  destination: arg.text(256),
  sourcePort: arg.u32(),
  destinationPort: arg.u32(),
  info: arg.text(4096),
  data: z.array(z.number().int().min(0).max(255)).max(MAX_PACKET_BYTES),
});

export type CapturedPacket = z.infer<typeof capturedPacketSchema>;

/** The main window's theme, so the inspector paints the same before it loads its own. */
export const themeSnapshotSchema = z.object({
  theme: arg.text(16).default(''),
  vars: z
    .record(arg.text(64), arg.text(256))
    .refine((vars) => Object.keys(vars).length <= 32, 'too many theme variables')
    .default({}),
});

export type ThemeSnapshot = z.infer<typeof themeSnapshotSchema>;

/**
 * The packet and theme the inspector shows. Read by the inspector after it
 * mounts, which avoids racing its event listener on first open.
 */
let lastPacket: CapturedPacket | null = null;
let lastTheme: ThemeSnapshot | null = null;

export function rememberInspector(packet: CapturedPacket, theme: ThemeSnapshot | null): void {
  lastPacket = packet;
  if (theme) lastTheme = theme;
}

export function inspectorPacket(): CapturedPacket | null {
  return lastPacket;
}

export function inspectorTheme(): ThemeSnapshot | null {
  return lastTheme;
}

export function clearInspectorState(): void {
  lastPacket = null;
  lastTheme = null;
}
