import type { CapturedPacketDto } from '#lib/api/daemon.ts';

const HEX_BYTES_PER_LINE = 16;

function asRecord(value: unknown): Record<string, unknown> | null {
  return value && typeof value === 'object' ? (value as Record<string, unknown>) : null;
}

function asNumber(value: unknown): number {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : 0;
}

function asByte(value: unknown): number {
  return asNumber(value) & 0xff;
}

/** Printable ASCII for a hex dump; everything else becomes `.`. */
export function hexDumpGlyph(byte: number): string {
  return byte >= 32 && byte < 127 ? String.fromCharCode(byte) : '.';
}

/** Classic offset / hex / ASCII dump of captured bytes. */
export function formatHexDump(data: readonly number[], bytesPerLine = HEX_BYTES_PER_LINE): string {
  if (data.length === 0 || bytesPerLine <= 0) return '';
  const lines: string[] = [];
  for (let offset = 0; offset < data.length; offset += bytesPerLine) {
    const slice = data.slice(offset, offset + bytesPerLine);
    const hex = slice.map((byte) => byte.toString(16).padStart(2, '0')).join(' ');
    const pad = '   '.repeat(bytesPerLine - slice.length);
    const ascii = slice.map(hexDumpGlyph).join('');
    lines.push(`${offset.toString(16).padStart(4, '0')}  ${hex}${pad}  ${ascii}`);
  }
  return lines.join('\n');
}

export function formatPacketEndpoint(address: string, port: number, empty = '—'): string {
  if (!address) return empty;
  if (!port) return address;
  return address.includes(':') ? `[${address}]:${port}` : `${address}:${port}`;
}

export function formatPacketTimestamp(timestampUs: number): string {
  const millis = Math.floor(timestampUs / 1000);
  const date = new Date(millis);
  if (Number.isNaN(date.getTime())) return '—';
  return date.toISOString();
}

/** Accepts camelCase or snake_case IPC payloads. Returns null when nothing usable arrived. */
export function normalizeInspectorPacket(value: unknown): CapturedPacketDto | null {
  const row = asRecord(value);
  if (!row) return null;
  const sequence = row.sequence ?? row.timestampUs ?? row.timestamp_us ?? row.data;
  if (sequence === undefined) return null;
  const data = Array.isArray(row.data) ? row.data.map(asByte) : [];
  return {
    captureId: String(row.captureId ?? row.capture_id ?? ''),
    sequence: asNumber(row.sequence),
    timestampUs: asNumber(row.timestampUs ?? row.timestamp_us),
    capturedLength: asNumber(row.capturedLength ?? row.captured_length),
    originalLength: asNumber(row.originalLength ?? row.original_length),
    linkLayer: asNumber(row.linkLayer ?? row.link_layer),
    protocol: String(row.protocol ?? ''),
    source: String(row.source ?? ''),
    destination: String(row.destination ?? ''),
    sourcePort: asNumber(row.sourcePort ?? row.source_port),
    destinationPort: asNumber(row.destinationPort ?? row.destination_port),
    info: String(row.info ?? ''),
    data,
  };
}
