import type { CaptureDevicesResponse, CapturedPacket, CaptureStatus } from '../daemon/messages';
import { pick } from './pick';

export interface CapturedPacketDto {
  captureId: string;
  sequence: number;
  timestampUs: number;
  capturedLength: number;
  originalLength: number;
  linkLayer: number;
  protocol: string;
  source: string;
  destination: string;
  sourcePort: number;
  destinationPort: number;
  info: string;
  /** Raw bytes as numbers, as serde wrote `Vec<u8>`; the renderer reads it as `number[]`. */
  data: number[];
}

export function packetToDto(captureId: string, p: CapturedPacket): CapturedPacketDto {
  return {
    captureId,
    sequence: p.sequence,
    timestampUs: p.timestampUs,
    capturedLength: p.capturedLength,
    originalLength: p.originalLength,
    linkLayer: p.linkLayer,
    protocol: p.protocol,
    source: p.source,
    destination: p.destination,
    sourcePort: p.sourcePort,
    destinationPort: p.destinationPort,
    info: p.info,
    data: Array.from(p.data),
  };
}

export function captureStatusToDto(s: CaptureStatus) {
  return pick(s, [
    'captureId',
    'state',
    'active',
    'packets',
    'bytes',
    'droppedPackets',
    'filteredPackets',
    'elapsedSeconds',
    'deviceName',
    'appName',
    'message',
  ] as const);
}

export function captureDevicesToDto(r: CaptureDevicesResponse) {
  return {
    devices: r.devices.map((d) =>
      pick(d, ['name', 'description', 'addresses', 'loopback'] as const),
    ),
    available: r.available,
    message: r.message,
  };
}
