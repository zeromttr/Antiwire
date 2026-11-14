import type { NetworkMappingState } from '../daemon/messages';
import { pick } from './pick';

export function networkMappingToDto(s: NetworkMappingState) {
  return {
    devices: s.devices.map((d) => ({
      ipAddress: d.ipAddress,
      macAddress: d.macAddress,
      manufacturer: d.manufacturer,
      mdnsName: d.mdnsName,
      isPresent: d.present,
      lastSeen: d.lastSeen,
      isWatched: d.watched,
    })),
    scanRanges: s.scanRanges.map((r) => pick(r, ['id', 'adapterId', 'cidr'] as const)),
    deviceWatches: s.deviceWatches.map((w) => ({
      id: w.id,
      ipAddress: w.ipAddress,
      macAddress: w.macAddress,
      intervalMinutes: w.intervalMinutes,
      enabled: w.enabled,
      isPresent: w.present,
      lastChecked: w.lastChecked,
    })),
    isScanning: s.isScanning,
    supported: s.supported,
    message: s.message,
  };
}
