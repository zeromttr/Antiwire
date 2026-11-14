import type { TrafficEvent } from '../daemon/messages';

export interface RealtimeTrafficDto {
  timestamp: number;
  applicationName: string;
  applicationPath: string;
  protocol: string;
  sourceIp: string;
  sourcePort: number;
  destinationIp: string;
  destinationPort: number;
  domain: string;
  bytesSent: number;
  bytesReceived: number;
  action: string;
  lastSeen: number;
  countryCode: string;
  isp: string;
  blocklistNames: string[];
}

export function trafficToDto(e: TrafficEvent): RealtimeTrafficDto {
  return {
    timestamp: e.timestamp,
    applicationName: e.appName,
    applicationPath: e.appPath,
    protocol: e.protocol,
    sourceIp: e.srcIp,
    sourcePort: e.srcPort,
    destinationIp: e.dstIp,
    destinationPort: e.dstPort,
    domain: e.dstDomain,
    bytesSent: e.bytesSent,
    bytesReceived: e.bytesReceived,
    action: e.action,
    lastSeen: e.lastSeen,
    countryCode: e.countryCode,
    isp: e.isp,
    blocklistNames: e.blocklistNames,
  };
}
