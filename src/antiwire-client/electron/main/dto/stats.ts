import type { ActiveApplicationsResponse, StatsResponse } from '../daemon/messages';
import { pick } from './pick';

export interface StatsDto {
  bytesSent: number;
  bytesReceived: number;
  activeConnections: number;
  blockedConnections: number;
  /** False when the collector cannot observe traffic volume, so every byte figure is zero. */
  byteAccountingAvailable: boolean;
  /** User-facing explanation of the degradation, empty while the collector is healthy. */
  collectorStatusDetail: string;
  /** Absent means a legacy daemon. False means the count could not be acquired. */
  activeConnectionsAvailable?: boolean;
  /** True when `activeConnections` is last-known after a failed refresh. */
  activeConnectionsStale: boolean;
  /**
   * Distinct applications owning live connections. Absent when the daemon
   * cannot attribute connections; never a confirmed zero.
   */
  activeApplications?: number;
  /** Product version of the running daemon; empty from a daemon that predates it. */
  daemonVersion: string;
  /** Bytes the history database occupies on disk. Absent when the daemon cannot read it. */
  databaseSizeBytes?: number;
}

export function statsToDto(s: StatsResponse): StatsDto {
  const dto: StatsDto = {
    bytesSent: s.totalBytesSent,
    bytesReceived: s.totalBytesReceived,
    activeConnections: s.activeConnectionsCount,
    blockedConnections: s.blockedConnectionsCount,
    byteAccountingAvailable: s.byteAccountingAvailable,
    collectorStatusDetail: s.collectorStatusDetail,
    activeConnectionsStale: s.activeConnectionsStale,
    daemonVersion: s.daemonVersion,
  };
  // Unset optionals are left out entirely, as serde's `skip_serializing_if` did.
  if (s.activeConnectionsAvailable !== undefined && s.activeConnectionsAvailable !== null) {
    dto.activeConnectionsAvailable = s.activeConnectionsAvailable;
  }
  if (s.activeApplicationsCount !== undefined && s.activeApplicationsCount !== null) {
    dto.activeApplications = s.activeApplicationsCount;
  }
  if (s.databaseSizeBytes !== undefined && s.databaseSizeBytes !== null) {
    dto.databaseSizeBytes = s.databaseSizeBytes;
  }
  return dto;
}

export function activeApplicationsToDto(r: ActiveApplicationsResponse) {
  return {
    applications: r.applications.map((a) =>
      pick(a, [
        'appName',
        'appPath',
        'connectionCount',
        'downloadRate',
        'uploadRate',
        'topDestinations',
        'destinationCount',
        'newestOpenedAt',
      ] as const),
    ),
    available: r.available,
  };
}
