import type { UpdateStatus } from '../daemon/messages';

const STATE_NAMES: Record<string, string> = {
  UPDATE_STATE_UP_TO_DATE: 'up_to_date',
  UPDATE_STATE_AVAILABLE: 'available',
  UPDATE_STATE_INSTALLING: 'installing',
  UPDATE_STATE_FAILED: 'failed',
  UPDATE_STATE_UNSUPPORTED: 'unsupported',
};

export function updateStateName(state: string | number): string {
  return (typeof state === 'string' && STATE_NAMES[state]) || 'unknown';
}

/**
 * `clientVersion` is this client's product version. The daemon reports its
 * own; the client asks to be reopened when the daemon's is newer.
 */
export function updateStatusToDto(s: UpdateStatus, clientVersion: string) {
  return {
    state: updateStateName(s.state),
    currentVersion: s.currentVersion,
    availableVersion: s.availableVersion,
    notes: s.notes,
    detail: s.detail,
    channel: s.channel || 'stable',
    lastCheckedAt: Number(s.lastCheckedAt) || 0,
    checkError: s.checkError ?? '',
    clientVersion,
  };
}
