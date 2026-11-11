import { UPDATE_CHANNELS, type UpdateChannel, type UpdateStatus } from '#lib/types/index.ts';

/** Which footer control the update status shows. `none` renders nothing. */
export type UpdateFooterView =
  | { kind: 'none' }
  | { kind: 'installing' }
  | { kind: 'reopen'; version: string }
  | { kind: 'failed'; version: string; detail: string }
  | { kind: 'available'; version: string }
  | { kind: 'unsupported'; version: string };

/** Foreground refresh cadence; the footer also refreshes on mount and when the window shows. */
export const UPDATE_CHECK_MS = 15 * 60 * 1000;
/** Refresh cadence while the daemon is installing, so the footer follows the restart. */
export const UPDATE_INSTALL_POLL_MS = 5_000;

const NO_VIEW: UpdateFooterView = { kind: 'none' };
const VERSION = /^(\d+(?:\.\d+)*)(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$/;

interface ParsedVersion {
  core: number[];
  /** Dot-separated prerelease identifiers; empty for a release. */
  pre: string[];
}

function parseVersion(version: string): ParsedVersion | null {
  const match = VERSION.exec(version.trim());
  if (!match) return null;
  return {
    core: match[1].split('.').map(Number),
    pre: match[2] ? match[2].slice(1).split('.') : [],
  };
}

/** Semver identifier order: numbers numerically and below words, words in ASCII order. */
function compareIdentifiers(a: string, b: string): number {
  const numericA = /^\d+$/.test(a);
  const numericB = /^\d+$/.test(b);
  if (numericA && numericB) return Math.sign(Number(a) - Number(b));
  if (numericA) return -1;
  if (numericB) return 1;
  return a < b ? -1 : a > b ? 1 : 0;
}

/**
 * Compares two versions by semver precedence, so 0.10.0 is newer than 0.9.9 and
 * 0.3.1-nightly.20261103.1 is newer than 0.3.1-nightly.20261102.9. Missing parts count as 0.
 * Build metadata is ignored. A pre-release sorts below its own release. Returns 0 when either
 * side is not a version, so an unknown version never looks newer.
 */
export function compareVersions(a: string, b: string): number {
  const left = parseVersion(a);
  const right = parseVersion(b);
  if (!left || !right) return 0;
  const parts = Math.max(left.core.length, right.core.length);
  for (let i = 0; i < parts; i++) {
    const difference = (left.core[i] ?? 0) - (right.core[i] ?? 0);
    if (difference !== 0) return Math.sign(difference);
  }
  if (left.pre.length === 0 || right.pre.length === 0) {
    return Math.sign(right.pre.length - left.pre.length);
  }
  for (let i = 0; i < Math.min(left.pre.length, right.pre.length); i++) {
    const order = compareIdentifiers(left.pre[i], right.pre[i]);
    if (order !== 0) return order;
  }
  return Math.sign(left.pre.length - right.pre.length);
}

/** The channel as the daemon stores it: anything it does not know is stable. */
export function normalizeUpdateChannel(channel: string): UpdateChannel {
  const trimmed = channel.trim().toLowerCase();
  return UPDATE_CHANNELS.find((known) => known === trimmed) ?? 'stable';
}

/** How far each channel is from stable; a lower number is more stable. */
const STABILITY: Record<UpdateChannel, number> = { stable: 0, beta: 1, nightly: 2 };

/**
 * The channel a release belongs to, from its version, by the daemon's rules: no prerelease is
 * stable, `-beta.N` and `-rc.N` are beta, `-nightly.…` is nightly. `null` for anything else.
 */
export function channelOfVersion(version: string): UpdateChannel | null {
  const parsed = parseVersion(version);
  if (!parsed) return null;
  if (parsed.pre.length === 0) return 'stable';
  if (parsed.pre[0] === 'beta' || parsed.pre[0] === 'rc') return 'beta';
  if (parsed.pre[0] === 'nightly') return 'nightly';
  return null;
}

/** What the Updates section says when the picked channel is not the saved one. */
export type ChannelSwitchNote =
  | { kind: 'none' }
  /** The installed release is less stable than the picked channel, which never goes back. */
  | { kind: 'stay'; version: string }
  /** The picked channel can offer its newest release at the next check. */
  | { kind: 'now' };

/**
 * The note for switching from the `saved` channel to `chosen` while `installed` runs. The
 * daemon never offers an older version, so a channel more stable than the installed release's
 * own reaches the user only with its first release newer than that one.
 */
export function channelSwitchNote(
  installed: string,
  saved: UpdateChannel,
  chosen: UpdateChannel,
): ChannelSwitchNote {
  if (chosen === saved) return { kind: 'none' };
  const own = channelOfVersion(installed);
  if (own && STABILITY[chosen] < STABILITY[own]) return { kind: 'stay', version: installed };
  return { kind: 'now' };
}

/**
 * Picks the footer control for an update status. A newer daemon wins over everything but an
 * install in progress, because the client has to be reopened before anything else applies.
 */
export function updateFooterView(status: UpdateStatus | null): UpdateFooterView {
  if (!status) return NO_VIEW;
  if (status.state === 'installing') return { kind: 'installing' };
  if (compareVersions(status.currentVersion, status.clientVersion) > 0) {
    return { kind: 'reopen', version: status.currentVersion };
  }
  if (status.state === 'failed') {
    return { kind: 'failed', version: status.availableVersion, detail: status.detail };
  }
  if (status.state === 'available') return { kind: 'available', version: status.availableVersion };
  if (
    status.state === 'unsupported' &&
    compareVersions(status.availableVersion, status.clientVersion) > 0
  ) {
    return { kind: 'unsupported', version: status.availableVersion };
  }
  return NO_VIEW;
}

/** What the Updates settings section says about the last check. */
export type UpdatesPanelStatus =
  | { kind: 'checking' }
  | { kind: 'unreachable'; detail: string }
  | { kind: 'installing' }
  | { kind: 'failed'; detail: string }
  | { kind: 'available'; version: string }
  | { kind: 'unsupported'; detail: string }
  | { kind: 'check_error'; detail: string }
  | { kind: 'up_to_date' }
  | { kind: 'unknown' };

/**
 * Picks the status line for the Updates section. A check in progress or one that could not
 * reach the daemon comes first, because it is what the user just asked for; then the same
 * order as the footer, with a release the daemon can install ahead of why a check failed.
 */
export function updatesPanelStatus(
  status: UpdateStatus | null,
  checking: boolean,
  checkFailure: string,
): UpdatesPanelStatus {
  if (checking) return { kind: 'checking' };
  if (checkFailure) return { kind: 'unreachable', detail: checkFailure };
  if (!status) return { kind: 'unknown' };
  if (status.state === 'installing') return { kind: 'installing' };
  if (status.state === 'failed') return { kind: 'failed', detail: status.detail };
  if (status.state === 'available') return { kind: 'available', version: status.availableVersion };
  if (status.state === 'unsupported') return { kind: 'unsupported', detail: status.detail };
  if (status.checkError) return { kind: 'check_error', detail: status.checkError };
  if (status.state === 'up_to_date') return { kind: 'up_to_date' };
  return { kind: 'unknown' };
}
