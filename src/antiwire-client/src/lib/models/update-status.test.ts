import { describe, expect, it } from 'bun:test';
import type { UpdateStatus } from '#lib/types/index.ts';
import {
  channelOfVersion,
  channelSwitchNote,
  compareVersions,
  normalizeUpdateChannel,
  updateFooterView,
  updatesPanelStatus,
} from './update-status';

function status(overrides: Partial<UpdateStatus> = {}): UpdateStatus {
  return {
    state: 'up_to_date',
    currentVersion: '0.2.0',
    availableVersion: '',
    notes: '',
    detail: '',
    channel: 'stable',
    lastCheckedAt: 0,
    checkError: '',
    clientVersion: '0.2.0',
    ...overrides,
  };
}

describe('compareVersions', () => {
  it('compares numerically, not as strings', () => {
    expect(compareVersions('0.10.0', '0.9.9')).toBe(1);
    expect(compareVersions('0.9.9', '0.10.0')).toBe(-1);
  });

  it('returns 0 for equal versions', () => {
    expect(compareVersions('1.2.3', '1.2.3')).toBe(0);
  });

  it('treats missing parts as zero', () => {
    expect(compareVersions('1.2', '1.2.0')).toBe(0);
    expect(compareVersions('1.2.1', '1.2')).toBe(1);
  });

  it('ranks a release above its own pre-release', () => {
    expect(compareVersions('0.2.0', '0.2.0-beta.1')).toBe(1);
    expect(compareVersions('0.2.0-beta.1', '0.2.0')).toBe(-1);
  });

  it('orders pre-releases of one version by semver precedence', () => {
    expect(compareVersions('0.2.0-rc.2', '0.2.0-beta.1')).toBe(1);
    expect(compareVersions('0.2.0-beta.10', '0.2.0-beta.9')).toBe(1);
    expect(compareVersions('0.2.0-beta', '0.2.0-beta.1')).toBe(-1);
    expect(compareVersions('0.3.1-nightly.20261103.1', '0.3.1-nightly.20261102.9')).toBe(1);
    expect(compareVersions('0.2.0-beta.1', '0.2.0-beta.1')).toBe(0);
  });

  it('asks a nightly client to reopen once the daemon moved to a newer nightly', () => {
    expect(
      updateFooterView(
        status({
          currentVersion: '0.3.1-nightly.20261103.1',
          clientVersion: '0.3.1-nightly.20261102.9',
        }),
      ),
    ).toEqual({ kind: 'reopen', version: '0.3.1-nightly.20261103.1' });
  });

  it('reads an unknown channel as stable', () => {
    expect(normalizeUpdateChannel('Nightly')).toBe('nightly');
    expect(normalizeUpdateChannel('beta ')).toBe('beta');
    expect(normalizeUpdateChannel('canary')).toBe('stable');
    expect(normalizeUpdateChannel('')).toBe('stable');
  });

  it('ignores build metadata', () => {
    expect(compareVersions('0.2.0+build-7', '0.2.0')).toBe(0);
  });

  it('returns 0 when either side is not a version', () => {
    expect(compareVersions('', '0.2.0')).toBe(0);
    expect(compareVersions('0.2.0', 'latest')).toBe(0);
  });
});

describe('updatesPanelStatus', () => {
  it('shows a check in progress, then one that could not reach the daemon', () => {
    expect(updatesPanelStatus(status(), true, 'offline')).toEqual({ kind: 'checking' });
    expect(updatesPanelStatus(status(), false, 'offline')).toEqual({
      kind: 'unreachable',
      detail: 'offline',
    });
  });

  it('offers an available release ahead of a feed error', () => {
    expect(
      updatesPanelStatus(
        status({ state: 'available', availableVersion: '0.3.0', checkError: 'beta feed' }),
        false,
        '',
      ),
    ).toEqual({ kind: 'available', version: '0.3.0' });
  });

  it('says why the feeds could not be read when nothing is offered', () => {
    expect(updatesPanelStatus(status({ checkError: 'the beta feed: 404' }), false, '')).toEqual({
      kind: 'check_error',
      detail: 'the beta feed: 404',
    });
  });

  it('covers every other state', () => {
    expect(updatesPanelStatus(null, false, '')).toEqual({ kind: 'unknown' });
    expect(updatesPanelStatus(status(), false, '')).toEqual({ kind: 'up_to_date' });
    expect(updatesPanelStatus(status({ state: 'unknown' }), false, '')).toEqual({
      kind: 'unknown',
    });
    expect(updatesPanelStatus(status({ state: 'installing' }), false, '')).toEqual({
      kind: 'installing',
    });
    expect(updatesPanelStatus(status({ state: 'failed', detail: 'x' }), false, '')).toEqual({
      kind: 'failed',
      detail: 'x',
    });
    expect(
      updatesPanelStatus(status({ state: 'unsupported', detail: 'debug build' }), false, ''),
    ).toEqual({ kind: 'unsupported', detail: 'debug build' });
  });
});

describe('updateFooterView', () => {
  it('shows nothing before the first status arrives', () => {
    expect(updateFooterView(null)).toEqual({ kind: 'none' });
  });

  it('shows nothing when unknown or up to date with the client', () => {
    expect(updateFooterView(status({ state: 'unknown' }))).toEqual({ kind: 'none' });
    expect(updateFooterView(status({ state: 'up_to_date' }))).toEqual({ kind: 'none' });
  });

  it('offers the available release with its version', () => {
    expect(updateFooterView(status({ state: 'available', availableVersion: '0.3.0' }))).toEqual({
      kind: 'available',
      version: '0.3.0',
    });
  });

  it('shows a static label while installing', () => {
    expect(updateFooterView(status({ state: 'installing', availableVersion: '0.3.0' }))).toEqual({
      kind: 'installing',
    });
  });

  it('offers a retry with the failure detail', () => {
    expect(
      updateFooterView(
        status({ state: 'failed', availableVersion: '0.3.0', detail: 'Download failed' }),
      ),
    ).toEqual({ kind: 'failed', version: '0.3.0', detail: 'Download failed' });
  });

  it('shows the version for an unsupported install only when it is newer than the client', () => {
    expect(
      updateFooterView(
        status({ state: 'unsupported', availableVersion: '0.3.0', clientVersion: '0.2.0' }),
      ),
    ).toEqual({ kind: 'unsupported', version: '0.3.0' });
    expect(
      updateFooterView(
        status({ state: 'unsupported', availableVersion: '0.2.0', clientVersion: '0.2.0' }),
      ),
    ).toEqual({ kind: 'none' });
  });

  it('asks for a reopen when the daemon is newer than the client', () => {
    expect(
      updateFooterView(
        status({ state: 'up_to_date', currentVersion: '0.10.0', clientVersion: '0.9.9' }),
      ),
    ).toEqual({ kind: 'reopen', version: '0.10.0' });
  });

  it('shows nothing when the client is newer than the daemon', () => {
    expect(
      updateFooterView(
        status({ state: 'up_to_date', currentVersion: '0.2.0', clientVersion: '0.3.0' }),
      ),
    ).toEqual({ kind: 'none' });
  });

  describe('precedence', () => {
    const newerDaemon = { currentVersion: '0.3.0', clientVersion: '0.2.0' };

    it('puts an install in progress above a reopen', () => {
      expect(updateFooterView(status({ ...newerDaemon, state: 'installing' })).kind).toBe(
        'installing',
      );
    });

    it('puts a reopen above a failure, an available release and an unsupported notice', () => {
      expect(
        updateFooterView(status({ ...newerDaemon, state: 'failed', availableVersion: '0.4.0' }))
          .kind,
      ).toBe('reopen');
      expect(
        updateFooterView(status({ ...newerDaemon, state: 'available', availableVersion: '0.4.0' }))
          .kind,
      ).toBe('reopen');
      expect(
        updateFooterView(
          status({ ...newerDaemon, state: 'unsupported', availableVersion: '0.4.0' }),
        ).kind,
      ).toBe('reopen');
    });

    it('puts a failure above an available release', () => {
      expect(
        updateFooterView(status({ state: 'failed', availableVersion: '0.3.0', detail: 'x' })).kind,
      ).toBe('failed');
    });
  });
});

describe('channelOfVersion', () => {
  it('reads the channel from the prerelease label', () => {
    expect(channelOfVersion('0.3.0')).toBe('stable');
    expect(channelOfVersion('0.4.0-beta.2')).toBe('beta');
    expect(channelOfVersion('0.4.0-rc.1')).toBe('beta');
    expect(channelOfVersion('0.4.1-nightly.20261107.12')).toBe('nightly');
    expect(channelOfVersion('0.4.0-alpha.1')).toBeNull();
    expect(channelOfVersion('')).toBeNull();
  });
});

describe('channelSwitchNote', () => {
  it('says nothing while the picked channel is the saved one', () => {
    expect(channelSwitchNote('0.3.0', 'stable', 'stable')).toEqual({ kind: 'none' });
  });

  it('warns that a more stable channel than the installed release waits for a newer one', () => {
    expect(channelSwitchNote('0.4.1-nightly.20261103.7', 'nightly', 'stable')).toEqual({
      kind: 'stay',
      version: '0.4.1-nightly.20261103.7',
    });
    expect(channelSwitchNote('0.4.0-beta.2', 'beta', 'stable')).toEqual({
      kind: 'stay',
      version: '0.4.0-beta.2',
    });
  });

  it('offers the newest release at once when the channel is no more stable than the install', () => {
    // A stable release on the beta channel: going back to stable loses nothing.
    expect(channelSwitchNote('0.3.0', 'beta', 'stable')).toEqual({ kind: 'now' });
    expect(channelSwitchNote('0.3.0', 'stable', 'nightly')).toEqual({ kind: 'now' });
    // An unknown version cannot be placed, so it is not held back.
    expect(channelSwitchNote('dev', 'nightly', 'stable')).toEqual({ kind: 'now' });
  });
});
