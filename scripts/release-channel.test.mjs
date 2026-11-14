import { describe, expect, test } from 'bun:test';
import { channelOf, compareVersions, nightlyVersion } from './release-channel.mjs';

describe('release-channel', () => {
  test('reads the channel from the version, as the daemon does', () => {
    expect(channelOf('0.3.0')).toBe('stable');
    expect(channelOf('0.3.0-beta.2')).toBe('beta');
    expect(channelOf('0.3.0-rc.1')).toBe('beta');
    expect(channelOf('0.3.1-nightly.20261102.41')).toBe('nightly');
    expect(() => channelOf('0.3.0-alpha.1')).toThrow('no update channel');
    expect(() => channelOf('v0.3.0')).toThrow('semantic version');
  });

  test('orders versions by semver precedence', () => {
    const ordered = [
      '0.2.9',
      '0.3.0-beta.2',
      '0.3.0-beta.10',
      '0.3.0-nightly.20261102.4',
      '0.3.0-rc.1',
      '0.3.0',
      '0.3.1-nightly.20261102.4',
      '0.3.1-nightly.20261103.1',
      '0.10.0',
    ];
    for (let i = 0; i < ordered.length - 1; i++) {
      expect(compareVersions(ordered[i + 1], ordered[i])).toBe(1);
      expect(compareVersions(ordered[i], ordered[i + 1])).toBe(-1);
    }
    expect(compareVersions('0.3.0', '0.3.0')).toBe(0);
  });

  test('a nightly sorts after the release it follows', () => {
    const unreleased = nightlyVersion({ base: '0.3.0', released: false, date: '20261102', run: 41 });
    expect(unreleased).toBe('0.3.0-nightly.20261102.41');
    expect(compareVersions(unreleased, '0.3.0')).toBe(-1);

    const released = nightlyVersion({ base: '0.3.0', released: true, date: '20261102', run: '41' });
    expect(released).toBe('0.3.1-nightly.20261102.41');
    expect(compareVersions(released, '0.3.0')).toBe(1);
    expect(channelOf(released)).toBe('nightly');

    // A prerelease base keeps its core version.
    expect(
      nightlyVersion({ base: '0.4.0-beta.1', released: false, date: '20261102', run: 1 }),
    ).toBe('0.4.0-nightly.20261102.1');
  });

  test('refuses a malformed date or run', () => {
    expect(() => nightlyVersion({ base: '0.3.0', date: '2026-11-02', run: 1 })).toThrow('yyyymmdd');
    expect(() => nightlyVersion({ base: '0.3.0', date: '20261102', run: '0' })).toThrow('run');
  });
});
