import { describe, expect, it } from 'bun:test';
import {
  destinationSummary,
  isNewlyActive,
  normalizeActiveApps,
  rankActiveApps,
} from './active-apps';

describe('active applications', () => {
  it('normalizes the daemon page defensively', () => {
    const page = normalizeActiveApps({
      available: true,
      applications: [
        {
          appName: 'Code',
          appPath: 'C:\\Code.exe',
          connectionCount: 3,
          downloadRate: 1500,
          uploadRate: -4,
          topDestinations: ['git.example.org', ''],
          destinationCount: 1,
          newestOpenedAt: 1_700_000_000,
        },
        null,
      ],
    });
    expect(page.available).toBe(true);
    expect(page.applications[0]).toEqual({
      name: 'Code',
      path: 'C:\\Code.exe',
      connections: 3,
      downloadRate: 1500,
      uploadRate: 0,
      destinations: ['git.example.org'],
      destinationCount: 1,
      newestOpenedAt: 1_700_000_000,
    });
    expect(page.applications[1]).toMatchObject({ name: '', connections: 0, destinations: [] });
    expect(normalizeActiveApps(undefined)).toEqual({ applications: [], available: false });
  });

  it('summarizes destinations as the busiest plus a count of the rest', () => {
    const app = normalizeActiveApps({
      applications: [{ topDestinations: ['a.example', 'b.example'], destinationCount: 5 }],
    }).applications[0];
    expect(destinationSummary(app)).toEqual({ primary: 'a.example', more: 4 });
    const none = normalizeActiveApps({ applications: [{}] }).applications[0];
    expect(destinationSummary(none)).toEqual({ primary: '', more: 0 });
  });

  it('ranks by current throughput, then connections, then name', () => {
    const { applications } = normalizeActiveApps({
      applications: [
        { appName: 'Idle', connectionCount: 9 },
        { appName: 'Busy', downloadRate: 900, uploadRate: 100 },
        { appName: 'Beta', downloadRate: 10, connectionCount: 1 },
        { appName: 'Alpha', downloadRate: 10, connectionCount: 1 },
      ],
    });
    expect(rankActiveApps(applications).map((app) => app.name)).toEqual([
      'Busy',
      'Alpha',
      'Beta',
      'Idle',
    ]);
    expect(rankActiveApps(applications, 2)).toHaveLength(2);
  });

  it('flags applications that opened a connection in the last minute', () => {
    const now = 1_700_000_100_000;
    const app = (openedAt: number) =>
      normalizeActiveApps({ applications: [{ newestOpenedAt: openedAt }] }).applications[0];
    expect(isNewlyActive(app(1_700_000_070), now)).toBe(true);
    expect(isNewlyActive(app(1_700_000_000), now)).toBe(false);
    expect(isNewlyActive(app(0), now)).toBe(false);
  });
});
