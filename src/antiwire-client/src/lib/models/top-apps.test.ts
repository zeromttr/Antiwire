import { describe, expect, it } from 'bun:test';
import type { AppSummary } from '#lib/types/index.ts';
import { topApplications } from './top-apps';

function summary(name: string, received: number, sent: number): AppSummary {
  return {
    applicationId: 1,
    applicationName: name,
    applicationPath: `C:\\${name}.exe`,
    connectionCount: 1,
    blockedCount: 0,
    totalBytes: received + sent,
    bytesSent: sent,
    bytesReceived: received,
  };
}

describe('top applications', () => {
  it('ranks by total data, drops idle apps, and limits the list', () => {
    const top = topApplications(
      [
        summary('Mail', 10, 0),
        summary('Idle', 0, 0),
        summary('Sync', 300, 100),
        summary('Code', 90, 10),
      ],
      2,
    );
    expect(top.map((app) => app.name)).toEqual(['Sync', 'Code']);
  });

  it('scales bars to the busiest app and shares to the whole', () => {
    const top = topApplications([summary('A', 75, 25), summary('B', 50, 0), summary('C', 50, 0)]);
    expect(top[0]).toMatchObject({ name: 'A', scale: 1, share: 0.5 });
    expect(top[1]).toMatchObject({ scale: 0.5, share: 0.25 });
  });

  it('returns nothing when there is no traffic', () => {
    expect(topApplications([summary('Idle', 0, 0)])).toEqual([]);
    expect(topApplications([])).toEqual([]);
  });
});
