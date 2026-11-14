import { beforeAll, describe, expect, mock, test } from 'bun:test';
import type { AiDecisionsPage } from '#lib/api/daemon.ts';
import { loadMessages } from '#lib/i18n/messages.ts';
import type { AiDecision } from '#lib/types/index.ts';
import {
  AI_DECISIONS_PAGE_SIZE,
  AiDecisionsWorkspace,
  type AiDecisionsApiClient,
  type AiDecisionsHost,
} from './ai-decisions-workspace';

beforeAll(async () => {
  await loadMessages('en');
});

function decision(domain: string): AiDecision {
  return {
    domain,
    model: 'typesafe',
    verdict: 'record',
    topCategory: 'tracking',
    topScore: 0.8,
    ratings: {
      advertising: 0,
      tracking: 0.8,
      telemetry: 0,
      analytics: 0,
      malicious: 0,
      fraud: 0,
      cryptomining: 0,
      tunnel: 0,
    },
    signals: {
      newlyRegistered: 0,
      registryHold: 0,
      hiddenRegistrant: 0,
      abusiveRegistrar: 0,
    },
    scanTier: 'basic',
    firstSeen: 1,
    updatedAt: 2,
  };
}

function page(domains: string[], totalCount = domains.length): AiDecisionsPage {
  return {
    decisions: domains.map(decision),
    totalCount,
    blockCount: 0,
    recordCount: totalCount,
    cleanCount: 0,
  };
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((r) => (resolve = r));
  return { promise, resolve };
}

function workspace(
  getAiDecisions: AiDecisionsApiClient['getAiDecisions'],
  deleteAiDecision: AiDecisionsApiClient['deleteAiDecision'] = async () => {},
  refreshAiDecision: AiDecisionsApiClient['refreshAiDecision'] = async (domain) => decision(domain),
  advancedAiDecision: AiDecisionsApiClient['advancedAiDecision'] = async (domain) =>
    decision(domain),
) {
  const toasts: string[] = [];
  let connected = true;
  const host: AiDecisionsHost = {
    get connected() {
      return connected;
    },
    toast: (title) => toasts.push(title),
  };
  const client = {
    getAiDecisions: mock(getAiDecisions),
    deleteAiDecision: mock(deleteAiDecision),
    refreshAiDecision: mock(refreshAiDecision),
    advancedAiDecision: mock(advancedAiDecision),
  };
  const ws = new AiDecisionsWorkspace(client, host);
  ws.mount();
  return {
    ws,
    client,
    toasts,
    disconnect: () => (connected = false),
  };
}

describe('AiDecisionsWorkspace', () => {
  test('reload sends the active filters and stores counts', async () => {
    const { ws, client } = workspace(async () => page(['a.example'], 1));
    ws.verdictFilter = 'record';
    ws.searchQuery = '  track ';
    await ws.reload();
    expect(client.getAiDecisions).toHaveBeenCalledWith({
      limit: AI_DECISIONS_PAGE_SIZE,
      offset: 0,
      verdictFilter: 'record',
      searchQuery: 'track',
    });
    expect(ws.ready).toBe(true);
    expect(ws.decisions.map((row) => row.domain)).toEqual(['a.example']);
    expect(ws.recordCount).toBe(1);
    expect(ws.hasMore).toBe(false);
  });

  test('loadMore appends the next page without duplicating shifted rows', async () => {
    const { ws, client } = workspace(async ({ offset }) =>
      offset === 0 ? page(['a.example', 'b.example'], 3) : page(['b.example', 'c.example'], 3),
    );
    await ws.reload();
    expect(ws.hasMore).toBe(true);
    await ws.loadMore();
    expect(client.getAiDecisions.mock.calls[1][0].offset).toBe(2);
    expect(ws.decisions.map((row) => row.domain)).toEqual(['a.example', 'b.example', 'c.example']);
    expect(ws.hasMore).toBe(false);
  });

  test('a superseded response is discarded', async () => {
    const slow = deferred<AiDecisionsPage>();
    let call = 0;
    const { ws } = workspace(() =>
      call++ === 0 ? slow.promise : Promise.resolve(page(['new.example'])),
    );
    const first = ws.reload();
    ws.verdictFilter = 'block';
    await ws.reload();
    slow.resolve(page(['stale.example']));
    await first;
    expect(ws.decisions.map((row) => row.domain)).toEqual(['new.example']);
    expect(ws.loading).toBe(false);
  });

  test('failures toast once and still mark the view ready', async () => {
    const { ws, toasts } = workspace(async () => {
      throw new Error('daemon offline');
    });
    await ws.reload();
    expect(toasts).toEqual(["Couldn't load AI decisions"]);
    expect(ws.ready).toBe(true);
    expect(ws.loading).toBe(false);
  });

  test('does not query while disconnected', async () => {
    const { ws, client, disconnect } = workspace(async () => page([]));
    disconnect();
    await ws.reload();
    expect(client.getAiDecisions).not.toHaveBeenCalled();
  });

  test('empty history is distinguished from an empty search', async () => {
    const { ws } = workspace(async () => page([], 0));
    await ws.reload();
    expect(ws.isEmptyHistory).toBe(true);
    ws.searchQuery = 'nothing';
    expect(ws.isEmptyHistory).toBe(false);
  });

  test('delete removes the row, adjusts counts, and ignores a stale reload', async () => {
    const slow = deferred<AiDecisionsPage>();
    let call = 0;
    const blocked = decision('ads.example');
    blocked.verdict = 'block';
    blocked.topCategory = 'malicious';
    const flagged = decision('metrics.example');
    const { ws, client } = workspace(async () => {
      call += 1;
      if (call === 1) {
        return {
          decisions: [blocked, flagged],
          totalCount: 2,
          blockCount: 1,
          recordCount: 1,
          cleanCount: 0,
        };
      }
      return slow.promise;
    });
    await ws.reload();
    ws.select('ads.example');
    const pendingReload = ws.reload();
    const removed = await ws.deleteDecision('ads.example');
    expect(removed).toBe(true);
    expect(client.deleteAiDecision).toHaveBeenCalledWith('ads.example');
    slow.resolve({
      decisions: [blocked, flagged],
      totalCount: 2,
      blockCount: 1,
      recordCount: 1,
      cleanCount: 0,
    });
    await pendingReload;
    expect(ws.decisions.map((row) => row.domain)).toEqual(['metrics.example']);
    expect(ws.totalCount).toBe(1);
    expect(ws.blockCount).toBe(0);
    expect(ws.recordCount).toBe(1);
    // The selection moves to the neighbour instead of emptying the detail panel.
    expect(ws.selectedDomain).toBe('metrics.example');
    expect(ws.deletingDomain).toBeNull();
  });

  test('refresh replaces the row and moves it out of a filter it no longer matches', async () => {
    const refreshed = decision('ads.example');
    refreshed.verdict = 'block';
    refreshed.topCategory = 'malicious';
    refreshed.topScore = 0.96;
    refreshed.model = 'jev-1.13.0';
    const { ws, client } = workspace(
      async () => page(['ads.example']),
      async () => {},
      async () => refreshed,
    );
    await ws.reload();
    ws.verdictFilter = 'record';
    const updated = await ws.refreshDecision('ads.example');
    expect(updated).toBe(true);
    expect(client.refreshAiDecision).toHaveBeenCalledWith('ads.example');
    expect(ws.decisions).toEqual([]);
    expect(ws.totalCount).toBe(0);
    expect(ws.blockCount).toBe(1);
    expect(ws.recordCount).toBe(0);
    expect(ws.refreshingDomain).toBeNull();
  });

  test('advanced check stores the registration signals and scan tier', async () => {
    const checked = decision('ads.example');
    checked.scanTier = 'advanced';
    checked.signals.hiddenRegistrant = 0.2;
    checked.model = 'jev-advanced';
    const { ws, client } = workspace(
      async () => page(['ads.example']),
      async () => {},
      async (domain) => decision(domain),
      async () => checked,
    );
    await ws.reload();
    const updated = await ws.advancedCheck('ads.example');
    expect(updated).toBe(true);
    expect(client.advancedAiDecision).toHaveBeenCalledWith('ads.example');
    expect(ws.decisions[0]?.scanTier).toBe('advanced');
    expect(ws.decisions[0]?.signals.hiddenRegistrant).toBe(0.2);
    expect(ws.checkingDomain).toBeNull();
  });

  test('a failed advanced check keeps the saved row', async () => {
    const { ws, toasts } = workspace(
      async () => page(['ads.example']),
      async () => {},
      async (domain) => decision(domain),
      async () => {
        throw new Error('registry unavailable');
      },
    );
    await ws.reload();
    const updated = await ws.advancedCheck('ads.example');
    expect(updated).toBe(false);
    expect(ws.decisions.map((row) => row.domain)).toEqual(['ads.example']);
    expect(toasts).toEqual(["Couldn't run the advanced check"]);
  });

  test('a failed refresh keeps the saved row', async () => {
    const { ws, toasts } = workspace(
      async () => page(['ads.example']),
      async () => {},
      async () => {
        throw new Error('provider timeout');
      },
    );
    await ws.reload();
    const updated = await ws.refreshDecision('ads.example');
    expect(updated).toBe(false);
    expect(toasts).toEqual(["Couldn't refresh the decision"]);
    expect(ws.decisions.map((row) => row.domain)).toEqual(['ads.example']);
    expect(ws.recordCount).toBe(1);
  });

  test('a failed delete keeps the row and toasts', async () => {
    const { ws, toasts } = workspace(
      async () => page(['ads.example']),
      async () => {
        throw new Error('database locked');
      },
    );
    await ws.reload();
    const removed = await ws.deleteDecision('ads.example');
    expect(removed).toBe(false);
    expect(toasts).toEqual(["Couldn't delete the decision"]);
    expect(ws.decisions.map((row) => row.domain)).toEqual(['ads.example']);
  });

  test('a reload selects the first row and keeps a selection that survives', async () => {
    let domains = ['a.example', 'b.example'];
    const { ws } = workspace(async () => page(domains));
    await ws.reload();
    expect(ws.selectedDomain).toBe('a.example');
    ws.select('b.example');
    expect(ws.selected?.domain).toBe('b.example');
    await ws.reload();
    expect(ws.selectedDomain).toBe('b.example');
    domains = ['c.example'];
    await ws.reload();
    expect(ws.selectedDomain).toBe('c.example');
    domains = [];
    await ws.reload();
    expect(ws.selectedDomain).toBeNull();
    expect(ws.selected).toBeNull();
  });
});
