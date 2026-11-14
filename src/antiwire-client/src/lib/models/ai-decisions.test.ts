import { beforeAll, describe, expect, test } from 'bun:test';
import { normalizeAiDecisionsPage } from '#lib/api/daemon.ts';
import { loadMessages } from '#lib/i18n/messages.ts';
import type { AiDecision } from '#lib/types/index.ts';
import {
  aiCategoryLabel,
  aiVerdictTabs,
  aiVerdictLabel,
  aiVerdictTone,
  formatAiScore,
  isAiVerdictFilter,
  sortedAiRatings,
} from './ai-decisions';

beforeAll(async () => {
  await loadMessages('en');
});

function decision(overrides: Partial<AiDecision> = {}): AiDecision {
  return {
    domain: 'ads.example',
    model: 'typesafe',
    verdict: 'block',
    topCategory: 'advertising',
    topScore: 0.97,
    ratings: {
      advertising: 0.97,
      tracking: 0.4,
      telemetry: 0,
      analytics: 0.4,
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
    firstSeen: 1_700_000_000,
    updatedAt: 1_700_000_100,
    ...overrides,
  };
}

describe('AI decision presentation', () => {
  test('verdicts map to tones and labels, with empty meaning clean', () => {
    expect(aiVerdictTone('block')).toBe('bad');
    expect(aiVerdictTone('record')).toBe('warn');
    expect(aiVerdictTone('')).toBe('ok');
    expect(aiVerdictLabel('block')).toBe('Blocked');
    expect(aiVerdictLabel('record')).toBe('Flagged');
    expect(aiVerdictLabel('')).toBe('Clean');
  });

  test('category labels reuse settings names and pass unknown ids through', () => {
    expect(aiCategoryLabel('fraud')).toBe('Lookalike fraud');
    expect(aiCategoryLabel('future_category')).toBe('future_category');
  });

  test('scores render as floored, clamped percentages', () => {
    expect(formatAiScore(0.995)).toBe('99%');
    expect(formatAiScore(1)).toBe('100%');
    expect(formatAiScore(-0.2)).toBe('0%');
    expect(formatAiScore(Number.NaN)).toBe('0%');
  });

  test('ratings sort highest first and keep category order on ties', () => {
    const rows = sortedAiRatings(decision());
    expect(rows.map((row) => row.category).slice(0, 3)).toEqual([
      'advertising',
      'tracking',
      'analytics',
    ]);
    expect(rows).toHaveLength(8);
  });

  test('verdict tabs carry per-verdict counts and a combined total', () => {
    const tabs = aiVerdictTabs({ blockCount: 2, recordCount: 3, cleanCount: 5 });
    expect(tabs).toEqual([
      { value: 'all', label: 'All', count: 10 },
      { value: 'block', label: 'Blocked', count: 2 },
      { value: 'record', label: 'Flagged', count: 3 },
      { value: 'clean', label: 'Clean', count: 5 },
    ]);
    expect(isAiVerdictFilter('clean')).toBe(true);
    expect(isAiVerdictFilter('allow')).toBe(false);
  });
});

describe('normalizeAiDecisionsPage', () => {
  test('coerces the IPC payload and fills missing ratings', () => {
    const page = normalizeAiDecisionsPage({
      decisions: [
        {
          domain: 'x.example',
          verdict: 'BLOCK',
          topCategory: 'tracking',
          topScore: 1.4,
          ratings: { tracking: '0.9' },
          firstSeen: 1,
          updatedAt: 2,
        },
        { domain: 'y.example', verdict: 'allow' },
      ],
      totalCount: 7,
      blockCount: 1,
      recordCount: 0,
      cleanCount: 6,
    });
    expect(page.totalCount).toBe(7);
    expect(page.cleanCount).toBe(6);
    const [first, second] = page.decisions;
    expect(first.verdict).toBe('block');
    expect(first.topScore).toBe(1);
    expect(first.ratings.tracking).toBe(0.9);
    expect(first.ratings.tunnel).toBe(0);
    expect(first.scanTier).toBe('basic');
    expect(second.verdict).toBe('');
  });

  test('tolerates a missing payload', () => {
    expect(normalizeAiDecisionsPage(null)).toEqual({
      decisions: [],
      totalCount: 0,
      blockCount: 0,
      recordCount: 0,
      cleanCount: 0,
    });
  });
});
