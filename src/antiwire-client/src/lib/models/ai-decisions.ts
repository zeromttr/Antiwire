import type { AiDecisionsPage, AiVerdictFilter } from '#lib/api/daemon.ts';
import type { UnderlineTab } from '#lib/components/ui/underline-tabs.ts';
import { m } from '#lib/i18n/messages.ts';
import {
  AI_CATEGORIES,
  type AiCategory,
  type AiDecision,
  type AiVerdict,
} from '#lib/types/index.ts';

const CATEGORY_LABELS: Record<AiCategory, () => string> = {
  advertising: m.settings_ai_advertising,
  tracking: m.settings_ai_tracking,
  telemetry: m.settings_ai_telemetry,
  analytics: m.settings_ai_analytics,
  malicious: m.settings_ai_malicious,
  fraud: m.settings_ai_fraud,
  cryptomining: m.settings_ai_cryptomining,
  tunnel: m.settings_ai_tunnel,
};

function isAiCategory(value: string): value is AiCategory {
  return (AI_CATEGORIES as readonly string[]).includes(value);
}

/** Localized category name; unknown ids from a newer daemon pass through unchanged. */
export function aiCategoryLabel(category: string): string {
  return isAiCategory(category) ? CATEGORY_LABELS[category]() : category;
}

export type AiVerdictTone = 'bad' | 'warn' | 'ok';

export function aiVerdictTone(verdict: AiVerdict): AiVerdictTone {
  if (verdict === 'block') return 'bad';
  if (verdict === 'record') return 'warn';
  return 'ok';
}

export function aiVerdictLabel(verdict: AiVerdict): string {
  if (verdict === 'block') return m.ai_decisions_verdict_block();
  if (verdict === 'record') return m.ai_decisions_verdict_record();
  return m.ai_decisions_verdict_clean();
}

export function aiVerdictDescription(verdict: AiVerdict): string {
  if (verdict === 'block') return m.ai_decisions_verdict_block_desc();
  if (verdict === 'record') return m.ai_decisions_verdict_record_desc();
  return m.ai_decisions_verdict_clean_desc();
}

/** 0-1 probability as a whole percentage; rounds down so 0.995 never reads as 100%. */
export function formatAiScore(score: number): string {
  const clamped = Number.isFinite(score) ? Math.min(1, Math.max(0, score)) : 0;
  return `${Math.floor(clamped * 100)}%`;
}

export interface AiRatingRow {
  category: AiCategory;
  label: string;
  score: number;
}

/** Every category score, highest first; ties keep the daemon's category order. */
export function sortedAiRatings(decision: AiDecision): AiRatingRow[] {
  return AI_CATEGORIES.map((category) => ({
    category,
    label: aiCategoryLabel(category),
    score: decision.ratings[category] ?? 0,
  })).sort((a, b) => b.score - a.score);
}

type VerdictCounts = Pick<AiDecisionsPage, 'blockCount' | 'recordCount' | 'cleanCount'>;

/** Verdict tabs with their counts; "All" is the sum of the three. */
export function aiVerdictTabs(counts: VerdictCounts): UnderlineTab[] {
  const tab = (value: AiVerdictFilter, label: string, count: number) => ({ value, label, count });
  return [
    tab(
      'all',
      m.ai_decisions_tab_all(),
      counts.blockCount + counts.recordCount + counts.cleanCount,
    ),
    tab('block', m.ai_decisions_verdict_block(), counts.blockCount),
    tab('record', m.ai_decisions_verdict_record(), counts.recordCount),
    tab('clean', m.ai_decisions_verdict_clean(), counts.cleanCount),
  ];
}

export function isAiVerdictFilter(value: string): value is AiVerdictFilter {
  return value === 'all' || value === 'block' || value === 'record' || value === 'clean';
}
