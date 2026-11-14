import type { AiDecision, AiDecisionsResponse } from '../daemon/messages';

export interface AiDecisionDto {
  domain: string;
  model: string;
  verdict: string;
  topCategory: string;
  topScore: number;
  ratings: {
    advertising: number;
    tracking: number;
    telemetry: number;
    analytics: number;
    malicious: number;
    fraud: number;
    cryptomining: number;
    tunnel: number;
  };
  signals: {
    newlyRegistered: number;
    registryHold: number;
    hiddenRegistrant: number;
    abusiveRegistrar: number;
  };
  scanTier: string;
  firstSeen: number;
  updatedAt: number;
}

export function decisionToDto(d: AiDecision): AiDecisionDto {
  return {
    domain: d.domain,
    model: d.model,
    verdict: d.verdict,
    topCategory: d.topCategory,
    topScore: d.topScore,
    ratings: {
      advertising: d.ratingAdvertising,
      tracking: d.ratingTracking,
      telemetry: d.ratingTelemetry,
      analytics: d.ratingAnalytics,
      malicious: d.ratingMalicious,
      fraud: d.ratingFraud,
      cryptomining: d.ratingCryptomining,
      tunnel: d.ratingTunnel,
    },
    signals: {
      newlyRegistered: d.ratingNewlyRegistered,
      registryHold: d.ratingRegistryHold,
      hiddenRegistrant: d.ratingHiddenRegistrant,
      abusiveRegistrar: d.ratingAbusiveRegistrar,
    },
    scanTier: d.scanTier,
    firstSeen: d.firstSeen,
    updatedAt: d.updatedAt,
  };
}

export function decisionsPageToDto(r: AiDecisionsResponse) {
  return {
    decisions: r.decisions.map(decisionToDto),
    totalCount: r.totalCount,
    blockCount: r.blockCount,
    recordCount: r.recordCount,
    cleanCount: r.cleanCount,
  };
}
