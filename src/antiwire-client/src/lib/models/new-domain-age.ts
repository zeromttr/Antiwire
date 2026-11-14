import { m } from '#lib/i18n/messages.ts';

/**
 * Ages the daemon accepts for blocking newly registered domains, in days.
 * Mirrors `antiwire_dns::NEW_DOMAIN_MAX_AGE_DAYS`.
 */
export const NEW_DOMAIN_MAX_AGE_DAYS = [7, 14, 30, 90] as const;

export type NewDomainMaxAgeDays = (typeof NEW_DOMAIN_MAX_AGE_DAYS)[number];

export const DEFAULT_NEW_DOMAIN_MAX_AGE_DAYS: NewDomainMaxAgeDays = 30;

const AGE_LABEL_FNS: Record<NewDomainMaxAgeDays, () => string> = {
  7: m.settings_new_domains_age_week,
  14: m.settings_new_domains_age_two_weeks,
  30: m.settings_new_domains_age_month,
  90: m.settings_new_domains_age_three_months,
};

/** A supported age, or the default for anything else (an unset or retired value). */
export function normalizeNewDomainMaxAge(value: unknown): NewDomainMaxAgeDays {
  const days = Number(value);
  return (
    NEW_DOMAIN_MAX_AGE_DAYS.find((option) => option === days) ?? DEFAULT_NEW_DOMAIN_MAX_AGE_DAYS
  );
}

/** Segmented-control options; values are day counts as strings. */
export function newDomainMaxAgeOptions(): { value: string; label: string }[] {
  return NEW_DOMAIN_MAX_AGE_DAYS.map((days) => ({
    value: String(days),
    label: AGE_LABEL_FNS[days](),
  }));
}
