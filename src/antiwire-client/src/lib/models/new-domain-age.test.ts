import { beforeAll, describe, expect, it } from 'bun:test';
import { loadMessages } from '#lib/i18n/messages.ts';
import {
  DEFAULT_NEW_DOMAIN_MAX_AGE_DAYS,
  newDomainMaxAgeOptions,
  normalizeNewDomainMaxAge,
} from './new-domain-age';

beforeAll(async () => {
  await loadMessages('en');
});

describe('new domain age', () => {
  it('offers one week, two weeks, one month and three months', () => {
    expect(newDomainMaxAgeOptions().map((option) => option.value)).toEqual(['7', '14', '30', '90']);
    expect(newDomainMaxAgeOptions().every((option) => option.label.length > 0)).toBe(true);
  });

  it('keeps a supported age and defaults anything else to a month', () => {
    expect(normalizeNewDomainMaxAge(14)).toBe(14);
    expect(normalizeNewDomainMaxAge('90')).toBe(90);
    expect(DEFAULT_NEW_DOMAIN_MAX_AGE_DAYS).toBe(30);
    for (const value of [0, 45, undefined, null, 'soon']) {
      expect(normalizeNewDomainMaxAge(value)).toBe(30);
    }
  });
});
