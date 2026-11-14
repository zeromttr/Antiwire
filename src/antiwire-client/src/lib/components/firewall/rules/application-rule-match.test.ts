import { describe, expect, it } from 'bun:test';
import type { Rule } from '#lib/types/index.ts';
import {
  applicationRuleTarget,
  findApplicationRule,
  hasExecutablePath,
} from './application-rule-match';

function rule(overrides: Partial<Rule>): Rule {
  return {
    id: 1,
    targetType: 'APPLICATION',
    targetValue: 'C:\\Program Files\\Google\\Chrome\\chrome.exe',
    action: 'BLOCK',
    direction: 'BOTH',
    ...overrides,
  };
}

describe('application-rule-match', () => {
  it('rejects empty and em-dash paths', () => {
    expect(hasExecutablePath('')).toBe(false);
    expect(hasExecutablePath('—')).toBe(false);
    expect(applicationRuleTarget('Chrome')).toBeNull();
    expect(applicationRuleTarget('C:\\Apps\\app.exe')).toBe('C:\\Apps\\app.exe');
  });

  it('matches the last exact path rule only', () => {
    const path = 'C:\\Apps\\app.exe';
    const nameRule = rule({ id: 1, targetValue: 'app.exe' });
    const older = rule({ id: 2, targetValue: path, action: 'ALLOW' });
    const newer = rule({ id: 3, targetValue: path, action: 'BLOCK' });
    expect(findApplicationRule([nameRule, older, newer], path)).toEqual(newer);
  });
});
