import { describe, expect, it } from 'bun:test';
import type { ConnectionLog, Rule } from '#lib/types/index.ts';
import {
  canTargetRecordRule,
  findApplicationRule,
  findDomainRule,
  findIpRule,
  isBlockingRule,
  normalizeDomainTarget,
  normalizeIpTarget,
  planRecordRuleToggle,
} from './record-rules';

function log(overrides: Partial<ConnectionLog> = {}): ConnectionLog {
  return {
    id: 1,
    applicationName: 'Chrome',
    applicationPath: 'C:\\Program Files\\Google\\Chrome\\chrome.exe',
    domain: 'ads.example.com',
    sourceIp: '192.168.1.10',
    sourcePort: 0,
    destinationIp: '93.184.216.34',
    port: 443,
    protocol: 'TCP',
    action: 'Allowed',
    bytesSent: 1024,
    bytesReceived: 4096,
    timestamp: 1_700_000_000,
    lastSeen: 1_700_000_100,
    closedAt: 0,
    countryCode: 'US',
    blocklistNames: [],
    ...overrides,
  };
}

function rule(overrides: Partial<Rule>): Rule {
  return {
    id: 1,
    targetType: 'DNS',
    targetValue: 'ads.example.com',
    action: 'BLOCK',
    direction: 'OUTBOUND',
    ...overrides,
  };
}

describe('normalize targets', () => {
  it('strips trailing dots and whitespace from domains', () => {
    expect(normalizeDomainTarget('  Ads.Example.COM. ')).toBe('ads.example.com');
  });

  it('treats host IPs and /32 networks as the same target', () => {
    expect(normalizeIpTarget('93.184.216.34/32')).toBe('93.184.216.34');
    expect(normalizeIpTarget('93.184.216.34')).toBe('93.184.216.34');
  });
});

describe('canTargetRecordRule', () => {
  it('rejects empty or invalid domain and IP values', () => {
    expect(canTargetRecordRule('domain', log())).toBe(true);
    expect(canTargetRecordRule('domain', log({ domain: '' }))).toBe(false);
    expect(canTargetRecordRule('ip', log({ destinationIp: '' }))).toBe(false);
    expect(canTargetRecordRule('ip', log({ destinationIp: 'foo:bar' }))).toBe(false);
    expect(canTargetRecordRule('ip', log({ destinationIp: '::1' }))).toBe(true);
    expect(
      canTargetRecordRule('application', log({ applicationName: '', applicationPath: '' })),
    ).toBe(false);
    expect(
      canTargetRecordRule('application', log({ applicationName: 'Chrome', applicationPath: '—' })),
    ).toBe(false);
  });
});

describe('findApplicationRule', () => {
  it('matches a rule by exact executable path only', () => {
    const pathRule = rule({
      id: 4,
      targetType: 'APPLICATION',
      targetValue: 'C:\\Program Files\\Google\\Chrome\\chrome.exe',
    });
    expect(findApplicationRule([pathRule], pathRule.targetValue)).toEqual(pathRule);

    const nameRule = rule({ id: 5, targetType: 'APPLICATION', targetValue: 'chrome.exe' });
    expect(
      findApplicationRule([nameRule], 'C:\\Program Files\\Google\\Chrome\\chrome.exe'),
    ).toBeUndefined();
  });

  it('returns the last matching path rule', () => {
    const path = 'C:\\Program Files\\Google\\Chrome\\chrome.exe';
    const older = rule({ id: 1, targetType: 'APPLICATION', targetValue: path, action: 'ALLOW' });
    const newer = rule({ id: 2, targetType: 'APPLICATION', targetValue: path, action: 'BLOCK' });
    expect(findApplicationRule([older, newer], path)).toEqual(newer);
  });
});

describe('findDomainRule / findIpRule', () => {
  it('uses the latest matching rule, the same way the daemon does', () => {
    const older = rule({ id: 1, action: 'ALLOW' });
    const newer = rule({ id: 2, action: 'BLOCK' });
    expect(findDomainRule([older, newer], 'ADS.example.com.')).toEqual(newer);
    expect(isBlockingRule(newer)).toBe(true);
  });

  it('matches a host IP against a stored /32 rule', () => {
    const ipRule = rule({
      id: 9,
      targetType: 'IP',
      targetValue: '93.184.216.34/32',
    });
    expect(findIpRule([ipRule], '93.184.216.34')).toEqual(ipRule);
  });
});

describe('planRecordRuleToggle', () => {
  it('adds an outbound DNS block when the domain is not blocked', () => {
    expect(planRecordRuleToggle('domain', log(), [])).toEqual({
      op: 'add',
      kind: 'domain',
      targetType: 'DNS',
      targetValue: 'ads.example.com',
      action: 'BLOCK',
      direction: 'OUTBOUND',
    });
  });

  it('adds a both-direction application block from the executable path', () => {
    const record = log();
    expect(planRecordRuleToggle('application', record, [])).toEqual({
      op: 'add',
      kind: 'application',
      targetType: 'APPLICATION',
      targetValue: record.applicationPath,
      action: 'BLOCK',
      direction: 'BOTH',
    });
  });

  it('adds an outbound IP block for the destination', () => {
    expect(planRecordRuleToggle('ip', log(), [])).toEqual({
      op: 'add',
      kind: 'ip',
      targetType: 'IP',
      targetValue: '93.184.216.34',
      action: 'BLOCK',
      direction: 'OUTBOUND',
    });
  });

  it('removes the matching block rule when the target is already blocked', () => {
    const existing = rule({ id: 12, targetType: 'DNS', targetValue: 'ads.example.com' });
    expect(planRecordRuleToggle('domain', log(), [existing])).toEqual({
      op: 'remove',
      kind: 'domain',
      rule: existing,
    });
  });

  it('returns null when the record has no usable target', () => {
    expect(planRecordRuleToggle('domain', log({ domain: '' }), [])).toBeNull();
    expect(
      planRecordRuleToggle(
        'application',
        log({ applicationName: 'Chrome', applicationPath: '' }),
        [],
      ),
    ).toBeNull();
  });

  it('removes the latest path rule, not a name-only chrome.exe rule', () => {
    const path = 'C:\\Program Files\\Google\\Chrome\\chrome.exe';
    const nameRule = rule({ id: 3, targetType: 'APPLICATION', targetValue: 'chrome.exe' });
    const olderPath = rule({ id: 4, targetType: 'APPLICATION', targetValue: path });
    const newerPath = rule({ id: 5, targetType: 'APPLICATION', targetValue: path });
    expect(planRecordRuleToggle('application', log(), [nameRule, olderPath, newerPath])).toEqual({
      op: 'remove',
      kind: 'application',
      rule: newerPath,
    });
  });
});
