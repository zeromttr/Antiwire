import { beforeAll, describe, expect, it } from 'bun:test';
import type { ConnectionLog } from '#lib/types/index.ts';
import { loadMessages, m } from '#lib/i18n/messages.ts';
import {
  recordBlockedByText,
  recordConnectionStatus,
  recordCountryLabel,
  recordDetailSubtitle,
  recordDetailTitle,
  recordExecutableName,
  recordStateTone,
} from './record-detail';

beforeAll(async () => {
  await loadMessages('en');
});

function log(overrides: Partial<ConnectionLog> = {}): ConnectionLog {
  return {
    id: 1,
    applicationName: 'Chrome',
    applicationPath: 'C:\\Program Files\\Google\\Chrome\\chrome.exe',
    domain: 'example.com',
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

describe('recordDetailTitle', () => {
  it('prefers the domain, then the destination IP, then the application', () => {
    expect(recordDetailTitle(log())).toBe('example.com');
    expect(recordDetailTitle(log({ domain: '  ' }))).toBe('93.184.216.34');
    expect(recordDetailTitle(log({ domain: '', destinationIp: '' }))).toBe('Chrome');
    expect(recordDetailTitle(log({ domain: '', destinationIp: '', applicationName: '' }))).toBe('');
  });
});

describe('recordExecutableName', () => {
  it('uses the path basename and falls back to the application name', () => {
    expect(recordExecutableName(log())).toBe('chrome.exe');
    expect(recordExecutableName(log({ applicationPath: '/usr/bin/brave' }))).toBe('brave');
    expect(recordExecutableName(log({ applicationPath: '' }))).toBe('Chrome');
  });
});

describe('recordDetailSubtitle', () => {
  it('joins the executable with the domain, or the IP when there is no domain', () => {
    expect(recordDetailSubtitle(log())).toBe('chrome.exe · example.com');
    expect(recordDetailSubtitle(log({ domain: '' }))).toBe('chrome.exe · 93.184.216.34');
    expect(recordDetailSubtitle(log({ applicationPath: '', domain: '' }))).toBe(
      'Chrome · 93.184.216.34',
    );
    expect(
      recordDetailSubtitle(
        log({ applicationName: '', applicationPath: '', domain: '', destinationIp: '' }),
      ),
    ).toBe('');
  });
});

describe('recordStateTone', () => {
  it('classifies firewall actions without treating listen as blocked', () => {
    expect(recordStateTone('Blocked')).toBe('blocked');
    expect(recordStateTone('DENY')).toBe('blocked');
    expect(recordStateTone('Listen')).toBe('listen');
    expect(recordStateTone('Allowed')).toBe('allowed');
  });
});

describe('recordCountryLabel', () => {
  it('keeps a region code and adds a display name when the locale knows it', () => {
    expect(recordCountryLabel('')).toBe('');
    expect(recordCountryLabel('  us ')).toMatch(/^US · /);
    expect(recordCountryLabel('ZZ')).toBe('ZZ');
  });
});

describe('recordBlockedByText', () => {
  it('formats matching list names and is empty when none were stored', () => {
    expect(recordBlockedByText(log())).toBe('');
    expect(recordBlockedByText(log({ blocklistNames: ['hagezi_light'] }))).toBe(
      m.settings_blocklist_hagezi_light_name(),
    );
  });
});

describe('recordConnectionStatus', () => {
  it('reports confirmed live connections as active and lets close evidence win', () => {
    expect(recordConnectionStatus(log({ isActive: true }))).toBe('active');
    expect(recordConnectionStatus(log({ isActive: true, closedAt: 1_700_000_200 }))).toBe('closed');
    expect(recordConnectionStatus(log({ isActive: false }))).toBe('unknown');
  });
  it('reports unknown for a missing close observation and closed otherwise', () => {
    expect(recordConnectionStatus(log({ closedAt: 0 }))).toBe('unknown');
    expect(recordConnectionStatus(log({ closedAt: 1_700_000_200 }))).toBe('closed');
  });
});
