import { beforeAll, describe, expect, test } from 'bun:test';
import type { SettingsDto } from '#lib/api/daemon.ts';
import { normalizeSettings } from '#lib/models/settings-mapper.ts';
import { loadMessages, m } from '#lib/i18n/messages.ts';
import {
  DEFAULT_DNS_PROTOCOL,
  DEFAULT_DNS_PROVIDER,
  DOQ_FALLBACK_PROVIDER,
  applyDnsProtocol,
  customResolverInvalid,
  dnsProtocol,
  dnsProviderOptionList,
  dnsProviderOptions,
  safeDnsProvider,
  settingsFieldsValid,
  showSave,
  siemHostInvalid,
  siemPortInvalid,
  siemProtocolOptions,
  siemProtocolValue,
  siemUrlInvalid,
} from './settings-form';

function dto(overrides: Partial<SettingsDto> = {}): SettingsDto {
  return {
    siemEnabled: false,
    aiEnabled: false,
    aiApiKey: '',
    aiApiKeySet: false,
    clearAiApiKey: false,
    aiDecisionMode: 'retroactive',
    aiConfidenceAdvertising: 80,
    aiConfidenceTracking: 80,
    aiConfidenceTelemetry: 80,
    aiConfidenceAnalytics: 80,
    aiConfidenceMalicious: 80,
    aiConfidenceFraud: 80,
    aiConfidenceCryptomining: 80,
    aiConfidenceTunnel: 80,
    aiAdvertisingEnabled: true,
    aiAdvertisingAction: 'record',
    aiTrackingEnabled: true,
    aiTrackingAction: 'record',
    aiTelemetryEnabled: true,
    aiTelemetryAction: 'record',
    aiAnalyticsEnabled: true,
    aiAnalyticsAction: 'record',
    aiMaliciousEnabled: true,
    aiMaliciousAction: 'record',
    aiFraudEnabled: true,
    aiFraudAction: 'record',
    aiCryptominingEnabled: true,
    aiCryptominingAction: 'record',
    aiTunnelEnabled: true,
    aiTunnelAction: 'record',
    saveDomainLookups: false,
    updateChannel: 'stable',
    logRetentionEnabled: true,
    logRetentionDays: 30,
    dohBlockingEnabled: false,
    dohProvider: 'cloudflare',
    dohCustomUrl: '',
    dnsResolverEnabled: true,
    dnsProtocol: 'doh',
    wazuhTransport: '',
    wazuhFilePath: '',
    wazuhManagerHost: '',
    wazuhManagerPort: 1514,
    wazuhProtocol: 'udp',
    siemFileEnabled: false,
    siemSyslogEnabled: false,
    siemWebhookEnabled: false,
    siemUrl: '',
    siemAuthToken: '',
    siemAuthTokenSet: false,
    clearSiemAuthToken: false,
    siemAuthHeader: '',
    siemSendAllowed: false,
    siemSendBlocked: false,
    siemSendNewApp: false,
    siemSendNewDomain: false,
    siemSendThreats: false,
    hostsBlocklistEnabled: false,
    hostsBlocklistSelectedLists: '',
    hostsBlocklistUpdateFrequency: '24hours',
    hostsBlocklistLastUpdated: '',
    hostsBlocklistCustomUrls: '',
    notifyEveryConnection: false,
    notifyNewConnection: false,
    notifyNewApp: true,
    notifyThreatDetected: true,
    persistRulesOffline: false,
    privateRelayCompatibility: false,
    windivertEnabled: false,
    windivertSupported: false,
    geoIpEnabled: false,
    logDaemonConnections: false,
    powerUserSettingsEnabled: false,
    dnsBlockResponseMode: 'sinkhole',
    dnsBlockCustomIp: '',
    dnsRebindingProtectionEnabled: false,
    dnsAnswerLocalNamesEnabled: true,
    dnsNewDomainBlockingEnabled: false,
    dnsNewDomainMaxAgeDays: 30,
    networkMappingAutoEnabled: false,
    networkMappingIntervalMinutes: 30,
    ...overrides,
  };
}

beforeAll(async () => {
  await loadMessages('en');
});

describe('settings DNS helpers', () => {
  test('defaults a blank protocol to DoH', () => {
    expect(dnsProtocol(dto({ dnsProtocol: '' }))).toBe(DEFAULT_DNS_PROTOCOL);
    expect(dnsProtocol(dto({ dnsProtocol: 'doq' }))).toBe('doq');
  });

  test('lists DoH providers and falls back when the current one is incompatible', () => {
    const doh = dto({ dohProvider: 'cloudflare' });
    expect(Object.keys(dnsProviderOptions(doh))).toContain('cloudflare');
    expect(dnsProviderOptionList(doh).some((option) => option.value === 'cloudflare')).toBe(true);
    expect(safeDnsProvider(doh)).toBe('cloudflare');
    expect(safeDnsProvider(dto({ dnsProtocol: 'doq', dohProvider: 'cloudflare' }))).toBe(
      DOQ_FALLBACK_PROVIDER,
    );
    expect(safeDnsProvider(dto({ dohProvider: '' }))).toBe(DEFAULT_DNS_PROVIDER);
  });

  test('applyDnsProtocol remaps providers that the next protocol cannot use', () => {
    expect(applyDnsProtocol(dto({ dohProvider: 'cloudflare' }), 'doq').dohProvider).toBe(
      DOQ_FALLBACK_PROVIDER,
    );
    expect(applyDnsProtocol(dto({ dohProvider: 'not-a-provider' }), 'doh').dohProvider).toBe(
      DEFAULT_DNS_PROVIDER,
    );
    expect(
      applyDnsProtocol(dto({ dnsProtocol: 'doq', dohProvider: 'google' }), 'doh').dohProvider,
    ).toBe('google');
    expect(applyDnsProtocol(dto({ dohProvider: 'quad9' }), 'doq').dohProvider).toBe('quad9');
    expect(applyDnsProtocol(dto({ dohProvider: 'cloudflare' }), 'dot').dohProvider).toBe(
      'cloudflare',
    );
    expect(applyDnsProtocol(dto({ dohProvider: 'opendns' }), 'doh3').dohProvider).toBe('opendns');
  });
});

describe('settings field validity and save chrome', () => {
  test('treats a missing settings object as valid', () => {
    expect(customResolverInvalid(null)).toBe(false);
    expect(siemHostInvalid(null)).toBe(false);
    expect(siemPortInvalid(null)).toBe(false);
    expect(siemUrlInvalid(null)).toBe(false);
    expect(settingsFieldsValid(null)).toBe(true);
  });

  test('flags an invalid custom resolver and SIEM fields', () => {
    expect(customResolverInvalid(dto({ dohProvider: 'custom', dohCustomUrl: 'not-a-url' }))).toBe(
      true,
    );
    expect(customResolverInvalid(dto({ dohProvider: 'custom', dohCustomUrl: '' }))).toBe(false);
    expect(customResolverInvalid(dto({ dohProvider: 'cloudflare', dohCustomUrl: 'nope' }))).toBe(
      false,
    );
    const syslog = { siemSyslogEnabled: true };
    const webhook = { siemWebhookEnabled: true };
    expect(siemHostInvalid(dto({ ...syslog, wazuhManagerHost: 'not a host' }))).toBe(true);
    expect(siemPortInvalid(dto({ ...syslog, wazuhManagerPort: 0 }))).toBe(true);
    expect(siemUrlInvalid(dto({ ...webhook, siemUrl: 'ftp://example' }))).toBe(true);
    expect(settingsFieldsValid(dto())).toBe(true);
    expect(settingsFieldsValid(dto({ ...syslog, wazuhManagerPort: 0 }))).toBe(false);
  });

  test("ignores a disabled sink's fields, which the form hides", () => {
    expect(siemHostInvalid(dto({ siemSyslogEnabled: false, wazuhManagerHost: 'not a host' }))).toBe(
      false,
    );
    expect(siemPortInvalid(dto({ siemSyslogEnabled: false, wazuhManagerPort: 0 }))).toBe(false);
    expect(siemUrlInvalid(dto({ siemWebhookEnabled: false, siemUrl: 'ftp://example' }))).toBe(
      false,
    );
    expect(
      settingsFieldsValid(
        dto({ siemSyslogEnabled: false, siemWebhookEnabled: false, wazuhManagerPort: 0 }),
      ),
    ).toBe(true);
  });

  test('hides save on About, while clean, disconnected, or invalid', () => {
    const ready = {
      connected: true,
      settings: dto(),
      section: 'General',
      isDirty: true,
      fieldsValid: true,
    };
    expect(showSave(ready)).toBe(true);
    expect(showSave({ ...ready, section: 'About' })).toBe(false);
    expect(showSave({ ...ready, isDirty: false })).toBe(false);
    expect(showSave({ ...ready, connected: false })).toBe(false);
    expect(showSave({ ...ready, settings: null })).toBe(false);
    expect(showSave({ ...ready, fieldsValid: false })).toBe(false);
  });

  test('normalizes the SIEM syslog protocol options', () => {
    expect(siemProtocolValue('tcp')).toBe('tcp');
    expect(siemProtocolValue('UDP')).toBe('udp');
    expect(siemProtocolValue('TLS')).toBe('tls');
    expect(siemProtocolValue('quic')).toBe('udp');
    expect(siemProtocolOptions().map((option) => option.value)).toEqual(['udp', 'tcp', 'tls']);
    expect(siemProtocolOptions()[0]?.label).toBe(m.settings_siem_protocol_udp());
  });

  test('confidence scores stay between 60 and 100', () => {
    const settings = normalizeSettings({
      ...dto(),
      aiConfidenceAdvertising: 0,
      aiConfidenceMalicious: 59,
      aiConfidenceTunnel: 140,
    });
    expect(settings.aiConfidenceAdvertising).toBe(60);
    expect(settings.aiConfidenceMalicious).toBe(60);
    expect(settings.aiConfidenceTunnel).toBe(100);
    expect(settings.aiConfidenceTracking).toBe(80);
  });

  test('a settings payload without lookup storage stays off', () => {
    const { saveDomainLookups: _saved, ...rest } = dto();
    expect(normalizeSettings(rest as SettingsDto & Record<string, unknown>).saveDomainLookups).toBe(
      false,
    );
  });

  test('new domain blocking reads either casing and keeps the age to a supported value', () => {
    const settings = normalizeSettings({
      ...dto(),
      dnsNewDomainBlockingEnabled: true,
      dnsNewDomainMaxAgeDays: 14,
    });
    expect(settings.dnsNewDomainBlockingEnabled).toBe(true);
    expect(settings.dnsNewDomainMaxAgeDays).toBe(14);

    const { dnsNewDomainBlockingEnabled: _enabled, dnsNewDomainMaxAgeDays: _days, ...rest } = dto();
    const snake = normalizeSettings({
      ...rest,
      dns_new_domain_blocking_enabled: true,
      dns_new_domain_max_age_days: 90,
    } as unknown as SettingsDto & Record<string, unknown>);
    expect(snake.dnsNewDomainBlockingEnabled).toBe(true);
    expect(snake.dnsNewDomainMaxAgeDays).toBe(90);

    const legacy = normalizeSettings(rest as SettingsDto & Record<string, unknown>);
    expect(legacy.dnsNewDomainBlockingEnabled).toBe(false);
    expect(legacy.dnsNewDomainMaxAgeDays).toBe(30);
  });
});
