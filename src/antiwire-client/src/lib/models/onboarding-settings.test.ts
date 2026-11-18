import { describe, expect, test } from 'bun:test';
import type { SettingsDto } from '../api/daemon';
import {
  applyOnboardingChoices,
  onboardingChoicesFromSettings,
  type OnboardingChoices,
} from './onboarding-settings';
import { RECOMMENDED_BLOCKLIST_IDS } from './blocklists';

const settings: SettingsDto = {
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
  dohProvider: 'google',
  dohCustomUrl: '',
  dnsResolverEnabled: true,
  dnsProtocol: 'doh',
  wazuhTransport: '',
  wazuhFilePath: '',
  wazuhManagerHost: '',
  wazuhManagerPort: 0,
  wazuhProtocol: '',
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
};

describe('onboarding settings', () => {
  test('recommends HaGeZi Normal and TIF on first setup', () => {
    const choices = onboardingChoicesFromSettings(settings, true);
    expect(choices.blocklistIds).toEqual([...RECOMMENDED_BLOCKLIST_IDS]);
  });

  test('preserves no-blocklist selection when reopening setup', () => {
    const choices = onboardingChoicesFromSettings(settings, false);
    expect(choices.blocklistIds).toEqual([]);
  });

  test('maps unlimited retention and alert choices without disabling the Alerts feed', () => {
    const choices: OnboardingChoices = {
      ...onboardingChoicesFromSettings(settings),
      desktopNotifications: false,
      newConnectionAlerts: true,
      newApplicationAlerts: false,
      threatAlerts: true,
      retention: 'unlimited',
      geoIpEnabled: true,
    };
    const updated = applyOnboardingChoices(settings, choices);

    expect(updated.notifyEveryConnection).toBe(false);
    expect(updated.notifyNewConnection).toBe(true);
    expect(updated.notifyNewApp).toBe(false);
    expect(updated.notifyThreatDetected).toBe(true);
    expect(updated.logRetentionEnabled).toBe(false);
    expect(updated.geoIpEnabled).toBe(true);
  });

  test('switches an incompatible DoQ provider to Quad9', () => {
    const choices: OnboardingChoices = {
      ...onboardingChoicesFromSettings(settings),
      resolverProtocol: 'doq',
      blocklistIds: ['hagezi_multi', 'hagezi_tif'],
      retention: 90,
    };
    const updated = applyOnboardingChoices(settings, choices);

    expect(updated.dohProvider).toBe('quad9');
    expect(updated.hostsBlocklistEnabled).toBe(true);
    expect(new Set(updated.hostsBlocklistSelectedLists.split(','))).toEqual(
      new Set(['hagezi_multi', 'hagezi_tif']),
    );
    expect(updated.logRetentionDays).toBe(90);
  });

  test('keeps DoH3 and its provider when setup reopens', () => {
    const doh3 = { ...settings, dnsProtocol: 'doh3', dohProvider: 'google' };
    const choices = onboardingChoicesFromSettings(doh3);
    expect(choices.resolverProtocol).toBe('doh3');

    const updated = applyOnboardingChoices(doh3, choices);
    expect(updated.dnsProtocol).toBe('doh3');
    expect(updated.dohProvider).toBe('google');
  });
});
