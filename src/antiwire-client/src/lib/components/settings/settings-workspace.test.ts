import { beforeAll, describe, expect, mock, test } from 'bun:test';
import type { SettingsDto, SettingsSaveResult } from '#lib/api/daemon.ts';
import { loadMessages, m } from '#lib/i18n/messages.ts';
import { SettingsWorkspace, type SettingsApiClient, type SettingsHost } from './settings-workspace';

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

const saved: SettingsSaveResult = { success: true, notApplied: [] };

function workspace(options?: { connected?: boolean; client?: Partial<SettingsApiClient> }) {
  const toasts: Array<[string, string, string]> = [];
  const saves: Array<[SettingsDto | null, SettingsDto]> = [];
  let connected = options?.connected ?? true;
  const host: SettingsHost = {
    get connected() {
      return connected;
    },
    toast: (title, body, color) => {
      toasts.push([title, body, color]);
    },
    saved: (before, after) => {
      saves.push([before, after]);
    },
  };
  const client = {
    getSettings: mock(async () => dto()),
    updateSettings: mock(async () => saved),
    ...options?.client,
  } as SettingsApiClient;
  const set = new SettingsWorkspace(client, host);
  return {
    set,
    client,
    toasts,
    saves,
    setConnected: (next: boolean) => {
      connected = next;
    },
  };
}

beforeAll(async () => {
  await loadMessages('en');
});

describe('SettingsWorkspace.loadSettings', () => {
  test('does not call the daemon while disconnected', async () => {
    const { set, client } = workspace({ connected: false });
    await set.loadSettings();
    expect(client.getSettings).not.toHaveBeenCalled();
    expect(set.settings).toBeNull();
  });

  test('stores loaded settings and aligns the saved revision', async () => {
    const { set } = workspace({
      client: { getSettings: mock(async () => dto({ notifyNewApp: false })) },
    });
    set.editRevision = 3;
    await set.loadSettings();
    expect(set.settings?.notifyNewApp).toBe(false);
    expect(set.savedRevision).toBe(3);
    expect(set.loading).toBe(false);
    expect(set.isDirty).toBe(false);
  });

  test('ignores a stale load when a newer one finishes first', async () => {
    let resolveSlow: (value: SettingsDto) => void = () => {};
    const slow = new Promise<SettingsDto>((resolve) => {
      resolveSlow = resolve;
    });
    const { set, client } = workspace({
      client: {
        getSettings: mock()
          .mockImplementationOnce(() => slow)
          .mockImplementationOnce(async () => dto({ dohProvider: 'quad9' })),
      },
    });
    const first = set.loadSettings();
    const second = set.loadSettings();
    await second;
    resolveSlow(dto({ dohProvider: 'google' }));
    await first;
    expect(client.getSettings).toHaveBeenCalledTimes(2);
    expect(set.settings?.dohProvider).toBe('quad9');
  });

  test('toasts a load failure without throwing', async () => {
    const { set, toasts } = workspace({
      client: {
        getSettings: mock(async () => {
          throw new Error('settings down');
        }),
      },
    });
    await set.loadSettings();
    expect(set.settings).toBeNull();
    expect(toasts[0]).toEqual([m.settings_toast_error_title(), 'settings down', 'var(--bad)']);
  });
});

describe('SettingsWorkspace.saveSettings', () => {
  test('tells the host what was saved before and after, so it can follow a new channel', async () => {
    const { set, saves } = workspace();
    await set.loadSettings();
    set.patch('updateChannel', 'nightly');
    await set.saveSettings();
    expect(saves).toHaveLength(1);
    expect(saves[0][0]?.updateChannel).toBe('stable');
    expect(saves[0][1].updateChannel).toBe('nightly');
  });

  test('does not tell the host about a save the daemon refused', async () => {
    const { set, saves } = workspace({
      client: { updateSettings: mock(async () => ({ success: false, notApplied: [] })) },
    });
    await set.loadSettings();
    set.patch('updateChannel', 'beta');
    await set.saveSettings();
    expect(saves).toHaveLength(0);
  });

  test('is a no-op while disconnected, clean, invalid, or already saving', async () => {
    const disconnected = workspace({ connected: false });
    disconnected.set.settings = dto();
    disconnected.set.editRevision = 1;
    await disconnected.set.saveSettings();
    expect(disconnected.client.updateSettings).not.toHaveBeenCalled();

    const clean = workspace();
    clean.set.settings = dto();
    await clean.set.saveSettings();
    expect(clean.client.updateSettings).not.toHaveBeenCalled();

    const invalid = workspace();
    invalid.set.settings = dto({ siemSyslogEnabled: true, wazuhManagerPort: 0 });
    invalid.set.editRevision = 1;
    await invalid.set.saveSettings();
    expect(invalid.client.updateSettings).not.toHaveBeenCalled();

    const busy = workspace();
    busy.set.settings = dto();
    busy.set.editRevision = 1;
    busy.set.saving = true;
    await busy.set.saveSettings();
    expect(busy.client.updateSettings).not.toHaveBeenCalled();
  });

  test('saves dirty settings, toasts, and reloads', async () => {
    const { set, client, toasts } = workspace({
      client: {
        getSettings: mock(async () => dto({ notifyNewApp: false })),
        updateSettings: mock(async () => saved),
      },
    });
    set.settings = dto();
    set.patch('notifyNewApp', false);
    await set.saveSettings();
    expect(client.updateSettings).toHaveBeenCalledTimes(1);
    expect(client.getSettings).toHaveBeenCalledTimes(1);
    expect(set.isDirty).toBe(false);
    expect(toasts[0]?.[0]).toBe(m.settings_toast_saved_title());
  });

  test('does not mark saved when the form changes during the write', async () => {
    let finishSave: (result: SettingsSaveResult) => void = () => {};
    const { set, toasts } = workspace({
      client: {
        updateSettings: mock(
          () =>
            new Promise<SettingsSaveResult>((resolve) => {
              finishSave = resolve;
            }),
        ),
      },
    });
    set.settings = dto();
    set.patch('notifyNewApp', false);
    const pending = set.saveSettings();
    set.patch('notifyThreatDetected', false);
    finishSave(saved);
    await pending;
    expect(set.isDirty).toBe(true);
    expect(toasts).toEqual([]);
  });

  test('toasts when the daemon rejects or throws', async () => {
    const rejected = workspace({
      client: { updateSettings: mock(async () => ({ success: false, notApplied: [] })) },
    });
    rejected.set.settings = dto();
    rejected.set.editRevision = 1;
    await rejected.set.saveSettings();
    expect(rejected.toasts[0]).toEqual([
      m.settings_toast_save_failed_title(),
      m.settings_error_daemon_rejected(),
      'var(--bad)',
    ]);

    const failed = workspace({
      client: {
        updateSettings: mock(async () => {
          throw new Error('write failed');
        }),
      },
    });
    failed.set.settings = dto();
    failed.set.editRevision = 1;
    await failed.set.saveSettings();
    expect(failed.toasts[0]).toEqual([
      m.settings_toast_save_failed_title(),
      'write failed',
      'var(--bad)',
    ]);
  });
});

describe('SettingsWorkspace patches and power user', () => {
  test('discard restores loaded settings across categories without writing', async () => {
    const { set, client } = workspace();
    await set.loadSettings();
    set.patch('notifyNewApp', false);
    set.patch('logRetentionDays', 7);
    set.discardChanges();
    expect(set.settings?.notifyNewApp).toBe(true);
    expect(set.settings?.logRetentionDays).toBe(30);
    expect(set.isDirty).toBe(false);
    expect(client.updateSettings).not.toHaveBeenCalled();
  });

  test('reverting the only changed field leaves the form clean', async () => {
    const { set, client } = workspace();
    await set.loadSettings();
    const saved = set.settings?.updateChannel;
    set.patch('updateChannel', 'nightly');
    expect(set.isDirty).toBe(true);
    set.revertField('updateChannel');
    expect(set.settings?.updateChannel).toBe(saved);
    expect(set.isDirty).toBe(false);
    expect(client.updateSettings).not.toHaveBeenCalled();
  });

  test('reverting one field keeps the other edits pending', async () => {
    const { set } = workspace();
    await set.loadSettings();
    set.patch('updateChannel', 'nightly');
    set.patch('logRetentionDays', 7);
    set.revertField('updateChannel');
    expect(set.settings?.logRetentionDays).toBe(7);
    expect(set.isDirty).toBe(true);
  });

  test('invalid retention cannot be saved', async () => {
    const { set, client } = workspace();
    await set.loadSettings();
    for (const days of [0, -1, 1.5, NaN]) {
      set.patch('logRetentionDays', days);
      expect(set.settingsFieldsValid).toBe(false);
      await set.saveSettings();
    }
    expect(client.updateSettings).not.toHaveBeenCalled();
    set.patch('logRetentionDays', 7);
    expect(set.settingsFieldsValid).toBe(true);
  });

  test('edits during reload are preserved', async () => {
    let finishLoad: (value: SettingsDto) => void = () => {};
    const { set } = workspace({
      client: {
        getSettings: () =>
          new Promise((resolve) => {
            finishLoad = resolve;
          }),
      },
    });
    set.settings = dto();
    const loading = set.loadSettings();
    set.patch('notifyNewApp', false);
    finishLoad(dto());
    await loading;
    expect(set.settings?.notifyNewApp).toBe(false);
    expect(set.isDirty).toBe(true);
  });

  test('patch is a no-op until settings are loaded', () => {
    const { set } = workspace();
    set.patch('notifyNewApp', false);
    expect(set.settings).toBeNull();
    expect(set.editRevision).toBe(0);
  });

  test('patch and DNS protocol changes bump the edit revision', () => {
    const { set } = workspace();
    set.settings = dto({ dohProvider: 'cloudflare' });
    set.patch('notifyNewApp', false);
    expect(set.settings?.notifyNewApp).toBe(false);
    expect(set.editRevision).toBe(1);
    set.setDnsProtocol('doq');
    expect(set.settings?.dnsProtocol).toBe('doq');
    expect(set.settings?.dohProvider).toBe('quad9');
    expect(set.editRevision).toBe(2);
    expect(set.showSave).toBe(true);
  });

  test('hides save on the About section', () => {
    const { set } = workspace();
    set.settings = dto();
    set.editRevision = 1;
    set.section = 'About';
    expect(set.showSave).toBe(false);
  });

  test('enabling power-user settings opens the warning instead of writing', () => {
    const { set } = workspace();
    set.settings = dto();
    set.onPowerUserToggle(true);
    expect(set.powerUserDialogOpen).toBe(true);
    expect(set.settings?.powerUserSettingsEnabled).toBe(false);
    expect(set.editRevision).toBe(0);
    set.confirmPowerUser();
    expect(set.settings?.powerUserSettingsEnabled).toBe(true);
    expect(set.editRevision).toBe(1);
  });

  test('disabling power-user settings restores daemon-safe defaults', () => {
    const { set } = workspace();
    set.settings = dto({
      powerUserSettingsEnabled: true,
      dnsBlockResponseMode: 'custom',
      dnsBlockCustomIp: '1.2.3.4',
      dnsRebindingProtectionEnabled: true,
      dnsAnswerLocalNamesEnabled: false,
    });
    set.onPowerUserToggle(false);
    expect(set.settings?.powerUserSettingsEnabled).toBe(false);
    expect(set.settings?.dnsBlockResponseMode).toBe('sinkhole');
    expect(set.settings?.dnsBlockCustomIp).toBe('');
    expect(set.settings?.dnsRebindingProtectionEnabled).toBe(false);
    expect(set.settings?.dnsAnswerLocalNamesEnabled).toBe(true);
    expect(set.editRevision).toBe(1);
  });
});

describe('SettingsWorkspace secrets', () => {
  test('typing a secret replaces it and cancels a pending removal', async () => {
    const { set } = workspace({
      client: { getSettings: mock(async () => dto({ aiApiKeySet: true })) },
    });
    await set.loadSettings();

    set.clearSecret('aiApiKey', 'clearAiApiKey');
    expect(set.settings?.clearAiApiKey).toBe(true);
    expect(set.isDirty).toBe(true);

    set.patchSecret('aiApiKey', 'clearAiApiKey', 'sk-new');
    expect(set.settings?.aiApiKey).toBe('sk-new');
    expect(set.settings?.clearAiApiKey).toBe(false);
  });

  test('a removal is sent with an empty value', async () => {
    const updateSettings = mock(async (_settings: SettingsDto) => saved);
    const { set } = workspace({
      client: {
        getSettings: mock(async () => dto({ siemAuthTokenSet: true })),
        updateSettings,
      },
    });
    await set.loadSettings();

    set.patchSecret('siemAuthToken', 'clearSiemAuthToken', 'typed');
    set.clearSecret('siemAuthToken', 'clearSiemAuthToken');
    await set.saveSettings();

    const sent = updateSettings.mock.calls[0]?.[0];
    expect(sent?.siemAuthToken).toBe('');
    expect(sent?.clearSiemAuthToken).toBe(true);
  });
});

describe('SettingsWorkspace partial saves', () => {
  test('warns about settings that were saved but did not take effect', async () => {
    const { set, toasts } = workspace({
      client: {
        updateSettings: mock(async () => ({
          success: true,
          notApplied: ['DNS: upstream unreachable', 'SIEM forwarding: bad URL'],
        })),
      },
    });
    set.settings = dto();
    set.patch('notifyNewApp', false);
    await set.saveSettings();
    expect(toasts[0]).toEqual([
      m.settings_toast_not_applied_title(),
      'DNS: upstream unreachable\nSIEM forwarding: bad URL',
      'var(--warn)',
    ]);
    expect(set.isDirty).toBe(false);
  });
});
