import type {
  AiCategory,
  AiDecision,
  AiVerdict,
  ConnectionLog,
  NotificationEvent,
  Rule,
  CountryRule,
} from '../types';
import type { CapturedPacketDto, SettingsDto, api } from '../api/daemon';

type NetworkState = Awaited<ReturnType<typeof api.getNetworkMappingState>>;

export function createFixtures(now: number) {
  const second = Math.floor(now / 1000);
  const apps = ['Safari', 'Mail', 'Music', 'Code', 'Cloud Sync', 'Weather'];
  const domains = [
    'cdn.example.com',
    'mail.example.com',
    'audio.example.net',
    'git.example.org',
    'sync.example.net',
    'weather.example.org',
  ];
  const countries = ['US', 'DE', 'GB', 'NL', 'JP', 'AU'];
  const logs: ConnectionLog[] = Array.from({ length: 96 }, (_, i) => {
    const app = i % apps.length;
    const blocked = i % 7 === 0;
    return {
      id: i + 1,
      applicationName: apps[app],
      applicationPath: `C:\\Preview\\${apps[app]}\\app.exe`,
      // Every fourth Safari row carries the daemon's inferred-domain marker.
      domain: blocked
        ? 'telemetry.example.net'
        : app === 0 && i % 4 === 0
          ? `${domains[app]} (inferred)`
          : domains[app],
      sourceIp: '192.0.2.10',
      sourcePort: 49152 + i,
      destinationIp: `198.51.100.${app + 20}`,
      port: i % 5 === 0 ? 53 : 443,
      protocol: i % 5 === 0 ? 'UDP' : 'TCP',
      action: blocked ? 'BLOCK' : 'ALLOW',
      bytesSent: blocked ? 0 : 8192 * (i + 1),
      bytesReceived: blocked ? 0 : 65536 * (i + 3),
      timestamp: second - i * 25,
      lastSeen: second - i * 12,
      closedAt: i % 4 === 0 ? second - i * 12 : 0,
      countryCode: countries[app],
      blocklistNames: blocked ? ['Preview privacy list'] : [],
    };
  });
  const rules: Rule[] = [
    {
      id: 1,
      targetType: 'DOMAIN',
      targetValue: 'telemetry.example.net',
      action: 'BLOCK',
      direction: 'OUTBOUND',
    },
    { id: 2, targetType: 'IP', targetValue: '203.0.113.42', action: 'BLOCK', direction: 'BOTH' },
    {
      id: 3,
      targetType: 'APPLICATION',
      targetValue: 'C:\\Preview\\Weather\\app.exe',
      action: 'BLOCK',
      direction: 'OUTBOUND',
    },
  ];
  const countryRules: CountryRule[] = [
    { id: 4, countryCode: 'AQ', action: 'BLOCK', direction: 'OUTBOUND', cidrCount: 3 },
  ];
  const alerts: NotificationEvent[] = [
    {
      id: 'preview-1',
      title: 'Tracker connection blocked',
      body: 'A sample request to telemetry.example.net matched the preview privacy list.',
      severity: 'warn',
      timestamp: String(second - 20),
      tag: 'NEW_DOMAIN',
    },
    {
      id: 'preview-2',
      title: 'New application detected',
      body: 'Code connected to git.example.org over HTTPS.',
      severity: 'info',
      timestamp: String(second - 2 * 60),
      tag: 'NEW_APP',
    },
    {
      id: 'preview-3',
      title: 'Privacy lists refreshed',
      body: 'Sample protection lists are up to date.',
      severity: 'ok',
      timestamp: String(second - 8 * 60),
      tag: 'HOSTS_SYNC',
    },
    {
      id: 'preview-4',
      title: 'Suspicious destination prevented',
      body: 'Sample outbound traffic to 203.0.113.42 was blocked by an IP rule.',
      severity: 'bad',
      timestamp: String(second - 12 * 60),
      tag: 'MALICIOUS_FLOW',
    },
    {
      id: 'preview-5',
      title: 'New network device',
      body: 'A sample device named Living-room TV joined the local network.',
      severity: 'info',
      timestamp: String(second - 26 * 3600),
      tag: 'NETWORK_DEVICE_CONNECTED',
    },
    {
      id: 'preview-6',
      title: 'Location database updated',
      body: 'The sample GeoIP database was refreshed to the latest release.',
      severity: 'ok',
      timestamp: String(second - 30 * 3600),
      tag: 'GEOIP_SYNC',
    },
  ];
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
    dohBlockingEnabled: true,
    dohProvider: 'cloudflare',
    dohCustomUrl: '',
    dnsResolverEnabled: true,
    dnsProtocol: 'doh',
    wazuhTransport: 'file',
    wazuhFilePath: '',
    wazuhManagerHost: '',
    wazuhManagerPort: 514,
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
    siemSendBlocked: true,
    siemSendNewApp: true,
    siemSendNewDomain: false,
    siemSendThreats: true,
    hostsBlocklistEnabled: true,
    hostsBlocklistSelectedLists: '',
    hostsBlocklistUpdateFrequency: 'daily',
    hostsBlocklistLastUpdated: new Date(now - 3600000).toISOString(),
    hostsBlocklistCustomUrls: '',
    notifyEveryConnection: false,
    notifyNewConnection: false,
    notifyNewApp: true,
    notifyThreatDetected: true,
    persistRulesOffline: true,
    privateRelayCompatibility: false,
    windivertEnabled: false,
    dnsBypassBlockingEnabled: false,
    windivertSupported: true,
    geoIpEnabled: true,
    logDaemonConnections: false,
    powerUserSettingsEnabled: false,
    dnsBlockResponseMode: 'sinkhole',
    dnsBlockCustomIp: '',
    dnsRebindingProtectionEnabled: false,
    dnsAnswerLocalNamesEnabled: true,
    dnsNewDomainBlockingEnabled: false,
    dnsNewDomainMaxAgeDays: 30,
    networkMappingAutoEnabled: true,
    networkMappingIntervalMinutes: 10,
  };
  const network: NetworkState = {
    devices: ['Studio Mac', 'Living Room TV', 'Office Printer', 'Home Hub', 'Tablet'].map(
      (name, i) => ({
        ipAddress: `192.0.2.${10 + i}`,
        macAddress: `02:00:00:00:00:0${i + 1}`,
        manufacturer: ['Apple', 'Samsung', 'Brother', 'Preview Networks', 'Apple'][i],
        mdnsName: name,
        isPresent: i !== 4,
        lastSeen: new Date(now - i * 60000).toISOString(),
        isWatched: i === 0,
      }),
    ),
    scanRanges: [{ id: 1, adapterId: 'preview-en0', cidr: '192.0.2.0/24' }],
    deviceWatches: [
      {
        id: 1,
        ipAddress: '192.0.2.10',
        macAddress: '02:00:00:00:00:01',
        intervalMinutes: 5,
        enabled: true,
        isPresent: true,
        lastChecked: new Date(now).toISOString(),
      },
    ],
    isScanning: false,
    supported: true,
    message: '',
  };
  const bucketEnd = Math.floor(second / 1800) * 1800;
  const activityDays = 28;
  const activity = Array.from({ length: activityDays * 48 }, (_, i) => ({
    bucketStart: bucketEnd - (activityDays * 48 - 1 - i) * 1800,
    eventCount: 20 + ((i * 37) % 240),
    // Volumes per half hour that average close to the preview's live rates
    // (~2.1 MB/s down, ~340 KB/s up), so 24h comparisons read realistically.
    bytesSent: 540_000_000 + (i % 13) * 12_000_000,
    bytesReceived: 3_200_000_000 + (i % 19) * 70_000_000,
    blockedCount: i % 11,
  }));
  const aiSamples: Array<
    [string, AiVerdict, AiCategory | '', Partial<Record<AiCategory, number>>]
  > = [
    ['telemetry.example.net', 'block', 'telemetry', { telemetry: 0.96, analytics: 0.41 }],
    ['ads.example.com', 'block', 'advertising', { advertising: 0.99, tracking: 0.72 }],
    ['pixel.example.org', 'record', 'tracking', { tracking: 0.88, advertising: 0.35 }],
    ['stats.example.net', 'record', 'analytics', { analytics: 0.83, telemetry: 0.3 }],
    ['secure-login.example.co', 'block', 'fraud', { fraud: 0.91, malicious: 0.64 }],
    ['cdn.example.com', '', '', { analytics: 0.06 }],
    ['mail.example.com', '', '', { tracking: 0.04 }],
    ['git.example.org', '', '', {}],
  ];
  const aiDecisions: AiDecision[] = aiSamples.map(([domain, verdict, topCategory, scores], i) => {
    const ratings: Record<AiCategory, number> = {
      advertising: 0.01,
      tracking: 0.01,
      telemetry: 0.01,
      analytics: 0.01,
      malicious: 0.01,
      fraud: 0.01,
      cryptomining: 0.01,
      tunnel: 0.01,
      ...scores,
    };
    return {
      domain,
      model: 'typesafe-preview',
      verdict,
      topCategory,
      topScore: Math.max(...Object.values(ratings)),
      ratings,
      signals: {
        newlyRegistered: 0,
        registryHold: 0,
        hiddenRegistrant: 0,
        abusiveRegistrar: 0,
      },
      scanTier: 'basic',
      firstSeen: second - 86400 - i * 3600,
      updatedAt: second - i * 540,
    };
  });
  return { logs, rules, countryRules, alerts, settings, network, activity, aiDecisions };
}

export function previewPacket(captureId: string, sequence: number, now: number): CapturedPacketDto {
  const data = [
    0x45, 0, 0, 40, 0, 1, 0x40, 0, 64, 6, 0, 0, 192, 0, 2, 10, 198, 51, 100, 20, 0xc3, 0x50, 1,
    0xbb, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, 2, 0xfa, 0xf0, 0, 0, 0, 0,
  ];
  return {
    captureId,
    sequence,
    timestampUs: now * 1000,
    capturedLength: data.length,
    originalLength: data.length,
    linkLayer: 101,
    protocol: 'TCP',
    source: '192.0.2.10',
    destination: '198.51.100.20',
    sourcePort: 50000,
    destinationPort: 443,
    info: 'Preview HTTPS connection · SYN',
    data,
  };
}
