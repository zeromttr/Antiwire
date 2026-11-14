import type { AppSummary, ConnectionLog, RuleDirection } from '../types';
import type { CapturedPacketDto, SettingsDto } from '../api/daemon';
import { reputationService } from '../models/reputation';
import { createFixtures, previewPacket } from './fixtures';
import { computeRegionStats } from '../utils/region-stats';

/** In-memory daemon substitute. No IPC, network requests, filesystem or persistent writes. */
const PREVIEW_LOOKUP_DELAY_MS: Record<string, number> = {
  lookup_domain: 900,
  lookup_dns_records: 700,
  get_seen_subdomains: 150,
  search_certificates: 1600,
};

/** A record's domain as the daemon reads it: lowercase, no inferred marker. */
function previewHost(value: unknown): string {
  return String(value ?? '')
    .trim()
    .replace(/ \(inferred\)$/, '')
    .replace(/\.$/, '')
    .toLowerCase();
}

/** The hint when it is the host or a parent of it, else the last two labels. */
function previewDomain(host: string, hint: unknown): string {
  const domain = previewHost(hint);
  if (domain.includes('.') && (host === domain || host.endsWith(`.${domain}`))) return domain;
  return host.split('.').slice(-2).join('.');
}

function reverseName(address: string): string {
  return `${address.split('.').reverse().join('.')}.in-addr.arpa`;
}

export function createPreviewBackend(clock = Date.now) {
  const started = clock();
  const fixtures = createFixtures(started);
  let nextId = 100;
  let connected = true;
  let scanUntil = 0;
  let inspector: CapturedPacketDto = previewPacket('preview-inspector', 1, started);
  const captures = new Map<
    string,
    {
      started: number;
      stopped?: number;
      device: string;
      appName: string;
      maxSeconds: number;
      maxBytes: number;
    }
  >();

  function filteredLogs(args: Record<string, unknown>): ConnectionLog[] {
    const query = String(args.searchQuery ?? '').toLowerCase();
    const action = String(args.actionFilter ?? '').toLowerCase();
    const protocol = String(args.protocolFilter ?? '').toUpperCase();
    const applicationId = Number(args.applicationId ?? 0);
    const country = String(args.countryFilter ?? '').toUpperCase();
    const port = Number(args.portFilter ?? 0);
    const host = String(args.hostFilter ?? '').toLowerCase();
    return fixtures.logs.filter((row) => {
      if (country && row.countryCode.toUpperCase() !== country) return false;
      if (port > 0 && row.port !== port) return false;
      if (host && row.domain.toLowerCase() !== host && row.destinationIp !== host) return false;
      if (args.applicationName && row.applicationName !== args.applicationName) return false;
      if (applicationId > 0 && appIdFor(row.applicationName) !== applicationId) return false;
      if ((action === 'blocked' || action === 'block') && row.action !== 'BLOCK') return false;
      if ((action === 'allowed' || action === 'allow') && row.action !== 'ALLOW') return false;
      if (protocol && protocol !== 'ALL' && row.protocol !== protocol) return false;
      if (args.timeWindowStart && row.lastSeen < Number(args.timeWindowStart)) return false;
      if (args.timeWindowEnd && row.lastSeen > Number(args.timeWindowEnd)) return false;
      if (args.timeFilterSeconds && row.lastSeen < clock() / 1000 - Number(args.timeFilterSeconds))
        return false;
      return (
        !query ||
        [
          row.applicationName,
          row.domain,
          row.destinationIp,
          row.sourceIp,
          row.protocol,
          String(row.port),
        ].some((value) => value.toLowerCase().includes(query))
      );
    });
  }

  /** Stable preview stand-in for the daemon's application row ids. */
  const appIds = new Map<string, number>();
  function appIdFor(name: string): number {
    let id = appIds.get(name);
    if (id === undefined) {
      id = appIds.size + 1;
      appIds.set(name, id);
    }
    return id;
  }

  function captureStatus(id: string) {
    const capture = captures.get(id);
    if (!capture) throw new Error('Browser preview: unknown capture');
    const limitMs = Math.min(
      capture.maxSeconds > 0 ? capture.maxSeconds * 1000 : Infinity,
      capture.maxBytes > 0 ? (capture.maxBytes / 4800) * 1000 : Infinity,
    );
    const end = Math.min(capture.stopped ?? clock(), capture.started + limitMs);
    const seconds = Math.max(0, (end - capture.started) / 1000);
    const active = capture.stopped === undefined && clock() < capture.started + limitMs;
    return {
      captureId: id,
      state: active ? 'capturing' : 'completed',
      active,
      packets: Math.floor(seconds * 120),
      bytes: Math.floor(seconds * 120) * 40,
      droppedPackets: 0,
      filteredPackets: capture.appName ? Math.floor(seconds * 40) : 0,
      elapsedSeconds: Math.floor(seconds),
      deviceName: capture.device,
      appName: capture.appName,
      message: 'Synthetic preview packets',
    };
  }

  function dispatch(command: string, args: Record<string, unknown>): unknown {
    switch (command) {
      case 'connect_daemon':
        connected = true;
        return true;
      case 'disconnect_daemon':
        connected = false;
        return;
      case 'get_connection_status':
        return { connected };
      case 'get_stats': {
        const seconds = Math.max(0, (clock() - started) / 1000);
        return {
          bytesReceived: Math.floor(840000000 + seconds * 2600000 + 200000 * Math.sin(seconds / 3)),
          bytesSent: Math.floor(96000000 + seconds * 340000),
          activeConnections: 42,
          blockedConnections: fixtures.logs.filter((row) => row.action === 'BLOCK').length,
          byteAccountingAvailable: true,
          activeConnectionsAvailable: true,
          activeConnectionsStale: false,
          activeApplications: new Set(fixtures.logs.map((row) => row.applicationName)).size,
          collectorStatusDetail: 'Synthetic browser preview',
          databaseSizeBytes: 48_300_000,
        };
      }
      case 'get_update_status':
      case 'check_for_updates':
        return {
          state: 'available',
          currentVersion: '0.1.0',
          availableVersion: '0.2.0',
          notes: 'Synthetic browser preview release notes.',
          detail: '',
          channel: 'stable',
          lastCheckedAt: Math.floor(clock() / 1000),
          checkError: '',
          clientVersion: '0.1.0',
        };
      case 'install_update':
        return { success: true, message: 'Synthetic browser preview' };
      case 'get_active_applications': {
        // Live-looking sample: every preview app is connected, rates drift so
        // the list reorders, and one app opened a connection moments ago.
        const seconds = Math.max(0, (clock() - started) / 1000);
        const byApp = new Map<string, ConnectionLog[]>();
        for (const row of fixtures.logs) {
          const rows = byApp.get(row.applicationName) ?? [];
          rows.push(row);
          byApp.set(row.applicationName, rows);
        }
        const applications = [...byApp.entries()].map(([name, rows], index) => {
          const wave = 0.55 + 0.45 * Math.sin(seconds / 4 + index * 1.7);
          const destinations = [...new Set(rows.map((row) => row.domain || row.destinationIp))];
          return {
            appName: name,
            appPath: rows[0].applicationPath,
            connectionCount: 1 + ((index * 3) % 7),
            downloadRate: Math.round((index + 1) * 180_000 * wave),
            uploadRate: Math.round((index + 1) * 22_000 * wave),
            topDestinations: destinations.slice(0, 3),
            destinationCount: destinations.length,
            newestOpenedAt: Math.floor(clock() / 1000) - (index === 2 ? 20 : 600 + index * 90),
          };
        });
        return { applications, available: true };
      }
      case 'get_country_statistics':
        return computeRegionStats(fixtures.logs);
      case 'get_connection_logs': {
        const rows = filteredLogs(args);
        const keys: Record<string, keyof ConnectionLog> = {
          last_seen: 'lastSeen',
          app: 'applicationName',
          src: 'sourceIp',
          dst: 'destinationIp',
          country: 'countryCode',
          timestamp: 'timestamp',
          bytes_sent: 'bytesSent',
          bytes_received: 'bytesReceived',
          domain: 'domain',
          application_name: 'applicationName',
          port: 'port',
          protocol: 'protocol',
          action: 'action',
        };
        const key = keys[String(args.orderBy)] ?? 'lastSeen';
        const direction = args.sortDescending === false ? 1 : -1;
        rows.sort(
          (a, b) =>
            direction *
            (typeof a[key] === 'number'
              ? Number(a[key]) - Number(b[key])
              : String(a[key]).localeCompare(String(b[key]))),
        );
        const offset = Math.max(0, Number(args.offset ?? 0));
        return {
          logs: rows.slice(offset, offset + Math.max(0, Number(args.limit ?? 100))),
          totalCount: rows.length,
          blockedCount: rows.filter((row) => row.action === 'BLOCK').length,
        };
      }
      case 'get_app_summaries': {
        const rows = filteredLogs(args);
        const apps = new Map<string, AppSummary>();
        for (const row of rows) {
          const app = apps.get(row.applicationName) ?? {
            applicationId: appIdFor(row.applicationName),
            applicationName: row.applicationName,
            applicationPath: row.applicationPath,
            connectionCount: 0,
            blockedCount: 0,
            totalBytes: 0,
            bytesSent: 0,
            bytesReceived: 0,
          };
          app.connectionCount++;
          app.blockedCount += Number(row.action === 'BLOCK');
          app.bytesSent += row.bytesSent;
          app.bytesReceived += row.bytesReceived;
          app.totalBytes += row.bytesSent + row.bytesReceived;
          apps.set(row.applicationName, app);
        }
        return {
          applications: [...apps.values()],
          totalCount: rows.length,
          blockedCount: rows.filter((row) => row.action === 'BLOCK').length,
        };
      }
      case 'get_activity_buckets': {
        const since = Number(args.since ?? 0);
        const until = Number(args.until ?? 0);
        if (since > 0 && until > 0) {
          return fixtures.activity.filter(
            (row) => row.bucketStart >= since && row.bucketStart < until,
          );
        }
        return fixtures.activity.slice(-Math.max(1, Number(args.days ?? 7)) * 48);
      }
      case 'get_rules':
        return fixtures.rules;
      case 'add_rule':
        fixtures.rules.push({
          id: nextId++,
          targetType: String(args.targetType),
          targetValue: String(args.targetValue),
          action: String(args.action),
          direction: (args.direction ?? 'OUTBOUND') as RuleDirection,
        });
        return true;
      case 'remove_rule':
        fixtures.rules = fixtures.rules.filter((row) => row.id !== args.id);
        return true;
      case 'get_country_rules':
        return fixtures.countryRules;
      case 'add_country_rule':
        fixtures.countryRules.push({
          id: nextId++,
          countryCode: String(args.countryCode),
          action: String(args.action),
          direction: (args.direction ?? 'OUTBOUND') as RuleDirection,
          cidrCount: Array.isArray(args.cidrs) ? args.cidrs.length : 0,
        });
        return { success: true, message: '' };
      case 'remove_country_rule':
        fixtures.countryRules = fixtures.countryRules.filter((row) => row.id !== args.id);
        return { success: true, message: '' };
      case 'get_ai_decisions': {
        const query = String(args.searchQuery ?? '')
          .trim()
          .toLowerCase();
        const verdictOf = (row: { verdict: string }) => row.verdict || 'clean';
        const searched = fixtures.aiDecisions.filter((row) => row.domain.includes(query));
        const filter = String(args.verdictFilter ?? 'all') || 'all';
        const rows = searched.filter((row) => filter === 'all' || verdictOf(row) === filter);
        const offset = Math.max(0, Number(args.offset ?? 0));
        const count = (verdict: string) =>
          searched.filter((row) => verdictOf(row) === verdict).length;
        return {
          decisions: rows.slice(offset, offset + (Number(args.limit) || 100)),
          totalCount: rows.length,
          blockCount: count('block'),
          recordCount: count('record'),
          cleanCount: count('clean'),
        };
      }
      case 'refresh_ai_decision': {
        const domain = String(args.domain ?? '')
          .trim()
          .replace(/\.$/, '')
          .toLowerCase();
        const row = fixtures.aiDecisions.find((item) => item.domain === domain);
        if (!row) throw new Error('Browser preview: decision not found');
        row.model = 'jev-refreshed';
        row.updatedAt = Math.floor(clock() / 1000);
        row.topScore = Math.min(1, Number((row.topScore + 0.01).toFixed(2)));
        if (row.topCategory in row.ratings) {
          row.ratings[row.topCategory as keyof typeof row.ratings] = row.topScore;
        }
        return row;
      }
      case 'advanced_ai_decision': {
        const domain = String(args.domain ?? '')
          .trim()
          .replace(/\.$/, '')
          .toLowerCase();
        const row = fixtures.aiDecisions.find((item) => item.domain === domain);
        if (!row) throw new Error('Browser preview: decision not found');
        row.model = 'jev-advanced';
        row.scanTier = 'advanced';
        row.updatedAt = Math.floor(clock() / 1000);
        row.signals = {
          newlyRegistered: 0.1,
          registryHold: 0,
          hiddenRegistrant: 0.2,
          abusiveRegistrar: 0,
        };
        return row;
      }
      case 'lookup_dns_records': {
        // Synthetic answers shaped like the daemon's: a CNAME chain for the
        // host, the zone's own records, mail policy and one DKIM selector.
        const host = previewHost(args.host);
        const domain = previewDomain(host, args.domain);
        const now = Math.floor(clock() / 1000);
        const answer = (name: string, recordType: string, data: string, ttl = 300) => ({
          name,
          recordType,
          ttl,
          data,
        });
        const set = (
          purpose: string,
          name: string,
          recordType: string,
          answers: ReturnType<typeof answer>[],
          status = 'noerror',
        ) => ({ purpose, name, recordType, status, authenticated: true, answers });
        const edge = `${host}.edge.preview-cdn.test`;
        const address = String(args.address ?? '').trim();
        return {
          upstream: 'DoH https://1.1.1.1/dns-query',
          domain,
          sets: [
            set('host', host, 'A', [
              answer(host, 'CNAME', edge, 3600),
              answer(edge, 'A', '198.51.100.20', 60),
              answer(edge, 'A', '198.51.100.21', 60),
            ]),
            set('host', host, 'AAAA', [
              answer(host, 'CNAME', edge, 3600),
              answer(edge, 'AAAA', '2001:db8:20::1', 60),
            ]),
            set('host', host, 'HTTPS', [
              answer(host, 'CNAME', edge, 3600),
              answer(edge, 'HTTPS', '1 . alpn="h3,h2" ipv4hint=198.51.100.20', 300),
            ]),
            set('domain', domain, 'NS', [
              answer(domain, 'NS', 'ns1.preview-dns.test', 86400),
              answer(domain, 'NS', 'ns2.preview-dns.test', 86400),
            ]),
            set('domain', domain, 'SOA', [
              answer(
                domain,
                'SOA',
                `ns1.preview-dns.test hostmaster.${domain} ${now} 7200 3600 1209600 3600`,
                3600,
              ),
            ]),
            set('domain', domain, 'TXT', [
              answer(domain, 'TXT', `v=spf1 include:_spf.${domain} ~all`, 3600),
              answer(domain, 'TXT', 'google-site-verification=preview-token', 3600),
            ]),
            set('domain', domain, 'CAA', [
              answer(domain, 'CAA', '0 issue "letsencrypt.org"', 3600),
              answer(domain, 'CAA', `0 iodef "mailto:security@${domain}"`, 3600),
            ]),
            set('mail', domain, 'MX', [
              answer(domain, 'MX', `10 mx1.mail.${domain}`, 3600),
              answer(domain, 'MX', `20 mx2.mail.${domain}`, 3600),
            ]),
            set('mail', `_dmarc.${domain}`, 'TXT', [
              answer(
                `_dmarc.${domain}`,
                'TXT',
                `v=DMARC1; p=quarantine; rua=mailto:dmarc@${domain}`,
                3600,
              ),
            ]),
            set('mail', `_mta-sts.${domain}`, 'TXT', [], 'nxdomain'),
            set('dkim', `google._domainkey.${domain}`, 'TXT', [
              answer(
                `google._domainkey.${domain}`,
                'TXT',
                'v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvPreviewKey',
                3600,
              ),
            ]),
            set('dkim', `k1._domainkey.${domain}`, 'TXT', [], 'nxdomain'),
            ...(address
              ? [
                  set('reverse', reverseName(address), 'PTR', [
                    answer(
                      reverseName(address),
                      'PTR',
                      `edge-${address.replace(/[.:]/g, '-')}.preview-cdn.test`,
                      3600,
                    ),
                  ]),
                ]
              : []),
          ],
        };
      }
      case 'get_seen_subdomains': {
        const host = previewHost(args.host);
        const domain = previewDomain(host, args.domain);
        const rows = new Map<
          string,
          {
            name: string;
            connections: number;
            blocked: number;
            firstSeen: number;
            lastSeen: number;
          }
        >();
        for (const row of fixtures.logs) {
          const name = previewHost(row.domain);
          if (name !== domain && !name.endsWith(`.${domain}`)) continue;
          const item = rows.get(name) ?? {
            name,
            connections: 0,
            blocked: 0,
            firstSeen: row.timestamp,
            lastSeen: row.lastSeen,
          };
          item.connections += 1;
          if (row.action === 'BLOCK') item.blocked += 1;
          item.firstSeen = Math.min(item.firstSeen, row.timestamp);
          item.lastSeen = Math.max(item.lastSeen, row.lastSeen);
          rows.set(name, item);
        }
        const names = [...rows.values()].sort((a, b) => b.connections - a.connections);
        return { names, truncated: false, domain };
      }
      case 'search_certificates': {
        const host = previewHost(args.host);
        const domain = previewDomain(host, args.domain);
        const now = Math.floor(clock() / 1000);
        const day = 86_400;
        const names = [
          [domain, 18, 900, 60, 'R11'],
          [`*.${domain}`, 12, 700, 60, 'R11'],
          [host, 9, 600, 45, 'E6'],
          [`api.${domain}`, 7, 500, 30, 'R11'],
          [`status.${domain}`, 3, 400, 20, 'E5'],
          [`staging.${domain}`, 2, 300, -40, 'R10'],
          [`old-portal.${domain}`, 1, 2000, -900, 'DigiCert TLS RSA SHA256 2020 CA1'],
        ] as const;
        const seen = new Set<string>();
        return {
          outcome: 'found',
          domain,
          certificates: 52,
          names: names
            .filter(([name]) => !seen.has(name) && seen.add(name))
            .map(([name, certificates, issuedAgo, expiresIn, issuer]) => ({
              name,
              certificates,
              firstIssued: now - issuedAgo * day,
              latestExpiry: now + expiresIn * day,
              issuer,
            })),
          truncated: false,
          detail: '',
        };
      }
      case 'lookup_domain': {
        // Synthetic registry answers: the telemetry host is a fresh, redacted
        // registration, the weather host has none, everything else is old and signed.
        const host = String(args.domain ?? '')
          .trim()
          .replace(/ \(inferred\)$/, '')
          .replace(/\.$/, '')
          .toLowerCase();
        const registered = host.split('.').slice(-2).join('.');
        const now = Math.floor(clock() / 1000);
        const day = 86_400;
        if (host.startsWith('weather.')) {
          return {
            outcome: 'not_found',
            registration: null,
            detail: `no registration found for ${registered}`,
          };
        }
        const fresh = host.startsWith('telemetry.');
        return {
          outcome: 'found',
          detail: '',
          registration: {
            domain: registered,
            source: 'rdap',
            registrar: fresh ? 'Preview Names LLC' : 'Example Registrar, Inc.',
            registrarId: fresh ? '9999' : '376',
            statuses: fresh
              ? ['add period', 'client transfer prohibited']
              : [
                  'client delete prohibited',
                  'client transfer prohibited',
                  'client update prohibited',
                ],
            nameservers: fresh
              ? ['ns1.preview-dns.test', 'ns2.preview-dns.test']
              : ['a.iana-servers.net', 'b.iana-servers.net'],
            registeredAt: fresh ? now - 12 * day : 808_372_800,
            expiresAt: fresh ? now + 353 * day : now + 320 * day,
            updatedAt: fresh ? now - 12 * day : now - 45 * day,
            registrantName: '',
            registrantOrganization: fresh ? '' : 'Internet Assigned Numbers Authority',
            redacted: fresh,
            dnssec: fresh ? 'unsigned' : 'signed',
            fetchedAt: now,
            dsRecords: fresh
              ? []
              : [
                  {
                    keyTag: 370,
                    algorithm: 13,
                    digestType: 2,
                    digest: 'BE74359954660069D5C63D200C39F5603827D7DD02B56F120EE9F3A86764247C',
                  },
                ],
            nameserverAddresses: fresh
              ? [{ name: 'ns1.preview-dns.test', addresses: ['192.0.2.53', '2001:db8::53'] }]
              : [],
            handle: fresh ? `D${now}-PREVIEW` : '2336799_DOMAIN_COM-VRSN',
            unicodeName: '',
            registrarUrl: fresh ? 'https://names.preview.test' : 'http://res-dom.iana.org',
            registrarCountry: fresh ? 'IS' : 'US',
            whoisServer: fresh ? 'whois.preview.test' : 'whois.iana.org',
            abuseEmail: fresh ? 'abuse@names.preview.test' : 'abuse@iana.org',
            abusePhone: fresh ? '+354.5550100' : '+1.3108239358',
            abuseUrl: fresh ? 'https://names.preview.test/report-abuse' : '',
            registrantCountry: fresh ? 'IS' : 'US',
            registrantRegion: fresh ? '' : 'CA',
            registrantContactUrl: fresh ? 'https://names.preview.test/contact/' + registered : '',
            registrarExpiresAt: fresh ? now + 354 * day : now + 321 * day,
            transferredAt: fresh ? 0 : now - 800 * day,
            databaseUpdatedAt: now - 300,
            registrySource: `https://rdap.preview.test/domain/${registered}`,
            registrarSource: fresh ? `https://rdap.names.preview.test/domain/${registered}` : '',
          },
        };
      }
      case 'delete_ai_decision': {
        const domain = String(args.domain ?? '')
          .trim()
          .replace(/\.$/, '')
          .toLowerCase();
        const before = fixtures.aiDecisions.length;
        fixtures.aiDecisions = fixtures.aiDecisions.filter((row) => row.domain !== domain);
        return fixtures.aiDecisions.length < before;
      }
      case 'get_alerts':
        return fixtures.alerts;
      case 'dismiss_alert':
        fixtures.alerts = fixtures.alerts.filter((row) => row.id !== args.id);
        return true;
      case 'clear_alerts':
        fixtures.alerts = [];
        return true;
      case 'delete_history': {
        // Mirror the daemon: logs active since the start, buckets from the one
        // holding it, and alerts raised since it.
        const since = args.all === true ? -Infinity : Number(args.since);
        if (args.all !== true && !(since > 0)) {
          throw new Error('A start time is required to delete recent history');
        }
        const bucketSince = Math.floor(since / 1800) * 1800;
        const before = fixtures.logs.length + fixtures.activity.length + fixtures.alerts.length;
        fixtures.logs = fixtures.logs.filter((row) => row.lastSeen < since);
        fixtures.activity = fixtures.activity.filter((row) => row.bucketStart < bucketSince);
        fixtures.alerts = fixtures.alerts.filter((row) => Number(row.timestamp) < since);
        return before - fixtures.logs.length - fixtures.activity.length - fixtures.alerts.length;
      }
      case 'get_settings':
        return fixtures.settings;
      case 'update_settings': {
        // Mirror the daemon: secrets are write-only, empty keeps the stored one.
        const next = structuredClone(args.settings as SettingsDto);
        const previous = fixtures.settings;
        fixtures.settings = {
          ...next,
          aiApiKey: '',
          aiApiKeySet: next.aiApiKey !== '' || (previous.aiApiKeySet && !next.clearAiApiKey),
          clearAiApiKey: false,
          siemAuthToken: '',
          siemAuthTokenSet:
            next.siemAuthToken !== '' || (previous.siemAuthTokenSet && !next.clearSiemAuthToken),
          clearSiemAuthToken: false,
        };
        return { success: true, notApplied: [] };
      }
      case 'sync_hosts_blocklist':
        fixtures.settings.hostsBlocklistLastUpdated = new Date(clock()).toISOString();
        return true;
      case 'get_network_mapping_state':
        return { ...fixtures.network, isScanning: clock() < scanUntil };
      case 'scan_network':
        scanUntil = clock() + 1800;
        fixtures.network.devices = createFixtures(clock()).network.devices;
        return true;
      case 'stop_network_scan':
        scanUntil = 0;
        return true;
      case 'clear_network_devices':
        fixtures.network.devices = [];
        return true;
      case 'save_network_device_watch': {
        const mac = String(args.macAddress);
        fixtures.network.deviceWatches = fixtures.network.deviceWatches.filter(
          (row) => row.macAddress !== mac,
        );
        fixtures.network.deviceWatches.push({
          id: Number(args.id) || nextId++,
          ipAddress: String(args.ipAddress),
          macAddress: mac,
          intervalMinutes: Number(args.intervalMinutes),
          enabled: args.enabled !== false,
          isPresent: true,
          lastChecked: new Date(clock()).toISOString(),
        });
        fixtures.network.devices.forEach((row) => {
          if (row.macAddress === mac) row.isWatched = true;
        });
        return true;
      }
      case 'remove_network_device_watch':
        fixtures.network.deviceWatches = fixtures.network.deviceWatches.filter(
          (row) => row.id !== args.id,
        );
        fixtures.network.devices.forEach((row) => {
          if (row.macAddress === args.macAddress) row.isWatched = false;
        });
        return true;
      case 'list_capture_devices':
        return {
          available: true,
          message: 'Synthetic capture provider',
          devices: [
            {
              name: 'preview-en0',
              description: 'Preview Wi-Fi',
              addresses: ['192.0.2.10'],
              loopback: false,
            },
          ],
        };
      case 'start_capture': {
        const id = `preview-capture-${nextId++}`;
        captures.set(id, {
          started: clock(),
          device: String(args.deviceName),
          appName: String(args.appName ?? ''),
          maxSeconds: Number(args.maxSeconds ?? 0),
          maxBytes: Number(args.maxBytes ?? 0),
        });
        return id;
      }
      case 'stop_capture': {
        const capture = captures.get(String(args.captureId));
        if (!capture) throw new Error('Browser preview: unknown capture');
        capture.stopped = clock();
        return true;
      }
      case 'get_capture_status':
        return captureStatus(String(args.captureId));
      case 'start_capture_packet_stream':
        return;
      case 'open_domain_reputation': {
        const service = reputationService(String(args.service));
        if (!service) throw new Error(`unknown reputation service '${String(args.service)}'`);
        window.open(service.previewUrl(String(args.domain)), '_blank', 'noopener');
        return;
      }
      case 'open_packet_inspector':
        inspector = structuredClone(args.packet as CapturedPacketDto);
        return;
      case 'get_packet_inspector_packet':
        return inspector;
      case 'get_packet_inspector_theme':
        return null;
      default:
        throw new Error(
          `Browser preview: '${command}' is unavailable; native file and window operations require the desktop app.`,
        );
    }
  }
  return {
    call(command: string, args: Record<string, unknown> = {}): unknown {
      const result = structuredClone(dispatch(command, args));
      // A registry lookup takes a moment for real; let the loading state show.
      // Remote lookups take a moment for real; let the loading states show.
      const delay = PREVIEW_LOOKUP_DELAY_MS[command];
      if (delay) {
        return new Promise((resolve) => setTimeout(() => resolve(result), delay));
      }
      return result;
    },
    packets(captureId: string): CapturedPacketDto[] {
      if (!captures.has(captureId)) return [];
      const status = captureStatus(captureId);
      if (!status.active || !status.packets) return [];
      return Array.from({ length: 6 }, (_, i) =>
        previewPacket(captureId, Math.max(1, status.packets - 5 + i), clock()),
      );
    },
  };
}

export const previewBackend = createPreviewBackend();
