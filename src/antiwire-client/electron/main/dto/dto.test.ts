import { describe, expect, it } from 'bun:test';
import type { NotificationEvent, TrafficEvent } from '../daemon/messages';
import { eventId, eventToDto, parseAlertId } from './alerts';
import {
  logRequest,
  logsToCsv,
  logsToJson,
  logToDto,
  neutralizeFormula,
  outcomeName,
  type ConnectionLogDto,
} from './records';
import { SETTINGS_FIELDS, settingsSchema, settingsToDto, settingsToRequest } from './settings';
import { updateStateName, updateStatusToDto } from './updates';

describe('alert ids', () => {
  it('numeric ids address daemon alerts', () => {
    expect(parseAlertId('42')).toEqual({ kind: 'database', id: 42 });
    expect(parseAlertId('0')).toEqual({ kind: 'database', id: 0 });
  });

  it('synthetic marker ids are dismissed locally', () => {
    // The lag marker is emitted with `id: 0`, rendered as `<timestamp>-<TYPE>`.
    const id = eventId({ id: 0, timestamp: 1_700_000_000, type: 'NOTIFICATIONS_LAGGED' });
    expect(id).toBe('1700000000-NOTIFICATIONS_LAGGED');
    expect(parseAlertId(id)).toEqual({ kind: 'local' });
  });

  it('malformed ids are rejected', () => {
    for (const bad of ['nope', '-LAGGED', '1700000000-', '']) expect(parseAlertId(bad)).toBeNull();
  });

  it('maps severities onto the UI tones', () => {
    const base: NotificationEvent = {
      id: 7,
      type: 'AI_ALERT',
      title: 't',
      message: 'm',
      timestamp: 5,
      severity: 'CRITICAL',
    };
    expect(eventToDto(base)).toEqual({
      id: '7',
      title: 't',
      body: 'm',
      severity: 'bad',
      timestamp: '5',
      tag: 'AI_ALERT',
    });
    expect(eventToDto({ ...base, severity: 'WARNING' }).severity).toBe('warn');
    expect(eventToDto({ ...base, severity: 'SUCCESS' }).severity).toBe('ok');
    expect(eventToDto({ ...base, severity: 'INFO' }).severity).toBe('info');
  });
});

const event: TrafficEvent = {
  timestamp: 3,
  appName: 'app',
  appPath: 'C:\\app.exe',
  protocol: 'TCP',
  srcIp: '10.0.0.1',
  srcPort: 5000,
  dstIp: '1.1.1.1',
  dstPort: 443,
  dstDomain: 'example.com',
  bytesSent: 1,
  bytesReceived: 2,
  action: 'ALLOWED',
  lastSeen: 4,
  countryCode: 'US',
  isp: 'isp',
  blocklistNames: [],
  id: 9,
  closedAt: 0,
  isActive: true,
};

describe('connection logs', () => {
  it('carries the source port', () => {
    expect(logToDto(event).sourcePort).toBe(5000);
  });

  it('lets close evidence win over liveness', () => {
    expect(logToDto(event).isActive).toBe(true);
    expect(logToDto({ ...event, closedAt: 10 }).isActive).toBe(false);
  });

  it('fills unset filters like the Rust request', () => {
    const request = logRequest({ limit: 10 });
    expect(request.orderBy).toBe('last_seen');
    expect(request.sortDescending).toBe(true);
    expect(request.appId).toBe(0);
  });

  it('neutralizes formulas', () => {
    expect(neutralizeFormula('plain')).toBe('plain');
    expect(neutralizeFormula('=1+1')).toBe("'=1+1");
    expect(neutralizeFormula('@SUM(A1)')).toBe("'@SUM(A1)");
  });

  it('quotes awkward CSV values', () => {
    const log: ConnectionLogDto = {
      ...logToDto(event),
      applicationName: 'evil",1,"x',
      domain: '=HYPERLINK("http://e")',
      action: 'allow',
    };
    const lines = logsToCsv([log]).split('\n');
    expect(lines[0]).toBe(
      'application,domain,source_ip,destination_ip,port,protocol,action,bytes_sent,bytes_received,timestamp,country',
    );
    expect(lines[1]).toBe(
      '"evil"",1,""x","\'=HYPERLINK(""http://e"")",10.0.0.1,1.1.1.1,443,TCP,allow,1,2,3,US',
    );
  });

  it('exports JSON with the Rust field order and indentation', () => {
    const json = logsToJson([logToDto(event)]);
    expect(Object.keys(JSON.parse(json)[0])).toEqual([
      'id',
      'closedAt',
      'isActive',
      'applicationName',
      'applicationPath',
      'domain',
      'sourceIp',
      'destinationIp',
      'port',
      'protocol',
      'action',
      'bytesSent',
      'bytesReceived',
      'timestamp',
      'lastSeen',
      'countryCode',
      'blocklistNames',
    ]);
    expect(json.startsWith('[\n  {\n    "id": 9,')).toBe(true);
  });
});

describe('enum names', () => {
  it('names lookup outcomes, defaulting unknown values to found', () => {
    expect(outcomeName('LOOKUP_OUTCOME_INVALID_DOMAIN')).toBe('invalid_domain');
    expect(outcomeName(99)).toBe('found');
  });

  it('names update states, defaulting to unknown', () => {
    expect(updateStateName('UPDATE_STATE_UP_TO_DATE')).toBe('up_to_date');
    expect(updateStateName('UPDATE_STATE_UNKNOWN')).toBe('unknown');
    expect(updateStateName(42)).toBe('unknown');
  });
});

describe('update status', () => {
  const base = {
    state: 'UPDATE_STATE_UP_TO_DATE',
    currentVersion: '0.3.0',
    availableVersion: '',
    notes: '',
    detail: '',
    channel: 'beta',
    lastCheckedAt: 1_700_000_000,
    checkError: '',
  };

  it('carries the channel and the last check', () => {
    expect(updateStatusToDto(base, '0.3.0')).toMatchObject({
      state: 'up_to_date',
      channel: 'beta',
      lastCheckedAt: 1_700_000_000,
      checkError: '',
      clientVersion: '0.3.0',
    });
  });

  it('reads a daemon from before channels as stable and never checked', () => {
    const old = { ...base, channel: '', lastCheckedAt: undefined, checkError: undefined };
    expect(updateStatusToDto(old as unknown as typeof base, '0.3.0')).toMatchObject({
      channel: 'stable',
      lastCheckedAt: 0,
      checkError: '',
    });
  });
});

describe('settings', () => {
  it('keeps secrets write-only and the GeoIP age read-only', () => {
    // A decoded response has every field, defaulted.
    const defaults = Object.fromEntries(
      Object.entries(SETTINGS_FIELDS).map(([name, kind]) => [
        name,
        kind === 'bool' ? false : kind === 'u32' ? 0 : '',
      ]),
    );
    const dto = settingsToDto({
      ...defaults,
      notifyEveryConnection: true,
      aiApiKeySet: true,
      windivertSupported: true,
      geoipDatabaseLastUpdated: '2026-01-01',
    });
    expect(dto.clearAiApiKey).toBe(false);
    expect(dto.aiApiKeySet).toBe(true);
    expect(dto.windivertSupported).toBe(true);

    const parsed = settingsSchema.parse({ ...dto, clearSiemAuthToken: true, extra: 'dropped' });
    const request = settingsToRequest(parsed);
    expect(request.clearSiemAuthToken).toBe(true);
    expect('geoipDatabaseLastUpdated' in request).toBe(false);
    expect('aiApiKeySet' in request).toBe(false);
    expect('windivertSupported' in request).toBe(false);
    expect('extra' in request).toBe(false);
  });
});
