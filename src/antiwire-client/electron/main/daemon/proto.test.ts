import { describe, expect, it } from 'bun:test';
import path from 'node:path';
import { SETTINGS_FIELDS } from '../dto/settings';
import { statsToDto } from '../dto/stats';
import { domainLookupToDto } from '../dto/records';
import type { UnaryRpcs } from './messages';
import { loadService, type AnyMethod } from './proto';

const PROTO = path.resolve(
  import.meta.dir,
  '../../../../antiwire-rs/crates/antiwire-proto/proto/antiwire.proto',
);
const service = await loadService(PROTO);

/** Encodes `response` as the daemon would and decodes it as the client does. */
function roundTrip<M extends keyof UnaryRpcs>(method: M, response: object): UnaryRpcs[M][1] {
  const def = service[method] as AnyMethod;
  return def.responseDeserialize(def.responseSerialize(response)) as UnaryRpcs[M][1];
}

describe('proto decoding', () => {
  it('has every method the client calls', () => {
    const methods: (keyof UnaryRpcs)[] = ['GetStats', 'LookupDomain', 'UpdateSettings'];
    for (const method of methods) expect(service[method]).toBeDefined();
    for (const stream of ['StreamNotifications', 'StreamCapturedPackets', 'DownloadCapture']) {
      expect(service[stream]?.responseStream).toBe(true);
    }
  });

  it('leaves unset optionals out, as a legacy daemon sends them', () => {
    const decoded = roundTrip('GetStats', { totalBytesSent: 1, activeConnectionsCount: 9 });
    expect(decoded.activeConnectionsAvailable).toBeUndefined();
    const dto = statsToDto(decoded);
    expect('activeConnectionsAvailable' in dto).toBe(false);
    expect('activeApplications' in dto).toBe(false);
    expect('databaseSizeBytes' in dto).toBe(false);
    expect(dto.activeConnections).toBe(9);
    expect(dto.daemonVersion).toBe('');
  });

  it('keeps an optional that is explicitly false', () => {
    const dto = statsToDto(
      roundTrip('GetStats', { activeConnectionsAvailable: false, activeApplicationsCount: 0 }),
    );
    expect(dto.activeConnectionsAvailable).toBe(false);
    expect(dto.activeApplications).toBe(0);
    expect(statsToDto(roundTrip('GetStats', { databaseSizeBytes: 12_345 })).databaseSizeBytes).toBe(
      12_345,
    );
  });

  it('decodes enums by name and an absent message as null', () => {
    const dto = domainLookupToDto(
      roundTrip('LookupDomain', { outcome: 'LOOKUP_OUTCOME_RATE_LIMITED', detail: 'slow down' }),
    );
    expect(dto).toEqual({ outcome: 'rate_limited', registration: null, detail: 'slow down' });
    expect(domainLookupToDto(roundTrip('LookupDomain', {})).outcome).toBe('found');
  });

  it('knows every field the settings messages share', () => {
    const settings = Object.fromEntries(
      Object.entries(SETTINGS_FIELDS).map(([name, kind]) => [
        name,
        kind === 'bool' ? true : kind === 'u32' ? 7 : `v-${name}`,
      ]),
    );
    const update = service.UpdateSettings as AnyMethod;
    const decodedRequest = update.requestDeserialize(update.requestSerialize(settings)) as Record<
      string,
      unknown
    >;
    const decodedResponse = roundTrip('GetSettings', settings);
    for (const name of Object.keys(SETTINGS_FIELDS)) {
      expect([name, decodedRequest[name]]).toEqual([name, settings[name]]);
      expect([name, decodedResponse[name]]).toEqual([name, settings[name]]);
    }
  });
});
