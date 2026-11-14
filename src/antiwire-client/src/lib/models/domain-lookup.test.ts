import { describe, expect, test } from 'bun:test';
import {
  differentDay,
  dnssecAlgorithmName,
  dsDigestName,
  formatRegistrationStatus,
  glueFor,
  safeMailto,
  safeWebUrl,
  isExpired,
  isHoldStatus,
  isInferredDomain,
  isNewlyRegistered,
  lookupHostname,
  normalizeDomainLookup,
  type DomainRegistration,
} from './domain-lookup';

const NOW = Date.UTC(2026, 8, 28);
const DAY = 86_400;

function registration(overrides: Partial<DomainRegistration> = {}): DomainRegistration {
  return {
    domain: 'example.com',
    source: 'rdap',
    registrar: 'Example Registrar',
    registrarId: '376',
    statuses: [],
    nameservers: [],
    registeredAt: 0,
    expiresAt: 0,
    updatedAt: 0,
    registrantName: '',
    registrantOrganization: '',
    redacted: false,
    dnssec: null,
    fetchedAt: 0,
    dsRecords: [],
    nameserverAddresses: [],
    handle: '',
    unicodeName: '',
    registrarUrl: '',
    registrarCountry: '',
    whoisServer: '',
    abuseEmail: '',
    abusePhone: '',
    abuseUrl: '',
    registrantCountry: '',
    registrantRegion: '',
    registrantContactUrl: '',
    registrarExpiresAt: 0,
    transferredAt: 0,
    databaseUpdatedAt: 0,
    registrySource: '',
    registrarSource: '',
    ...overrides,
  };
}

describe('normalizeDomainLookup', () => {
  test('reads a found record, trimming and dropping empty values', () => {
    const result = normalizeDomainLookup({
      outcome: 'found',
      detail: '',
      registration: {
        domain: ' example.com ',
        source: 'whois',
        registrar: 'Example Registrar',
        registrarId: '',
        statuses: ['client transfer prohibited', ''],
        nameservers: ['a.iana-servers.net'],
        registeredAt: 808372800,
        expiresAt: 0,
        updatedAt: -5,
        registrantName: '',
        registrantOrganization: 'Example Org',
        redacted: true,
        dnssec: 'signed',
        fetchedAt: 1790600000,
      },
    });
    expect(result.outcome).toBe('found');
    expect(result.registration).toMatchObject({
      domain: 'example.com',
      source: 'whois',
      statuses: ['client transfer prohibited'],
      registeredAt: 808372800,
      updatedAt: 0,
      redacted: true,
      dnssec: true,
    });
  });

  test('keeps the outcome and detail for a registry refusal', () => {
    const result = normalizeDomainLookup({
      outcome: 'rate_limited',
      registration: null,
      detail: 'registry rate limited the lookup',
    });
    expect(result).toEqual({
      outcome: 'rate_limited',
      registration: null,
      detail: 'registry rate limited the lookup',
    });
  });

  test('treats an unknown outcome or a found response without a record as unavailable', () => {
    expect(normalizeDomainLookup({ outcome: 'weird' }).outcome).toBe('unavailable');
    expect(normalizeDomainLookup({ outcome: 'found', registration: null }).outcome).toBe(
      'unavailable',
    );
    expect(normalizeDomainLookup(null).outcome).toBe('unavailable');
  });

  test('reads unsigned and unstated DNSSEC apart', () => {
    const read = (dnssec: string) =>
      normalizeDomainLookup({ outcome: 'found', registration: { domain: 'a.com', dnssec } })
        .registration?.dnssec;
    expect(read('unsigned')).toBe(false);
    expect(read('')).toBeNull();
  });
});

describe('registration extras', () => {
  test('reads DS records and glue, dropping incomplete entries', () => {
    const result = normalizeDomainLookup({
      outcome: 'found',
      registration: {
        domain: 'example.com',
        handle: '2336799_DOMAIN_COM-VRSN',
        abuseEmail: 'abuse@registrar.example',
        registrarExpiresAt: 1_800_000_000,
        dsRecords: [
          { keyTag: 370, algorithm: 13, digestType: 2, digest: 'be74' },
          { keyTag: 1, algorithm: 8, digestType: 2 },
          'junk',
        ],
        nameserverAddresses: [
          { name: 'ns1.example.com', addresses: ['192.0.2.53'] },
          { name: 'ns2.example.com', addresses: [] },
        ],
      },
    });
    const registration = result.registration!;
    expect(registration.handle).toBe('2336799_DOMAIN_COM-VRSN');
    expect(registration.abuseEmail).toBe('abuse@registrar.example');
    expect(registration.registrarExpiresAt).toBe(1_800_000_000);
    expect(registration.dsRecords).toEqual([
      { keyTag: 370, algorithm: 13, digestType: 2, digest: 'BE74' },
    ]);
    expect(glueFor(registration, 'NS1.example.com')).toEqual(['192.0.2.53']);
    expect(glueFor(registration, 'ns2.example.com')).toEqual([]);
  });

  test('names DNSSEC algorithms and digests, falling back to the number', () => {
    expect(dnssecAlgorithmName(13)).toBe('ECDSAP256SHA256');
    expect(dnssecAlgorithmName(99)).toBe('#99');
    expect(dsDigestName(2)).toBe('SHA-256');
    expect(dsDigestName(9)).toBe('#9');
  });

  test('only opens web and mail links', () => {
    expect(safeWebUrl('https://registrar.example/abuse')).toBe('https://registrar.example/abuse');
    expect(safeWebUrl('http://www.markmonitor.com')).toBe('http://www.markmonitor.com/');
    expect(safeWebUrl('javascript:alert(1)')).toBe('');
    expect(safeWebUrl('file:///etc/passwd')).toBe('');
    expect(safeWebUrl('not a url')).toBe('');
    expect(safeMailto('abuse@registrar.example')).toBe('mailto:abuse@registrar.example');
    expect(safeMailto('abuse@registrar.example?cc=x@y.z')).toBe('');
    expect(safeMailto('REDACTED')).toBe('');
  });

  test('compares calendar days', () => {
    expect(differentDay(1_800_000_000, 1_800_000_100)).toBe(false);
    expect(differentDay(1_800_000_000, 1_800_000_000 + 86_400)).toBe(true);
    expect(differentDay(0, 1_800_000_000)).toBe(false);
  });
});

describe('lookupHostname', () => {
  test('normalizes a hostname', () => {
    expect(lookupHostname(' WWW.Example.COM. ')).toBe('www.example.com');
  });

  test('drops the inferred marker the daemon appends', () => {
    expect(lookupHostname('cdn.example.com (inferred)')).toBe('cdn.example.com');
    expect(isInferredDomain('cdn.example.com (inferred)')).toBe(true);
    expect(isInferredDomain('cdn.example.com')).toBe(false);
  });

  test('drops leading labels a hostname cannot carry', () => {
    expect(lookupHostname('_dmarc.example.com')).toBe('example.com');
    expect(lookupHostname('*.cdn.example.com')).toBe('cdn.example.com');
  });

  test('refuses names the registry client would reject', () => {
    expect(lookupHostname('exa mple.com')).toBe('');
    expect(lookupHostname('example.com/path')).toBe('');
    expect(lookupHostname('example.com:443')).toBe('');
    expect(lookupHostname('-bad.example')).toBe('');
    expect(lookupHostname('example.-bad')).toBe('');
    expect(lookupHostname('router.lan')).toBe('');
  });

  test('refuses addresses, single labels and local names', () => {
    expect(lookupHostname('')).toBe('');
    expect(lookupHostname('198.51.100.7')).toBe('');
    expect(lookupHostname('2001:db8::1')).toBe('');
    expect(lookupHostname('localhost')).toBe('');
    expect(lookupHostname('printer.local')).toBe('');
    expect(lookupHostname('7.100.51.198.in-addr.arpa')).toBe('');
  });
});

describe('registration age', () => {
  test('flags a registration younger than thirty days', () => {
    const nowSeconds = NOW / 1000;
    expect(isNewlyRegistered(registration({ registeredAt: nowSeconds - 3 * DAY }), NOW)).toBe(true);
    expect(isNewlyRegistered(registration({ registeredAt: nowSeconds - 45 * DAY }), NOW)).toBe(
      false,
    );
    expect(isNewlyRegistered(registration(), NOW)).toBe(false);
  });

  test('flags an expiry in the past only', () => {
    const nowSeconds = NOW / 1000;
    expect(isExpired(registration({ expiresAt: nowSeconds - DAY }), NOW)).toBe(true);
    expect(isExpired(registration({ expiresAt: nowSeconds + DAY }), NOW)).toBe(false);
    expect(isExpired(registration(), NOW)).toBe(false);
  });
});

describe('registration statuses', () => {
  test('reads RDAP and WHOIS spellings the same way', () => {
    expect(formatRegistrationStatus('client transfer prohibited')).toBe(
      'Client transfer prohibited',
    );
    expect(formatRegistrationStatus('clientTransferProhibited')).toBe('Client transfer prohibited');
    expect(formatRegistrationStatus('')).toBe('');
  });

  test('recognizes hold statuses', () => {
    expect(isHoldStatus('serverHold')).toBe(true);
    expect(isHoldStatus('client hold')).toBe(true);
    expect(isHoldStatus('active')).toBe(false);
  });
});
