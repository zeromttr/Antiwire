import { describe, expect, test } from 'bun:test';
import {
  allValidated,
  dnsGroups,
  failedQueries,
  filterNames,
  formatTtl,
  isUnder,
  normalizeCertificateSearch,
  normalizeDnsRecords,
  normalizeSeenSubdomains,
} from './domain-records';

const answer = (name: string, recordType: string, data: string, ttl = 300) => ({
  name,
  recordType,
  data,
  ttl,
});

const RAW = {
  upstream: 'DoH https://1.1.1.1/dns-query',
  domain: 'example.com',
  sets: [
    {
      purpose: 'host',
      name: 'www.example.com',
      recordType: 'A',
      status: 'noerror',
      authenticated: true,
      answers: [
        answer('www.example.com', 'CNAME', 'www.example.com.cdn.test'),
        answer('www.example.com.cdn.test', 'A', '192.0.2.1'),
      ],
    },
    {
      purpose: 'domain',
      name: 'example.com',
      recordType: 'TXT',
      status: 'noerror',
      authenticated: true,
      answers: [
        answer('example.com', 'TXT', 'v=spf1 include:_spf.example.com -all'),
        answer('example.com', 'TXT', 'google-site-verification=abc'),
      ],
    },
    {
      purpose: 'domain',
      name: 'example.com',
      recordType: 'NS',
      status: 'noerror',
      authenticated: true,
      answers: [answer('example.com', 'NS', 'a.iana-servers.net')],
    },
    {
      purpose: 'mail',
      name: 'example.com',
      recordType: 'MX',
      status: 'noerror',
      authenticated: true,
      answers: [
        answer('example.com', 'MX', '20 backup.example.com'),
        answer('example.com', 'MX', '10 mail.example.com'),
      ],
    },
    {
      purpose: 'mail',
      name: '_dmarc.example.com',
      recordType: 'TXT',
      status: 'noerror',
      authenticated: true,
      answers: [answer('_dmarc.example.com', 'TXT', 'v=DMARC1; p=reject')],
    },
    {
      purpose: 'dkim',
      name: 'google._domainkey.example.com',
      recordType: 'TXT',
      status: 'noerror',
      authenticated: true,
      answers: [answer('google._domainkey.example.com', 'TXT', 'v=DKIM1; k=rsa; p=MIIB')],
    },
    {
      purpose: 'dkim',
      name: 'k1._domainkey.example.com',
      recordType: 'TXT',
      status: 'nxdomain',
      authenticated: true,
      answers: [],
    },
    {
      purpose: 'reverse',
      name: '1.2.0.192.in-addr.arpa',
      recordType: 'PTR',
      status: 'servfail',
      authenticated: false,
      answers: [],
    },
    { purpose: 'bogus', name: '', recordType: 'A', status: 'x', answers: 'nope' },
  ],
};

describe('normalizeDnsRecords', () => {
  test('keeps readable sets and drops malformed ones', () => {
    const records = normalizeDnsRecords(RAW);
    expect(records.upstream).toBe('DoH https://1.1.1.1/dns-query');
    expect(records.sets).toHaveLength(8);
    expect(records.sets[0].answers[0]).toEqual(
      answer('www.example.com', 'CNAME', 'www.example.com.cdn.test'),
    );
    expect(normalizeDnsRecords(null)).toEqual({ upstream: '', domain: '', sets: [] });
  });
});

describe('dnsGroups', () => {
  const groups = dnsGroups(normalizeDnsRecords(RAW), 'www.example.com');

  test('follows the CNAME chain for the host', () => {
    expect(groups.host.map((row) => [row.label, row.owner, row.data])).toEqual([
      ['CNAME', '', 'www.example.com.cdn.test'],
      ['A', 'www.example.com.cdn.test', '192.0.2.1'],
    ]);
  });

  test('pulls SPF out of the domain TXT records into mail', () => {
    expect(groups.zone.map((row) => row.label)).toEqual(['NS', 'TXT']);
    expect(groups.mail.map((row) => [row.label, row.data])).toEqual([
      ['MX', '10 mail.example.com'],
      ['MX', '20 backup.example.com'],
      ['SPF', 'v=spf1 include:_spf.example.com -all'],
      ['DMARC', 'v=DMARC1; p=reject'],
    ]);
  });

  test('names the DKIM selectors that answered', () => {
    expect(groups.dkim).toEqual([
      { label: 'DKIM', owner: 'google', data: 'v=DKIM1; k=rsa; p=MIIB', ttl: 300 },
    ]);
    expect(groups.reverse).toEqual([]);
  });
});

describe('record summaries', () => {
  test('reports validation and failed questions', () => {
    const records = normalizeDnsRecords(RAW);
    expect(allValidated(records)).toBe(true);
    expect(failedQueries(records)).toBe(1);
    expect(allValidated({ upstream: '', domain: '', sets: [] })).toBe(false);
  });
});

describe('formatTtl', () => {
  test('uses the two largest units', () => {
    expect(formatTtl(3600)).toBe('1h');
    expect(formatTtl(300)).toBe('5m');
    expect(formatTtl(93_600)).toBe('1d 2h');
    expect(formatTtl(3_661)).toBe('1h 1m');
    expect(formatTtl(86_401)).toBe('1d');
    expect(formatTtl(0)).toBe('0s');
  });
});

describe('subdomain lists', () => {
  test('normalizes local and certificate names', () => {
    const seen = normalizeSeenSubdomains({
      names: [{ name: 'API.example.com', connections: 3, blocked: 1, lastSeen: 1_800_000_000 }],
      truncated: true,
    });
    expect(seen.names[0]).toEqual({
      name: 'api.example.com',
      connections: 3,
      blocked: 1,
      firstSeen: 0,
      lastSeen: 1_800_000_000,
    });
    expect(seen.truncated).toBe(true);

    const ct = normalizeCertificateSearch({
      outcome: 'found',
      domain: 'example.com',
      certificates: 12,
      names: [{ name: '*.example.com', certificates: 2, issuer: 'R11' }, { name: '' }],
    });
    expect(ct.names).toHaveLength(1);
    expect(ct.names[0].issuer).toBe('R11');
    expect(normalizeCertificateSearch({ outcome: 'weird' }).outcome).toBe('unavailable');
  });

  test('matches names under a domain and filters lists', () => {
    expect(isUnder('api.example.com', 'example.com')).toBe(true);
    expect(isUnder('example.com', 'example.com')).toBe(true);
    expect(isUnder('notexample.com', 'example.com')).toBe(false);
    const names = [{ name: 'api.example.com' }, { name: 'www.example.com' }];
    expect(filterNames(names, ' API ')).toEqual([{ name: 'api.example.com' }]);
    expect(filterNames(names, '')).toHaveLength(2);
  });
});
