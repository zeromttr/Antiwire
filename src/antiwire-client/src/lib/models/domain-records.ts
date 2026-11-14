/**
 * Live DNS records, locally seen subdomains and Certificate Transparency
 * names for one domain, read on request by the daemon.
 */

import type { DomainLookupOutcome } from './domain-lookup';

export type DnsRecordPurpose = 'host' | 'domain' | 'mail' | 'dkim' | 'reverse';
export type DnsStatus = 'noerror' | 'nxdomain' | 'servfail' | 'refused' | 'error';

export type DnsAnswer = { name: string; recordType: string; ttl: number; data: string };

export type DnsRecordSet = {
  purpose: DnsRecordPurpose;
  name: string;
  recordType: string;
  status: DnsStatus;
  /** The upstream validated this answer with DNSSEC. */
  authenticated: boolean;
  answers: DnsAnswer[];
};

export type DnsRecords = {
  /** Transport and endpoint asked, e.g. `DoH https://1.1.1.1/dns-query`. */
  upstream: string;
  /** Domain the domain and mail questions were asked for. */
  domain: string;
  sets: DnsRecordSet[];
};

export type SeenSubdomain = {
  name: string;
  connections: number;
  blocked: number;
  /** Unix seconds; 0 when unknown. */
  firstSeen: number;
  lastSeen: number;
};

export type SeenSubdomains = {
  names: SeenSubdomain[];
  truncated: boolean;
  /** Domain the names are under. */
  domain: string;
};

export type CertificateHostname = {
  name: string;
  certificates: number;
  firstIssued: number;
  latestExpiry: number;
  issuer: string;
};

export type CertificateSearch = {
  outcome: DomainLookupOutcome;
  domain: string;
  certificates: number;
  names: CertificateHostname[];
  truncated: boolean;
  detail: string;
};

const PURPOSES: readonly DnsRecordPurpose[] = ['host', 'domain', 'mail', 'dkim', 'reverse'];
const STATUSES: readonly DnsStatus[] = ['noerror', 'nxdomain', 'servfail', 'refused', 'error'];
const OUTCOMES: readonly DomainLookupOutcome[] = [
  'found',
  'not_found',
  'rate_limited',
  'no_authority',
  'unavailable',
  'invalid_domain',
];

function record(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' ? (value as Record<string, unknown>) : {};
}

function text(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

function count(value: unknown): number {
  const n = Number(value);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : 0;
}

function list(value: unknown): Record<string, unknown>[] {
  return Array.isArray(value) ? value.map(record) : [];
}

function oneOf<T extends string>(value: unknown, allowed: readonly T[], fallback: T): T {
  return allowed.find((item) => item === value) ?? fallback;
}

export function normalizeDnsRecords(raw: unknown): DnsRecords {
  const d = record(raw);
  return {
    upstream: text(d.upstream),
    domain: text(d.domain),
    sets: list(d.sets)
      .map((set) => ({
        purpose: oneOf(set.purpose, PURPOSES, 'domain'),
        name: text(set.name),
        recordType: text(set.recordType).toUpperCase(),
        status: oneOf(set.status, STATUSES, 'error'),
        authenticated: set.authenticated === true,
        answers: list(set.answers)
          .map((answer) => ({
            name: text(answer.name),
            recordType: text(answer.recordType).toUpperCase(),
            ttl: count(answer.ttl),
            data: text(answer.data),
          }))
          .filter((answer) => answer.recordType && answer.data),
      }))
      .filter((set) => set.name && set.recordType),
  };
}

export function normalizeSeenSubdomains(raw: unknown): SeenSubdomains {
  const d = record(raw);
  return {
    names: list(d.names)
      .map((item) => ({
        name: text(item.name).toLowerCase(),
        connections: count(item.connections),
        blocked: count(item.blocked),
        firstSeen: count(item.firstSeen),
        lastSeen: count(item.lastSeen),
      }))
      .filter((item) => item.name),
    truncated: d.truncated === true,
    domain: text(d.domain),
  };
}

export function normalizeCertificateSearch(raw: unknown): CertificateSearch {
  const d = record(raw);
  return {
    outcome: oneOf(d.outcome, OUTCOMES, 'unavailable'),
    domain: text(d.domain),
    certificates: count(d.certificates),
    names: list(d.names)
      .map((item) => ({
        name: text(item.name).toLowerCase(),
        certificates: count(item.certificates),
        firstIssued: count(item.firstIssued),
        latestExpiry: count(item.latestExpiry),
        issuer: text(item.issuer),
      }))
      .filter((item) => item.name),
    truncated: d.truncated === true,
    detail: text(d.detail),
  };
}

/** One labelled group of answers for display. */
export type DnsRow = {
  /** Record type shown in the row's badge, e.g. `MX`, `SPF`, `DKIM`. */
  label: string;
  /** Name the answer belongs to when it differs from the group's subject. */
  owner: string;
  data: string;
  ttl: number;
};

function answersOf(
  sets: readonly DnsRecordSet[],
  purpose: DnsRecordPurpose,
  types: readonly string[],
  name?: string,
): DnsAnswer[] {
  return sets
    .filter(
      (set) =>
        set.purpose === purpose &&
        types.includes(set.recordType) &&
        (name === undefined || set.name === name),
    )
    .flatMap((set) => set.answers);
}

function dedupe(rows: DnsRow[]): DnsRow[] {
  const seen = new Set<string>();
  return rows.filter((row) => {
    const key = `${row.label}\u0000${row.owner}\u0000${row.data}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function row(answer: DnsAnswer, subject: string, label = answer.recordType): DnsRow {
  return {
    label,
    owner: answer.name === subject ? '' : answer.name,
    data: answer.data,
    ttl: answer.ttl,
  };
}

const TYPE_ORDER = ['CNAME', 'A', 'AAAA', 'HTTPS', 'NS', 'SOA', 'CAA', 'TXT', 'MX'];

function byType(a: DnsRow, b: DnsRow): number {
  const rank = (label: string) => {
    const index = TYPE_ORDER.indexOf(label);
    return index < 0 ? TYPE_ORDER.length : index;
  };
  return rank(a.label) - rank(b.label);
}

/**
 * Answers grouped for display. The host group follows the CNAME chain; SPF,
 * DMARC and the other mail policies are pulled out of TXT answers and named.
 */
export function dnsGroups(records: DnsRecords, host: string) {
  const { sets, domain } = records;
  const hostRows = dedupe(
    answersOf(sets, 'host', ['A', 'AAAA', 'HTTPS'], host).map((answer) => row(answer, host)),
  ).sort(byType);
  const domainTxt = answersOf(sets, 'domain', ['TXT'], domain);
  const domainRows =
    host === domain
      ? []
      : dedupe(
          answersOf(sets, 'domain', ['A', 'AAAA', 'HTTPS'], domain).map((answer) =>
            row(answer, domain),
          ),
        );
  const zoneRows = dedupe([
    ...domainRows,
    ...answersOf(sets, 'domain', ['NS', 'SOA', 'CAA'], domain).map((answer) => row(answer, domain)),
    ...domainTxt
      .filter((answer) => !/^v=spf1\b/i.test(answer.data))
      .map((answer) => row(answer, domain)),
  ]).sort(byType);

  const policy = (prefix: string, label: string): DnsRow[] =>
    answersOf(sets, 'mail', ['TXT'], `${prefix}.${domain}`).map((answer) =>
      row(answer, answer.name, label),
    );
  const mailRows = dedupe([
    ...answersOf(sets, 'mail', ['MX'], domain)
      .map((answer) => row(answer, domain))
      .sort((a, b) => mxPriority(a.data) - mxPriority(b.data)),
    ...domainTxt
      .filter((answer) => /^v=spf1\b/i.test(answer.data))
      .map((answer) => row(answer, domain, 'SPF')),
    ...policy('_dmarc', 'DMARC'),
    ...policy('_mta-sts', 'MTA-STS'),
    ...policy('_smtp._tls', 'TLS-RPT'),
    ...policy('default._bimi', 'BIMI'),
  ]);
  const dkimRows = dedupe(
    sets
      .filter((set) => set.purpose === 'dkim')
      .flatMap((set) =>
        set.answers
          .filter((answer) => answer.recordType === 'TXT')
          .map((answer) => ({
            label: 'DKIM',
            owner: set.name.split('._domainkey.')[0],
            data: answer.data,
            ttl: answer.ttl,
          })),
      ),
  );
  const reverseRows = dedupe(
    answersOf(sets, 'reverse', ['PTR']).map((answer) => ({
      label: 'PTR',
      owner: '',
      data: answer.data,
      ttl: answer.ttl,
    })),
  );
  return { host: hostRows, zone: zoneRows, mail: mailRows, dkim: dkimRows, reverse: reverseRows };
}

function mxPriority(data: string): number {
  const n = Number(data.split(' ')[0]);
  return Number.isFinite(n) ? n : Number.MAX_SAFE_INTEGER;
}

/** True when every set that answered was validated with DNSSEC. */
export function allValidated(records: DnsRecords): boolean {
  const answered = records.sets.filter((set) => set.answers.length > 0);
  return answered.length > 0 && answered.every((set) => set.authenticated);
}

/** Sets the upstream could not answer at all, as opposed to names that do not exist. */
export function failedQueries(records: DnsRecords): number {
  return records.sets.filter((set) => set.status === 'servfail' || set.status === 'error').length;
}

/** `hostname` is `domain` itself or somewhere beneath it. */
export function isUnder(hostname: string, domain: string): boolean {
  return hostname === domain || hostname.endsWith(`.${domain}`);
}

/** Case-insensitive substring filter for long name lists. */
export function filterNames<T extends { name: string }>(items: readonly T[], query: string): T[] {
  const needle = query.trim().toLowerCase();
  return needle ? items.filter((item) => item.name.includes(needle)) : [...items];
}

/** A TTL in its two largest units, e.g. `1h`, `5m`, `1d 2h`. */
export function formatTtl(seconds: number): string {
  const units: [number, string][] = [
    [86_400, 'd'],
    [3_600, 'h'],
    [60, 'm'],
    [1, 's'],
  ];
  let rest = Math.max(0, Math.floor(seconds));
  const parts: string[] = [];
  for (const [size, suffix] of units) {
    if (rest >= size && parts.length < 2) {
      parts.push(`${Math.floor(rest / size)}${suffix}`);
      rest %= size;
    } else if (parts.length) {
      break;
    }
  }
  return parts.join(' ') || '0s';
}
