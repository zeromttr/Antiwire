/**
 * Official registration records, read on request by the daemon from the
 * domain's registry (RDAP, or WHOIS where the registry has no RDAP).
 */

export type DomainLookupOutcome =
  | 'found'
  | 'not_found'
  | 'rate_limited'
  | 'no_authority'
  | 'unavailable'
  /** The daemon found no hostname in the name it was given. */
  | 'invalid_domain';

export type DomainRegistration = {
  /** Registered name the record describes, e.g. `example.com` for `www.example.com`. */
  domain: string;
  source: 'rdap' | 'whois';
  registrar: string;
  registrarId: string;
  statuses: string[];
  nameservers: string[];
  /** Unix seconds; 0 when the registry does not publish it. */
  registeredAt: number;
  expiresAt: number;
  updatedAt: number;
  registrantName: string;
  registrantOrganization: string;
  redacted: boolean;
  /** `null` when the registry does not say. */
  dnssec: boolean | null;
  fetchedAt: number;
  dsRecords: DelegationSigner[];
  /** Name servers the registry publishes glue addresses for. */
  nameserverAddresses: { name: string; addresses: string[] }[];
  /** Registry object id, e.g. `2138514_DOMAIN_COM-VRSN`. */
  handle: string;
  /** Unicode form of an internationalized name. */
  unicodeName: string;
  registrarUrl: string;
  registrarCountry: string;
  whoisServer: string;
  /** The registrar's published abuse contact. */
  abuseEmail: string;
  abusePhone: string;
  abuseUrl: string;
  /** Country and region only: the daemon never reads a registrant's street, email or phone. */
  registrantCountry: string;
  registrantRegion: string;
  registrantContactUrl: string;
  /** Expiration in the registrar's own record; can differ from `expiresAt`. */
  registrarExpiresAt: number;
  transferredAt: number;
  /** When the source last refreshed the record it served. */
  databaseUpdatedAt: number;
  /** Registry record read: its RDAP URL, or its WHOIS server. */
  registrySource: string;
  /** Registrar record merged in, when one was. */
  registrarSource: string;
};

export type DelegationSigner = {
  keyTag: number;
  algorithm: number;
  digestType: number;
  digest: string;
};

export type DomainLookupResult = {
  outcome: DomainLookupOutcome;
  registration: DomainRegistration | null;
  /** The daemon's English error text, for anything but `found`. */
  detail: string;
};

/** Registrations younger than this are flagged as new: a common trait of throwaway domains. */
export const NEWLY_REGISTERED_DAYS = 30;

const OUTCOMES: readonly DomainLookupOutcome[] = [
  'found',
  'not_found',
  'rate_limited',
  'no_authority',
  'unavailable',
  'invalid_domain',
];

/**
 * The daemon appends this to a domain it inferred from shared DNS traffic
 * rather than saw requested (`antiwire_store::INFERRED_SUFFIX`).
 */
export const INFERRED_SUFFIX = ' (inferred)';

function text(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

function seconds(value: unknown): number {
  const n = Number(value);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : 0;
}

function strings(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.map(text).filter(Boolean);
}

function objects(value: unknown): Record<string, unknown>[] {
  if (!Array.isArray(value)) return [];
  return value.filter(
    (item): item is Record<string, unknown> => !!item && typeof item === 'object',
  );
}

function count(value: unknown): number {
  const n = Number(value);
  return Number.isInteger(n) && n >= 0 ? n : 0;
}

function normalizeRegistration(raw: unknown): DomainRegistration | null {
  if (!raw || typeof raw !== 'object') return null;
  const d = raw as Record<string, unknown>;
  const domain = text(d.domain);
  if (!domain) return null;
  const dnssec = text(d.dnssec);
  return {
    domain,
    source: text(d.source) === 'whois' ? 'whois' : 'rdap',
    registrar: text(d.registrar),
    registrarId: text(d.registrarId),
    statuses: strings(d.statuses),
    nameservers: strings(d.nameservers),
    registeredAt: seconds(d.registeredAt),
    expiresAt: seconds(d.expiresAt),
    updatedAt: seconds(d.updatedAt),
    registrantName: text(d.registrantName),
    registrantOrganization: text(d.registrantOrganization),
    redacted: d.redacted === true,
    dnssec: dnssec === 'signed' ? true : dnssec === 'unsigned' ? false : null,
    fetchedAt: seconds(d.fetchedAt),
    dsRecords: objects(d.dsRecords)
      .map((ds) => ({
        keyTag: count(ds.keyTag),
        algorithm: count(ds.algorithm),
        digestType: count(ds.digestType),
        digest: text(ds.digest).toUpperCase(),
      }))
      .filter((ds) => ds.digest),
    nameserverAddresses: objects(d.nameserverAddresses)
      .map((glue) => ({ name: text(glue.name), addresses: strings(glue.addresses) }))
      .filter((glue) => glue.name && glue.addresses.length),
    handle: text(d.handle),
    unicodeName: text(d.unicodeName),
    registrarUrl: text(d.registrarUrl),
    registrarCountry: text(d.registrarCountry),
    whoisServer: text(d.whoisServer),
    abuseEmail: text(d.abuseEmail),
    abusePhone: text(d.abusePhone),
    abuseUrl: text(d.abuseUrl),
    registrantCountry: text(d.registrantCountry),
    registrantRegion: text(d.registrantRegion),
    registrantContactUrl: text(d.registrantContactUrl),
    registrarExpiresAt: seconds(d.registrarExpiresAt),
    transferredAt: seconds(d.transferredAt),
    databaseUpdatedAt: seconds(d.databaseUpdatedAt),
    registrySource: text(d.registrySource),
    registrarSource: text(d.registrarSource),
  };
}

/** Reads the `lookup_domain` response; anything unreadable counts as unavailable. */
export function normalizeDomainLookup(raw: unknown): DomainLookupResult {
  const d = raw && typeof raw === 'object' ? (raw as Record<string, unknown>) : {};
  const outcome = OUTCOMES.find((value) => value === d.outcome) ?? 'unavailable';
  const registration = normalizeRegistration(d.registration);
  if (outcome === 'found' && !registration) {
    return { outcome: 'unavailable', registration: null, detail: text(d.detail) };
  }
  return {
    outcome,
    registration: outcome === 'found' ? registration : null,
    detail: text(d.detail),
  };
}

/** A record's domain was inferred from shared DNS traffic, not seen requested. */
export function isInferredDomain(domain: string): boolean {
  return domain.trim().endsWith(INFERRED_SUFFIX.trim());
}

/** The label rule `antiwire-lookup` enforces: LDH, 1–63 characters, no edge hyphen. */
const LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const LOCAL_SUFFIXES = ['local', 'arpa', 'localhost', 'internal', 'home', 'lan'];

/**
 * The hostname a record's registration can be looked up for, or `''`.
 *
 * Registries hold names, not addresses, and a single label is not a
 * registration. Leading labels a hostname cannot carry (`_dmarc`, `*`) are
 * dropped, since the registration belongs to the name beneath them.
 */
export function lookupHostname(domain: string): string {
  let host = domain.trim();
  if (host.endsWith(INFERRED_SUFFIX.trim())) {
    host = host.slice(0, -INFERRED_SUFFIX.trim().length);
  }
  host = host.trim().replace(/\.$/, '').toLowerCase();
  if (!host || host.length > 253) return '';
  const labels = host.split('.');
  const tld = labels[labels.length - 1];
  if (LOCAL_SUFFIXES.includes(tld)) return '';
  // IPv4: four numeric labels. IPv6 and anything with a port or path fails LABEL.
  if (labels.length === 4 && labels.every((label) => /^\d+$/.test(label))) return '';
  let start = 0;
  while (start < labels.length && !LABEL.test(labels[start])) start++;
  const kept = labels.slice(start);
  if (kept.length < 2 || !kept.every((label) => LABEL.test(label))) return '';
  return kept.join('.');
}

/** True when the registration is younger than {@link NEWLY_REGISTERED_DAYS}. */
export function isNewlyRegistered(registration: DomainRegistration, now = Date.now()): boolean {
  if (!registration.registeredAt) return false;
  const ageDays = (now - registration.registeredAt * 1000) / 86_400_000;
  return ageDays >= 0 && ageDays < NEWLY_REGISTERED_DAYS;
}

/** True when the registration has already expired. */
export function isExpired(registration: DomainRegistration, now = Date.now()): boolean {
  return registration.expiresAt > 0 && registration.expiresAt * 1000 < now;
}

/**
 * EPP status codes read as a sentence: RDAP publishes `client transfer
 * prohibited`, WHOIS `clientTransferProhibited`.
 */
export function formatRegistrationStatus(status: string): string {
  const words = status
    .trim()
    .replace(/([a-z])([A-Z])/g, '$1 $2')
    .replace(/[_-]+/g, ' ')
    .replace(/\s+/g, ' ')
    .toLowerCase();
  return words ? words[0].toUpperCase() + words.slice(1) : '';
}

/**
 * A registry-supplied link safe to open: only `http:`/`https:`, so a hostile
 * record cannot smuggle `javascript:` or `file:` into an anchor.
 */
export function safeWebUrl(value: string): string {
  try {
    const url = new URL(value.trim());
    return url.protocol === 'https:' || url.protocol === 'http:' ? url.href : '';
  } catch {
    return '';
  }
}

/** A `mailto:` link for a plain address, or `''`. */
export function safeMailto(value: string): string {
  const address = value.trim();
  return /^[^\s@<>()"',;:]+@[^\s@<>()"',;:]+\.[^\s@<>()"',;:]+$/.test(address)
    ? `mailto:${address}`
    : '';
}

/** DNSSEC algorithm mnemonics from the IANA registry (RFC 8624). */
const DNSSEC_ALGORITHMS: Record<number, string> = {
  5: 'RSASHA1',
  7: 'RSASHA1-NSEC3-SHA1',
  8: 'RSASHA256',
  10: 'RSASHA512',
  13: 'ECDSAP256SHA256',
  14: 'ECDSAP384SHA384',
  15: 'ED25519',
  16: 'ED448',
};

const DS_DIGESTS: Record<number, string> = { 1: 'SHA-1', 2: 'SHA-256', 4: 'SHA-384' };

export function dnssecAlgorithmName(algorithm: number): string {
  return DNSSEC_ALGORITHMS[algorithm] ?? `#${algorithm}`;
}

export function dsDigestName(digestType: number): string {
  return DS_DIGESTS[digestType] ?? `#${digestType}`;
}

/** Glue addresses for one name server, matched case-insensitively. */
export function glueFor(registration: DomainRegistration, server: string): string[] {
  const name = server.toLowerCase();
  return (
    registration.nameserverAddresses.find((glue) => glue.name.toLowerCase() === name)?.addresses ??
    []
  );
}

/** True when two instants fall on different calendar days (UTC). */
export function differentDay(a: number, b: number): boolean {
  if (!a || !b) return false;
  return Math.floor(a / 86_400) !== Math.floor(b / 86_400);
}

/** Hold statuses stop a name from resolving; they are worth calling out. */
export function isHoldStatus(status: string): boolean {
  return /hold/i.test(status);
}
