import { api } from '#lib/api/daemon.ts';
import type { DomainLookupResult } from '#lib/models/domain-lookup.ts';
import {
  isUnder,
  type CertificateSearch,
  type DnsRecords,
  type SeenSubdomains,
} from '#lib/models/domain-records.ts';
import { daemonErrorMessage, debugError, formatErrorMessage } from '#lib/utils/index.ts';
import { Reactive } from '#lib/state/reactive.ts';

export type LookupEntry<T> =
  | { state: 'loading' }
  | { state: 'done'; result: T; at: number }
  /** The daemon call itself failed (disconnected, timed out). */
  | { state: 'error'; message: string };

/**
 * Answers for this session, keyed by the name they describe. A lookup is only
 * ever started by the user; nothing here asks a remote server on its own.
 *
 * Every write stores a new entry object and notifies, so a selector returning
 * `cache.get(key)` sees a new reference when that key's answer changes.
 */
abstract class BaseLookupCache<T> extends Reactive {
  #entries = new Map<string, LookupEntry<T>>();
  #label: string;
  #ttlMs: number;

  constructor(label: string, ttlMs: number) {
    super();
    this.#label = label;
    this.#ttlMs = ttlMs;
  }

  readonly get = (key: string): LookupEntry<T> | undefined => {
    const entry = this.#entries.get(key);
    if (entry?.state === 'done' && Date.now() - entry.at > this.#ttlMs) return undefined;
    return entry;
  };

  /** Runs `fetch` unless a fresh answer or a lookup in flight exists; `force` asks again. */
  protected async request(key: string, fetch: () => Promise<T>, force: boolean): Promise<void> {
    const current = this.get(key);
    if (current?.state === 'loading') return;
    if (current?.state === 'done' && !force) return;
    this.#set(key, { state: 'loading' });
    try {
      const result = await fetch();
      this.#set(key, { state: 'done', result, at: Date.now() });
    } catch (error) {
      debugError('records', `${this.#label}-failed`, error);
      this.#set(key, {
        state: 'error',
        message: daemonErrorMessage(formatErrorMessage(error)),
      });
    }
  }

  #set(key: string, entry: LookupEntry<T>) {
    this.#entries.set(key, entry);
    this.changed();
  }
}

class LookupCache<T> extends BaseLookupCache<T> {
  readonly lookup = (key: string, fetch: () => Promise<T>, force = false): Promise<void> =>
    this.request(key, fetch, force);
}

/** Registration lookups know their own fetch: the daemon's WHOIS/RDAP lookup. */
class RegistrationLookups extends BaseLookupCache<DomainLookupResult> {
  readonly lookup = (host: string, force = false): Promise<void> =>
    this.request(host, () => api.lookupDomain(host), force);
}

const MINUTE = 60_000;

/** Registration records change rarely; reopening a record should not ask again. Keyed by hostname. */
export const domainLookups = new RegistrationLookups('domain-lookup', 10 * MINUTE);

/** DNS answers change within minutes. Keyed by hostname. */
export const dnsLookups = new LookupCache<DnsRecords>('dns-lookup', 2 * MINUTE);
/** Local history grows as the machine connects. Keyed by hostname. */
export const seenSubdomainLookups = new LookupCache<SeenSubdomains>('seen-subdomains', MINUTE);
/** crt.sh is slow and rate limited; keep its answer for the session. Keyed by hostname. */
export const certificateSearches = new LookupCache<CertificateSearch>('ct-search', 60 * MINUTE);

/**
 * The registered domain for `host` from a lookup that already answered: the
 * registration's name, else the zone the DNS lookup found. `''` when neither
 * has run, so callers fall back to the daemon finding it.
 */
export function knownDomain(host: string): string {
  const registration = domainLookups.get(host);
  if (
    registration?.state === 'done' &&
    registration.result.registration &&
    isUnder(host, registration.result.registration.domain)
  ) {
    return registration.result.registration.domain;
  }
  const dns = dnsLookups.get(host);
  if (dns?.state === 'done' && isUnder(host, dns.result.domain)) return dns.result.domain;
  return '';
}
