import clsx from 'clsx';
import { FileSearch, History, RefreshCw } from 'lucide-react';
import { useEffect, useId, useMemo, useState } from 'react';
import Button from '#lib/components/ui/Button.tsx';
import SearchBox from '#lib/components/ui/SearchBox.tsx';
import Spinner from '#lib/components/ui/Spinner.tsx';
import { api } from '#lib/api/daemon.ts';
import { m } from '#lib/i18n/messages.ts';
import { lookupHostname } from '#lib/models/domain-lookup.ts';
import { filterNames, type CertificateSearch } from '#lib/models/domain-records.ts';
import {
  certificateSearches,
  dnsLookups,
  domainLookups,
  knownDomain,
  seenSubdomainLookups,
} from '#lib/stores/domain-lookups.ts';
import { useSelector } from '#lib/state/reactive.ts';
import { displayText, formatDate, formatTimeAgo } from '#lib/utils/index.ts';
import styles from './RecordSubdomains.module.css';

interface Props {
  /** The record's domain; the section hides itself for IP-only records. */
  domain: string;
  connected: boolean;
}

/** Rows shown per list before "Show all". */
const PAGE = 25;
/** Lists longer than this get a filter box. */
const FILTER_AT = 12;

function certFailure(result: CertificateSearch): string {
  switch (result.outcome) {
    case 'rate_limited':
      return m.records_subdomains_ct_rate_limited();
    case 'invalid_domain':
      return m.records_lookup_invalid_domain();
    default:
      return m.records_subdomains_ct_unavailable();
  }
}

function isValid(expiry: number, now: number): boolean {
  return expiry * 1000 > now;
}

export function RecordSubdomains({ domain, connected }: Props) {
  const titleId = useId();
  const host = lookupHostname(domain);
  // `knownDomain` reads both the registration and the DNS caches.
  useSelector(domainLookups, (c) => (host ? c.get(host) : undefined));
  useSelector(dnsLookups, (c) => (host ? c.get(host) : undefined));
  const hint = host ? knownDomain(host) : '';
  const local = useSelector(seenSubdomainLookups, (c) => (host ? c.get(host) : undefined));
  const certs = useSelector(certificateSearches, (c) => (host ? c.get(host) : undefined));
  const localResult = local?.state === 'done' ? local.result : null;
  const certResult = certs?.state === 'done' ? certs.result : null;
  /**
   * Best name for the domain in copy: whatever a lookup has confirmed, else
   * the last two labels. The daemon finds the real zone before it searches.
   */
  const domainLabel =
    localResult?.domain || certResult?.domain || hint || host.split('.').slice(-2).join('.');
  const localNames = useMemo(
    () => new Set(localResult?.names.map((item) => item.name) ?? []),
    [localResult],
  );

  const [query, setQuery] = useState('');
  const [showAllLocal, setShowAllLocal] = useState(false);
  const [showAllCerts, setShowAllCerts] = useState(false);

  const total = (localResult?.names.length ?? 0) + (certResult?.names.length ?? 0);
  const localRows = useMemo(
    () => filterNames(localResult?.names ?? [], query),
    [localResult, query],
  );
  const certRows = useMemo(() => filterNames(certResult?.names ?? [], query), [certResult, query]);

  function showLocal(force = false) {
    if (!host || !connected) return;
    const domainHint = knownDomain(host);
    void seenSubdomainLookups.lookup(host, () => api.getSeenSubdomains(host, domainHint), force);
  }

  function searchCertificates(force = false) {
    if (!host || !connected) return;
    const domainHint = knownDomain(host);
    void certificateSearches.lookup(host, () => api.searchCertificates(host, domainHint), force);
  }

  // Local history needs no remote server once the domain is known, so it loads by itself.
  const hasLocal = local !== undefined;
  useEffect(() => {
    if (!host || !hint || !connected || hasLocal) return;
    const domainHint = knownDomain(host);
    void seenSubdomainLookups.lookup(host, () => api.getSeenSubdomains(host, domainHint));
  }, [host, hint, connected, hasLocal]);

  if (!host) return null;

  let localBody;
  if (!local) {
    localBody = (
      <>
        <p className={styles.note}>{m.records_subdomains_local_hint()}</p>
        <div>
          <Button variant="secondary" size="sm" disabled={!connected} onClick={() => showLocal()}>
            <History size={14} strokeWidth={2} />
            {m.records_subdomains_local_button()}
          </Button>
        </div>
      </>
    );
  } else if (local.state === 'loading') {
    localBody = (
      <div className={styles.loading} role="status">
        <Spinner size={14} />
        {m.records_subdomains_loading()}
      </div>
    );
  } else if (local.state === 'error') {
    localBody = (
      <p className={styles.note}>{m.records_lookup_failed({ message: local.message })}</p>
    );
  } else if (!local.result.names.length) {
    localBody = (
      <p className={styles.note}>
        {m.records_subdomains_local_empty({ domain: displayText(local.result.domain) })}
      </p>
    );
  } else {
    localBody = (
      <>
        <ul className={styles.names}>
          {(showAllLocal ? localRows : localRows.slice(0, PAGE)).map((item) => (
            <li key={item.name}>
              <span className={clsx(styles.name, 'mono')}>{displayText(item.name)}</span>
              <span className={styles.meta}>
                {item.connections ? (
                  <>
                    {m.records_subdomains_connections({
                      count: item.connections.toLocaleString(),
                    })}
                    {item.blocked ? (
                      <>
                        {' · '}
                        <span className={styles.bad}>
                          {m.records_app_blocked({ count: item.blocked.toLocaleString() })}
                        </span>
                      </>
                    ) : null}
                  </>
                ) : (
                  m.records_subdomains_dns_only()
                )}
                {item.lastSeen
                  ? ` · ${m.records_subdomains_last_seen({ age: formatTimeAgo(item.lastSeen) })}`
                  : null}
              </span>
            </li>
          ))}
        </ul>
        {!showAllLocal && localRows.length > PAGE && (
          <div>
            <Button variant="ghost" size="sm" onClick={() => setShowAllLocal(true)}>
              {m.records_subdomains_show_all({ count: localRows.length })}
            </Button>
          </div>
        )}
        {local.result.truncated && (
          <p className={clsx(styles.note, styles.small)}>
            {m.records_subdomains_truncated({ count: local.result.names.length })}
          </p>
        )}
      </>
    );
  }

  let certBody;
  if (!certs) {
    certBody = (
      <>
        <p className={styles.note}>
          {m.records_subdomains_ct_hint({ domain: displayText(domainLabel) })}
        </p>
        <div>
          <Button
            variant="secondary"
            size="sm"
            disabled={!connected}
            onClick={() => searchCertificates()}
          >
            <FileSearch size={14} strokeWidth={2} />
            {m.records_subdomains_ct_button()}
          </Button>
        </div>
      </>
    );
  } else if (certs.state === 'loading') {
    certBody = (
      <div className={styles.loading} role="status">
        <Spinner size={14} />
        {m.records_subdomains_ct_loading()}
      </div>
    );
  } else if (certs.state === 'error') {
    certBody = <p className={styles.note}>{m.records_lookup_failed({ message: certs.message })}</p>;
  } else if (certs.result.outcome !== 'found') {
    certBody = <p className={styles.note}>{certFailure(certs.result)}</p>;
  } else if (!certs.result.names.length) {
    certBody = (
      <p className={styles.note}>
        {m.records_subdomains_ct_empty({ domain: displayText(certs.result.domain) })}
      </p>
    );
  } else {
    const at = certs.at;
    certBody = (
      <>
        <p className={clsx(styles.note, styles.small)}>
          {m.records_subdomains_ct_summary({
            names: certs.result.names.length.toLocaleString(),
            certificates: certs.result.certificates.toLocaleString(),
          })}
        </p>
        <ul className={styles.names}>
          {(showAllCerts ? certRows : certRows.slice(0, PAGE)).map((item) => {
            const valid = isValid(item.latestExpiry, at);
            return (
              <li key={item.name} className={clsx(!valid && styles.expired)}>
                <span className={clsx(styles.name, 'mono')}>
                  {displayText(item.name)}
                  {localNames.has(item.name) && (
                    <>
                      {' '}
                      <span className={styles.here}>{m.records_subdomains_seen_here()}</span>
                    </>
                  )}
                </span>
                <span className={styles.meta}>
                  {m.records_subdomains_cert_count({
                    count: item.certificates.toLocaleString(),
                  })}
                  {item.latestExpiry
                    ? ` · ${
                        valid
                          ? m.records_subdomains_valid_until({
                              date: formatDate(item.latestExpiry),
                            })
                          : m.records_subdomains_expired({ date: formatDate(item.latestExpiry) })
                      }`
                    : null}
                  {item.issuer ? ` · ${displayText(item.issuer)}` : null}
                </span>
              </li>
            );
          })}
        </ul>
        {!showAllCerts && certRows.length > PAGE && (
          <div>
            <Button variant="ghost" size="sm" onClick={() => setShowAllCerts(true)}>
              {m.records_subdomains_show_all({ count: certRows.length })}
            </Button>
          </div>
        )}
        {certs.result.truncated && (
          <p className={clsx(styles.note, styles.small)}>{m.records_subdomains_ct_truncated()}</p>
        )}
        <p className={clsx(styles.note, styles.small)}>
          {m.records_subdomains_ct_source({ age: formatTimeAgo(at) })}
        </p>
      </>
    );
  }

  return (
    <section className={styles.lookup} aria-labelledby={titleId}>
      <div className={styles.head}>
        <h3 id={titleId}>{m.records_subdomains_title()}</h3>
      </div>

      {total > FILTER_AT && (
        <SearchBox
          value={query}
          onValueChange={setQuery}
          placeholder={m.records_subdomains_filter()}
          ariaLabel={m.records_subdomains_filter()}
        />
      )}

      <div className={styles.block}>
        <h4>
          {m.records_subdomains_local()}
          {local && local.state !== 'loading' && (
            <Button
              variant="ghost"
              size="sm"
              iconOnly
              aria-label={m.records_subdomains_refresh_aria()}
              disabled={!connected}
              onClick={() => showLocal(true)}
            >
              <RefreshCw size={12} strokeWidth={2} />
            </Button>
          )}
        </h4>
        {localBody}
      </div>

      <div className={styles.block}>
        <h4>
          {m.records_subdomains_ct()}
          {certs && certs.state !== 'loading' && (
            <Button
              variant="ghost"
              size="sm"
              iconOnly
              aria-label={m.records_subdomains_ct_refresh_aria()}
              disabled={!connected}
              onClick={() => searchCertificates(true)}
            >
              <RefreshCw size={12} strokeWidth={2} />
            </Button>
          )}
        </h4>
        {certBody}
      </div>
    </section>
  );
}

export default RecordSubdomains;
