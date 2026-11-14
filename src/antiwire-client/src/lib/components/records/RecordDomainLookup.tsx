import clsx from 'clsx';
import { ExternalLink, Globe, RefreshCw } from 'lucide-react';
import { useEffect, useId, useRef } from 'react';
import Button from '#lib/components/ui/Button.tsx';
import Spinner from '#lib/components/ui/Spinner.tsx';
import { m } from '#lib/i18n/messages.ts';
import { getLocale } from '#lib/paraglide/runtime.js';
import { recordCountryLabel } from './detail/record-detail';
import {
  differentDay,
  dnssecAlgorithmName,
  dsDigestName,
  formatRegistrationStatus,
  glueFor,
  safeMailto,
  safeWebUrl,
  type DomainRegistration,
  isExpired,
  isHoldStatus,
  isInferredDomain,
  isNewlyRegistered,
  lookupHostname,
  INFERRED_SUFFIX,
  type DomainLookupResult,
} from '#lib/models/domain-lookup.ts';
import RecordReputationMenu from './RecordReputationMenu';
import { domainLookups } from '#lib/stores/domain-lookups.ts';
import { useSelector } from '#lib/state/reactive.ts';
import { displayText, formatDate, formatDateTime, formatTimeAgo } from '#lib/utils/index.ts';
import styles from './RecordDomainLookup.module.css';

interface Props {
  /** The record's domain; IP-only records cannot be looked up. */
  domain: string;
  connected: boolean;
}

/** Registry-supplied URLs pass safeWebUrl, so only http(s) ever reaches href. */
function Link({ url, label }: { url: string; label: string }) {
  return (
    <a className={styles.link} href={safeWebUrl(url)} target="_blank" rel="noreferrer noopener">
      {label}
      <ExternalLink size={11} strokeWidth={2} aria-hidden="true" />
    </a>
  );
}

function dateOrDash(ts: number): string {
  return formatDate(ts) || m.common_em_dash();
}

function countryLabel(code: string): string {
  return code.length === 2 ? recordCountryLabel(code, getLocale()) : code;
}

function hostOf(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return url;
  }
}

function sourceLabel(registration: DomainRegistration): string {
  const whois = registration.source === 'whois';
  if (registration.registrarSource) {
    return whois ? m.records_lookup_source_both_whois() : m.records_lookup_source_both_rdap();
  }
  return whois ? m.records_lookup_source_whois() : m.records_lookup_source_rdap();
}

function scrollIntoScroller(el: HTMLElement) {
  const scroller = el.parentElement;
  if (!scroller) return;
  const top =
    scroller.scrollTop + el.getBoundingClientRect().top - scroller.getBoundingClientRect().top;
  const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  scroller.scrollTo({ top, behavior: reduce ? 'auto' : 'smooth' });
}

export function RecordDomainLookup({ domain, connected }: Props) {
  const titleId = useId();
  const host = lookupHostname(domain);
  const inferred = isInferredDomain(domain);
  // A name that exists but no public registry holds, e.g. `router.lan`.
  const privateName =
    domain.replace(INFERRED_SUFFIX, '').trim() && !/^[\d.:]+$/.test(domain.trim());
  const entry = useSelector(domainLookups, (c) => (host ? c.get(host) : undefined));
  const registration =
    entry?.state === 'done' && entry.result.outcome === 'found' ? entry.result.registration : null;
  // Only a finished lookup renders dates, so its answer time is the reference.
  const now = entry?.state === 'done' ? entry.at : 0;
  const holds = registration?.statuses.some(isHoldStatus) ?? false;

  const sectionEl = useRef<HTMLElement>(null);
  const wasLoading = useRef(false);
  const loading = entry?.state === 'loading';

  // A finished lookup lands below the record facts; bring it into view once.
  useEffect(() => {
    if (wasLoading.current && !loading && sectionEl.current) scrollIntoScroller(sectionEl.current);
    wasLoading.current = loading;
  }, [loading]);

  function lookup(force = false) {
    if (!host || !connected) return;
    void domainLookups.lookup(host, force);
  }

  function failureText(result: DomainLookupResult): string {
    switch (result.outcome) {
      case 'not_found':
        return m.records_lookup_not_found({ domain: displayText(host) });
      case 'rate_limited':
        return m.records_lookup_rate_limited();
      case 'no_authority':
        return m.records_lookup_no_authority();
      case 'invalid_domain':
        return m.records_lookup_invalid_domain();
      default:
        return m.records_lookup_unavailable();
    }
  }

  function renderRegistration(registration: DomainRegistration, at: number) {
    const newly = isNewlyRegistered(registration, now);
    const expired = isExpired(registration, now);
    const registrantLocation = [
      registration.registrantRegion,
      countryLabel(registration.registrantCountry),
    ]
      .filter(Boolean)
      .join(', ');
    const registrantKnown =
      registration.registrantOrganization ||
      registration.registrantName ||
      registrantLocation ||
      safeWebUrl(registration.registrantContactUrl);
    return (
      <>
        {registration.domain !== host && (
          <p className={styles.recordFor}>
            {m.records_lookup_record_for({ domain: displayText(registration.domain) })}
          </p>
        )}
        {(newly || expired || holds) && (
          <div className={styles.badges}>
            {newly && (
              <span className={clsx(styles.badge, styles.warn)}>
                {m.records_lookup_badge_new()}
              </span>
            )}
            {expired && (
              <span className={clsx(styles.badge, styles.bad)}>
                {m.records_lookup_badge_expired()}
              </span>
            )}
            {holds && (
              <span className={clsx(styles.badge, styles.bad)}>
                {m.records_lookup_badge_hold()}
              </span>
            )}
          </div>
        )}

        <h4>{m.records_lookup_group_domain()}</h4>
        <dl className={styles.facts}>
          {registration.unicodeName && (
            <div>
              <dt>{m.records_lookup_unicode()}</dt>
              <dd>{displayText(registration.unicodeName)}</dd>
            </div>
          )}
          {registration.handle && (
            <div>
              <dt>{m.records_lookup_handle()}</dt>
              <dd className={clsx('mono', styles.small)}>{registration.handle}</dd>
            </div>
          )}
          <div>
            <dt>{m.records_lookup_registered()}</dt>
            <dd className={clsx(newly && styles.warn)}>
              {registration.registeredAt
                ? m.records_lookup_registered_age({
                    date: formatDate(registration.registeredAt),
                    age: formatTimeAgo(registration.registeredAt, now),
                  })
                : m.common_em_dash()}
            </dd>
          </div>
          <div>
            <dt>{m.records_lookup_expires()}</dt>
            <dd className={clsx(expired && styles.bad)}>{dateOrDash(registration.expiresAt)}</dd>
          </div>
          {differentDay(registration.registrarExpiresAt, registration.expiresAt) && (
            <div>
              <dt>{m.records_lookup_registrar_expires()}</dt>
              <dd>{formatDate(registration.registrarExpiresAt)}</dd>
            </div>
          )}
          <div>
            <dt>{m.records_lookup_updated()}</dt>
            <dd>{dateOrDash(registration.updatedAt)}</dd>
          </div>
          {registration.transferredAt ? (
            <div>
              <dt>{m.records_lookup_transferred()}</dt>
              <dd>{formatDate(registration.transferredAt)}</dd>
            </div>
          ) : null}
          <div>
            <dt>{m.records_lookup_status()}</dt>
            <dd className={styles.chips}>
              {registration.statuses.length
                ? registration.statuses.map((status) => (
                    <span
                      key={status}
                      className={clsx(styles.chip, isHoldStatus(status) && styles.hold)}
                    >
                      {formatRegistrationStatus(status)}
                    </span>
                  ))
                : m.common_em_dash()}
            </dd>
          </div>
        </dl>

        <h4>{m.records_lookup_registrant()}</h4>
        {registrantKnown && (
          <dl className={styles.facts}>
            {registration.registrantOrganization && (
              <div>
                <dt>{m.records_lookup_organization()}</dt>
                <dd>{registration.registrantOrganization}</dd>
              </div>
            )}
            {registration.registrantName && (
              <div>
                <dt>{m.records_lookup_name()}</dt>
                <dd>{registration.registrantName}</dd>
              </div>
            )}
            {registrantLocation && (
              <div>
                <dt>{m.records_lookup_location()}</dt>
                <dd>{registrantLocation}</dd>
              </div>
            )}
            {safeWebUrl(registration.registrantContactUrl) && (
              <div>
                <dt>{m.records_lookup_contact()}</dt>
                <dd>
                  <Link
                    url={registration.registrantContactUrl}
                    label={m.records_lookup_contact_form()}
                  />
                </dd>
              </div>
            )}
          </dl>
        )}
        {(registration.redacted || !registrantKnown) && (
          <p className={styles.note}>
            {registration.redacted ? m.records_lookup_redacted() : m.common_em_dash()}
          </p>
        )}

        <h4>{m.records_lookup_registrar()}</h4>
        <dl className={styles.facts}>
          <div>
            <dt>{m.records_lookup_name()}</dt>
            <dd>
              {registration.registrar || m.common_em_dash()}
              {registration.registrarId ? (
                <>
                  {' '}
                  <span className={styles.aside}>
                    {m.records_lookup_iana_id({ id: registration.registrarId })}
                  </span>
                </>
              ) : null}
            </dd>
          </div>
          {safeWebUrl(registration.registrarUrl) && (
            <div>
              <dt>{m.records_lookup_website()}</dt>
              <dd>
                <Link
                  url={registration.registrarUrl}
                  label={displayText(hostOf(registration.registrarUrl))}
                />
              </dd>
            </div>
          )}
          {registration.registrarCountry && (
            <div>
              <dt>{m.records_lookup_country()}</dt>
              <dd>{countryLabel(registration.registrarCountry)}</dd>
            </div>
          )}
          {registration.whoisServer && (
            <div>
              <dt>{m.records_lookup_whois()}</dt>
              <dd className={clsx('mono', styles.small)}>
                {displayText(registration.whoisServer)}
              </dd>
            </div>
          )}
          {registration.abuseEmail && (
            <div>
              <dt>{m.records_lookup_abuse_email()}</dt>
              <dd className={styles.small}>
                {safeMailto(registration.abuseEmail) ? (
                  <a className={styles.link} href={safeMailto(registration.abuseEmail)}>
                    {registration.abuseEmail}
                  </a>
                ) : (
                  registration.abuseEmail
                )}
              </dd>
            </div>
          )}
          {registration.abusePhone && (
            <div>
              <dt>{m.records_lookup_abuse_phone()}</dt>
              <dd className={clsx('mono', styles.small)}>{registration.abusePhone}</dd>
            </div>
          )}
          {safeWebUrl(registration.abuseUrl) && (
            <div>
              <dt>{m.records_lookup_abuse_report()}</dt>
              <dd>
                <Link url={registration.abuseUrl} label={m.records_lookup_abuse_report_link()} />
              </dd>
            </div>
          )}
        </dl>

        <h4>{m.records_lookup_group_dns()}</h4>
        <dl className={styles.facts}>
          <div>
            <dt>{m.records_lookup_dnssec()}</dt>
            <dd>
              {registration.dnssec === true
                ? m.records_lookup_dnssec_signed()
                : registration.dnssec === false
                  ? m.records_lookup_dnssec_unsigned()
                  : m.common_em_dash()}
            </dd>
          </div>
          {registration.dsRecords.length > 0 && (
            <div>
              <dt>{m.records_lookup_ds()}</dt>
              <dd className={styles.list}>
                {registration.dsRecords.map((ds) => (
                  <span key={`${ds.keyTag}:${ds.digestType}:${ds.digest}`} className={styles.ds}>
                    <span>
                      {m.records_lookup_ds_line({
                        tag: ds.keyTag,
                        algorithm: dnssecAlgorithmName(ds.algorithm),
                        digest: dsDigestName(ds.digestType),
                      })}
                    </span>
                    <span className={clsx('mono', styles.digest)}>{ds.digest}</span>
                  </span>
                ))}
              </dd>
            </div>
          )}
          <div>
            <dt>{m.records_lookup_nameservers()}</dt>
            <dd className={clsx('mono', styles.list)}>
              {registration.nameservers.length
                ? registration.nameservers.map((server) => (
                    <span key={server}>
                      {displayText(server)}
                      {glueFor(registration, server).map((address) => (
                        <span key={address}>
                          {' '}
                          <span className={styles.glue}>{address}</span>
                        </span>
                      ))}
                    </span>
                  ))
                : m.common_em_dash()}
            </dd>
          </div>
        </dl>

        <div className={styles.sources}>
          <p>
            {m.records_lookup_source({
              source: sourceLabel(registration),
              age: formatTimeAgo(at),
            })}
          </p>
          {registration.databaseUpdatedAt ? (
            <p>
              {m.records_lookup_database_updated({
                date: formatDateTime(registration.databaseUpdatedAt),
              })}
            </p>
          ) : null}
          <p className={styles.sourceLinks}>
            {safeWebUrl(registration.registrySource) ? (
              <Link url={registration.registrySource} label={m.records_lookup_registry_record()} />
            ) : registration.registrySource ? (
              <span className="mono">{registration.registrySource}</span>
            ) : null}
            {safeWebUrl(registration.registrarSource) ? (
              <Link
                url={registration.registrarSource}
                label={m.records_lookup_registrar_record()}
              />
            ) : registration.registrarSource ? (
              <span className="mono">{registration.registrarSource}</span>
            ) : null}
          </p>
        </div>
      </>
    );
  }

  let body;
  if (!host) {
    body = (
      <p className={styles.note}>
        {privateName
          ? m.records_lookup_not_public({
              domain: displayText(domain.replace(INFERRED_SUFFIX, '').trim()),
            })
          : m.records_lookup_no_domain()}
      </p>
    );
  } else if (!entry) {
    body = (
      <>
        <p className={styles.note}>{m.records_lookup_hint({ domain: displayText(host) })}</p>
        <div>
          <Button variant="secondary" size="sm" disabled={!connected} onClick={() => lookup()}>
            <Globe size={14} strokeWidth={2} />
            {m.records_lookup_button()}
          </Button>
        </div>
      </>
    );
  } else if (entry.state === 'loading') {
    body = (
      <div className={styles.loading} role="status">
        <Spinner size={14} />
        {m.records_lookup_loading()}
      </div>
    );
  } else if (entry.state === 'error' || !registration) {
    body = (
      <>
        <p className={clsx(styles.note, styles.failure)}>
          {entry.state === 'error'
            ? m.records_lookup_failed({ message: entry.message })
            : failureText(entry.result)}
        </p>
        {(entry.state === 'error' ||
          !['not_found', 'invalid_domain'].includes(entry.result.outcome)) && (
          <div>
            <Button
              variant="secondary"
              size="sm"
              disabled={!connected}
              onClick={() => lookup(true)}
            >
              {m.records_lookup_retry()}
            </Button>
          </div>
        )}
      </>
    );
  } else {
    body = renderRegistration(registration, entry.at);
  }

  return (
    <section
      ref={sectionEl}
      className={styles.lookup}
      aria-labelledby={titleId}
      aria-busy={loading}
    >
      <div className={styles.head}>
        <h3 id={titleId}>{m.records_lookup_title()}</h3>
        <div className={styles.headActions}>
          {host && <RecordReputationMenu domain={host} />}
          {entry && entry.state !== 'loading' && (
            <Button
              variant="ghost"
              size="sm"
              iconOnly
              aria-label={m.records_lookup_refresh_aria()}
              disabled={!connected}
              onClick={() => lookup(true)}
            >
              <RefreshCw size={13} strokeWidth={2} />
            </Button>
          )}
        </div>
      </div>

      {host && inferred && (
        <p className={clsx(styles.note, styles.inferred)}>{m.records_lookup_inferred()}</p>
      )}

      {body}
    </section>
  );
}

export default RecordDomainLookup;
