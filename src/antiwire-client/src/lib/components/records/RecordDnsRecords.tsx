import clsx from 'clsx';
import { RefreshCw, Server, ShieldCheck } from 'lucide-react';
import { useId } from 'react';
import Button from '#lib/components/ui/Button.tsx';
import Spinner from '#lib/components/ui/Spinner.tsx';
import { api } from '#lib/api/daemon.ts';
import { m } from '#lib/i18n/messages.ts';
import { lookupHostname } from '#lib/models/domain-lookup.ts';
import {
  allValidated,
  dnsGroups,
  failedQueries,
  formatTtl,
  type DnsRow,
} from '#lib/models/domain-records.ts';
import { dnsLookups, knownDomain } from '#lib/stores/domain-lookups.ts';
import { useSelector } from '#lib/state/reactive.ts';
import { displayText, formatTimeAgo } from '#lib/utils/index.ts';
import styles from './RecordDnsRecords.module.css';

interface Props {
  /** The record's domain; the section hides itself for IP-only records. */
  domain: string;
  /** Address the connection reached, for reverse DNS. */
  address: string;
  connected: boolean;
}

/** DKIM keys are guessed from this many common selectors (daemon `DKIM_SELECTORS`). */
const DKIM_SELECTOR_COUNT = 15;

function Rows({ items }: { items: DnsRow[] }) {
  return (
    <ul className={styles.rows}>
      {items.map((item, index) => (
        <li key={index}>
          <span className={styles.type}>{item.label}</span>
          <span className={styles.value}>
            {/* A CNAME target owns every row after it; name it once. */}
            {item.owner && item.owner !== items[index - 1]?.owner && (
              <span className={clsx(styles.owner, 'mono')}>{displayText(item.owner)}</span>
            )}
            <span className={clsx(styles.data, 'mono')}>{displayText(item.data)}</span>
          </span>
          <span className={styles.ttl}>
            <span className={styles.srOnly}>{m.records_dns_ttl_label()}</span>
            {formatTtl(item.ttl)}
          </span>
        </li>
      ))}
    </ul>
  );
}

export function RecordDnsRecords({ domain, address, connected }: Props) {
  const titleId = useId();
  const host = lookupHostname(domain);
  const entry = useSelector(dnsLookups, (c) => (host ? c.get(host) : undefined));
  const records = entry?.state === 'done' ? entry.result : null;
  const groups = records ? dnsGroups(records, host) : null;

  function lookup(force = false) {
    if (!host || !connected) return;
    const hint = knownDomain(host);
    void dnsLookups.lookup(host, () => api.lookupDnsRecords(host, hint, address), force);
  }

  if (!host) return null;

  let body;
  if (!entry) {
    body = (
      <>
        <p className={styles.note}>{m.records_dns_hint({ host: displayText(host) })}</p>
        <div>
          <Button variant="secondary" size="sm" disabled={!connected} onClick={() => lookup()}>
            <Server size={14} strokeWidth={2} />
            {m.records_dns_button()}
          </Button>
        </div>
      </>
    );
  } else if (entry.state === 'loading') {
    body = (
      <div className={styles.loading} role="status">
        <Spinner size={14} />
        {m.records_dns_loading()}
      </div>
    );
  } else if (entry.state === 'error' || !records || !groups) {
    body = (
      <>
        <p className={styles.note}>
          {m.records_lookup_failed({
            message: entry.state === 'error' ? entry.message : m.records_lookup_unavailable(),
          })}
        </p>
        <div>
          <Button variant="secondary" size="sm" disabled={!connected} onClick={() => lookup(true)}>
            {m.records_lookup_retry()}
          </Button>
        </div>
      </>
    );
  } else {
    const failed = failedQueries(records);
    body = (
      <>
        {allValidated(records) && (
          <span className={styles.validated}>
            <ShieldCheck size={13} strokeWidth={2} aria-hidden="true" />
            {m.records_dns_validated()}
          </span>
        )}

        <h4>
          {m.records_dns_group_host()}{' '}
          <span className={clsx(styles.subject, 'mono')}>{displayText(host)}</span>
        </h4>
        {groups.host.length ? (
          <Rows items={groups.host} />
        ) : (
          <p className={styles.note}>{m.records_dns_none()}</p>
        )}

        <h4>
          {m.records_lookup_group_domain()}{' '}
          <span className={clsx(styles.subject, 'mono')}>{displayText(records.domain)}</span>
        </h4>
        {groups.zone.length ? (
          <Rows items={groups.zone} />
        ) : (
          <p className={styles.note}>{m.records_dns_none()}</p>
        )}

        <h4>{m.records_dns_group_mail()}</h4>
        {groups.mail.length || groups.dkim.length ? (
          <Rows items={[...groups.mail, ...groups.dkim]} />
        ) : (
          <p className={styles.note}>
            {m.records_dns_no_mail({ domain: displayText(records.domain) })}
          </p>
        )}
        <p className={clsx(styles.note, styles.small)}>
          {m.records_dns_dkim_checked({ count: DKIM_SELECTOR_COUNT })}
        </p>

        {address && (
          <>
            <h4>
              {m.records_dns_group_reverse()}{' '}
              <span className={clsx(styles.subject, 'mono')}>{address}</span>
            </h4>
            {groups.reverse.length ? (
              <Rows items={groups.reverse} />
            ) : (
              <p className={styles.note}>{m.records_dns_none()}</p>
            )}
          </>
        )}

        <div className={styles.sources}>
          <p>
            {m.records_dns_asked({
              upstream: displayText(records.upstream),
              age: formatTimeAgo(entry.at),
            })}
          </p>
          {failed ? <p>{m.records_dns_unanswered({ count: failed })}</p> : null}
        </div>
      </>
    );
  }

  return (
    <section
      className={styles.lookup}
      aria-labelledby={titleId}
      aria-busy={entry?.state === 'loading'}
    >
      <div className={styles.head}>
        <h3 id={titleId}>{m.records_dns_title()}</h3>
        {entry && entry.state !== 'loading' && (
          <Button
            variant="ghost"
            size="sm"
            iconOnly
            aria-label={m.records_dns_refresh_aria()}
            disabled={!connected}
            onClick={() => lookup(true)}
          >
            <RefreshCw size={13} strokeWidth={2} />
          </Button>
        )}
      </div>
      {body}
    </section>
  );
}

export default RecordDnsRecords;
