import clsx from 'clsx';
import { memo, useEffect, useMemo, useRef, type CSSProperties } from 'react';
import { DestinationCountries } from '#lib/components/analytics/DestinationCountries.tsx';
import { EmptyState } from '#lib/components/ui/EmptyState.tsx';
import DaemonOffline from '#lib/components/shell/DaemonOffline.tsx';
import { Status } from '#lib/components/ui/Status.tsx';
import { statusToneFromColor } from '#lib/components/ui/status-tone.ts';
import { Tooltip } from '#lib/components/ui/Tooltip.tsx';
import { VirtualScrollList } from '#lib/components/ui/VirtualScrollList.tsx';
import { m } from '#lib/i18n/messages.ts';
import { useSelector } from '#lib/state/reactive.ts';
import { daemon } from '#lib/stores/daemon.ts';
import {
  aggregateAnalyticsLogs,
  topCountries,
  type AnalyticsHostRow,
} from '#lib/utils/analytics-aggregates.ts';
import { displayText } from '#lib/utils/index.ts';
import styles from './AnalyticsPage.module.css';

const HOST_ROW_HEIGHT = 48;

function hostRowKey(row: AnalyticsHostRow) {
  return row.host;
}

const HostRow = memo(function HostRow({ host: h }: { host: AnalyticsHostRow }) {
  return (
    <div className={clsx(styles.hostRow, styles.hostsGrid)}>
      <div className={styles.hostMain}>
        <span className={clsx('mono', styles.hostName)}>
          <Tooltip text={displayText(h.host)} label={m.analytics_tooltip_remote_host()}>
            {displayText(h.host)}
          </Tooltip>
        </span>
        <span className={styles.hostOrg} title={h.org}>
          {h.org}
        </span>
      </div>
      <span className={styles.geo}>{h.geo}</span>
      <Status tone={statusToneFromColor(h.repFg)}>{h.rep}</Status>
      <span className={clsx('mono', styles.num, styles.right)}>{h.sockets}</span>
      <div className={styles.volume}>
        <span className={styles.volBar}>
          <span
            className={styles.volFill}
            style={{ '--pct': h.pct / 100, background: h.color } as CSSProperties}
          ></span>
        </span>
        <span className={clsx('mono', styles.num, styles.volLabel)}>{h.totalLabel}</span>
      </div>
      <span className={clsx('mono', styles.num, styles.right, styles.seen)}>{h.seen}</span>
    </div>
  );
});

const renderHostRow = ({ item }: { item: AnalyticsHostRow }) => <HostRow host={item} />;

export default function AnalyticsPage() {
  const connected = useSelector(daemon, (d) => d.state.connected);
  const logs = useSelector(daemon, (d) => d.state.analyticsLogs);
  const regionStats = useSelector(daemon, (d) => d.state.analyticsCountryStatistics);
  const aggregates = useMemo(() => aggregateAnalyticsLogs(logs), [logs]);
  const { hosts, ports, dnsEntries, dnsSummary } = aggregates;
  const countries = useMemo(() => topCountries(regionStats), [regionStats]);

  /** Share of all sampled DNS lookups that were answered rather than blocked. */
  const dnsResolvedShare = dnsSummary.lookups
    ? `${Math.round(((dnsSummary.lookups - dnsSummary.blocked) / dnsSummary.lookups) * 100)}%`
    : m.common_em_dash();

  const loadedWhileConnected = useRef(false);
  useEffect(() => {
    if (!connected) {
      loadedWhileConnected.current = false;
      return;
    }
    if (loadedWhileConnected.current) return;
    // Latch only after an applied fetch so a reconnect retries; a failure write would loop.
    void daemon.loadConnectionLogs({ limit: 300 }).then(
      (applied) => {
        if (applied) loadedWhileConnected.current = true;
      },
      () => {},
    );
  }, [connected]);

  return (
    <div className={styles.page} data-testid="page-analytics" data-page-motion="analytics">
      <div className={clsx(styles.scroll, 'scroll')}>
        <header className={styles.pageHead}>
          <h1>{m.nav_analytics()}</h1>
          <p className={styles.sub}>{m.analytics_page_sub()}</p>
        </header>
        {!connected ? (
          <DaemonOffline text={m.analytics_empty_disconnected()} />
        ) : (
          <div className={styles.grid}>
            <div className={styles.col}>
              <section
                className={clsx(styles.hosts, 'panel')}
                data-motion-stage="1"
                aria-labelledby="analytics-hosts"
              >
                <div className={styles.cardHead}>
                  <h2 id="analytics-hosts">{m.analytics_remote_hosts_title()}</h2>
                  <span className={styles.meta}>
                    {m.analytics_destinations_meta({ count: hosts.length })}
                  </span>
                </div>
                <div className={clsx(styles.hostsThead, styles.hostsGrid)}>
                  <span>{m.analytics_col_host_org()}</span>
                  <span>{m.analytics_col_geo()}</span>
                  <span>{m.analytics_col_trust()}</span>
                  <span className={styles.right}>{m.analytics_col_sockets()}</span>
                  <span>{m.analytics_col_volume()}</span>
                  <span className={styles.right}>{m.analytics_col_last_seen()}</span>
                </div>
                <div className={styles.hostsBody}>
                  <VirtualScrollList
                    items={hosts}
                    estimateSize={HOST_ROW_HEIGHT}
                    getItemKey={hostRowKey}
                    row={renderHostRow}
                    empty={<EmptyState text={m.analytics_empty_no_hosts()} compact />}
                  />
                </div>
              </section>

              <section
                className={clsx(styles.ports, 'panel')}
                data-motion-stage="2"
                aria-labelledby="analytics-ports"
              >
                <div className={styles.cardHead}>
                  <h2 id="analytics-ports">{m.analytics_port_distribution_title()}</h2>
                  <span className={styles.meta}>{m.analytics_port_share_meta()}</span>
                </div>
                <ol className={styles.portList}>
                  {ports.length > 0 ? (
                    ports.map((p) => (
                      <li key={p.label}>
                        <span className={clsx('mono', styles.port)}>{p.label}</span>
                        <span className={styles.service}>{p.service}</span>
                        <span className={styles.portBar}>
                          <span style={{ '--pct': p.share / 100 } as CSSProperties}></span>
                        </span>
                        <span className={clsx('mono', styles.num, styles.share)}>{p.share}%</span>
                      </li>
                    ))
                  ) : (
                    <li className={styles.portEmpty}>{m.common_em_dash()}</li>
                  )}
                </ol>
              </section>
            </div>

            <aside className={styles.col} data-motion-stage="3">
              <section className={clsx('panel', styles.region)}>
                <DestinationCountries
                  countryCounts={regionStats.countryCounts}
                  unknownCount={regionStats.unknownCount}
                  totalCount={regionStats.totalCount}
                  unknownPct={regionStats.unknownPct}
                  countries={countries}
                />
              </section>

              <section className={clsx(styles.dns, 'panel')} aria-labelledby="analytics-dns">
                <div className={styles.cardHead}>
                  <h2 id="analytics-dns">{m.analytics_dns_title()}</h2>
                </div>
                <div className={styles.dnsSummary}>
                  <span className={styles.dnsValue}>{dnsResolvedShare}</span>
                  <span className={styles.dnsUnit}>{m.analytics_dns_resolved_share()}</span>
                  <span className={styles.dnsCaption}>
                    {m.analytics_dns_summary({
                      lookups: dnsSummary.lookups,
                      blocked: dnsSummary.blocked,
                    })}
                  </span>
                </div>
                <div className={styles.dnsList}>
                  {dnsEntries.length > 0 ? (
                    dnsEntries.map((d) => (
                      <div key={d.name} className={styles.dnsRow}>
                        <span className={clsx('mono', styles.dnsName)}>
                          <Tooltip
                            text={displayText(d.name)}
                            label={m.analytics_tooltip_remote_host()}
                          >
                            {displayText(d.name)}
                          </Tooltip>
                        </span>
                        <span className={clsx('mono', styles.num, styles.dnsCount)}>
                          {m.analytics_dns_query_count({ count: d.q })}
                        </span>
                        <Status tone={statusToneFromColor(d.color)} className={styles.dnsStatus}>
                          {d.verdict}
                        </Status>
                      </div>
                    ))
                  ) : (
                    <EmptyState text={m.analytics_empty_no_dns()} compact />
                  )}
                </div>
              </section>
            </aside>
          </div>
        )}
      </div>
    </div>
  );
}
