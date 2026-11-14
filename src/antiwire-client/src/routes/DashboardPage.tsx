import clsx from 'clsx';
import { ChevronRight } from 'lucide-react';
import {
  memo,
  useCallback,
  useEffect,
  useId,
  useMemo,
  useRef,
  useState,
  type ComponentType,
  type ReactNode,
} from 'react';
import { createPortal } from 'react-dom';
import { Link, useNavigate } from 'react-router';
import { api } from '#lib/api/daemon.ts';
import { ActivityHeatmap } from '#lib/components/charts/ActivityHeatmap.tsx';
import { ActiveApplicationsPanel } from '#lib/components/dashboard/ActiveApplicationsPanel.tsx';
import { AnimatedText } from '#lib/components/ui/AnimatedText.tsx';
import { AppAvatar } from '#lib/components/ui/AppAvatar.tsx';
import { CollectorNotice } from '#lib/components/ui/CollectorNotice.tsx';
import { ErrorBoundary } from '#lib/components/ui/ErrorBoundary.tsx';
import { ScrollFade } from '#lib/components/ui/ScrollFade.tsx';
import { StatCell } from '#lib/components/ui/StatCell.tsx';
import { m } from '#lib/i18n/messages.ts';
import {
  MAX_ACTIVITY_HISTORY_WEEKS,
  activityWeekOffsetForDateKey,
} from '#lib/models/activity-heatmap.ts';
import {
  DASHBOARD_SPARK_POINTS,
  DASHBOARD_SPARK_SOURCE_SEC,
  averageDelta,
  averageRateOverWindow,
  blockedSince,
  formatAverageDelta,
  hourlyBlockedSeries,
  sparkValuesFromTail,
  type AverageDelta,
} from '#lib/models/dashboard-stats.ts';
import {
  TOP_APPS_VISIBLE_ROWS,
  TOP_APPS_WINDOW_SECONDS,
  topApplications,
  type TopApp,
} from '#lib/models/top-apps.ts';
import { getLocale } from '#lib/paraglide/runtime.js';
import { shallowEqual, useSelector } from '#lib/state/reactive.ts';
import { daemon } from '#lib/stores/daemon.ts';
import { dashboardStatHistory } from '#lib/stores/dashboard-stat-history.ts';
import { throughputChart } from '#lib/stores/throughput-chart.ts';
import type { AppSummary } from '#lib/types/index.ts';
import { useFloatingTip, type FloatingTip } from '#lib/utils/floating-tip.ts';
import {
  appTint,
  debugError,
  displayText,
  formatBytes,
  formatThroughput,
} from '#lib/utils/index.ts';
import { recordsApplicationUrl } from '#lib/utils/records-url.ts';
import styles from './DashboardPage.module.css';

type ThroughputChartComponent = ComponentType<{ downloadRate: number; uploadRate: number }>;

/** Top applications cover the last 24 hours, separate from the all-history summaries. */
const TOP_APPS_REFRESH_MS = 30_000;
const NO_BARS: number[] = [];

// The async work behind the dashboard's effects lives at module scope: React
// Compiler cannot compile a component whose effect closures hold a try/catch
// or a dynamic import(), and these components re-render every second.

/** The top-apps window's summaries, or null when the load failed (already logged). */
async function loadDaySummaries(): Promise<AppSummary[] | null> {
  try {
    const page = await api.getAppSummaries({ timeFilterSeconds: TOP_APPS_WINDOW_SECONDS });
    return [...(page.applications ?? [])];
  } catch (error) {
    debugError('dashboard', 'top-apps-load-failed', error);
    return null;
  }
}

function loadThroughputChart(): Promise<ThroughputChartComponent> {
  return import('#lib/components/charts/ThroughputChart.tsx').then((module) => module.default);
}

const percentFormat = new Intl.NumberFormat(undefined, {
  style: 'percent',
  maximumFractionDigits: 0,
});

/** Wall-clock time; the averages are recomputed with each daemon tick anyway. */
function nowMs(): number {
  return Date.now();
}

function deltaArrow(delta: AverageDelta): string {
  return delta.direction === 'up' ? '↑' : delta.direction === 'down' ? '↓' : '';
}

function averageCaption(delta: AverageDelta | null, color: string): ReactNode {
  if (delta == null) return m.dashboard_stat_no_history();
  if (delta.direction === 'flat') return m.dashboard_stat_level_average();
  return (
    <>
      <span className={styles.delta} style={{ color }}>
        {deltaArrow(delta)} {formatAverageDelta(delta)}
      </span>{' '}
      {m.dashboard_stat_vs_average()}
    </>
  );
}

function useSparkBars(samples: readonly number[]): number[] {
  return useMemo(
    () => sparkValuesFromTail(samples, DASHBOARD_SPARK_POINTS, DASHBOARD_SPARK_SOURCE_SEC, 1),
    [samples],
  );
}

/** Download or upload tile: the live rate, its sparkline, and the 24h average delta. */
const RateCell = memo(function RateCell({ direction }: { direction: 'download' | 'upload' }) {
  const isDown = direction === 'download';
  const rate = useSelector(daemon, (d) => (isDown ? d.state.downloadRate : d.state.uploadRate));
  const activityBuckets = useSelector(daemon, (d) => d.state.activityBuckets);
  const samples = useSelector(throughputChart, (store) => store.samples);
  const series = useMemo(
    () => samples.map((sample) => (isDown ? sample.download : sample.upload)),
    [samples, isDown],
  );
  const bars = useSparkBars(series);
  const throughput = formatThroughput(rate);
  const delta = averageDelta(
    rate,
    averageRateOverWindow(activityBuckets, isDown ? 'bytesReceived' : 'bytesSent', nowMs()),
  );
  const color = isDown ? 'var(--acc)' : 'var(--acc-sub)';
  return (
    <StatCell
      label={isDown ? m.dashboard_stat_download() : m.dashboard_stat_upload()}
      value={throughput.value}
      unit={throughput.unit}
      color={color}
      bars={bars}
      barsLabel={
        isDown ? m.dashboard_stat_bars_download_aria() : m.dashboard_stat_bars_upload_aria()
      }
      caption={averageCaption(delta, color)}
    />
  );
});

const ConnectionsCell = memo(function ConnectionsCell() {
  const { available, stale, activeConnections, activeApplications } = useSelector(
    daemon,
    (d) => ({
      available: d.state.stats.activeConnectionsAvailable,
      stale: d.state.stats.activeConnectionsStale,
      activeConnections: d.state.stats.activeConnections,
      activeApplications: d.state.stats.activeApplications,
    }),
    shallowEqual,
  );
  const sockets = useSelector(dashboardStatHistory, (store) => store.sockets);
  const socketBars = useSparkBars(sockets);
  const value = available ? String(activeConnections) : m.common_em_dash();
  const unit = !available
    ? m.dashboard_stat_active_unit_unavailable()
    : stale
      ? m.dashboard_stat_active_unit_stale()
      : m.dashboard_stat_active_unit();
  const valueColor = !available ? 'var(--t3)' : stale ? 'var(--warn)' : 'var(--t1)';
  return (
    <StatCell
      label={m.dashboard_stat_active_connections()}
      value={value}
      color="var(--t2)"
      valueColor={valueColor}
      bars={available ? socketBars : NO_BARS}
      barsLabel={m.dashboard_stat_bars_connections_aria()}
      caption={
        available && !stale && activeApplications != null ? (
          activeApplications === 1 ? (
            m.dashboard_stat_across_apps_one({ count: activeApplications })
          ) : (
            m.dashboard_stat_across_apps_other({ count: activeApplications })
          )
        ) : (
          <span className={clsx(stale && styles.warn)}>{unit}</span>
        )
      }
    />
  );
});

const BlockedCell = memo(function BlockedCell() {
  const blocked = useSelector(daemon, (d) => d.state.stats.blockedConnections ?? 0);
  // The recent blocked tally comes from the daemon's half-hour activity
  // buckets, which the store keeps for four weeks.
  const activityBuckets = useSelector(daemon, (d) => d.state.activityBuckets);
  const { recent, bars } = useMemo(() => {
    const now = nowMs();
    return {
      recent: blockedSince(activityBuckets, now),
      bars: hourlyBlockedSeries(activityBuckets, now, 12),
    };
  }, [activityBuckets]);
  const sinceTime = new Intl.DateTimeFormat(getLocale(), {
    hour: '2-digit',
    minute: '2-digit',
  }).format(new Date(recent.sinceSec * 1000));
  return (
    <StatCell
      label={m.dashboard_stat_blocked_today()}
      value={String(blocked)}
      color="var(--bad)"
      bars={bars}
      barsLabel={m.dashboard_stat_bars_blocked_aria()}
      caption={
        <>
          <span className={clsx(styles.count, recent.count > 0 && styles.bad)}>{recent.count}</span>{' '}
          {m.dashboard_stat_blocked_since({ time: sinceTime })}
        </>
      }
    />
  );
});

const ThroughputPanel = memo(function ThroughputPanel({
  Chart,
}: {
  Chart: ThroughputChartComponent | null;
}) {
  const { downloadRate, uploadRate } = useSelector(
    daemon,
    (d) => ({ downloadRate: d.state.downloadRate, uploadRate: d.state.uploadRate }),
    shallowEqual,
  );
  const downloadLabel = formatThroughput(downloadRate).label;
  const uploadLabel = formatThroughput(uploadRate).label;
  return (
    <div className={clsx('panel-gradient', styles.throughput)} data-motion-stage="2">
      <div className={styles.tpHeader}>
        <div className={styles.tpTitle}>{m.dashboard_throughput_title()}</div>
        <div className={styles.legend}>
          <span className={clsx(styles.leg, styles.down)}>
            <span className={styles.sq}></span> {m.dashboard_legend_down()}{' '}
            <AnimatedText text={downloadLabel} />
          </span>
          <span className={clsx(styles.leg, styles.up)}>
            <span className={clsx(styles.sq, styles.sub)}></span> {m.dashboard_legend_up()}{' '}
            <AnimatedText text={uploadLabel} />
          </span>
        </div>
      </div>
      <div className={styles.throughputChartMount}>
        <ErrorBoundary kind="chart">
          {Chart && <Chart downloadRate={downloadRate} uploadRate={uploadRate} />}
        </ErrorBoundary>
      </div>
    </div>
  );
});

const HeatmapSection = memo(function HeatmapSection() {
  const week = useSelector(
    daemon,
    (d) => ({
      buckets: d.state.activityWeekBuckets,
      weekStartSec: d.state.activityWeekStartSec,
      loading: d.state.activityWeekLoading,
      offset: d.state.activityWeekOffset,
    }),
    shallowEqual,
  );
  const weekOffset = week.offset;
  const onPrev = useCallback(() => void daemon.loadActivityWeek(weekOffset - 1), [weekOffset]);
  const onNext = useCallback(() => void daemon.loadActivityWeek(weekOffset + 1), [weekOffset]);
  const onSelectDate = useCallback(
    (dateKey: string) => {
      const offset = activityWeekOffsetForDateKey(dateKey);
      if (offset === null || offset === weekOffset) return;
      void daemon.loadActivityWeek(offset);
    },
    [weekOffset],
  );
  return (
    <ErrorBoundary kind="chart">
      <ActivityHeatmap
        buckets={week.buckets}
        weekStartSec={week.weekStartSec}
        loading={week.loading}
        canGoPrev={weekOffset > -MAX_ACTIVITY_HISTORY_WEEKS}
        canGoNext={weekOffset < 0}
        onPrev={onPrev}
        onNext={onNext}
        onSelectDate={onSelectDate}
      />
    </ErrorBoundary>
  );
});

interface TopAppRowProps {
  app: TopApp;
  describedBy: string | undefined;
  tip: Pick<FloatingTip<TopApp>, 'show' | 'move' | 'hide'>;
  onOpen: (name: string) => void;
}

const TopAppRow = memo(function TopAppRow({ app, describedBy, tip, onOpen }: TopAppRowProps) {
  return (
    <button
      type="button"
      className={styles.appRow}
      aria-describedby={describedBy}
      onMouseEnter={(event) => tip.show(app, event)}
      onMouseMove={tip.move}
      onMouseLeave={tip.hide}
      onFocus={(event) => tip.show(app, event)}
      onBlur={tip.hide}
      onClick={() => {
        tip.hide();
        onOpen(app.name);
      }}
    >
      <AppAvatar name={app.name} path={app.path} size={22} />
      <span className={styles.appName}>{displayText(app.name)}</span>
      <span className={styles.bar} aria-hidden="true">
        <span
          className={styles.fill}
          style={{ width: `${Math.max(app.scale * 100, 2)}%`, background: appTint(app.name) }}
        ></span>
      </span>
      <span className={styles.total}>{formatBytes(app.totalBytes)}</span>
    </button>
  );
});

const TopApplications = memo(function TopApplications({
  connected,
  onOpen,
}: {
  connected: boolean;
  onOpen: (name: string) => void;
}) {
  const [daySummaries, setDaySummaries] = useState<AppSummary[] | null>(null);
  const topApps = useMemo(
    () => (daySummaries ? topApplications(daySummaries) : null),
    [daySummaries],
  );

  // Same hover card as the activity heatmap, instead of the browser's title tooltip.
  const appTipId = useId();
  const appTip = useFloatingTip<TopApp>({ estimatedTipHeight: 96, followPointer: true });
  // Rows get a stable tip handle; only `hover` changes as the pointer moves between them.
  const { show, move, hide, hover, placement, tipRef } = appTip;
  const rowTip = useMemo(() => ({ show, move, hide }), [show, move, hide]);

  useEffect(() => {
    if (!connected) return;
    let cancelled = false;
    const load = () =>
      loadDaySummaries().then((summaries) => {
        if (!cancelled && summaries) setDaySummaries(summaries);
      });
    void load();
    const timer = setInterval(load, TOP_APPS_REFRESH_MS);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [connected]);

  return (
    <>
      <section className={clsx('panel', styles.topApps)} aria-labelledby="top-apps-title">
        <div className={styles.sectionHeader}>
          <h2 className={styles.sectionTitle} id="top-apps-title">
            {m.dashboard_top_apps_title()}
          </h2>
          <span className={styles.sectionSub}>{m.dashboard_top_apps_sub()}</span>
          <Link className={styles.link} to="/firewall">
            {m.dashboard_view_all()}
            <ChevronRight size={13} strokeWidth={2} aria-hidden="true" />
          </Link>
        </div>
        {topApps === null ? (
          Array.from({ length: TOP_APPS_VISIBLE_ROWS }, (_, index) => (
            <div key={index} className={clsx(styles.appRow, styles.placeholder)} aria-hidden="true">
              <span className={styles.phAvatar}></span>
              <span className={styles.phText}></span>
              <span className={styles.phBar}></span>
              <span className={clsx(styles.phText, styles.short)}></span>
            </div>
          ))
        ) : topApps.length === 0 ? (
          <p className={styles.appsEmpty}>{m.dashboard_top_apps_empty()}</p>
        ) : (
          <ScrollFade visibleRows={TOP_APPS_VISIBLE_ROWS} rowHeight={44} bleed={8}>
            {topApps.map((app) => (
              <TopAppRow
                key={app.path || app.name}
                app={app}
                describedBy={hover?.name === app.name ? appTipId : undefined}
                tip={rowTip}
                onOpen={onOpen}
              />
            ))}
          </ScrollFade>
        )}
      </section>

      {hover &&
        createPortal(
          <div
            ref={tipRef}
            className={clsx(styles.appTip, placement === 'bottom' && styles.below)}
            id={appTipId}
            role="tooltip"
          >
            <div className={styles.tipHead}>
              <span className={styles.tipName}>{displayText(hover.name)}</span>
              <span className={styles.tipShare}>{percentFormat.format(hover.share)}</span>
            </div>
            <div className={styles.tipRow}>
              <span className={clsx(styles.tipSwatch, styles.down)}></span>
              <span className={styles.tipLabel}>{m.dashboard_activity_tip_down()}</span>
              <span className={styles.tipValue}>{formatBytes(hover.bytesReceived)}</span>
            </div>
            <div className={styles.tipRow}>
              <span className={clsx(styles.tipSwatch, styles.up)}></span>
              <span className={styles.tipLabel}>{m.dashboard_activity_tip_up()}</span>
              <span className={styles.tipValue}>{formatBytes(hover.bytesSent)}</span>
            </div>
          </div>,
          document.body,
        )}
    </>
  );
});

export default function DashboardPage() {
  const connected = useSelector(daemon, (d) => d.state.connected);
  const navigate = useNavigate();
  const openAppRecords = useCallback(
    (name: string) => navigate(recordsApplicationUrl(name)),
    [navigate],
  );

  const refreshedWhileConnected = useRef(false);
  useEffect(() => {
    if (!connected) {
      refreshedWhileConnected.current = false;
      return;
    }
    if (refreshedWhileConnected.current) return;
    refreshedWhileConnected.current = true;
    void daemon.refreshAll();
  }, [connected]);

  // Lazy: the dashboard is the default route, so the chart stays out of the
  // first-paint chunk. A remount (dashboard revisit) retries a failed fetch.
  const [Chart, setChart] = useState<ThroughputChartComponent | null>(null);
  useEffect(() => {
    let cancelled = false;
    loadThroughputChart().then(
      (Component) => {
        if (!cancelled) setChart(() => Component);
      },
      (error: unknown) => {
        debugError('dashboard', 'throughput-chart-load-failed', error);
      },
    );
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <div className={styles.page} data-testid="page-dashboard" data-page-motion="dashboard">
      <div className={clsx(styles.scroll, 'scroll')}>
        <CollectorNotice />
        <div className={clsx(styles.statStrip, 'panel')} data-motion-stage="1">
          <RateCell direction="download" />
          <RateCell direction="upload" />
          <ConnectionsCell />
          <BlockedCell />
        </div>

        <ThroughputPanel Chart={Chart} />

        <HeatmapSection />

        <div className={styles.bottomGrid} data-motion-stage="3">
          <TopApplications connected={connected} onOpen={openAppRecords} />
          <ActiveApplicationsPanel connected={connected} onOpen={openAppRecords} />
        </div>
      </div>
    </div>
  );
}
