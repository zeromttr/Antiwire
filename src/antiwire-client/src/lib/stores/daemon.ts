import { api } from '#lib/api/daemon.ts';
import type { RegionStats } from '#lib/utils/region-stats.ts';
import type { HistoryDeletionRange } from '#lib/utils/history-deletion.ts';
import { browserPreviewMode } from '#lib/preview/runtime.ts';
import {
  MAX_ACTIVITY_HISTORY_WEEKS,
  activityWeekRangeSec,
  activityWeekStartSecForOffset,
  sumActivityBytesForLocalDay,
  type ActivityBucket,
} from '#lib/models/activity-heatmap.ts';
import { counterRatePerSecond } from '#lib/models/throughput.ts';
import type {
  AppSummary,
  ConnectionLog,
  CountryRule,
  NotificationEvent,
  Rule,
  Stats,
  Toast,
} from '#lib/types/index.ts';
import { Reactive } from '#lib/state/reactive.ts';
import { catchAsyncError, debugError, debugLog, isNative } from '#lib/utils/index.ts';
import { throughputChart } from './throughput-chart.ts';
import { dashboardStatHistory } from './dashboard-stat-history.ts';
import { livePace, windowActivity } from './window-activity.ts';

/*
 * State model: `daemon.state` is an immutable snapshot. Every change builds a
 * new `DaemonState` object (`#patch`) with the changed members replaced and
 * the rest shared, then notifies once per microtask. So:
 *
 * - `useSelector(daemon, (d) => d.state.connected)` re-renders only when
 *   `connected` changes;
 * - `useSelector(daemon, (d) => d.state.rules)` only when the rules array is
 *   replaced, which happens only when the daemon returned new rules;
 * - never write to `daemon.state` from outside: use the methods.
 *
 * The 1 Hz poll skips the write entirely when nothing it reports changed.
 */

export interface DaemonState {
  connected: boolean;
  connecting: boolean;
  /** When the next automatic connection attempt starts, in epoch ms; null while none waits. */
  nextReconnectAt: number | null;
  error: string | null;
  stats: Stats;
  rules: Rule[];
  countryRules: CountryRule[];
  /** Unfiltered app rollups for the dashboard and as a firewall fallback. */
  appSummaries: AppSummary[];
  /** Records-page logs for the current filter/page. Isolated from analytics. */
  recordsLogs: ConnectionLog[];
  recordsLogsTotalCount: number;
  /** Records-page app rollups for the current filter window. */
  recordsAppSummaries: AppSummary[];
  /** Analytics-page connection sample. Isolated from records filters. */
  analyticsLogs: ConnectionLog[];
  /** Country totals across all saved records, independent of the analytics sample. */
  analyticsCountryStatistics: RegionStats;
  activityBuckets: ActivityBucket[];
  /** Weekly history pager: 0 = current Mon–Sun week, negative = past weeks. */
  activityWeekOffset: number;
  activityWeekBuckets: ActivityBucket[];
  activityWeekStartSec: number | null;
  activityWeekLoading: boolean;
  notifications: NotificationEvent[];
  toasts: Toast[];
  downloadRate: number;
  uploadRate: number;
  socketCount: number;
  bytesToday: number;
  alertCount: number;
}

const MAX_VISIBLE_TOASTS = 5;
const TOAST_DURATION_MS = 4000;
const ACTIVE_POLL_MS = 1000;
/** Visible but unfocused: the rates stay live without redrawing every second. */
const BACKGROUND_POLL_MS = 3000;
const HIDDEN_POLL_MS = 15_000;
/** Four weeks of 30-minute buckets: the heatmap shows one week, the records
 *  quick filters scrub back three more. Retention drops what it cannot keep. */
const ACTIVITY_FETCH_DAYS = 28;

const defaultStats: Stats = {
  bytesSent: 0,
  bytesReceived: 0,
  activeConnections: 0,
  blockedConnections: 0,
  // Assume healthy until the daemon says otherwise, so the warning never flashes on load.
  byteAccountingAvailable: true,
  collectorStatusDetail: '',
  // Unknown until the daemon reports a real sample so a failed read cannot look like zero.
  activeConnectionsAvailable: false,
  activeConnectionsStale: false,
  activeApplications: null,
  databaseSizeBytes: null,
};

function initialState(): DaemonState {
  return {
    connected: false,
    connecting: false,
    nextReconnectAt: null,
    error: null,
    stats: { ...defaultStats },
    rules: [],
    countryRules: [],
    appSummaries: [],
    recordsLogs: [],
    recordsLogsTotalCount: 0,
    recordsAppSummaries: [],
    analyticsLogs: [],
    analyticsCountryStatistics: {
      countryCounts: {},
      totalCount: 0,
      unknownCount: 0,
      unknownPct: 0,
    },
    activityBuckets: [],
    activityWeekOffset: 0,
    activityWeekBuckets: [],
    activityWeekStartSec: null,
    activityWeekLoading: false,
    notifications: [],
    toasts: [],
    downloadRate: 0,
    uploadRate: 0,
    socketCount: 0,
    bytesToday: 0,
    alertCount: 0,
  };
}

type RecordsRefreshOptions = {
  actionFilter?: string;
  timeFilterSeconds?: number;
  timeWindowStart?: number;
  timeWindowEnd?: number;
  offset?: number;
  limit?: number;
  applicationName?: string;
  applicationId?: number;
  searchQuery?: string;
  orderBy?: string;
  sortDescending?: boolean;
  protocolFilter?: string;
  countryFilter?: string;
  portFilter?: number;
  hostFilter?: string;
  refreshSummaries?: boolean;
};

interface PendingRecordsRefresh {
  opts?: RecordsRefreshOptions;
  resolve: () => void;
  reject: (reason?: unknown) => void;
}

function alertCountOf(notifications: readonly NotificationEvent[]): number {
  return notifications.filter((x) => x.severity === 'bad' || x.severity === 'warn').length;
}

export class DaemonStore extends Reactive {
  #state: DaemonState = initialState();

  #reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  #backoffMs = 5000;
  #throughputTimer: ReturnType<typeof setTimeout> | null = null;
  #throughputPollInFlight = false;
  #refreshAllPromise: Promise<void> | null = null;
  #activityPollTick = 0;
  #windowVisible = true;
  #prevReceived = 0;
  #prevSent = 0;
  #previousStatsAt = 0;
  // Last values fanned out to the state + history stores. When a poll observes
  // no change (idle machine, zero traffic), the state write and the per-second
  // history appends are skipped — otherwise every 1 Hz tick re-renders every
  // dashboard subscriber, sparkline and the chart for nothing.
  #lastPushedDl = Number.NaN;
  #lastPushedUl = Number.NaN;
  #lastPushedSockets = Number.NaN;
  #lastPushedBlocked = Number.NaN;
  #lastPushedBytesSent = Number.NaN;
  #lastPushedBytesReceived = Number.NaN;
  #lastPushedByteAccounting: boolean | undefined = undefined;
  #lastPushedCollectorDetail: string | undefined = undefined;
  #lastPushedActiveAvailable: boolean | undefined = undefined;
  #lastPushedActiveStale: boolean | undefined = undefined;
  #lastPushedActiveApplications: number | null | undefined = undefined;
  #lastPushedDatabaseSize: number | null | undefined = undefined;
  #recordsFetchId = 0;
  #analyticsFetchId = 0;
  #recordsSummaryKey: string | null = null;
  #activeRecordsRefresh: PendingRecordsRefresh | null = null;
  #pendingRecordsRefresh: PendingRecordsRefresh | null = null;
  #toastTimers = new Map<string, ReturnType<typeof setTimeout>>();
  /** Retained-week cache: past weeks are immutable, so one fetch per week. */
  #activityWeekCache = new Map<number, ActivityBucket[]>();
  #activityWeekFetchId = 0;
  #stopForeground: () => void;

  constructor() {
    super();
    // Back in front: show current numbers now rather than at the slower tick.
    this.#stopForeground = windowActivity.onForeground(() => {
      if (!this.#windowVisible || !this.#state.connected) return;
      this.#stopThroughputTimer();
      void this.#pollThroughput();
    });
  }

  /** The current snapshot. Replaced, never mutated; see the note at the top of this file. */
  get state(): DaemonState {
    return this.#state;
  }

  #patch(patch: Partial<DaemonState>) {
    this.#state = { ...this.#state, ...patch };
    this.changed();
  }

  /** `activityBuckets` with the derived `bytesToday` and, on the current week, its buckets. */
  #activityPatch(activityBuckets: ActivityBucket[]): Partial<DaemonState> {
    return {
      activityBuckets,
      bytesToday: sumActivityBytesForLocalDay(activityBuckets),
      ...this.#currentWeekPatch(activityBuckets),
    };
  }

  #currentWeekPatch(activityBuckets = this.#state.activityBuckets): Partial<DaemonState> {
    if (this.#state.activityWeekOffset !== 0) return {};
    // Recompute the week anchor on every refresh so a Monday rollover while
    // the app is open moves the current-week window forward automatically.
    const weekStartSec = activityWeekStartSecForOffset(Date.now(), 0);
    const { since, until } = activityWeekRangeSec(weekStartSec);
    return {
      activityWeekStartSec: weekStartSec,
      activityWeekBuckets: activityBuckets.filter(
        (bucket) => bucket.bucketStart >= since && bucket.bucketStart < until,
      ),
    };
  }

  /**
   * Loads one calendar week (Mon–Sun local) of 30-minute buckets.
   *
   * The current week is derived live from the rolling 28-day poll so the
   * heatmap stays fresh without an extra RPC; past weeks fetch their explicit
   * retained range once and cache it. Purged weeks resolve to an empty list.
   */
  readonly loadActivityWeek = async (offsetWeeks: number): Promise<void> => {
    const requested = Math.trunc(offsetWeeks);
    if (!Number.isFinite(requested)) return;
    const clamped = Math.max(-MAX_ACTIVITY_HISTORY_WEEKS, Math.min(0, requested));
    const fetchId = ++this.#activityWeekFetchId;
    const weekStartSec = activityWeekStartSecForOffset(Date.now(), clamped);
    this.#patch({ activityWeekOffset: clamped, activityWeekStartSec: weekStartSec });

    if (clamped === 0) {
      this.#patch({ activityWeekLoading: false, ...this.#currentWeekPatch() });
      return;
    }

    const cached = this.#activityWeekCache.get(weekStartSec);
    if (cached) {
      if (fetchId !== this.#activityWeekFetchId) return;
      this.#patch({ activityWeekBuckets: [...cached], activityWeekLoading: false });
      return;
    }

    this.#patch({ activityWeekLoading: true });
    try {
      const { since, until } = activityWeekRangeSec(weekStartSec);
      const buckets = await api.getActivityBuckets({ since, until });
      if (fetchId !== this.#activityWeekFetchId) return;
      this.#activityWeekCache.set(weekStartSec, [...buckets]);
      // A week is 336 buckets; cap the cache so unlimited paging cannot grow
      // it without bound (52 weeks max depth, plus margin for week rollover).
      while (this.#activityWeekCache.size > MAX_ACTIVITY_HISTORY_WEEKS + 2) {
        const oldest = this.#activityWeekCache.keys().next();
        if (oldest.done) break;
        this.#activityWeekCache.delete(oldest.value);
      }
      this.#patch({ activityWeekBuckets: [...buckets] });
    } catch (e) {
      if (fetchId !== this.#activityWeekFetchId) return;
      debugError('daemon', 'loadActivityWeek:failed', e);
    } finally {
      if (fetchId === this.#activityWeekFetchId) this.#patch({ activityWeekLoading: false });
    }
  };

  readonly connect = async (): Promise<void> => {
    if ((!isNative() && !browserPreviewMode) || this.#state.connecting) return;
    // This attempt replaces the one that was waiting, whoever asked for it.
    this.#cancelReconnect();
    this.#patch({ connecting: true, error: null, nextReconnectAt: null });
    try {
      await api.connectDaemon();
      const status = await api.getConnectionStatus();
      // A connect that returns without a connection has failed too, and is retried.
      if (!status.connected) throw new Error('Daemon not connected');
      this.#patch({ connected: true });
      this.#backoffMs = 5000;
      this.#prevReceived = 0;
      this.#prevSent = 0;
      this.#previousStatsAt = 0;
      dashboardStatHistory.reset();
      this.#recordsSummaryKey = null;
      this.#activityPollTick = 0;
      this.#activityWeekFetchId += 1;
      this.#activityWeekCache.clear();
      this.#patch({
        activityWeekOffset: 0,
        activityWeekStartSec: activityWeekStartSecForOffset(Date.now(), 0),
        activityWeekBuckets: [],
        activityWeekLoading: false,
      });
      await this.refreshAll();
      if (import.meta.env?.DEV && browserPreviewMode === 'sample') {
        // Populate history immediately so a newly opened preview has useful charts.
        for (let i = 0; i < 80; i++) {
          throughputChart.record(
            2600000 + Math.sin(i / 5) * 900000,
            340000 + Math.cos(i / 7) * 150000,
          );
          dashboardStatHistory.record(
            42 + Math.round(Math.sin(i / 6) * 8),
            this.#state.stats.blockedConnections,
          );
        }
        this.#patch({ downloadRate: 2600000, uploadRate: 340000 });
      }
      this.#startThroughputTimer();
    } catch (e) {
      this.#patch({ connected: false, error: e instanceof Error ? e.message : String(e) });
      this.#scheduleReconnect();
    } finally {
      this.#patch({ connecting: false });
    }
  };

  #cancelReconnect() {
    if (this.#reconnectTimer) clearTimeout(this.#reconnectTimer);
    this.#reconnectTimer = null;
  }

  #scheduleReconnect() {
    this.#cancelReconnect();
    this.#reconnectTimer = setTimeout(() => {
      this.#reconnectTimer = null;
      void this.connect();
      this.#backoffMs = Math.min(this.#backoffMs * 2, 60000);
    }, this.#backoffMs);
    this.#patch({ nextReconnectAt: Date.now() + this.#backoffMs });
  }

  #stopThroughputTimer() {
    if (this.#throughputTimer) clearTimeout(this.#throughputTimer);
    this.#throughputTimer = null;
  }

  #throughputPollDelay() {
    return this.#windowVisible ? livePace(ACTIVE_POLL_MS, BACKGROUND_POLL_MS) : HIDDEN_POLL_MS;
  }

  #scheduleThroughputPoll() {
    if (!this.#state.connected || this.#throughputTimer) return;
    this.#throughputTimer = setTimeout(() => {
      this.#throughputTimer = null;
      void this.#pollThroughput();
    }, this.#throughputPollDelay());
  }

  readonly setWindowVisible = (visible: boolean) => {
    if (this.#windowVisible === visible) return;
    this.#windowVisible = visible;
    this.#stopThroughputTimer();
    if (!this.#state.connected) return;
    if (visible) {
      void this.#pollThroughput();
    } else {
      this.#scheduleThroughputPoll();
    }
  };

  async #pollThroughput() {
    if (!this.#state.connected || this.#throughputPollInFlight) return;
    this.#throughputPollInFlight = true;
    try {
      const stats = await api.getStats();
      const sampledAt = Date.now();
      const elapsed = sampledAt - this.#previousStatsAt;
      const dl =
        this.#previousStatsAt === 0
          ? 0
          : counterRatePerSecond(stats.bytesReceived, this.#prevReceived, elapsed);
      const ul =
        this.#previousStatsAt === 0
          ? 0
          : counterRatePerSecond(stats.bytesSent, this.#prevSent, elapsed);
      this.#prevReceived = stats.bytesReceived;
      this.#prevSent = stats.bytesSent;
      this.#previousStatsAt = sampledAt;

      if (this.#windowVisible) {
        const sockets = stats.activeConnections;
        const blocked = stats.blockedConnections;
        const unchanged =
          dl === this.#lastPushedDl &&
          ul === this.#lastPushedUl &&
          sockets === this.#lastPushedSockets &&
          blocked === this.#lastPushedBlocked &&
          stats.bytesSent === this.#lastPushedBytesSent &&
          stats.bytesReceived === this.#lastPushedBytesReceived &&
          stats.byteAccountingAvailable === this.#lastPushedByteAccounting &&
          stats.collectorStatusDetail === this.#lastPushedCollectorDetail &&
          stats.activeConnectionsAvailable === this.#lastPushedActiveAvailable &&
          stats.activeConnectionsStale === this.#lastPushedActiveStale &&
          stats.activeApplications === this.#lastPushedActiveApplications &&
          stats.databaseSizeBytes === this.#lastPushedDatabaseSize;
        if (!unchanged) {
          this.#lastPushedDl = dl;
          this.#lastPushedUl = ul;
          this.#lastPushedSockets = sockets;
          this.#lastPushedBlocked = blocked;
          this.#lastPushedBytesSent = stats.bytesSent;
          this.#lastPushedBytesReceived = stats.bytesReceived;
          this.#lastPushedByteAccounting = stats.byteAccountingAvailable;
          this.#lastPushedCollectorDetail = stats.collectorStatusDetail;
          this.#lastPushedActiveAvailable = stats.activeConnectionsAvailable;
          this.#lastPushedActiveStale = stats.activeConnectionsStale;
          this.#lastPushedActiveApplications = stats.activeApplications;
          this.#lastPushedDatabaseSize = stats.databaseSizeBytes;
          const patch: Partial<DaemonState> = {
            downloadRate: dl,
            uploadRate: ul,
            stats,
            bytesToday: sumActivityBytesForLocalDay(this.#state.activityBuckets),
          };
          if (stats.activeConnectionsAvailable) {
            patch.socketCount = sockets;
            dashboardStatHistory.record(sockets, blocked);
          } else if (this.#lastPushedActiveAvailable) {
            dashboardStatHistory.record(this.#lastPushedSockets, blocked);
          }
          this.#patch(patch);
          throughputChart.record(dl, ul);
        }

        this.#activityPollTick += 1;
        if (this.#activityPollTick % 30 === 0) {
          void catchAsyncError(
            api.getActivityBuckets({ days: ACTIVITY_FETCH_DAYS }).then((buckets) => {
              this.#patch(this.#activityPatch(buckets));
            }),
            (error) => debugError('daemon', 'pollThroughput:activity-failed', error),
          );
        }
      }
    } catch {
      this.#patch({ connected: false });
      this.#stopThroughputTimer();
      this.#scheduleReconnect();
    } finally {
      this.#throughputPollInFlight = false;
      this.#scheduleThroughputPoll();
    }
  }

  #startThroughputTimer() {
    this.#stopThroughputTimer();
    this.#scheduleThroughputPoll();
  }

  readonly refreshAll = (): Promise<void> => {
    if (!this.#state.connected) return Promise.resolve();
    if (this.#refreshAllPromise) return this.#refreshAllPromise;

    const current = (async () => {
      try {
        const [
          statsResult,
          rulesResult,
          summariesResult,
          countryResult,
          activityResult,
          alertsResult,
        ] = await Promise.allSettled([
          api.getStats().then((stats) => ({ stats, sampledAt: Date.now() })),
          api.getRules(),
          api.getAppSummaries(),
          api.getCountryRules(),
          api.getActivityBuckets({ days: ACTIVITY_FETCH_DAYS }),
          api.getAlerts(),
        ]);

        const patch: Partial<DaemonState> = {};

        if (statsResult.status === 'fulfilled') {
          const { stats, sampledAt } = statsResult.value;
          patch.stats = stats;
          if (stats.activeConnectionsAvailable) {
            patch.socketCount = stats.activeConnections;
            dashboardStatHistory.record(stats.activeConnections, stats.blockedConnections);
          }
          this.#prevReceived = stats.bytesReceived;
          this.#prevSent = stats.bytesSent;
          this.#previousStatsAt = sampledAt;
        }

        if (rulesResult.status === 'fulfilled') {
          patch.rules = [...rulesResult.value];
        }

        if (summariesResult.status === 'fulfilled') {
          patch.appSummaries = [...(summariesResult.value.applications ?? [])];
          this.#recordsSummaryKey = null;
        }

        if (countryResult.status === 'fulfilled') {
          patch.countryRules = [...countryResult.value];
        }

        if (alertsResult.status === 'fulfilled') {
          const merged = new Map<string, NotificationEvent>();
          for (const notification of this.#state.notifications) {
            merged.set(notification.id, notification);
          }
          for (const notification of alertsResult.value) {
            merged.set(notification.id, notification);
          }
          patch.notifications = [...merged.values()]
            .sort((a, b) => Number(b.timestamp) - Number(a.timestamp))
            .slice(0, 100);
          patch.alertCount = alertCountOf(patch.notifications);
        }

        this.#patch(patch);

        if (activityResult.status === 'fulfilled') {
          if (this.#state.activityWeekStartSec == null) {
            this.#patch({
              activityWeekStartSec: activityWeekStartSecForOffset(Date.now(), 0),
            });
          }
          this.#patch(this.#activityPatch([...activityResult.value]));
        }

        if (
          statsResult.status === 'rejected' &&
          rulesResult.status === 'rejected' &&
          summariesResult.status === 'rejected'
        ) {
          throw statsResult.reason;
        }
      } catch (e) {
        this.#patch({ error: e instanceof Error ? e.message : String(e) });
      }
    })();

    this.#refreshAllPromise = current;
    void current.finally(() => {
      if (this.#refreshAllPromise === current) this.#refreshAllPromise = null;
    });
    return current;
  };

  readonly loadConnectionLogs = async (opts?: {
    offset?: number;
    limit?: number;
    applicationName?: string;
    actionFilter?: string;
    timeFilterSeconds?: number;
    timeWindowStart?: number;
    timeWindowEnd?: number;
    searchQuery?: string;
    orderBy?: string;
    sortDescending?: boolean;
    protocolFilter?: string;
  }): Promise<boolean> => {
    if (!this.#state.connected) return false;
    const fetchId = ++this.#analyticsFetchId;
    try {
      const [page, countryStatistics] = await Promise.all([
        api.getConnectionLogs({
          offset: opts?.offset ?? 0,
          limit: opts?.limit ?? 1000,
          applicationName: opts?.applicationName,
          actionFilter: opts?.actionFilter,
          timeFilterSeconds: opts?.timeFilterSeconds,
          timeWindowStart: opts?.timeWindowStart,
          timeWindowEnd: opts?.timeWindowEnd,
          searchQuery: opts?.searchQuery,
          orderBy: opts?.orderBy,
          sortDescending: opts?.sortDescending,
          protocolFilter: opts?.protocolFilter,
        }),
        api.getCountryStatistics(),
      ]);
      if (fetchId !== this.#analyticsFetchId) return false;
      this.#patch({ analyticsLogs: [...page.logs], analyticsCountryStatistics: countryStatistics });
      return true;
    } catch (e) {
      if (fetchId !== this.#analyticsFetchId) return false;
      debugError('daemon', 'loadConnectionLogs:failed', e);
      throw e;
    }
  };

  #recordsSummaryCacheKey(opts?: RecordsRefreshOptions) {
    return `${opts?.actionFilter ?? ''}\u0000${opts?.timeFilterSeconds ?? 0}\u0000${opts?.timeWindowStart ?? ''}\u0000${opts?.timeWindowEnd ?? ''}`;
  }

  async #runRecordsRefresh(request: PendingRecordsRefresh) {
    const { opts } = request;
    const fetchId = ++this.#recordsFetchId;
    const summaryKey = this.#recordsSummaryCacheKey(opts);
    const shouldRefreshSummaries =
      opts?.refreshSummaries === true || this.#recordsSummaryKey !== summaryKey;

    debugLog('daemon', 'refreshRecords:start', {
      fetchId,
      opts,
      refreshSummaries: shouldRefreshSummaries,
    });

    try {
      const [logsResult, summariesResult] = await Promise.allSettled([
        api.getConnectionLogs({
          offset: opts?.offset ?? 0,
          limit: opts?.limit ?? 200,
          actionFilter: opts?.actionFilter,
          timeFilterSeconds: opts?.timeFilterSeconds,
          timeWindowStart: opts?.timeWindowStart,
          timeWindowEnd: opts?.timeWindowEnd,
          applicationName: opts?.applicationName,
          applicationId: opts?.applicationId,
          searchQuery: opts?.searchQuery,
          orderBy: opts?.orderBy,
          sortDescending: opts?.sortDescending,
          protocolFilter: opts?.protocolFilter,
          countryFilter: opts?.countryFilter,
          portFilter: opts?.portFilter,
          hostFilter: opts?.hostFilter,
        }),
        shouldRefreshSummaries
          ? api.getAppSummaries({
              actionFilter: opts?.actionFilter,
              timeFilterSeconds: opts?.timeFilterSeconds,
              timeWindowStart: opts?.timeWindowStart,
              timeWindowEnd: opts?.timeWindowEnd,
            })
          : Promise.resolve(null),
      ]);

      if (logsResult.status === 'fulfilled') {
        this.#patch({
          recordsLogs: [...logsResult.value.logs],
          recordsLogsTotalCount: logsResult.value.totalCount,
        });
        debugLog('daemon', 'refreshRecords:logs', {
          fetchId,
          rows: logsResult.value.logs.length,
          totalCount: logsResult.value.totalCount,
        });
      } else {
        debugError('daemon', 'refreshRecords:logs-failed', logsResult.reason);
      }

      if (summariesResult.status === 'fulfilled' && summariesResult.value) {
        this.#patch({ recordsAppSummaries: [...(summariesResult.value.applications ?? [])] });
        this.#recordsSummaryKey = summaryKey;
        debugLog('daemon', 'refreshRecords:summaries', {
          fetchId,
          apps: summariesResult.value.applications?.length ?? 0,
          totalCount: summariesResult.value.totalCount,
        });
      } else if (summariesResult.status === 'rejected') {
        debugError('daemon', 'refreshRecords:summaries-failed', summariesResult.reason);
      }

      if (logsResult.status === 'rejected') {
        throw logsResult.reason;
      }

      debugLog('daemon', 'refreshRecords:done', { fetchId });
      request.resolve();
    } catch (e) {
      request.reject(e);
    }
  }

  #startNextRecordsRefresh() {
    const request = this.#activeRecordsRefresh;
    if (!request) return;

    void this.#runRecordsRefresh(request).finally(() => {
      if (this.#activeRecordsRefresh !== request) return;
      this.#activeRecordsRefresh = this.#pendingRecordsRefresh;
      this.#pendingRecordsRefresh = null;
      if (this.#activeRecordsRefresh) this.#startNextRecordsRefresh();
    });
  }

  readonly refreshRecords = (opts?: RecordsRefreshOptions): Promise<void> => {
    if (!this.#state.connected) {
      return Promise.reject(new Error('Daemon not connected'));
    }

    let resolveRequest!: () => void;
    let rejectRequest!: (reason?: unknown) => void;
    const promise = new Promise<void>((resolve, reject) => {
      resolveRequest = resolve;
      rejectRequest = reject;
    });
    const request: PendingRecordsRefresh = {
      opts,
      resolve: resolveRequest,
      reject: rejectRequest,
    };

    if (this.#activeRecordsRefresh) {
      // Keep only the newest queued filter/page state. Settle any superseded
      // pending request when the latest request completes so callers do not
      // resolve prematurely with stale records.
      if (this.#pendingRecordsRefresh) {
        const prev = this.#pendingRecordsRefresh;
        const currentResolve = request.resolve;
        const currentReject = request.reject;
        request.resolve = () => {
          prev.resolve();
          currentResolve();
        };
        request.reject = (reason?: unknown) => {
          prev.reject(reason);
          currentReject(reason);
        };
      }
      this.#pendingRecordsRefresh = request;
      return promise;
    }

    this.#activeRecordsRefresh = request;
    this.#startNextRecordsRefresh();
    return promise;
  };

  #setNotifications(notifications: NotificationEvent[]) {
    this.#patch({ notifications, alertCount: alertCountOf(notifications) });
  }

  readonly addNotification = (n: NotificationEvent) => {
    if (this.#state.notifications.some((notification) => notification.id === n.id)) return;
    this.#setNotifications([n, ...this.#state.notifications].slice(0, 100));
  };

  readonly dismissNotification = async (id: string) => {
    const dismissed = await api.dismissAlert(id);
    if (!dismissed) throw new Error('The alert could not be dismissed');
    this.#setNotifications(
      this.#state.notifications.filter((notification) => notification.id !== id),
    );
  };

  readonly clearAlerts = async () => {
    const cleared = await api.clearAlerts();
    if (!cleared) throw new Error('The alerts could not be cleared');
    this.#setNotifications([]);
  };

  /**
   * Deletes history in the daemon, then drops the local copies of it: alerts
   * are merged rather than replaced on refresh, and past activity weeks are
   * cached, so neither would otherwise go away. Resolves to the rows removed.
   */
  readonly deleteHistory = async (range: HistoryDeletionRange): Promise<number> => {
    const deleted = await api.deleteHistory(range);
    this.#setNotifications(
      range.all
        ? []
        : this.#state.notifications.filter(
            (notification) => Number(notification.timestamp) < range.since,
          ),
    );
    this.#activityWeekFetchId += 1;
    this.#activityWeekCache.clear();
    this.#recordsSummaryKey = null;
    await this.refreshAll();
    if (this.#state.activityWeekOffset !== 0) {
      await this.loadActivityWeek(this.#state.activityWeekOffset);
    }
    return deleted;
  };

  #clearToastTimer(id: string) {
    const timer = this.#toastTimers.get(id);
    if (timer === undefined) return;
    clearTimeout(timer);
    this.#toastTimers.delete(id);
  }

  readonly addToast = (title: string, body: string, color: string) => {
    const toast: Toast = { id: crypto.randomUUID(), title, body, color };
    const next = [...this.#state.toasts, toast];
    const evicted =
      next.length > MAX_VISIBLE_TOASTS ? next.slice(0, next.length - MAX_VISIBLE_TOASTS) : [];
    for (const item of evicted) {
      this.#clearToastTimer(item.id);
    }
    this.#patch({ toasts: next.slice(-MAX_VISIBLE_TOASTS) });
    this.#toastTimers.set(
      toast.id,
      setTimeout(() => {
        this.#toastTimers.delete(toast.id);
        this.#patch({ toasts: this.#state.toasts.filter((t) => t.id !== toast.id) });
      }, TOAST_DURATION_MS),
    );
  };

  readonly dismissToast = (id: string) => {
    this.#clearToastTimer(id);
    if (!this.#state.toasts.some((t) => t.id === id)) return;
    this.#patch({ toasts: this.#state.toasts.filter((t) => t.id !== id) });
  };

  /**
   * Stops every timer (poll, reconnect, toasts) and the foreground listener.
   * The app never calls it; tests and hot reload do.
   */
  readonly dispose = () => {
    this.#stopThroughputTimer();
    this.#cancelReconnect();
    for (const timer of this.#toastTimers.values()) clearTimeout(timer);
    this.#toastTimers.clear();
    this.#stopForeground();
  };
}

export const daemon = new DaemonStore();
