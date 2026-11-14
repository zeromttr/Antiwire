import type { AppSummary, ConnectionLog } from '#lib/types/index.ts';
import type { ActivityBucket } from '#lib/models/activity-heatmap.ts';
import { m } from '#lib/i18n/messages.ts';
import type { RecordsSortKey } from '#lib/models/records-sort.ts';
import { debugError, debugLog, debugWarn, formatCompactCount } from '#lib/utils/index.ts';
import { windowActivity } from '#lib/stores/window-activity.ts';
import { TrackedReactive } from '#lib/state/tracked.ts';
import {
  RECORDS_PAGE_SIZE,
  buildRecordsAppList,
  canPageBack,
  canPageForward,
  nextRecordsSort,
  recordsColumnDefs,
  recordsGrandTotal,
  recordsHref,
  recordsLogItemKey,
  recordsLogKeys,
  recordsNoAppMatch,
  liveAppIndex,
  recordsAppFilterCounts,
  recordsRefreshOptions,
  recordsScopeStats,
  recordsUrlFilters,
  recordsUrlLoadKey,
  recordsVisibleEnd,
  shouldRefreshSummaries,
  type RecordFacets,
  type RecordsAppFilter,
  type RecordsVerdict,
} from './list/records-list';

const FILTER_DEBOUNCE_MS = 300;
const RELATIVE_TIME_MS = 30_000;
/** Realtime reloads at most this often while the window is unfocused. */
const REALTIME_BACKGROUND_MS = 3_000;
/** Keep the arrival highlight on a row for a beat after its entrance animation. */
const NEW_RECORD_HIGHLIGHT_MS = 900;

export type RecordsRefreshCall = ReturnType<typeof recordsRefreshOptions> & {
  refreshSummaries: boolean;
};

export type RecordsHost = {
  readonly connected: boolean;
  readonly logs: readonly ConnectionLog[];
  readonly summaries: readonly AppSummary[];
  readonly logsTotalCount: number;
  readonly activityBuckets: readonly ActivityBucket[];
  refreshRecords(opts: RecordsRefreshCall): Promise<void>;
  /** Opens the daemon's live traffic stream and resolves with its unsubscribe. */
  subscribeTraffic(handler: () => void): Promise<() => void>;
  toast(title: string, body: string, color: string): void;
  currentUrl(): { pathname: string; search: string };
  goto(href: string): void;
};

/**
 * Records route state and daemon loads. The page owns connect/URL/skeleton
 * effects and the presentational panels; this class owns filters, paging,
 * and inspect so those stay testable without a DOM.
 */
export class RecordsWorkspace extends TrackedReactive {
  appQuery = '';
  /** Which applications the panel lists. */
  appFilter: RecordsAppFilter = 'all';
  /** Applications with live connections, from the shared live poll. */
  liveApps: readonly {
    name: string;
    path: string;
    connections: number;
    downloadRate: number;
    uploadRate: number;
  }[] = [];
  selectedApp = 'ALL';
  /** Exact application row id for the selection; undefined means name-wide. */
  selectedAppId: number | undefined = undefined;
  filter = '';
  /** Exact filters from the quick filter chips. */
  facets: RecordFacets = {};
  proto = 'ALL';
  verdict: RecordsVerdict = 'all';
  sortKey: RecordsSortKey | null = null;
  sortDir: 1 | -1 = -1;
  now = Date.now();
  pageOffset = 0;
  recordsLoading = true;
  timeWindowStart: number | undefined = undefined;
  timeWindowEnd: number | undefined = undefined;
  selectedRecord: ConnectionLog | null = null;
  detailOpen = false;
  realtime = false;
  /** Keys of rows that arrived from the live stream, for the arrival animation. */
  newRecordKeys: ReadonlySet<string> = new Set();

  private loadRequestId = 0;
  private lastUrlLoadKey = '';
  private filterDebounceTimer: ReturnType<typeof setTimeout> | null = null;
  private clockTimer: ReturnType<typeof setInterval> | null = null;
  private realtimeToken = 0;
  private realtimeUnlisten: (() => void) | null = null;
  private realtimeRefreshing = false;
  private realtimePending = false;
  private realtimeLastAt = 0;
  private realtimeDeferTimer: ReturnType<typeof setTimeout> | null = null;
  private stopForeground: (() => void) | null = null;
  /** Base-identity occurrence counts from the last load (see recordsLogKeys). */
  private knownRecordCounts = new Map<string, number>();
  private newRecordTimers = new Map<string, ReturnType<typeof setTimeout>>();

  get connected() {
    return this.host.connected;
  }

  get logs() {
    return this.host.logs;
  }

  get summaries() {
    return this.host.summaries;
  }

  get logsTotalCount() {
    return this.host.logsTotalCount;
  }

  get activityBuckets() {
    return this.host.activityBuckets;
  }

  get grandTotal() {
    return recordsGrandTotal(this.summaries, this.logsTotalCount);
  }

  get liveIndex() {
    const liveApps = this.liveApps;
    return this.memo('liveIndex', [liveApps], () => liveAppIndex(liveApps));
  }

  // Filters and sorts every application; read by the panel, `noAppMatch` and `selectApp`.
  get appList() {
    const { summaries, appQuery: query, selectedApp, selectedAppId, grandTotal } = this;
    const { appFilter: filter, liveIndex: live } = this;
    const allLabel = m.records_all_applications();
    const deps = [summaries, query, selectedApp, selectedAppId, grandTotal, filter, live, allLabel];
    return this.memo('appList', deps, () =>
      buildRecordsAppList(summaries, {
        query,
        selectedApp,
        selectedAppId,
        allLabel,
        grandTotal,
        filter,
        live,
      }),
    );
  }

  get appFilterCounts() {
    return recordsAppFilterCounts(this.summaries, this.liveIndex);
  }

  get noAppMatch() {
    return recordsNoAppMatch(this.appQuery, this.appList.length);
  }

  /** Allowed, blocked and byte totals for the selected scope. */
  get scopeStats() {
    const { summaries, selectedApp, selectedAppId } = this;
    return this.memo('scopeStats', [summaries, selectedApp, selectedAppId], () =>
      recordsScopeStats(summaries, selectedApp, selectedAppId),
    );
  }

  get activeSortKey() {
    return this.sortKey ?? 'lastSeen';
  }

  get activeSortDir() {
    return this.sortKey ? this.sortDir : -1;
  }

  get canGoBack() {
    return canPageBack(this.pageOffset);
  }

  get canGoForward() {
    return canPageForward(this.pageOffset, this.logsTotalCount);
  }

  get visibleCount() {
    return this.logs.length;
  }

  get visibleEnd() {
    return recordsVisibleEnd(this.pageOffset, this.visibleCount);
  }

  get totalCountLabel() {
    return formatCompactCount(this.logsTotalCount);
  }

  get visibleCountLabel() {
    return formatCompactCount(this.visibleEnd);
  }

  /** One application selected: its name would repeat on every row. */
  get showApplicationColumn() {
    return this.selectedApp === 'ALL';
  }

  get colDefs() {
    return recordsColumnDefs(this.showApplicationColumn);
  }

  get wantsSidebarSkeleton() {
    return this.recordsLoading && this.summaries.length === 0;
  }

  get wantsGridSkeleton() {
    return this.recordsLoading;
  }

  constructor(private readonly host: RecordsHost) {
    super();
    this.track(
      'appQuery',
      'appFilter',
      'liveApps',
      'selectedApp',
      'selectedAppId',
      'filter',
      'facets',
      'proto',
      'verdict',
      'sortKey',
      'sortDir',
      'now',
      'pageOffset',
      'recordsLoading',
      'timeWindowStart',
      'timeWindowEnd',
      'selectedRecord',
      'detailOpen',
      'realtime',
      'newRecordKeys',
    );
  }

  applyUrlFilters = (search: string) => {
    const filters = recordsUrlFilters(search);
    this.selectedApp = filters.application ?? 'ALL';
    // An id without a name (or with ALL) selects nothing exact.
    this.selectedAppId =
      filters.application && filters.applicationId ? filters.applicationId : undefined;
    this.timeWindowStart = filters.timeWindowStart;
    this.timeWindowEnd = filters.timeWindowEnd;
    this.pageOffset = 0;
  };

  syncUrl = () => {
    const next = recordsHref(
      this.selectedApp,
      this.timeWindowStart,
      this.timeWindowEnd,
      this.selectedAppId,
    );
    const url = this.host.currentUrl();
    const current = `${url.pathname}${url.search}`;
    if (next !== current) {
      this.host.goto(next);
    }
  };

  onUrlChange = (search: string) => {
    this.applyUrlFilters(search);

    if (!this.host.connected) {
      this.lastUrlLoadKey = '';
      this.recordsLoading = false;
      return;
    }

    const loadKey = recordsUrlLoadKey(search);
    if (loadKey === this.lastUrlLoadKey) return;
    this.lastUrlLoadKey = loadKey;
    void this.load('url-change', search);
  };

  selectApp = (key: string) => {
    debugLog('records', 'selectApp', { key, previous: this.selectedApp });
    // The panel passes the row key (`name::path`), which is unique per
    // install path; a bare name falls back to the legacy name-wide match.
    const row = this.appList.find((item) => item.key === key);
    if (row) {
      this.selectedApp = row.isAll ? 'ALL' : row.name;
      this.selectedAppId = row.isAll ? undefined : row.appId || undefined;
    } else {
      this.selectedApp = key;
      this.selectedAppId = undefined;
    }
    // The inspected record belongs to the previous scope.
    this.detailOpen = false;
    this.pageOffset = 0;
    this.syncUrl();
  };

  clearTimeWindow = () => {
    this.timeWindowStart = undefined;
    this.timeWindowEnd = undefined;
    this.pageOffset = 0;
    this.syncUrl();
  };

  selectTimeWindow = (start: number, end: number) => {
    if (!Number.isFinite(start) || !Number.isFinite(end) || end <= start) return;
    this.timeWindowStart = start;
    this.timeWindowEnd = end;
    this.pageOffset = 0;
    this.syncUrl();
  };

  selectProto = (next: string) => {
    if (this.proto === next) return;
    this.proto = next;
    this.pageOffset = 0;
    return this.load('proto-change');
  };

  selectVerdict = (next: RecordsVerdict) => {
    if (this.verdict === next) return;
    debugLog('records', 'selectVerdict', { next, previous: this.verdict });
    this.verdict = next;
    this.pageOffset = 0;
    return this.load('verdict-change');
  };

  /** Set or clear one kind of exact filter; setting replaces the previous value of that kind. */
  setFacet = <K extends keyof RecordFacets>(kind: K, value: RecordFacets[K] | undefined) => {
    if (this.facets[kind] === value) return;
    const next = { ...this.facets };
    if (value === undefined) delete next[kind];
    else next[kind] = value;
    this.facets = next;
    this.pageOffset = 0;
    return this.load('facet-change');
  };

  onFilterInput = (value: string) => {
    this.filter = value;
    if (this.filterDebounceTimer) clearTimeout(this.filterDebounceTimer);
    this.filterDebounceTimer = setTimeout(() => {
      this.pageOffset = 0;
      void this.load('filter-change');
    }, FILTER_DEBOUNCE_MS);
  };

  toggleSort = (key: RecordsSortKey) => {
    const next = nextRecordsSort(this.sortKey, this.sortDir, key);
    this.sortKey = next.sortKey;
    this.sortDir = next.sortDir;
    this.pageOffset = 0;
    return this.load('sort-change');
  };

  goToPreviousPage = () => {
    if (!this.canGoBack || this.recordsLoading) return;
    this.pageOffset = Math.max(0, this.pageOffset - RECORDS_PAGE_SIZE);
    return this.load('page-back');
  };

  goToNextPage = () => {
    if (!this.canGoForward || this.recordsLoading) return;
    this.pageOffset += RECORDS_PAGE_SIZE;
    return this.load('page-forward');
  };

  refresh = async () => {
    if (!this.host.connected || this.recordsLoading) return;
    await this.load('manual-refresh');
  };

  toggleRealtime = () => {
    this.realtime = !this.realtime;
    if (this.realtime) {
      if (typeof document !== 'undefined') {
        document.addEventListener('visibilitychange', this.onVisibilityChange);
      }
      void this.subscribeRealtime();
    } else {
      if (typeof document !== 'undefined') {
        document.removeEventListener('visibilitychange', this.onVisibilityChange);
      }
      this.unsubscribeRealtime();
    }
  };

  private async subscribeRealtime() {
    const token = ++this.realtimeToken;
    try {
      const unlisten = await this.host.subscribeTraffic(this.onTrafficEvent);
      if (!this.realtime || token !== this.realtimeToken) {
        unlisten();
        return;
      }
      this.realtimeUnlisten = unlisten;
    } catch (e) {
      debugError('records', 'realtime-subscribe-failed', e);
    }
  }

  private unsubscribeRealtime() {
    this.realtimeToken += 1;
    this.realtimePending = false;
    this.cancelDeferredRefresh();
    this.realtimeUnlisten?.();
    this.realtimeUnlisten = null;
  }

  /** Reopen the stream after a reconnect; the old subscription ends with the daemon. */
  realtimeResync = () => {
    if (!this.realtime) return;
    // Re-adding the same listener is a no-op; after `dispose()` it restores it.
    if (typeof document !== 'undefined') {
      document.addEventListener('visibilitychange', this.onVisibilityChange);
    }
    this.unsubscribeRealtime();
    void this.subscribeRealtime();
  };

  private onTrafficEvent = () => {
    void this.realtimeRefresh();
  };

  private onVisibilityChange = () => {
    if (typeof document !== 'undefined' && !document.hidden) void this.realtimeRefresh();
  };

  /**
   * Latest-wins refresh: at most one query in flight and one queued, so a burst
   * of traffic events cannot stack queries. The daemon pushes events; the only
   * timer defers a refresh while the window is unfocused, to at most one every
   * `REALTIME_BACKGROUND_MS`.
   */
  realtimeRefresh = async () => {
    if (!this.realtime || !this.host.connected) return;
    if (typeof document !== 'undefined' && document.hidden) {
      this.realtimePending = true;
      return;
    }
    if (windowActivity.background) {
      const wait = REALTIME_BACKGROUND_MS - (Date.now() - this.realtimeLastAt);
      if (wait > 0) {
        this.realtimeDeferTimer ??= setTimeout(() => {
          this.realtimeDeferTimer = null;
          void this.realtimeRefresh();
        }, wait);
        return;
      }
    }
    if (this.recordsLoading) return;
    if (this.realtimeRefreshing) {
      this.realtimePending = true;
      return;
    }
    this.realtimeRefreshing = true;
    this.realtimeLastAt = Date.now();
    try {
      await this.load('realtime', undefined, { silent: true });
    } finally {
      this.realtimeRefreshing = false;
      if (this.realtimePending) {
        this.realtimePending = false;
        if (this.realtime) void this.realtimeRefresh();
      }
    }
  };

  private markNewRecords(keys: string[]) {
    const next = new Set(this.newRecordKeys);
    for (const key of keys) {
      next.add(key);
      const existing = this.newRecordTimers.get(key);
      if (existing) clearTimeout(existing);
      this.newRecordTimers.set(
        key,
        setTimeout(() => {
          this.newRecordTimers.delete(key);
          const remaining = new Set(this.newRecordKeys);
          remaining.delete(key);
          this.newRecordKeys = remaining;
        }, NEW_RECORD_HIGHLIGHT_MS),
      );
    }
    this.newRecordKeys = next;
  }

  private trackRecordArrivals(reason: string) {
    const logs = this.host.logs;
    const counts = new Map<string, number>();
    for (const row of logs) {
      const base = recordsLogItemKey(row);
      counts.set(base, (counts.get(base) ?? 0) + 1);
    }
    if (reason === 'realtime' && this.knownRecordCounts.size > 0) {
      // Multiset diff: identical base identities can repeat (parallel flows
      // sharing one timestamp second), so a Set diff would collapse them and
      // flag the wrong row. Highlight the earliest list occurrences of each
      // grown identity — the list sorts newest-first, so arrivals land on top.
      const pending = new Map<string, number>();
      for (const [base, count] of counts) {
        const delta = count - (this.knownRecordCounts.get(base) ?? 0);
        if (delta > 0) pending.set(base, delta);
      }
      if (pending.size > 0) {
        const keys = recordsLogKeys(logs);
        const arrivals: string[] = [];
        logs.forEach((row, index) => {
          const base = recordsLogItemKey(row);
          const left = pending.get(base) ?? 0;
          if (left <= 0) return;
          pending.set(base, left - 1);
          const key = keys[index];
          if (key !== undefined) arrivals.push(key);
        });
        if (arrivals.length > 0) this.markNewRecords(arrivals);
      }
    }
    this.knownRecordCounts = counts;
  }

  inspectRecord = (row: ConnectionLog) => {
    this.selectedRecord = row;
    this.detailOpen = true;
  };

  private cancelDeferredRefresh(): boolean {
    if (!this.realtimeDeferTimer) return false;
    clearTimeout(this.realtimeDeferTimer);
    this.realtimeDeferTimer = null;
    return true;
  }

  startClock = () => {
    // A refresh deferred while unfocused runs as soon as the window is back.
    this.stopForeground = windowActivity.onForeground(() => {
      if (this.cancelDeferredRefresh()) void this.realtimeRefresh();
    });
    this.now = Date.now();
    this.clockTimer = setInterval(() => {
      this.now = Date.now();
    }, RELATIVE_TIME_MS);
  };

  dispose = () => {
    if (typeof document !== 'undefined') {
      document.removeEventListener('visibilitychange', this.onVisibilityChange);
    }
    this.unsubscribeRealtime();
    this.cancelDeferredRefresh();
    this.stopForeground?.();
    this.stopForeground = null;
    for (const timer of this.newRecordTimers.values()) clearTimeout(timer);
    this.newRecordTimers.clear();
    if (this.filterDebounceTimer) {
      clearTimeout(this.filterDebounceTimer);
      this.filterDebounceTimer = null;
    }
    if (this.clockTimer) {
      clearInterval(this.clockTimer);
      this.clockTimer = null;
    }
  };

  load = async (reason: string, urlSearch?: string, options: { silent?: boolean } = {}) => {
    if (!this.host.connected) {
      this.recordsLoading = false;
      debugLog('records', `skip load (${reason}): daemon not connected`);
      return;
    }

    const silent = options.silent === true;
    const requestId = ++this.loadRequestId;
    const refreshOptions = recordsRefreshOptions({
      verdict: this.verdict,
      pageOffset: this.pageOffset,
      selectedApp: this.selectedApp,
      selectedAppId: this.selectedAppId,
      filter: this.filter,
      sortKey: this.sortKey,
      sortDir: this.sortDir,
      proto: this.proto,
      facets: this.facets,
      timeWindowStart: this.timeWindowStart,
      timeWindowEnd: this.timeWindowEnd,
      urlSearch,
    });
    if (!silent) this.recordsLoading = true;
    debugLog('records', `load start (${reason})`, {
      requestId,
      silent,
      verdict: this.verdict,
      actionFilter: refreshOptions.actionFilter,
      urlSearch: urlSearch ?? this.host.currentUrl().search,
      selectedApp: this.selectedApp,
    });

    try {
      await this.host.refreshRecords({
        ...refreshOptions,
        refreshSummaries: shouldRefreshSummaries(reason),
      });
      if (requestId !== this.loadRequestId) {
        debugWarn('records', `load stale (${reason})`, {
          requestId,
          current: this.loadRequestId,
        });
        return;
      }
      debugLog('records', `load done (${reason})`, {
        requestId,
        logs: this.host.logs.length,
        apps: this.host.summaries.length,
      });
      this.trackRecordArrivals(reason);
    } catch (e) {
      if (requestId !== this.loadRequestId) return;
      debugError('records', `load failed (${reason})`, e);
      if (!silent) {
        this.host.toast(
          m.records_toast_load_failed_title(),
          e instanceof Error ? e.message : String(e),
          'var(--bad)',
        );
      }
    } finally {
      if (requestId === this.loadRequestId && !silent) {
        this.recordsLoading = false;
      }
    }
  };
}
