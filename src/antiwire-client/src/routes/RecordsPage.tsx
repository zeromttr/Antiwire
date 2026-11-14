// Reads a mutable workspace while rendering, so React Compiler must not
// cache it (see src/lib/state/compiler-opt-out.test.ts).
'use no memo';

import clsx from 'clsx';
import { useEffect, useRef, useState } from 'react';
import { useLocation } from 'react-router';
import { navigate } from '#lib/navigation.ts';
import { activeApps } from '#lib/stores/active-apps.ts';
import { m } from '#lib/i18n/messages.ts';
import CollectorNotice from '#lib/components/ui/CollectorNotice.tsx';
import DaemonOffline from '#lib/components/shell/DaemonOffline.tsx';
import RecordInspector from '#lib/components/records/RecordInspector.tsx';
import RecordsAppsPanel from '#lib/components/records/RecordsAppsPanel.tsx';
import RecordsTablePanel from '#lib/components/records/RecordsTablePanel.tsx';
import { RecordsWorkspace, type RecordsHost } from '#lib/components/records/records-workspace.ts';
import type { RecordsAppFilter } from '#lib/components/records/list/records-list.ts';
import { daemon } from '#lib/stores/daemon.ts';
import { api } from '#lib/api/daemon.ts';
import { isNative, listen } from '#lib/bridge.ts';
import { shallowEqual, useReactive, useSelector } from '#lib/state/reactive.ts';
import type { AppSummary, ConnectionLog } from '#lib/types/index.ts';
import { debugError, debugLog, isDebugEnabled } from '#lib/utils/index.ts';
import styles from './RecordsPage.module.css';

const SKELETON_MIN_MS = 600;

const EMPTY_LOGS: readonly ConnectionLog[] = [];
const EMPTY_SUMMARIES: readonly AppSummary[] = [];
const EMPTY_LIVE: RecordsWorkspace['liveApps'] = [];

type DebugWindow = Window & { __antiwireDebug?: Record<string, unknown> };

/** Writes a tracked workspace field (the former `bind:` target); the setter notifies. */
function setField<T extends object, K extends keyof T>(target: T, key: K, value: T[K]): void {
  target[key] = value;
}

/** The route's host: reads the daemon store directly, so it stays current without re-creation. */
function createRecordsHost(): RecordsHost {
  return {
    get connected() {
      return daemon.state.connected;
    },
    get logs() {
      return daemon.state.recordsLogs ?? EMPTY_LOGS;
    },
    get summaries() {
      return daemon.state.recordsAppSummaries ?? EMPTY_SUMMARIES;
    },
    get logsTotalCount() {
      return daemon.state.recordsLogsTotalCount ?? 0;
    },
    get activityBuckets() {
      return daemon.state.activityBuckets;
    },
    refreshRecords: (opts) => daemon.refreshRecords(opts),
    subscribeTraffic: async (handler) => {
      if (!isNative()) return () => {};
      await api.startRealtimeTraffic();
      const stopStream = () =>
        void api
          .stopRealtimeTraffic()
          .catch((error) => debugError('records', 'realtime-stop-failed', error));
      try {
        const unlisten = listen('traffic://event', () => handler());
        return () => {
          unlisten();
          stopStream();
        };
      } catch (error) {
        stopStream();
        throw error;
      }
    },
    toast: (title, body, color) => daemon.addToast(title, body, color),
    // BrowserRouter keeps the document URL in step with the route.
    currentUrl: () => ({ pathname: window.location.pathname, search: window.location.search }),
    goto: (href) => {
      // The router's own navigate, installed by the app shell.
      navigate(href, { replace: true });
    },
  };
}

/**
 * Keeps a skeleton up for at least `SKELETON_MIN_MS` once shown, so a fast
 * load does not flash it.
 */
function useSkeletonHold(wants: boolean): boolean {
  const [hold, setHold] = useState(true);
  const [prevWants, setPrevWants] = useState(wants);
  if (wants !== prevWants) {
    setPrevWants(wants);
    if (wants) setHold(true);
  }
  const shownAt = useRef(0);
  useEffect(() => {
    if (wants || shownAt.current === 0) shownAt.current = Date.now();
    if (wants) return;
    const remaining = Math.max(0, SKELETON_MIN_MS - (Date.now() - shownAt.current));
    const timer = setTimeout(() => setHold(false), remaining);
    return () => clearTimeout(timer);
  }, [wants]);
  return wants || hold;
}

export default function RecordsPage() {
  const [rec] = useState(() => new RecordsWorkspace(createRecordsHost()));
  useReactive(rec);
  // Re-render on the daemon slice the workspace reads through its host.
  const { connected } = useSelector(
    daemon,
    (d) => ({
      connected: d.state.connected,
      logs: d.state.recordsLogs,
      summaries: d.state.recordsAppSummaries,
      total: d.state.recordsLogsTotalCount,
      buckets: d.state.activityBuckets,
    }),
    shallowEqual,
  );
  const { search } = useLocation();

  const showSidebarSkeleton = useSkeletonHold(rec.wantsSidebarSkeleton);
  const showGridSkeleton = useSkeletonHold(rec.wantsGridSkeleton);

  const lastConnected = useRef(false);
  useEffect(() => {
    rec.onUrlChange(search);
    if (connected && !lastConnected.current) rec.realtimeResync();
    lastConnected.current = connected;
  }, [rec, search, connected]);

  // Teardown that a later mount can undo (StrictMode mounts twice): the clock
  // and a live stream that was on restart with the next mount.
  useEffect(() => {
    rec.startClock();
    rec.realtimeResync();

    const debugWindow = window as DebugWindow;
    if (isDebugEnabled()) {
      debugWindow.__antiwireDebug = {
        ...(debugWindow.__antiwireDebug ?? {}),
        records: () => ({
          connected: rec.connected,
          selectedApp: rec.selectedApp,
          verdict: rec.verdict,
          logs: rec.logs.length,
          logsTotalCount: rec.logsTotalCount,
          apps: rec.summaries.length,
          recordsLoading: rec.recordsLoading,
          urlSearch: window.location.search,
        }),
      };
      debugLog('records', 'debug helpers ready — inspect window.__antiwireDebug.records()');
    }

    return () => {
      rec.dispose();
      if (debugWindow.__antiwireDebug) delete debugWindow.__antiwireDebug.records;
    };
  }, [rec]);

  // Live indicators in the applications panel come from the shared live poll.
  useEffect(() => {
    if (!connected) return;
    return activeApps.retain();
  }, [connected]);
  const livePage = useSelector(activeApps, (a) => a.page);
  useEffect(() => {
    setField(rec, 'liveApps', livePage?.available ? livePage.applications : EMPTY_LIVE);
  }, [rec, livePage]);

  // The record inspector sits beside the table instead of covering it.
  const inspected = rec.detailOpen ? rec.selectedRecord : null;

  return (
    <div className={styles.page} data-testid="page-records" data-page-motion="records">
      <div className={styles.scroll}>
        <CollectorNotice />
        {!rec.connected ? (
          <DaemonOffline text={m.records_empty_disconnected()} />
        ) : (
          <div className={clsx(styles.grid, !!inspected && styles.inspecting)}>
            <RecordsAppsPanel
              appQuery={rec.appQuery}
              onAppQueryChange={(value) => setField(rec, 'appQuery', value)}
              apps={rec.appList}
              selectedName={rec.selectedApp === 'ALL' ? undefined : rec.selectedApp}
              filter={rec.appFilter}
              counts={rec.appFilterCounts}
              onFilterChange={(next: RecordsAppFilter) => setField(rec, 'appFilter', next)}
              showSkeleton={showSidebarSkeleton}
              noAppMatch={rec.noAppMatch}
              onSelectApp={rec.selectApp}
            />
            <RecordsTablePanel
              filter={rec.filter}
              now={rec.now}
              logs={rec.logs}
              activityBuckets={rec.activityBuckets}
              selectedRecord={rec.selectedRecord}
              detailOpen={rec.detailOpen}
              recordsLoading={rec.recordsLoading}
              connected={rec.connected}
              realtime={rec.realtime}
              newRecordKeys={rec.newRecordKeys}
              showSkeleton={showGridSkeleton}
              proto={rec.proto}
              verdict={rec.verdict}
              facets={rec.facets}
              applicationName={rec.selectedApp === 'ALL' ? undefined : rec.selectedApp}
              applicationId={rec.selectedAppId}
              timeWindowStart={rec.timeWindowStart}
              timeWindowEnd={rec.timeWindowEnd}
              stats={rec.scopeStats}
              showApplication={rec.showApplicationColumn}
              colDefs={rec.colDefs}
              activeSortKey={rec.activeSortKey}
              activeSortDir={rec.activeSortDir}
              canGoBack={rec.canGoBack}
              canGoForward={rec.canGoForward}
              visibleCountLabel={rec.visibleCountLabel}
              totalCountLabel={rec.totalCountLabel}
              onRefresh={() => void rec.refresh()}
              onToggleRealtime={rec.toggleRealtime}
              onFilterInput={rec.onFilterInput}
              onFacet={rec.setFacet}
              onClearTime={rec.clearTimeWindow}
              onSelectTime={rec.selectTimeWindow}
              onSelectProto={rec.selectProto}
              onSelectVerdict={rec.selectVerdict}
              onToggleSort={rec.toggleSort}
              onPreviousPage={rec.goToPreviousPage}
              onNextPage={rec.goToNextPage}
              onInspect={rec.inspectRecord}
            />
            {inspected && (
              <div className={styles.inspectorSlot}>
                <RecordInspector
                  record={inspected}
                  onclose={() => setField(rec, 'detailOpen', false)}
                  onmutated={() => void rec.load('rule-toggle')}
                />
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
