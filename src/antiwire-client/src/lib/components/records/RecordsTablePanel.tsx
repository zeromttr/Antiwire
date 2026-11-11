import clsx from 'clsx';
import { ArrowDown, ArrowUp, Ban, ChevronLeft, ChevronRight, Radio, RefreshCw } from 'lucide-react';
import { memo, useCallback, useMemo, type CSSProperties } from 'react';
import AppAvatar from '#lib/components/ui/AppAvatar.tsx';
import Button from '#lib/components/ui/Button.tsx';
import SegmentedControl from '#lib/components/ui/SegmentedControl.tsx';
import Tooltip from '#lib/components/ui/Tooltip.tsx';
import VirtualScrollList from '#lib/components/ui/VirtualScrollList.tsx';
import EmptyState from '#lib/components/ui/EmptyState.tsx';
import RecordsSearchFilters from './search/RecordsSearchFilters';
import RecordsTimeFilter from './search/RecordsTimeFilter';
import RecordsPanelSkeleton from './list/RecordsPanelSkeleton';
import type { RecordsSortKey } from '#lib/models/records-sort.ts';
import { recordProtocolColorVar } from '#lib/models/protocol-colors.ts';
import { recordProtocolLabel } from '#lib/models/well-known-ports.ts';
import { m } from '#lib/i18n/messages.ts';
import type { ConnectionLog } from '#lib/types/index.ts';
import type { ActivityBucket } from '#lib/models/activity-heatmap.ts';
import { displayText, formatBytes, formatDateTime, formatTimeAgo } from '#lib/utils/index.ts';
import {
  destinationIpTooltip,
  recordBlocklistTooltip,
  recordsLogItemKey,
  recordsLogKeys,
  recordActionLabel,
  recordsStateStyle,
  type RecordFacets,
  type RecordsScopeStats,
  type RecordsVerdict,
} from './list/records-list';
import styles from './RecordsTablePanel.module.css';

interface Props {
  filter?: string;
  now: number;
  logs: readonly ConnectionLog[];
  activityBuckets?: readonly ActivityBucket[];
  selectedRecord: ConnectionLog | null;
  detailOpen: boolean;
  recordsLoading: boolean;
  connected: boolean;
  realtime: boolean;
  newRecordKeys: ReadonlySet<string>;
  showSkeleton: boolean;
  proto: string;
  verdict: RecordsVerdict;
  facets: RecordFacets;
  /** Omitted while every application is selected. */
  applicationName?: string;
  applicationId?: number;
  timeWindowStart?: number;
  timeWindowEnd?: number;
  /** Totals for the selected scope, shown in the footer. */
  stats: RecordsScopeStats;
  /** False while one application is selected: the column would repeat it. */
  showApplication: boolean;
  colDefs: { key: RecordsSortKey; label: string; just: string }[];
  activeSortKey: RecordsSortKey;
  activeSortDir: 1 | -1;
  canGoBack: boolean;
  canGoForward: boolean;
  visibleCountLabel: string;
  totalCountLabel: string;
  onRefresh: () => void;
  onToggleRealtime: () => void;
  /** Every edit of the search text (was `bind:filter` plus `onFilterInput`). */
  onFilterInput: (value: string) => void;
  onFacet: <K extends keyof RecordFacets>(kind: K, value: RecordFacets[K] | undefined) => void;
  onClearTime: () => void;
  onSelectTime: (start: number, end: number) => void;
  onSelectProto: (next: string) => void;
  onSelectVerdict: (next: RecordsVerdict) => void;
  onToggleSort: (key: RecordsSortKey) => void;
  onPreviousPage: () => void;
  onNextPage: () => void;
  onInspect: (row: ConnectionLog) => void;
}

const EMPTY_BUCKETS: readonly ActivityBucket[] = [];

interface RowProps {
  row: ConnectionLog;
  cols: string;
  selected: boolean;
  isNew: boolean;
  showApplication: boolean;
  now: number;
  onInspect: (row: ConnectionLog) => void;
}

const SocketRow = memo(function SocketRow({
  row,
  cols,
  selected,
  isNew,
  showApplication,
  now,
  onInspect,
}: RowProps) {
  const st = recordsStateStyle(row);
  const protoLabel = recordProtocolLabel(row.protocol, row.port);
  const protoColor = recordProtocolColorVar(protoLabel);
  const blocklistTip = recordBlocklistTooltip(row);
  const blocked = st.dot === 'var(--bad)';
  // A blocked row differs by shape as well as colour.
  const dot = blocked ? (
    <span className={styles.ban} role="img" aria-label={recordActionLabel(row.action)}>
      <Ban size={13} strokeWidth={2.4} aria-hidden="true" />
    </span>
  ) : (
    <span
      className={styles.dot}
      role="img"
      aria-label={recordActionLabel(row.action)}
      style={{ background: st.dot }}
    ></span>
  );
  return (
    <div
      className={clsx(styles.tr, selected && styles.selected, isNew && styles.new)}
      style={{ '--cols': cols } as CSSProperties}
      onClick={() => onInspect(row)}
    >
      <div className={clsx(styles.td, styles.dotCell)}>
        <span className={styles.dotHit}>
          {blocklistTip ? (
            <Tooltip text={displayText(blocklistTip)} label={m.records_tooltip_blocklists()}>
              {dot}
            </Tooltip>
          ) : (
            dot
          )}
        </span>
      </div>
      {showApplication && (
        <div className={clsx(styles.td, styles.appCell)}>
          <AppAvatar name={row.applicationName} path={row.applicationPath} size={18} />
          <Tooltip
            text={displayText(row.applicationPath || row.applicationName)}
            label={m.records_tooltip_application_path()}
          >
            {displayText(row.applicationName)}
          </Tooltip>
        </div>
      )}
      <div className={clsx(styles.td, styles.dest)}>
        <span className={clsx(styles.destHost, blocked && styles.blocked)}>
          {row.domain ? (
            <Tooltip text={displayText(row.domain)} label={m.records_tooltip_remote_host()}>
              {displayText(row.domain)}
            </Tooltip>
          ) : row.destinationIp ? (
            <Tooltip text={destinationIpTooltip(row)} label={m.records_tooltip_dst_ip()}>
              {row.destinationIp}
            </Tooltip>
          ) : (
            m.common_em_dash()
          )}
        </span>
        <span className={styles.destSub}>
          <span className="mono">
            {[row.domain ? row.destinationIp : '', row.countryCode].filter(Boolean).join(' · ') ||
              m.common_em_dash()}
          </span>
          {blocklistTip && <span className={styles.reason}>{displayText(blocklistTip)}</span>}
        </span>
      </div>
      <div className={clsx(styles.td, styles.port)}>
        <span className="mono">{row.port > 0 ? row.port : m.common_em_dash()}</span>
        {protoLabel && (
          <span
            className={clsx(styles.proto, !!protoColor && styles.named)}
            style={{ color: protoColor }}
          >
            {protoLabel}
          </span>
        )}
      </div>
      <div className={clsx(styles.td, 'mono', styles.right)}>
        {row.bytesSent ? formatBytes(row.bytesSent) : m.common_em_dash()}
      </div>
      <div className={clsx(styles.td, 'mono', styles.right)}>
        {row.bytesReceived ? formatBytes(row.bytesReceived) : m.common_em_dash()}
      </div>
      <div className={clsx(styles.td, styles.right, styles.dim)}>
        <Tooltip text={formatDateTime(row.lastSeen)} label={m.records_tooltip_last_seen()}>
          {formatTimeAgo(row.lastSeen, now)}
        </Tooltip>
      </div>
    </div>
  );
});

export function RecordsTablePanel({
  filter = '',
  now,
  logs,
  activityBuckets = EMPTY_BUCKETS,
  selectedRecord,
  detailOpen,
  recordsLoading,
  connected,
  realtime,
  newRecordKeys,
  showSkeleton,
  proto,
  verdict,
  facets,
  applicationName,
  applicationId,
  timeWindowStart,
  timeWindowEnd,
  stats,
  showApplication,
  colDefs,
  activeSortKey,
  activeSortDir,
  canGoBack,
  canGoForward,
  visibleCountLabel,
  totalCountLabel,
  onRefresh,
  onToggleRealtime,
  onFilterInput,
  onFacet,
  onClearTime,
  onSelectTime,
  onSelectProto,
  onSelectVerdict,
  onToggleSort,
  onPreviousPage,
  onNextPage,
  onInspect,
}: Props) {
  // Deduped per-page keys (see recordsLogKeys): recomputed only when `logs`
  // changes, so the virtualizer does not churn on unrelated re-renders.
  const logKeys = useMemo(() => recordsLogKeys(logs), [logs]);
  // By key, not identity: live reloads replace the row objects.
  const selectedKey = detailOpen && selectedRecord ? recordsLogItemKey(selectedRecord) : null;
  const gridColumns = showApplication
    ? '14px minmax(110px, 0.9fr) minmax(0, 1.7fr) 96px 84px 84px 88px'
    : '14px minmax(0, 2fr) 96px 84px 84px 88px';
  const getLogKey = useCallback(
    (row: ConnectionLog, index: number) => logKeys[index] ?? recordsLogItemKey(row),
    [logKeys],
  );

  const renderRow = ({ item: row, index }: { item: ConnectionLog; index: number }) => {
    const key = logKeys[index] ?? recordsLogItemKey(row);
    return (
      <SocketRow
        row={row}
        cols={gridColumns}
        selected={selectedKey !== null && recordsLogItemKey(row) === selectedKey}
        isNew={newRecordKeys.has(key)}
        showApplication={showApplication}
        now={now}
        onInspect={onInspect}
      />
    );
  };

  return (
    <div className={styles.panel}>
      <div className={styles.filterBar}>
        <Button
          variant="ghost"
          size="sm"
          iconOnly
          aria-label={m.records_refresh_aria()}
          disabled={!connected || recordsLoading}
          onClick={onRefresh}
        >
          <RefreshCw size={14} className={recordsLoading ? 'spinning' : ''} />
        </Button>
        <Button
          variant={realtime ? 'secondary' : 'ghost'}
          size="sm"
          iconOnly
          aria-label={m.records_realtime_aria()}
          aria-pressed={realtime}
          disabled={!connected}
          onClick={onToggleRealtime}
        >
          <Radio size={14} strokeWidth={2} className={realtime ? 'realtime-live' : ''} />
        </Button>
        <div className={styles.divider}></div>
        <RecordsSearchFilters
          value={filter}
          logs={logs}
          facets={facets}
          now={now}
          connected={connected}
          applicationName={applicationName}
          applicationId={applicationId}
          onFilterChange={onFilterInput}
          onFacet={onFacet}
        />
        <RecordsTimeFilter
          start={timeWindowStart}
          end={timeWindowEnd}
          logs={logs}
          activityBuckets={activityBuckets}
          now={now}
          onSelect={onSelectTime}
          onClear={onClearTime}
        />
        <div className={styles.divider}></div>
        <SegmentedControl
          options={[
            { value: 'ALL', label: m.records_protocol_all() },
            { value: 'TCP', label: m.records_protocol_tcp() },
            { value: 'UDP', label: m.records_protocol_udp() },
          ]}
          value={proto}
          ariaLabel={m.records_protocol_filter_aria()}
          onChange={onSelectProto}
        />
        <SegmentedControl
          options={[
            { value: 'all', label: m.records_verdict_all() },
            { value: 'allowed', label: m.records_verdict_allowed() },
            { value: 'blocked', label: m.records_verdict_blocked() },
          ]}
          value={verdict}
          ariaLabel={m.records_verdict_filter_aria()}
          onChange={(v) => onSelectVerdict(v as RecordsVerdict)}
        />
      </div>

      <div className={styles.thead} style={{ '--cols': gridColumns } as CSSProperties}>
        <span aria-hidden="true"></span>
        {colDefs.map((col) => (
          <button
            key={col.key}
            type="button"
            className={styles.th}
            style={{
              justifyContent: col.just,
              color: activeSortKey === col.key ? 'var(--t1)' : 'var(--t3)',
            }}
            onClick={() => onToggleSort(col.key)}
          >
            {col.label}
            <span className={styles.arrow}>
              {activeSortKey === col.key ? (activeSortDir === 1 ? '▲' : '▼') : ''}
            </span>
          </button>
        ))}
      </div>

      <div className={clsx(styles.tbody, showSkeleton && styles.loading)}>
        {showSkeleton ? (
          <RecordsPanelSkeleton variant="grid" />
        ) : (
          <VirtualScrollList
            items={logs}
            estimateSize={48}
            getItemKey={getLogKey}
            row={renderRow}
            empty={<EmptyState text={m.records_empty_no_sockets()} compact />}
          />
        )}
      </div>

      <div className={styles.footer}>
        <span className={styles.pageCount}>
          {m.records_page_of({ visible: visibleCountLabel, total: totalCountLabel })}
        </span>
        <div className={styles.stats}>
          <Tooltip text={stats.allowed.toLocaleString()} label={m.records_verdict_allowed()}>
            <span className={styles.stat}>
              <span className={styles.dot} style={{ background: 'var(--ok)' }}></span>
              <span className="mono">{stats.allowed.toLocaleString()}</span>
            </span>
          </Tooltip>
          <Tooltip text={stats.blocked.toLocaleString()} label={m.records_verdict_blocked()}>
            <span className={styles.stat}>
              <span className={styles.ban}>
                <Ban size={13} strokeWidth={2.4} aria-hidden="true" />
              </span>
              <span className="mono">{stats.blocked.toLocaleString()}</span>
            </span>
          </Tooltip>
          <span className={styles.divider}></span>
          <Tooltip text={formatBytes(stats.bytesSent)} label={m.records_detail_field_sent()}>
            <span className={styles.stat}>
              <ArrowUp className={styles.up} size={12} strokeWidth={2.6} aria-hidden="true" />
              <span className="mono">{formatBytes(stats.bytesSent)}</span>
            </span>
          </Tooltip>
          <Tooltip
            text={formatBytes(stats.bytesReceived)}
            label={m.records_detail_field_received()}
          >
            <span className={styles.stat}>
              <ArrowDown className={styles.down} size={12} strokeWidth={2.6} aria-hidden="true" />
              <span className="mono">{formatBytes(stats.bytesReceived)}</span>
            </span>
          </Tooltip>
        </div>
        <div className={styles.pageControls}>
          <Button
            variant="ghost"
            size="sm"
            iconOnly
            aria-label={m.records_page_previous_aria()}
            disabled={!canGoBack || recordsLoading}
            onClick={onPreviousPage}
          >
            <ChevronLeft size={14} strokeWidth={2} />
          </Button>
          <Button
            variant="ghost"
            size="sm"
            iconOnly
            aria-label={m.records_page_next_aria()}
            disabled={!canGoForward || recordsLoading}
            onClick={onNextPage}
          >
            <ChevronRight size={14} strokeWidth={2} />
          </Button>
        </div>
      </div>
    </div>
  );
}

export default RecordsTablePanel;
