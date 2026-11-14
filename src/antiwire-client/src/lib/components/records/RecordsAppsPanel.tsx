import clsx from 'clsx';
import { ArrowDown, ArrowUp, X } from 'lucide-react';
import {
  memo,
  useCallback,
  useId,
  type CSSProperties,
  type FocusEvent,
  type KeyboardEvent,
  type MouseEvent,
} from 'react';
import { createPortal } from 'react-dom';
import AppAvatar from '#lib/components/ui/AppAvatar.tsx';
import Dropdown from '#lib/components/ui/Dropdown.tsx';
import SearchBox from '#lib/components/ui/SearchBox.tsx';
import VirtualScrollList from '#lib/components/ui/VirtualScrollList.tsx';
import RecordsPanelSkeleton from './list/RecordsPanelSkeleton';
import { m } from '#lib/i18n/messages.ts';
import { displayText, formatThroughput } from '#lib/utils/index.ts';
import { useFloatingTip } from '#lib/utils/floating-tip.ts';
import {
  recordsAppItemKey,
  shortPath,
  type RecordsAppFilter,
  type RecordsAppRow,
} from './list/records-list';
import styles from './RecordsAppsPanel.module.css';

interface Props {
  appQuery?: string;
  /** `bind:appQuery`: every edit of the application search. */
  onAppQueryChange?: (value: string) => void;
  apps: readonly RecordsAppRow[];
  /** The selected application's name; omitted while every application is shown. */
  selectedName?: string;
  filter: RecordsAppFilter;
  counts: Record<RecordsAppFilter, number>;
  showSkeleton: boolean;
  noAppMatch: boolean;
  onFilterChange: (next: RecordsAppFilter) => void;
  onSelectApp: (key: string) => void;
}

/** Two lines per row: name, then live activity, blocks or the install path. */
const ROW_HEIGHT = 48;

type TipEvent = MouseEvent<HTMLElement> | FocusEvent<HTMLElement>;

interface RowProps {
  app: RecordsAppRow;
  /** This application's record count against the largest in the list, 0 to 100. */
  share: number;
  filter: RecordsAppFilter;
  describedBy: string | undefined;
  onSelectApp: (key: string) => void;
  onShowTip: (app: RecordsAppRow, event: TipEvent) => void;
  onMoveTip: (event: MouseEvent<HTMLElement>) => void;
  onHideTip: () => void;
}

const AppRow = memo(function AppRow({
  app,
  share,
  filter,
  describedBy,
  onSelectApp,
  onShowTip,
  onMoveTip,
  onHideTip,
}: RowProps) {
  return (
    <button
      className={clsx(styles.appItem, app.selected && styles.active)}
      aria-current={app.selected ? 'true' : undefined}
      data-app-key={app.key}
      tabIndex={-1}
      aria-describedby={describedBy}
      onClick={() => onSelectApp(app.key)}
      onMouseEnter={(event) => onShowTip(app, event)}
      onMouseMove={onMoveTip}
      onMouseLeave={onHideTip}
      onFocus={(event) => onShowTip(app, event)}
      onBlur={onHideTip}
    >
      <span className={styles.avatar}>
        <AppAvatar name={app.name} path={app.path ?? ''} size={26} />
        {app.live && (
          <span
            className={clsx(styles.liveDot, 'live-dot')}
            role="img"
            aria-label={m.records_app_live_aria()}
          ></span>
        )}
      </span>
      <span className={styles.meta}>
        <span className={styles.appName}>{displayText(app.name)}</span>
        {app.live && !(filter === 'blocked' && app.blocked > 0) ? (
          <span className={clsx(styles.sub, styles.live)}>
            {m.records_app_live({ count: app.live.connections })}
            <span className={styles.rate}>
              <ArrowDown size={10} strokeWidth={2.4} aria-hidden="true" />
              {formatThroughput(app.live.downloadRate + app.live.uploadRate).label}
            </span>
          </span>
        ) : app.blocked > 0 ? (
          <span className={clsx(styles.sub, styles.blocked)}>
            {m.records_app_blocked({ count: app.blocked })}
          </span>
        ) : app.path ? (
          <span className={clsx(styles.sub, styles.path)}>{displayText(shortPath(app.path))}</span>
        ) : null}
      </span>
      <span className={styles.tally}>
        <span className={styles.appCount}>{app.count.toLocaleString()}</span>
        <span className={styles.share} aria-hidden="true">
          <span style={{ '--share': `${share}%` } as CSSProperties}></span>
        </span>
      </span>
    </button>
  );
});

export function RecordsAppsPanel({
  appQuery = '',
  onAppQueryChange,
  apps,
  selectedName,
  filter,
  counts,
  showSkeleton,
  noAppMatch,
  onFilterChange,
  onSelectApp,
}: Props) {
  // The row's hover card: the full install path and activity, in place of a native title.
  const appTipId = useId();
  const filterId = useId();
  const {
    hover: tip,
    placement: tipPlacement,
    tipRef,
    show: showFloating,
    move: moveTip,
    hide: hideTip,
  } = useFloatingTip<RecordsAppRow>({ estimatedTipHeight: 120, followPointer: true });

  const showTip = useCallback(
    (app: RecordsAppRow, event: TipEvent) => showFloating(app, event),
    [showFloating],
  );

  // "All applications" is the band's title, not a row: closing the selection returns to it.
  const rows = apps.filter((app) => !app.isAll);
  const largest = rows.reduce((max, app) => Math.max(max, app.count), 0);
  const filterEmpty = filter !== 'all' && rows.length === 0 && !appQuery.trim();
  const hoverKey = tip?.key;

  function onListKeydown(event: KeyboardEvent<HTMLDivElement>) {
    const keys = ['ArrowDown', 'ArrowUp', 'Home', 'End'];
    if (!keys.includes(event.key) || rows.length === 0) return;
    event.preventDefault();
    const last = rows.length - 1;
    // -1 while every application is shown: the first arrow key enters the list.
    const index = rows.findIndex((app) => app.selected);
    const next =
      event.key === 'Home'
        ? 0
        : event.key === 'End'
          ? last
          : index < 0
            ? event.key === 'ArrowDown'
              ? 0
              : last
            : Math.min(last, Math.max(0, index + (event.key === 'ArrowDown' ? 1 : -1)));
    if (next === index) return;
    const target = rows[next];
    if (!target) return;
    onSelectApp(target.key);
    // Keep the newly selected row in view; the list may be virtualized.
    const list = event.currentTarget;
    queueMicrotask(() => {
      list
        .querySelector<HTMLElement>(`[data-app-key="${CSS.escape(target.key)}"]`)
        ?.scrollIntoView({ block: 'nearest' });
    });
  }

  const renderRow = ({ item: app }: { item: RecordsAppRow }) => (
    <AppRow
      app={app}
      share={largest > 0 ? Math.max(4, Math.round((app.count / largest) * 100)) : 0}
      filter={filter}
      describedBy={hoverKey === app.key ? appTipId : undefined}
      onSelectApp={onSelectApp}
      onShowTip={showTip}
      onMoveTip={moveTip}
      onHideTip={hideTip}
    />
  );

  return (
    <>
      <div className={styles.panel}>
        <div className={styles.band}>
          {selectedName ? (
            <span className={styles.chip}>
              <span className={styles.chipText}>
                {m.records_selected_application({ name: displayText(selectedName) })}
              </span>
              <button
                type="button"
                className={styles.chipClose}
                aria-label={m.records_all_applications()}
                onClick={() => onSelectApp('ALL')}
              >
                <X size={11} strokeWidth={2.6} aria-hidden="true" />
              </button>
            </span>
          ) : (
            <span className={styles.bandTitle}>{m.records_all_applications()}</span>
          )}
        </div>

        <div className={styles.controls}>
          <SearchBox
            value={appQuery}
            onValueChange={onAppQueryChange}
            placeholder={m.records_search_apps_placeholder()}
            ariaLabel={m.records_search_apps_aria()}
            className={styles.search}
            suffix={
              <Dropdown
                variant="inline"
                id={filterId}
                options={[
                  { value: 'all', label: m.records_apps_filter_all(), detail: String(counts.all) },
                  {
                    value: 'live',
                    label: m.records_apps_filter_live(),
                    detail: String(counts.live),
                  },
                  {
                    value: 'blocked',
                    label: m.records_apps_filter_blocked(),
                    detail: String(counts.blocked),
                  },
                ]}
                value={filter}
                ariaLabel={m.records_apps_filter_aria()}
                onChange={(next) => onFilterChange(next as RecordsAppFilter)}
              />
            }
          />
        </div>
        {/* Arrow keys move the selection; each move filters the records. */}
        <div
          className={styles.appList}
          role="listbox"
          tabIndex={0}
          aria-label={m.records_applications_title()}
          onKeyDown={onListKeydown}
        >
          {showSkeleton ? (
            <div className={styles.loading}>
              <RecordsPanelSkeleton variant="sidebar" />
            </div>
          ) : (
            <>
              <VirtualScrollList
                items={rows}
                estimateSize={ROW_HEIGHT}
                getItemKey={recordsAppItemKey}
                row={renderRow}
              />
              {filterEmpty ? (
                <div className={styles.noMatch}>
                  {filter === 'live' ? m.records_apps_none_live() : m.records_apps_none_blocked()}
                </div>
              ) : noAppMatch ? (
                <div className={styles.noMatch}>{m.records_no_app_match({ query: appQuery })}</div>
              ) : null}
            </>
          )}
        </div>
      </div>

      {tip &&
        createPortal(
          <div
            ref={tipRef}
            className={clsx(styles.appTip, tipPlacement === 'bottom' && styles.below)}
            id={appTipId}
            role="tooltip"
          >
            <div className={styles.tipHead}>
              <span className={styles.tipName}>{displayText(tip.name)}</span>
              {tip.live && (
                <span className={styles.tipLive}>
                  {m.records_app_live({ count: tip.live.connections })}
                </span>
              )}
            </div>
            {tip.path && <span className={styles.tipPath}>{displayText(tip.path)}</span>}
            <div className={styles.tipStats}>
              <span>{m.records_app_records({ count: tip.count.toLocaleString() })}</span>
              {tip.blocked > 0 && (
                <span className={styles.tipBlocked}>
                  {m.records_app_blocked({ count: tip.blocked.toLocaleString() })}
                </span>
              )}
              {tip.live && (
                <span className={styles.tipRates}>
                  <span className={styles.rateDown}>
                    <ArrowDown size={11} strokeWidth={2.2} aria-hidden="true" />
                    {formatThroughput(tip.live.downloadRate).label}
                  </span>
                  <span className={styles.rateUp}>
                    <ArrowUp size={11} strokeWidth={2.2} aria-hidden="true" />
                    {formatThroughput(tip.live.uploadRate).label}
                  </span>
                </span>
              )}
            </div>
          </div>,
          document.body,
        )}
    </>
  );
}

export default RecordsAppsPanel;
