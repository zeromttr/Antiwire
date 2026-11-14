import clsx from 'clsx';
import { ChevronLeft, ChevronRight } from 'lucide-react';
import {
  memo,
  useCallback,
  useId,
  useMemo,
  useState,
  type CSSProperties,
  type FocusEvent,
  type MouseEvent,
} from 'react';
import { createPortal } from 'react-dom';
import { Button } from '#lib/components/ui/Button.tsx';
import { DateInput } from '#lib/components/ui/DateInput.tsx';
import { Dropdown } from '#lib/components/ui/Dropdown.tsx';
import { toDateKey } from '#lib/components/ui/date-input.ts';
import { m } from '#lib/i18n/messages.ts';
import {
  ACTIVITY_INTERVAL_SECONDS,
  ACTIVITY_INTERVALS,
  buildActivityHeatmapRows,
  buildActivityHeatmapRowsForWeek,
  cellBackground,
  formatActivityWeekLabel,
  formatBucketTimeRange,
  isInactiveCell,
  type ActivityBucket,
  type ActivityHeatmapCell,
  type ActivityHeatmapRow,
  type ActivityInterval,
} from '#lib/models/activity-heatmap.ts';
import { navigate } from '#lib/navigation.ts';
import { formatBytes } from '#lib/utils/index.ts';
import { useFloatingTip } from '#lib/utils/floating-tip.ts';
import { recordsTimeWindowUrl } from '#lib/utils/records-url.ts';
import styles from './ActivityHeatmap.module.css';

interface Props {
  buckets?: ActivityBucket[];
  /** Monday 00:00 (local) unix seconds; when set, the heatmap pages by week. */
  weekStartSec?: number | null;
  loading?: boolean;
  canGoPrev?: boolean;
  canGoNext?: boolean;
  onPrev?: () => void;
  onNext?: () => void;
  /** Fires with a `YYYY-MM-DD` key when the pager date selector picks a day. */
  onSelectDate?: (dateKey: string) => void;
}

const NO_BUCKETS: ActivityBucket[] = [];
const HOURS = [0, 3, 6, 9, 12, 15, 18, 21];

type CellEvent = MouseEvent<HTMLButtonElement> | FocusEvent<HTMLButtonElement>;

interface RowHandlers {
  onEnter: (cell: ActivityHeatmapCell, event: CellEvent) => void;
  onFocus: (cell: ActivityHeatmapCell, event: CellEvent) => void;
  onBlur: () => void;
  onLeave: () => void;
  onOpen: (cell: ActivityHeatmapCell) => void;
}

interface RowProps {
  row: ActivityHeatmapRow;
  rowIndex: number;
  /** Start of the selected bucket when it is in this row, else null. */
  chosenStart: number | null;
  /** Start of the bucket the tooltip describes when it is in this row, else null. */
  tipStart: number | null;
  tooltipId: string;
  handlers: RowHandlers;
}

/**
 * One day. Memoized so hovering a cell re-renders only the rows that gain or
 * lose the selection, not the whole week.
 */
const HeatmapRow = memo(function HeatmapRow({
  row,
  rowIndex,
  chosenStart,
  tipStart,
  tooltipId,
  handlers,
}: RowProps) {
  const selected = chosenStart !== null;
  return (
    // Clearing hover state only; the cells stay the keyboard-operable elements.
    <div
      className={clsx(styles.row, row.isToday && styles.today, selected && styles.selected)}
      data-testid="activity-day"
      data-selected={selected}
      // Tracked at row level: the 3px gaps and day gutter live inside the row,
      // so sweeping across a day's buckets must not tear down the highlight,
      // tooltip, and axis readout per cell.
      onMouseLeave={handlers.onLeave}
    >
      <div className={clsx(styles.day, 'mono', row.isToday && styles.today)}>
        <span>{row.label}</span>
        <span
          className={clsx(styles.todayDot, row.isToday && styles.visible)}
          aria-hidden="true"
        ></span>
      </div>
      <div
        className={styles.cells}
        style={{ gridTemplateColumns: `repeat(${row.cells.length}, minmax(0, 1fr))` }}
      >
        {row.cells.map((cell, slot) => (
          <button
            key={cell.bucketStart}
            type="button"
            className={clsx(
              styles.cell,
              'cell',
              isInactiveCell(cell.bytesSent, cell.bytesReceived) && styles.inactive,
              chosenStart === cell.bucketStart && styles.chosen,
            )}
            style={
              {
                '--cell-color': cellBackground(cell.intensity, cell.bytesSent, cell.bytesReceived),
                '--slot-row': rowIndex,
                '--slot-col': slot,
              } as CSSProperties
            }
            aria-label={`${row.label} ${formatBucketTimeRange(cell.bucketStart, cell.bucketSeconds)}`}
            aria-describedby={tipStart === cell.bucketStart ? tooltipId : undefined}
            onMouseEnter={(event) => handlers.onEnter(cell, event)}
            onFocus={(event) => handlers.onFocus(cell, event)}
            onBlur={handlers.onBlur}
            onClick={() => handlers.onOpen(cell)}
          ></button>
        ))}
      </div>
    </div>
  );
});

function rowStartFor(row: ActivityHeatmapRow, cell: ActivityHeatmapCell | null): number | null {
  if (!cell) return null;
  return row.cells.some((entry) => entry.bucketStart === cell.bucketStart)
    ? cell.bucketStart
    : null;
}

function openBucket(cell: ActivityHeatmapCell) {
  if (isInactiveCell(cell.bytesSent, cell.bytesReceived)) return;
  const end = cell.bucketStart + cell.bucketSeconds;
  navigate(recordsTimeWindowUrl(cell.bucketStart, end));
}

export const ActivityHeatmap = memo(function ActivityHeatmap({
  buckets = NO_BUCKETS,
  weekStartSec = null,
  loading = false,
  canGoPrev = false,
  canGoNext = false,
  onPrev,
  onNext,
  onSelectDate,
}: Props) {
  const [hoveredCell, setHoveredCell] = useState<ActivityHeatmapCell | null>(null);
  const [focusedCell, setFocusedCell] = useState<ActivityHeatmapCell | null>(null);
  const selectedCell = hoveredCell ?? focusedCell;
  const tooltipId = useId();

  /** Bucket granularity; coarser intervals aggregate the 30-minute base buckets. */
  const [interval, setIntervalChoice] = useState<ActivityInterval>('30m');
  const intervalSec = ACTIVITY_INTERVAL_SECONDS[interval];

  const intervalOptions = [
    { value: '30m', label: m.dashboard_activity_interval_30m() },
    { value: '1h', label: m.dashboard_activity_interval_1h() },
    { value: '4h', label: m.dashboard_activity_interval_4h() },
    { value: '1d', label: m.dashboard_activity_interval_1d() },
  ];

  const showPager = onPrev !== undefined || onNext !== undefined;
  const showDatePicker = showPager && onSelectDate !== undefined;
  const weekLabel = weekStartSec != null ? formatActivityWeekLabel(weekStartSec) : '';
  // The week label itself is the picker trigger: it shows the viewed week's
  // range as a selectable button that opens the shared date picker, while
  // `value` (the week's Monday) drives the calendar. Picking any day jumps
  // to its week.
  const pickerDateKey =
    weekStartSec != null ? toDateKey(new Date(weekStartSec * 1000)) : toDateKey(new Date());
  const pickerLabel = weekLabel ? `${weekLabel}${loading ? ' · …' : ''}` : undefined;
  const rows = useMemo(
    () =>
      weekStartSec != null
        ? buildActivityHeatmapRowsForWeek(buckets, weekStartSec * 1000, Date.now(), intervalSec)
        : buildActivityHeatmapRows(buckets, Date.now(), intervalSec),
    [buckets, weekStartSec, intervalSec],
  );
  const columnCount = rows[0]?.cells.length ?? 0;
  // Hour ticks stay aligned with the columns: the classic 3-hour ticks for
  // dense grids, one tick per column start for sparse ones.
  const axisTicks =
    columnCount >= 24
      ? HOURS
      : Array.from({ length: columnCount }, (_, i) => (i * 24) / columnCount);
  const showAxisRow = columnCount > 1;

  const tip = useFloatingTip<ActivityHeatmapCell>({ estimatedTipHeight: 72 });
  const { show: showTip, hide: hideTip } = tip;

  const chooseInterval = useCallback(
    (next: string) => {
      if (next === interval || !ACTIVITY_INTERVALS.includes(next as ActivityInterval)) return;
      setIntervalChoice(next as ActivityInterval);
      // Cells are structurally different per interval; drop any pinned tooltip.
      setHoveredCell(null);
      setFocusedCell(null);
      hideTip();
    },
    [interval, hideTip],
  );

  const handlers = useMemo<RowHandlers>(
    () => ({
      onEnter: (cell, event) => {
        setHoveredCell(cell);
        showTip(cell, event);
      },
      onFocus: (cell, event) => {
        setFocusedCell(cell);
        showTip(cell, event);
      },
      onBlur: () => {
        setFocusedCell(null);
        hideTip();
      },
      onLeave: () => {
        setHoveredCell(null);
        hideTip();
      },
      onOpen: openBucket,
    }),
    [showTip, hideTip],
  );

  return (
    <>
      <div className={clsx(styles.heatmap, 'panel')}>
        <div className={styles.header}>
          <div className={styles.title}>
            <span>{m.dashboard_activity_title_prefix()}</span>
            <span aria-hidden="true">·</span>
            <div className={styles.intervalMenu}>
              <Dropdown
                id="activity-interval"
                options={intervalOptions}
                value={interval}
                onChange={chooseInterval}
              />
            </div>
            <span>{m.dashboard_activity_title_suffix()}</span>
          </div>
          {showPager && (
            <div className={styles.pager}>
              <Button
                variant="ghost"
                size="sm"
                iconOnly
                disabled={!canGoPrev || loading}
                aria-label="Previous week"
                onClick={() => onPrev?.()}
              >
                <ChevronLeft size={14} strokeWidth={2} aria-hidden="true" />
              </Button>
              {showDatePicker ? (
                <div className={styles.weekPicker} aria-live="polite">
                  <DateInput
                    value={pickerDateKey}
                    displayText={pickerLabel}
                    ariaLabel={m.dashboard_activity_title_prefix()}
                    bare
                    onChange={(dateKey) => onSelectDate?.(dateKey)}
                  />
                </div>
              ) : (
                <div className={clsx(styles.pagerLabel, 'mono')} aria-live="polite">
                  {weekLabel}
                  {loading ? ' · …' : ''}
                </div>
              )}
              <Button
                variant="ghost"
                size="sm"
                iconOnly
                disabled={!canGoNext || loading}
                aria-label="Next week"
                onClick={() => onNext?.()}
              >
                <ChevronRight size={14} strokeWidth={2} aria-hidden="true" />
              </Button>
            </div>
          )}
          <div className={clsx(styles.axis, 'mono')}>
            <span className={clsx(styles.axisText, selectedCell && styles.inspecting)}>
              {selectedCell
                ? formatBucketTimeRange(selectedCell.bucketStart, selectedCell.bucketSeconds)
                : m.dashboard_activity_axis()}
            </span>
          </div>
        </div>
        <div
          className={clsx(styles.gridScroll, 'grid-scroll', loading && [styles.loading, 'loading'])}
        >
          <div className={styles.grid} style={{ minWidth: columnCount >= 6 ? '560px' : undefined }}>
            {rows.map((row, rowIndex) => (
              <HeatmapRow
                key={row.label}
                row={row}
                rowIndex={rowIndex}
                chosenStart={rowStartFor(row, selectedCell)}
                tipStart={rowStartFor(row, tip.hover)}
                tooltipId={tooltipId}
                handlers={handlers}
              />
            ))}
            {showAxisRow && (
              <div className={clsx(styles.row, styles.axisRow)}>
                <div className={styles.day}></div>
                <div
                  className={clsx(styles.cells, styles.axisCells)}
                  style={{ gridTemplateColumns: `repeat(${axisTicks.length}, minmax(0, 1fr))` }}
                >
                  {axisTicks.map((h) => (
                    <div key={h} className={clsx(styles.hour, 'mono')}>
                      {String(h).padStart(2, '0')}:00
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      {tip.hover &&
        createPortal(
          <div
            ref={tip.tipRef}
            className={clsx(styles.tip, 'mono', tip.placement === 'bottom' && styles.below)}
            id={tooltipId}
            role="tooltip"
          >
            <div className={styles.tipTime}>
              {formatBucketTimeRange(tip.hover.bucketStart, tip.hover.bucketSeconds)}
            </div>
            <div className={styles.tipRow}>
              <span className={clsx(styles.tipSwatch, styles.down)}></span>
              <span className={styles.tipLabel}>{m.dashboard_activity_tip_down()}</span>
              <span className={clsx(styles.tipValue, styles.down)}>
                {formatBytes(tip.hover.bytesReceived)}
              </span>
            </div>
            <div className={styles.tipRow}>
              <span className={clsx(styles.tipSwatch, styles.up)}></span>
              <span className={styles.tipLabel}>{m.dashboard_activity_tip_up()}</span>
              <span className={clsx(styles.tipValue, styles.up)}>
                {formatBytes(tip.hover.bytesSent)}
              </span>
            </div>
          </div>,
          document.body,
        )}
    </>
  );
});

export default ActivityHeatmap;
