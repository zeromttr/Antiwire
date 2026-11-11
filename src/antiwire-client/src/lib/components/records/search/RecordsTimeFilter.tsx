import clsx from 'clsx';
import { CalendarDays, ChevronDown, ChevronLeft, ChevronRight, X } from 'lucide-react';
import { useEffect, useId, useMemo, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import Button from '#lib/components/ui/Button.tsx';
import DateInput from '#lib/components/ui/DateInput.tsx';
import TimeInput from '#lib/components/ui/TimeInput.tsx';
import { toTimeKey } from '#lib/components/ui/time-input.ts';
import { popoverIn, popoverOut } from '#lib/motion.ts';
import { usePresence } from '#lib/use-presence.ts';
import { useFloatingTip } from '#lib/utils/floating-tip.ts';
import { cellBackground, ACTIVITY_LEVELS } from '#lib/models/activity-heatmap.ts';
import type { ActivityBucket } from '#lib/models/activity-heatmap.ts';
import type { ConnectionLog } from '#lib/types/index.ts';
import { formatBytes } from '#lib/utils/index.ts';
import { m } from '#lib/i18n/messages.ts';
import {
  buildTimeFilterData,
  customTimeWindow,
  dayTimeWindow,
  formatTimeWindowShort,
  hourTimeWindow,
  type TrafficBucket,
} from './records-quick-filters';
import styles from './RecordsTimeFilter.module.css';

type ActivityTip = { title: string; range: string; bucket: TrafficBucket };

const WEEK_DAYS = 7;
/** Three previous weeks stay inside the 28 days of activity the daemon fetches. */
const MAX_WEEK_OFFSET_DAYS = 21;

interface Props {
  start?: number;
  end?: number;
  logs: readonly ConnectionLog[];
  activityBuckets?: readonly ActivityBucket[];
  now: number;
  onSelect: (start: number, end: number) => void;
  onClear: () => void;
}

const EMPTY_BUCKETS: readonly ActivityBucket[] = [];

const weekdayFormatter = new Intl.DateTimeFormat(undefined, { weekday: 'short' });
const fullDateFormatter = new Intl.DateTimeFormat(undefined, { dateStyle: 'full' });
const tipTimeFormatter = new Intl.DateTimeFormat(undefined, {
  hour: 'numeric',
  minute: '2-digit',
});
const allDayRange = `${tipTimeFormatter.format(new Date(2000, 0, 1, 0, 0))} – ${tipTimeFormatter.format(new Date(2000, 0, 1, 23, 59))}`;
const LEVELS = Array.from({ length: ACTIVITY_LEVELS }, (_, index) => (index + 1) / ACTIVITY_LEVELS);

/** Same five-stage shading as the Dashboard heatmap. */
function shade(bucket: TrafficBucket): string {
  return cellBackground(bucket.intensity, bucket.sent, bucket.received);
}

function dayTip(day: TrafficBucket): ActivityTip {
  return {
    title: fullDateFormatter.format(new Date(`${day.key}T12:00`)),
    range: allDayRange,
    bucket: day,
  };
}

function dateKey(date: Date) {
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, '0');
  const day = String(date.getDate()).padStart(2, '0');
  return `${year}-${month}-${day}`;
}

function shiftDateKey(key: string, days: number): string {
  const date = new Date(`${key}T12:00`);
  date.setDate(date.getDate() + days);
  return dateKey(date);
}

function directionLabel(direction: TrafficBucket['direction']) {
  if (direction === 'up') return m.records_time_upload();
  if (direction === 'down') return m.records_time_download();
  if (direction === 'balanced') return m.records_time_balanced();
  return m.records_time_no_activity();
}

export function RecordsTimeFilter({
  start,
  end,
  logs,
  activityBuckets = EMPTY_BUCKETS,
  now,
  onSelect,
  onClear,
}: Props) {
  const [open, setOpen] = useState(false);
  const root = useRef<HTMLDivElement>(null);
  const [selectedDate, setSelectedDate] = useState(() => dateKey(new Date()));
  const [startTime, setStartTime] = useState('00:00');
  const [endTime, setEndTime] = useState('23:59');
  const [invalidTime, setInvalidTime] = useState(false);
  const [weekOffset, setWeekOffset] = useState(0);
  const { present: popoverPresent, ref: popoverRef } = usePresence<HTMLDivElement>(
    open,
    popoverIn(),
    popoverOut(),
  );

  const active = Boolean(start && end);
  const label = start && end ? formatTimeWindowShort(start, end) : m.records_time_any();
  const data = useMemo(() => {
    const weekEnd = new Date(now);
    weekEnd.setHours(12, 0, 0, 0);
    weekEnd.setDate(weekEnd.getDate() - weekOffset);
    return buildTimeFilterData(logs, weekEnd, selectedDate, activityBuckets);
  }, [logs, now, weekOffset, selectedDate, activityBuckets]);
  const current = new Date(now);
  const timeMax =
    selectedDate === dateKey(current)
      ? toTimeKey(current.getHours(), current.getMinutes())
      : undefined;

  const tooltipId = useId();
  const {
    hover,
    placement: tipPlacement,
    tipRef,
    show: showTip,
    hide: hideTip,
  } = useFloatingTip<ActivityTip>({ estimatedTipHeight: 104 });

  function hourTip(hour: TrafficBucket, index: number): ActivityTip {
    const from = new Date(`${selectedDate}T${String(index).padStart(2, '0')}:00`);
    const to = new Date(from.getTime() + 59 * 60_000);
    return {
      title: fullDateFormatter.format(from),
      range: `${tipTimeFormatter.format(from)} – ${tipTimeFormatter.format(to)}`,
      bucket: hour,
    };
  }

  function windowKeys(offset: number) {
    const last = new Date(now);
    last.setHours(12, 0, 0, 0);
    last.setDate(last.getDate() - offset);
    const first = new Date(last);
    first.setDate(first.getDate() - (WEEK_DAYS - 1));
    return { start: dateKey(first), end: dateKey(last) };
  }

  function stepWeek(delta: number) {
    const nextOffset = Math.min(Math.max(weekOffset - delta, 0), MAX_WEEK_OFFSET_DAYS);
    if (nextOffset === weekOffset) return;
    const shift = weekOffset - nextOffset;
    const previousWindow = windowKeys(weekOffset);
    const inWindow = selectedDate >= previousWindow.start && selectedDate <= previousWindow.end;
    setWeekOffset(nextOffset);
    if (inWindow) {
      const moved = shiftDateKey(selectedDate, shift);
      const todayKey = dateKey(new Date(now));
      setSelectedDate(moved > todayKey ? todayKey : moved);
    }
  }

  /** A day applies at once and stays open, so it can be narrowed to an hour. */
  function chooseDay(day: TrafficBucket) {
    setSelectedDate(day.key);
    setInvalidTime(false);
    const range = dayTimeWindow(day.key);
    onSelect(range.start, range.end);
  }

  /** An hour or a custom range is the finest choice: apply and close. */
  function chooseHour(hour: number) {
    const range = hourTimeWindow(selectedDate, hour);
    onSelect(range.start, range.end);
    setOpen(false);
  }

  function applyCustomTime() {
    const range = customTimeWindow(selectedDate, startTime, endTime);
    setInvalidTime(!range);
    if (!range) return;
    onSelect(range.start, range.end);
    setOpen(false);
  }

  function isSelectedDay(day: TrafficBucket): boolean {
    if (!start || !end) return false;
    const range = dayTimeWindow(day.key);
    return start >= range.start && end <= range.end;
  }

  function isSelectedHour(index: number): boolean {
    if (!start || !end) return false;
    const range = hourTimeWindow(selectedDate, index);
    return start === range.start && end === range.end;
  }

  useEffect(() => {
    if (!open) return;
    const closeOutside = (event: PointerEvent) => {
      if (!root.current?.contains(event.target as Node)) setOpen(false);
    };
    window.addEventListener('pointerdown', closeOutside);
    return () => window.removeEventListener('pointerdown', closeOutside);
  }, [open]);

  useEffect(() => {
    // Closing the popover unmounts the hovered buttons without a mouseleave.
    if (!open) hideTip();
  }, [open, hideTip]);

  return (
    <>
      <div className={styles.timeFilter} ref={root}>
        <div className={clsx(styles.triggerWrap, active && styles.active)}>
          <button
            type="button"
            className={styles.trigger}
            aria-label={m.records_time_button_aria()}
            aria-expanded={open}
            aria-controls="records-time-filter"
            onClick={() => setOpen((v) => !v)}
          >
            <CalendarDays size={14} strokeWidth={1.9} aria-hidden="true" />
            <span className={styles.triggerLabel}>{label}</span>
            {!active && <ChevronDown size={13} strokeWidth={2} aria-hidden="true" />}
          </button>
          {active && (
            <button
              type="button"
              className={styles.clear}
              aria-label={m.records_clear_time_filter_aria()}
              onClick={() => {
                onClear();
                setOpen(false);
              }}
            >
              <X size={12} strokeWidth={2.2} />
            </button>
          )}
        </div>

        {popoverPresent && (
          <div
            ref={popoverRef}
            id="records-time-filter"
            className={styles.popover}
            role="dialog"
            tabIndex={-1}
            aria-label={m.records_time_filter_title()}
            onKeyDown={(event) => {
              if (event.key === 'Escape') setOpen(false);
            }}
          >
            <div className={styles.head}>
              <div>
                <strong>{m.records_time_filter_title()}</strong>
                <span>{m.records_time_filter_desc()}</span>
              </div>
              <div className={styles.legend} aria-hidden="true">
                <span>{m.records_time_less()}</span>
                {LEVELS.map((level) => (
                  <i key={level} style={{ background: cellBackground(level, 0, 1) }}></i>
                ))}
                <span>{m.records_time_more()}</span>
              </div>
            </div>

            <div className={styles.weekNav}>
              <Button
                variant="ghost"
                size="sm"
                iconOnly
                aria-label={m.records_time_previous_week()}
                disabled={weekOffset >= MAX_WEEK_OFFSET_DAYS}
                onClick={() => stepWeek(-WEEK_DAYS)}
              >
                <ChevronLeft size={14} strokeWidth={2.2} aria-hidden="true" />
              </Button>
              <div className={styles.days}>
                {data.days.map((day) => {
                  const selected = isSelectedDay(day);
                  return (
                    <button
                      key={day.key}
                      type="button"
                      className={clsx(
                        selected && styles.selected,
                        day.key === selectedDate && styles.current,
                      )}
                      aria-pressed={selected}
                      aria-label={m.records_time_day_aria({
                        date: day.key,
                        direction: directionLabel(day.direction),
                      })}
                      aria-describedby={hover?.bucket.key === day.key ? tooltipId : undefined}
                      onMouseEnter={(event) => showTip(dayTip(day), event)}
                      onMouseLeave={hideTip}
                      onFocus={(event) => showTip(dayTip(day), event)}
                      onBlur={hideTip}
                      onClick={() => chooseDay(day)}
                    >
                      <span className={styles.weekday}>
                        {weekdayFormatter.format(new Date(`${day.key}T12:00`))}
                      </span>
                      <strong>{Number(day.key.slice(-2))}</strong>
                      <i style={{ background: shade(day) }}></i>
                    </button>
                  );
                })}
              </div>
              <Button
                variant="ghost"
                size="sm"
                iconOnly
                aria-label={m.records_time_next_week()}
                disabled={weekOffset === 0}
                onClick={() => stepWeek(WEEK_DAYS)}
              >
                <ChevronRight size={14} strokeWidth={2.2} aria-hidden="true" />
              </Button>
            </div>

            <div className={styles.hours} role="group" aria-label={m.records_time_filter_desc()}>
              {data.hours.map((hour, index) => (
                <button
                  key={hour.key}
                  type="button"
                  className={clsx(isSelectedHour(index) && styles.selected)}
                  aria-label={m.records_time_hour_aria({
                    date: selectedDate,
                    hour: index,
                    direction: directionLabel(hour.direction),
                  })}
                  aria-describedby={hover?.bucket.key === hour.key ? tooltipId : undefined}
                  onMouseEnter={(event) => showTip(hourTip(hour, index), event)}
                  onMouseLeave={hideTip}
                  onFocus={(event) => showTip(hourTip(hour, index), event)}
                  onBlur={hideTip}
                  onClick={() => chooseHour(index)}
                >
                  <i style={{ background: shade(hour) }}></i>
                  <span>{index % 6 === 0 ? String(index).padStart(2, '0') : ''}</span>
                </button>
              ))}
            </div>

            <div className={styles.customTime}>
              <DateInput
                value={selectedDate}
                ariaLabel={m.records_time_filter_title()}
                onValueChange={(next) => {
                  setSelectedDate(next);
                  setInvalidTime(false);
                }}
              />
              <div className={styles.timeField}>
                <span>{m.records_time_from()}</span>
                <TimeInput
                  value={startTime}
                  ariaLabel={m.records_time_from()}
                  max={timeMax}
                  onValueChange={setStartTime}
                />
              </div>
              <div className={styles.timeField}>
                <span>{m.records_time_to()}</span>
                <TimeInput
                  value={endTime}
                  ariaLabel={m.records_time_to()}
                  max={timeMax}
                  onValueChange={setEndTime}
                />
              </div>
              <Button variant="secondary" size="sm" onClick={applyCustomTime}>
                {m.records_time_apply()}
              </Button>
            </div>
            {invalidTime && (
              <p className={styles.timeError} role="alert">
                {m.records_time_invalid()}
              </p>
            )}

            <div className={styles.foot}>
              <span className={styles.showing}>
                {start && end
                  ? m.records_time_showing({ range: formatTimeWindowShort(start, end) })
                  : null}
              </span>
              <Button variant="primary" size="sm" onClick={() => setOpen(false)}>
                {m.records_time_done()}
              </Button>
            </div>
          </div>
        )}
      </div>

      {hover &&
        createPortal(
          <div
            ref={tipRef}
            className={clsx(styles.tip, 'mono', tipPlacement === 'bottom' && styles.below)}
            id={tooltipId}
            role="tooltip"
          >
            <div className={styles.tipHead}>
              <span className={styles.tipDate}>{hover.title}</span>
              <span className={styles.tipRange}>{hover.range}</span>
            </div>
            <div className={styles.tipRow}>
              <span className={clsx(styles.tipSwatch, styles.down)}></span>
              <span className={styles.tipLabel}>{m.dashboard_activity_tip_down()}</span>
              <span className={styles.tipValue}>{formatBytes(hover.bucket.received)}</span>
            </div>
            <div className={styles.tipRow}>
              <span className={clsx(styles.tipSwatch, styles.up)}></span>
              <span className={styles.tipLabel}>{m.dashboard_activity_tip_up()}</span>
              <span className={styles.tipValue}>{formatBytes(hover.bucket.sent)}</span>
            </div>
          </div>,
          document.body,
        )}
    </>
  );
}

export default RecordsTimeFilter;
