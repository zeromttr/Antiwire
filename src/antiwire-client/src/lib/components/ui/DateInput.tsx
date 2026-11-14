import clsx from 'clsx';
import { CalendarDays, ChevronLeft, ChevronRight } from 'lucide-react';
import { useEffect, useId, useMemo, useRef, useState, type KeyboardEvent } from 'react';
import { m } from '#lib/i18n/messages.ts';
import { CalendarView } from './CalendarView.tsx';
import { PickerPopover, type PickerPopoverHandle } from './PickerPopover.tsx';
import {
  daysInMonth,
  firstDayOfWeek,
  isAfterDay,
  monthGrid,
  parseDateKey,
  shiftDays,
  shiftMonths,
  toDateKey,
  viewKey,
  viewOf,
  weekdayLabels,
  yearWindowStart,
  type MonthView,
} from './date-input';
import styles from './DateInput.module.css';

interface Props {
  /** `YYYY-MM-DD`; empty shows today. Controlled (was `bind:value`). */
  value?: string;
  ariaLabel?: string;
  className?: string;
  /** Overrides the trigger's shown text (e.g. a week range) while `value` still drives the calendar. */
  displayText?: string;
  /** Borderless transparent trigger for embedding inside a joined control group. */
  bare?: boolean;
  /** `bind:value`: a day was picked. */
  onValueChange?: (value: string) => void;
  /** Same moment as `onValueChange`. */
  onChange?: (value: string) => void;
}

const MIN_YEAR = 1900;
const YEAR_WINDOW = 12;

/** Locale formatters, built once per module. */
const FORMAT = (() => {
  const weekStart = firstDayOfWeek(
    typeof navigator === 'undefined' ? undefined : navigator.language,
  );
  const monthShortFormatter = new Intl.DateTimeFormat(undefined, { month: 'short' });
  return {
    weekStart,
    weekdays: weekdayLabels(undefined, weekStart),
    monthFormatter: new Intl.DateTimeFormat(undefined, { month: 'long', year: 'numeric' }),
    valueFormatter: new Intl.DateTimeFormat(undefined, {
      day: 'numeric',
      month: 'short',
      year: 'numeric',
    }),
    dayFormatter: new Intl.DateTimeFormat(undefined, { dateStyle: 'full' }),
    monthLabels: Array.from({ length: 12 }, (_, month) =>
      monthShortFormatter.format(new Date(2000, month, 1)),
    ),
  };
})();

export function DateInput({
  value = '',
  ariaLabel,
  className = '',
  displayText,
  bare = false,
  onValueChange,
  onChange,
}: Props) {
  const uid = useId();
  const panelId = `${uid}-panel`;
  const { weekStart, weekdays, monthFormatter, valueFormatter, dayFormatter, monthLabels } = FORMAT;

  const popover = useRef<PickerPopoverHandle | null>(null);
  const picker = useRef<HTMLDivElement | null>(null);
  const [open, setOpen] = useState(false);
  const [direction, setDirection] = useState<-1 | 0 | 1>(0);
  const [focusedKey, setFocusedKey] = useState('');
  const [focusMonth, setFocusMonth] = useState(0);
  const [focusYear, setFocusYear] = useState(0);
  const [mode, setMode] = useState<'days' | 'months' | 'years'>('days');
  const [today, setToday] = useState(() => new Date());
  const [view, setView] = useState<MonthView>(() => viewOf(parseDateKey(value) ?? new Date()));
  /** Bumped to move DOM focus to the active cell after the next render. */
  const [focusTick, setFocusTick] = useState(0);
  const requestFocus = () => setFocusTick((tick) => tick + 1);

  const futureDay = (date: Date): boolean => isAfterDay(date, today);
  const futureMonth = (year: number, month: number): boolean =>
    year > today.getFullYear() || (year === today.getFullYear() && month > today.getMonth());
  const futureYear = (year: number): boolean => year > today.getFullYear();

  // Follow outside value changes while closed (and re-anchor when closing).
  const [synced, setSynced] = useState({ value, open });
  if (synced.value !== value || synced.open !== open) {
    setSynced({ value, open });
    const next = parseDateKey(value);
    if (next && !open) setView(viewOf(futureDay(next) ? today : next));
  }

  const selected = parseDateKey(value) ?? today;
  const selectedKey = toDateKey(selected);
  const cells = useMemo(() => monthGrid(view, weekStart), [view, weekStart]);
  const windowStart = yearWindowStart(view.year, YEAR_WINDOW);
  const years = useMemo(
    () => Array.from({ length: YEAR_WINDOW }, (_, index) => windowStart + index),
    [windowStart],
  );
  const pickerKey =
    mode === 'days'
      ? `days:${viewKey(view)}`
      : mode === 'months'
        ? `months:${view.year}`
        : `years:${windowStart}`;
  const periodLabel =
    mode === 'days'
      ? monthFormatter.format(new Date(view.year, view.month, 1))
      : mode === 'months'
        ? String(view.year)
        : `${windowStart} – ${windowStart + YEAR_WINDOW - 1}`;
  const periodAria =
    mode === 'days'
      ? `${periodLabel}: ${m.common_date_choose_month_year()}`
      : mode === 'months'
        ? `${periodLabel}: ${m.common_date_choose_year()}`
        : periodLabel;
  const prevLabel =
    mode === 'days'
      ? m.common_date_prev_month()
      : mode === 'months'
        ? m.common_date_prev_year()
        : m.common_date_prev_years();
  const nextLabel =
    mode === 'days'
      ? m.common_date_next_month()
      : mode === 'months'
        ? m.common_date_next_year()
        : m.common_date_next_years();
  const nextDisabled =
    mode === 'days'
      ? view.year === today.getFullYear() && view.month === today.getMonth()
      : mode === 'months'
        ? view.year >= today.getFullYear()
        : windowStart + YEAR_WINDOW > today.getFullYear();
  const focusedIndex = cells.findIndex((day) => toDateKey(day) === focusedKey);
  const activeIndex = focusedIndex >= 0 ? focusedIndex : 0;
  const focusedDate = cells[activeIndex];
  const displayValue = valueFormatter.format(selected);
  const shownValue = displayText ?? displayValue;
  const triggerLabel = ariaLabel ? `${ariaLabel}: ${shownValue}` : shownValue;

  function focusCell() {
    const selector =
      mode === 'days'
        ? `[data-date="${focusedKey}"]`
        : mode === 'months'
          ? `[data-month="${focusMonth}"]`
          : `[data-year="${focusYear}"]`;
    picker.current?.querySelector<HTMLButtonElement>(selector)?.focus({ preventScroll: true });
  }

  const focusCellRef = useRef(focusCell);
  useEffect(() => {
    focusCellRef.current = focusCell;
  });
  useEffect(() => {
    if (focusTick > 0) focusCellRef.current();
  }, [focusTick]);

  function onOpen() {
    const now = new Date();
    setToday(now);
    setMode('days');
    setDirection(0);
    const anchor = isAfterDay(selected, now) ? now : selected;
    setView(viewOf(anchor));
    setFocusedKey(toDateKey(anchor));
    requestFocus();
  }

  function focusDayInView(target: MonthView) {
    const day = Math.min(selected.getDate(), daysInMonth(target.year, target.month));
    const candidate = new Date(target.year, target.month, day);
    setFocusedKey(toDateKey(futureDay(candidate) ? today : candidate));
  }

  function setDayFocus(date: Date) {
    const clamped = futureDay(date) ? today : date;
    setFocusedKey(toDateKey(clamped));
    const next = viewOf(clamped);
    if (next.year !== view.year || next.month !== view.month) {
      setDirection(clamped.getTime() < new Date(view.year, view.month, 1).getTime() ? -1 : 1);
      setView(next);
    }
    requestFocus();
  }

  function shiftMonthView(delta: number) {
    const next = viewOf(shiftMonths(new Date(view.year, view.month, 1), delta));
    if (next.year < MIN_YEAR) return;
    setDirection(delta > 0 ? 1 : -1);
    setView(next);
    focusDayInView(next);
    requestFocus();
  }

  function setMonthFocus(month: number) {
    setFocusMonth(Math.min(month, view.year === today.getFullYear() ? today.getMonth() : 11));
    requestFocus();
  }

  function showMonths() {
    setDirection(0);
    setMode('months');
    setFocusMonth(Math.min(view.month, view.year === today.getFullYear() ? today.getMonth() : 11));
    requestFocus();
  }

  function stepMonths(delta: number) {
    const max = today.getFullYear() * 12 + today.getMonth();
    const min = MIN_YEAR * 12;
    const total = Math.min(Math.max(view.year * 12 + focusMonth + delta, min), max);
    const year = Math.floor(total / 12);
    const month = total % 12;
    if (year === view.year && month === focusMonth) return;
    setDirection(delta > 0 ? 1 : -1);
    setView({ year, month });
    setFocusMonth(month);
    requestFocus();
  }

  function stepYearFocus(delta: number) {
    const next = Math.min(Math.max(view.year + delta, MIN_YEAR), today.getFullYear());
    if (next === view.year) return;
    setDirection(delta > 0 ? 1 : -1);
    setView({ year: next, month: view.month });
    setFocusMonth(Math.min(focusMonth, next === today.getFullYear() ? today.getMonth() : 11));
    requestFocus();
  }

  function chooseMonth(month: number) {
    if (futureMonth(view.year, month)) return;
    setDirection(month === view.month ? 0 : month > view.month ? 1 : -1);
    const next = { year: view.year, month };
    setView(next);
    setMode('days');
    focusDayInView(next);
    requestFocus();
  }

  function showYears() {
    setDirection(0);
    setMode('years');
    setFocusYear(Math.min(view.year, today.getFullYear()));
    requestFocus();
  }

  function setYearFocus(year: number) {
    const next = Math.min(Math.max(year, MIN_YEAR), today.getFullYear());
    if (next === focusYear) return;
    setDirection(next > focusYear ? 1 : -1);
    setFocusYear(next);
    if (next < windowStart || next > windowStart + YEAR_WINDOW - 1) {
      setView({ year: next, month: view.month });
    }
    requestFocus();
  }

  function stepYearPage(delta: number) {
    const next = Math.min(Math.max(focusYear + delta, MIN_YEAR), today.getFullYear());
    if (next === focusYear) return;
    setDirection(delta > 0 ? 1 : -1);
    setFocusYear(next);
    setView({ year: next, month: view.month });
    requestFocus();
  }

  function chooseYear(year: number) {
    if (futureYear(year)) return;
    setDirection(year === view.year ? 0 : year > view.year ? 1 : -1);
    setView({ year, month: view.month });
    setMode('months');
    setFocusMonth(Math.min(view.month, year === today.getFullYear() ? today.getMonth() : 11));
    requestFocus();
  }

  function stepPeriod(delta: number) {
    if (mode === 'days') shiftMonthView(delta);
    else if (mode === 'months') stepYearFocus(delta);
    else stepYearPage(delta * YEAR_WINDOW);
  }

  function onPeriodClick() {
    if (mode === 'days') showMonths();
    else if (mode === 'months') showYears();
  }

  function select(date: Date) {
    const key = toDateKey(date);
    if (key !== value) {
      onValueChange?.(key);
      onChange?.(key);
    }
    popover.current?.closePanel(true);
  }

  function onTriggerKeyDown(event: KeyboardEvent<HTMLButtonElement>) {
    if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
      event.preventDefault();
      if (open) focusCell();
      else popover.current?.openPanel();
    }
  }

  function onDaysKeyDown(event: KeyboardEvent, target: HTMLElement) {
    if (!target.hasAttribute('data-date') || !focusedDate) return;
    let handled = true;
    switch (event.key) {
      case 'ArrowLeft':
        setDayFocus(shiftDays(focusedDate, -1));
        break;
      case 'ArrowRight':
        setDayFocus(shiftDays(focusedDate, 1));
        break;
      case 'ArrowUp':
        setDayFocus(shiftDays(focusedDate, -7));
        break;
      case 'ArrowDown':
        setDayFocus(shiftDays(focusedDate, 7));
        break;
      case 'Home':
        setDayFocus(shiftDays(focusedDate, -(activeIndex % 7)));
        break;
      case 'End':
        setDayFocus(shiftDays(focusedDate, 6 - (activeIndex % 7)));
        break;
      case 'PageUp': {
        const previous = shiftMonths(focusedDate, -1);
        if (previous.getFullYear() >= MIN_YEAR) setDayFocus(previous);
        break;
      }
      case 'PageDown':
        setDayFocus(shiftMonths(focusedDate, 1));
        break;
      case 'Enter':
      case ' ':
        select(focusedDate);
        break;
      default:
        handled = false;
    }
    if (handled) event.preventDefault();
  }

  function onMonthsKeyDown(event: KeyboardEvent, target: HTMLElement) {
    if (!target.hasAttribute('data-month')) return;
    let handled = true;
    switch (event.key) {
      case 'ArrowLeft':
        stepMonths(-1);
        break;
      case 'ArrowRight':
        stepMonths(1);
        break;
      case 'ArrowUp':
        stepMonths(-3);
        break;
      case 'ArrowDown':
        stepMonths(3);
        break;
      case 'Home':
        setMonthFocus(0);
        break;
      case 'End':
        setMonthFocus(11);
        break;
      case 'PageUp':
        stepYearFocus(-1);
        break;
      case 'PageDown':
        stepYearFocus(1);
        break;
      case 'Enter':
      case ' ':
        chooseMonth(focusMonth);
        break;
      default:
        handled = false;
    }
    if (handled) event.preventDefault();
  }

  function onYearsKeyDown(event: KeyboardEvent, target: HTMLElement) {
    if (!target.hasAttribute('data-year')) return;
    let handled = true;
    switch (event.key) {
      case 'ArrowLeft':
        setYearFocus(focusYear - 1);
        break;
      case 'ArrowRight':
        setYearFocus(focusYear + 1);
        break;
      case 'ArrowUp':
        setYearFocus(focusYear - 3);
        break;
      case 'ArrowDown':
        setYearFocus(focusYear + 3);
        break;
      case 'Home':
        setYearFocus(windowStart);
        break;
      case 'End':
        setYearFocus(windowStart + YEAR_WINDOW - 1);
        break;
      case 'PageUp':
        stepYearPage(-YEAR_WINDOW);
        break;
      case 'PageDown':
        stepYearPage(YEAR_WINDOW);
        break;
      case 'Enter':
      case ' ':
        chooseYear(focusYear);
        break;
      default:
        handled = false;
    }
    if (handled) event.preventDefault();
  }

  function onPanelKeyDown(event: KeyboardEvent<HTMLDivElement>) {
    const target = event.target as HTMLElement;
    if (mode === 'days') onDaysKeyDown(event, target);
    else if (mode === 'months') onMonthsKeyDown(event, target);
    else onYearsKeyDown(event, target);
  }

  const periodText = (
    <span
      key={periodLabel}
      className={clsx(
        styles.periodText,
        direction === 1 && styles.fromEnd,
        direction === -1 && styles.fromStart,
      )}
    >
      {periodLabel}
    </span>
  );

  return (
    <PickerPopover
      ref={popover}
      open={open}
      onOpenChange={setOpen}
      className={className}
      bare={bare}
      icon={CalendarDays}
      panelId={panelId}
      triggerLabel={triggerLabel}
      panelLabel={ariaLabel ?? shownValue}
      valueText={shownValue}
      valueKey={displayText ?? value}
      panelWidth={252}
      onOpen={onOpen}
      onTriggerKeyDown={onTriggerKeyDown}
      onPanelKeyDown={onPanelKeyDown}
    >
      <header className={styles.panelHead}>
        <button
          type="button"
          className={styles.nav}
          aria-label={prevLabel}
          onClick={() => stepPeriod(-1)}
        >
          <ChevronLeft size={14} strokeWidth={2.2} aria-hidden="true" />
        </button>
        {mode === 'years' ? (
          <span className={styles.period}>{periodText}</span>
        ) : (
          <button
            type="button"
            className={clsx(styles.period, styles.periodButton)}
            aria-label={periodAria}
            onClick={onPeriodClick}
          >
            {periodText}
          </button>
        )}
        <button
          type="button"
          className={styles.nav}
          aria-label={nextLabel}
          disabled={nextDisabled}
          onClick={() => stepPeriod(1)}
        >
          <ChevronRight size={14} strokeWidth={2.2} aria-hidden="true" />
        </button>
      </header>

      {mode === 'days' && (
        <div className={styles.weekdays} aria-hidden="true">
          {weekdays.map((weekday, index) => (
            <span key={index}>{weekday}</span>
          ))}
        </div>
      )}

      <CalendarView
        key={pickerKey}
        mode={mode}
        direction={direction}
        open={open}
        pickerRef={picker}
        cells={cells}
        view={view}
        selected={selected}
        selectedKey={selectedKey}
        today={today}
        activeIndex={activeIndex}
        years={years}
        monthLabels={monthLabels}
        dayFormatter={dayFormatter}
        monthFormatter={monthFormatter}
        onFocusDay={setFocusedKey}
        focusMonth={focusMonth}
        focusYear={focusYear}
        onFocusMonthChange={setFocusMonth}
        onFocusYearChange={setFocusYear}
        futureDay={futureDay}
        futureMonth={futureMonth}
        futureYear={futureYear}
        onSelect={select}
        onChooseMonth={chooseMonth}
        onChooseYear={chooseYear}
      />

      <footer className={styles.panelFoot}>
        <button type="button" className={styles.today} onClick={() => select(today)}>
          {m.common_date_today()}
        </button>
      </footer>
    </PickerPopover>
  );
}

export default DateInput;
