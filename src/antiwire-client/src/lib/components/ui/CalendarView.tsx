import clsx from 'clsx';
import type { CSSProperties, Ref } from 'react';
import { sameDay, toDateKey, type MonthView } from './date-input';
import styles from './CalendarView.module.css';

interface Props {
  mode: 'days' | 'months' | 'years';
  direction: -1 | 0 | 1;
  /** Whether the popover is open; replays the selected-day pop. */
  open: boolean;
  /** Receives the grid container (was `bind:picker`), so the parent can focus cells. */
  pickerRef?: Ref<HTMLDivElement>;
  cells: Date[];
  view: MonthView;
  selected: Date;
  selectedKey: string;
  today: Date;
  activeIndex: number;
  years: number[];
  monthLabels: string[];
  dayFormatter: Intl.DateTimeFormat;
  monthFormatter: Intl.DateTimeFormat;
  focusMonth: number;
  focusYear: number;
  /** `bind:focusMonth`: a month cell received focus. */
  onFocusMonthChange: (month: number) => void;
  /** `bind:focusYear`: a year cell received focus. */
  onFocusYearChange: (year: number) => void;
  futureDay: (date: Date) => boolean;
  futureMonth: (year: number, month: number) => boolean;
  futureYear: (year: number) => boolean;
  onSelect: (date: Date) => void;
  onFocusDay: (key: string) => void;
  onChooseMonth: (month: number) => void;
  onChooseYear: (year: number) => void;
}

export function CalendarView({
  mode,
  direction,
  open,
  pickerRef,
  cells,
  view,
  selected,
  selectedKey,
  today,
  activeIndex,
  years,
  monthLabels,
  dayFormatter,
  monthFormatter,
  focusMonth,
  focusYear,
  onFocusMonthChange,
  onFocusYearChange,
  futureDay,
  futureMonth,
  futureYear,
  onSelect,
  onFocusDay,
  onChooseMonth,
  onChooseYear,
}: Props) {
  return (
    <div className={clsx(styles.view, open && styles.open)} data-dir={direction} ref={pickerRef}>
      {mode === 'days' ? (
        <div className={styles.grid}>
          {cells.map((day, index) => {
            const dayKey = toDateKey(day);
            const isToday = sameDay(day, today);
            return (
              <button
                key={dayKey}
                type="button"
                className={clsx(
                  styles.day,
                  day.getMonth() !== view.month && styles.outside,
                  dayKey === selectedKey && styles.selected,
                  isToday && styles.isToday,
                )}
                data-date={dayKey}
                style={{ '--row': Math.floor(index / 7) } as CSSProperties}
                tabIndex={index === activeIndex ? 0 : -1}
                aria-label={dayFormatter.format(day)}
                aria-current={isToday ? 'date' : undefined}
                disabled={futureDay(day)}
                onClick={() => onSelect(day)}
                onFocus={() => onFocusDay(dayKey)}
              >
                <span className={styles.dayNum}>{day.getDate()}</span>
              </button>
            );
          })}
        </div>
      ) : mode === 'months' ? (
        <div className={clsx(styles.grid, styles.months)}>
          {monthLabels.map((monthLabel, month) => (
            <button
              key={month}
              type="button"
              className={clsx(
                styles.pick,
                selected.getFullYear() === view.year &&
                  selected.getMonth() === month &&
                  styles.selected,
                view.year === today.getFullYear() && month === today.getMonth() && styles.isToday,
              )}
              data-month={month}
              style={{ '--row': Math.floor(month / 3) } as CSSProperties}
              tabIndex={month === focusMonth ? 0 : -1}
              aria-label={monthFormatter.format(new Date(view.year, month, 1))}
              disabled={futureMonth(view.year, month)}
              onClick={() => onChooseMonth(month)}
              onFocus={() => onFocusMonthChange(month)}
            >
              {monthLabel}
            </button>
          ))}
        </div>
      ) : (
        <div className={clsx(styles.grid, styles.years)}>
          {years.map((year, index) => (
            <button
              key={year}
              type="button"
              className={clsx(
                styles.pick,
                'mono',
                selected.getFullYear() === year && styles.selected,
                today.getFullYear() === year && styles.isToday,
              )}
              data-year={year}
              style={{ '--row': Math.floor(index / 3) } as CSSProperties}
              tabIndex={year === focusYear ? 0 : -1}
              disabled={futureYear(year)}
              onClick={() => onChooseYear(year)}
              onFocus={() => onFocusYearChange(year)}
            >
              {year}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

export default CalendarView;
