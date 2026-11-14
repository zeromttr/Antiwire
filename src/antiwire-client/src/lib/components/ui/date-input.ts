export type MonthView = { year: number; month: number };

const DATE_KEY = /^(\d{4})-(\d{2})-(\d{2})$/;
const WEEK_CELLS = 42;
const SUNDAY_REFERENCE = new Date(2023, 0, 1);

function pad(value: number): string {
  return String(value).padStart(2, '0');
}

export function parseDateKey(key: string): Date | null {
  const match = DATE_KEY.exec(key);
  if (!match) return null;
  const year = Number(match[1]);
  const month = Number(match[2]) - 1;
  const day = Number(match[3]);
  const date = new Date(year, month, day);
  return date.getFullYear() === year && date.getMonth() === month && date.getDate() === day
    ? date
    : null;
}

export function toDateKey(date: Date): string {
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}`;
}

export function viewOf(date: Date): MonthView {
  return { year: date.getFullYear(), month: date.getMonth() };
}

export function viewKey(view: MonthView): string {
  return `${view.year}-${pad(view.month + 1)}`;
}

export function daysInMonth(year: number, month: number): number {
  return new Date(year, month + 1, 0).getDate();
}

export function shiftDays(date: Date, delta: number): Date {
  return new Date(date.getFullYear(), date.getMonth(), date.getDate() + delta);
}

export function shiftMonths(date: Date, delta: number): Date {
  const year = date.getFullYear() + Math.floor((date.getMonth() + delta) / 12);
  const month = (((date.getMonth() + delta) % 12) + 12) % 12;
  return new Date(year, month, Math.min(date.getDate(), daysInMonth(year, month)));
}

export function sameDay(a: Date, b: Date): boolean {
  return (
    a.getFullYear() === b.getFullYear() &&
    a.getMonth() === b.getMonth() &&
    a.getDate() === b.getDate()
  );
}

/** True when `date` falls on a later calendar day than `reference`. */
export function isAfterDay(date: Date, reference: Date): boolean {
  return toDateKey(date) > toDateKey(reference);
}

/** First year of the `span`-year window that contains `year` (e.g. 2026 → 2016 at span 12). */
export function yearWindowStart(year: number, span = 12): number {
  return Math.floor(year / span) * span;
}

/** Locale week start as 0 = Sunday … 6 = Saturday, falling back to Monday. */
export function firstDayOfWeek(locale?: string): number {
  if (locale) {
    try {
      const resolved = new Intl.Locale(locale) as Intl.Locale & {
        weekInfo?: { firstDay?: number };
        getWeekInfo?: () => { firstDay?: number };
      };
      const info = resolved.getWeekInfo?.() ?? resolved.weekInfo;
      if (info?.firstDay) return info.firstDay % 7;
    } catch {
      // Unknown locale tags fall back to Monday.
    }
  }
  return 1;
}

/** Six seven-day rows covering the view month plus its leading and trailing days. */
export function monthGrid(view: MonthView, weekStart: number): Date[] {
  const first = new Date(view.year, view.month, 1);
  const offset = (first.getDay() - weekStart + 7) % 7;
  const start = shiftDays(first, -offset);
  return Array.from({ length: WEEK_CELLS }, (_, index) => shiftDays(start, index));
}

export function weekdayLabels(locale: string | undefined, weekStart: number): string[] {
  const formatter = new Intl.DateTimeFormat(locale, { weekday: 'short' });
  return Array.from({ length: 7 }, (_, index) =>
    formatter.format(shiftDays(SUNDAY_REFERENCE, weekStart + index)),
  );
}
