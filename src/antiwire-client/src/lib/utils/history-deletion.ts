/** Units the "delete recent history" control offers, smallest first. */
export const HISTORY_DELETION_UNITS = ['hours', 'days', 'weeks', 'months'] as const;
export type HistoryDeletionUnit = (typeof HISTORY_DELETION_UNITS)[number];

/** Largest amount accepted for any unit; past this, "delete all" is the clearer choice. */
export const MAX_HISTORY_DELETION_AMOUNT = 999;

/** What to delete: everything, or everything from `since` (unix seconds) onwards. */
export type HistoryDeletionRange = { all: true } | { all: false; since: number };

export function isValidHistoryDeletionAmount(amount: number): boolean {
  return Number.isInteger(amount) && amount >= 1 && amount <= MAX_HISTORY_DELETION_AMOUNT;
}

/**
 * Start of the last `amount` `unit`s before `now`, in unix seconds.
 *
 * Months are calendar months in local time, and land on the last day of a
 * shorter month: one month before 31 March is the end of February, not
 * 3 March.
 */
export function historyDeletionStart(
  amount: number,
  unit: HistoryDeletionUnit,
  now: Date = new Date(),
): number {
  if (!isValidHistoryDeletionAmount(amount)) {
    throw new RangeError(`Invalid history deletion amount: ${amount}`);
  }
  const start = new Date(now.getTime());
  switch (unit) {
    case 'hours':
      start.setTime(now.getTime() - amount * 3_600_000);
      break;
    case 'days':
      start.setDate(now.getDate() - amount);
      break;
    case 'weeks':
      start.setDate(now.getDate() - amount * 7);
      break;
    case 'months': {
      const day = now.getDate();
      start.setDate(1);
      start.setMonth(now.getMonth() - amount);
      const lastDay = new Date(start.getFullYear(), start.getMonth() + 1, 0).getDate();
      start.setDate(Math.min(day, lastDay));
      break;
    }
  }
  return Math.floor(start.getTime() / 1000);
}

const INTL_UNITS: Record<HistoryDeletionUnit, string> = {
  hours: 'hour',
  days: 'day',
  weeks: 'week',
  months: 'month',
};

/**
 * The unit's name as `Intl` writes it after `amount` in `locale`, e.g.
 * "hour" for 1 and "hours" for 2, so every locale gets its own plural forms.
 */
export function historyDeletionUnitLabel(
  unit: HistoryDeletionUnit,
  amount: number,
  locale: string,
): string {
  const parts = new Intl.NumberFormat(locale, {
    style: 'unit',
    unit: INTL_UNITS[unit],
    unitDisplay: 'long',
  }).formatToParts(amount);
  const label = parts
    .filter((part) => part.type === 'unit')
    .map((part) => part.value)
    .join('')
    .trim();
  return label || unit;
}
