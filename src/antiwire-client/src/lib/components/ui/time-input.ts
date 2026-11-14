export type TimeParts = { hours: number; minutes: number };

const TIME_KEY = /^(\d{2}):(\d{2})$/;

function pad(value: number): string {
  return String(value).padStart(2, '0');
}

export function parseTimeKey(key: string): TimeParts | null {
  const match = TIME_KEY.exec(key);
  if (!match) return null;
  const hours = Number(match[1]);
  const minutes = Number(match[2]);
  if (hours > 23 || minutes > 59) return null;
  return { hours, minutes };
}

export function toTimeKey(hours: number, minutes: number): string {
  return `${pad(hours)}:${pad(minutes)}`;
}

/** True when `parts` is later in the day than `bound` on a 24-hour clock. */
export function isAfterTime(parts: TimeParts, bound: TimeParts): boolean {
  return (
    parts.hours > bound.hours || (parts.hours === bound.hours && parts.minutes > bound.minutes)
  );
}

/** Caps `parts` at `bound`, keeping the value when no bound is given. */
export function clampTime(parts: TimeParts, bound: TimeParts | null): TimeParts {
  return bound && isAfterTime(parts, bound) ? { ...bound } : parts;
}
