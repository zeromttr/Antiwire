/**
 * Whole seconds from `now` until `at` (both epoch ms), rounded up so the count reaches 0
 * only when the attempt is due. Null while no attempt is scheduled.
 */
export function secondsUntil(at: number | null, now: number): number | null {
  if (at === null) return null;
  return Math.max(0, Math.ceil((at - now) / 1000));
}
