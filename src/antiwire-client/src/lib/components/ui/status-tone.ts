export type StatusTone = 'ok' | 'bad' | 'warn' | 'info' | 'idle' | 'accent';

/**
 * Map a theme colour reference (as models hand to the view, e.g. `var(--bad)`)
 * onto a Status tone, so data-driven colours render through one component.
 */
export function statusToneFromColor(color: string | null | undefined): StatusTone {
  const value = color ?? '';
  if (value.includes('--bad')) return 'bad';
  if (value.includes('--warn')) return 'warn';
  if (value.includes('--ok')) return 'ok';
  if (value.includes('--acc-sub')) return 'info';
  if (value.includes('--acc')) return 'accent';
  return 'idle';
}
