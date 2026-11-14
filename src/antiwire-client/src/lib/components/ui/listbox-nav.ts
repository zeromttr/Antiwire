/**
 * Keyboard navigation helper shared by listbox-style controls
 * (Dropdown menu, SegmentedControl tablist).
 *
 * Pure function so it can be unit-tested without a DOM.
 */
export type ListboxNavKey = 'ArrowDown' | 'ArrowUp' | 'ArrowLeft' | 'ArrowRight' | 'Home' | 'End';

export function moveActiveIndex(
  current: number,
  count: number,
  key: ListboxNavKey,
  orientation: 'vertical' | 'horizontal' | 'both' = 'both',
): number {
  if (count <= 0) return -1;
  const clamped = current >= 0 && current < count ? current : -1;

  const next = (delta: number) => {
    if (clamped === -1) return delta > 0 ? 0 : count - 1;
    return (clamped + delta + count) % count;
  };

  switch (key) {
    case 'Home':
      return 0;
    case 'End':
      return count - 1;
    case 'ArrowDown':
      if (orientation === 'horizontal') return clamped;
      return next(1);
    case 'ArrowUp':
      if (orientation === 'horizontal') return clamped;
      return next(-1);
    case 'ArrowRight':
      if (orientation === 'vertical') return clamped;
      return next(1);
    case 'ArrowLeft':
      if (orientation === 'vertical') return clamped;
      return next(-1);
  }
}
