import { useMemo } from 'react';
import { BlocklistPicker } from '#lib/components/blocklists/BlocklistPicker.tsx';
import type { StepProps } from './onboarding-steps';

export function BlocklistsStep({ choices, patch }: StepProps) {
  const selected = useMemo(() => new Set(choices.blocklistIds), [choices.blocklistIds]);
  // The step body already scrolls, so the picker lays out at full height.
  return (
    <BlocklistPicker selected={selected} onchange={(next) => patch('blocklistIds', [...next])} />
  );
}

export default BlocklistsStep;
