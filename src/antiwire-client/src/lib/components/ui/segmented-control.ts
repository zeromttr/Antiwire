export type SegmentedTone = 'accent' | 'ok' | 'bad';

export type SegmentedOption =
  | string
  | {
      value: string;
      label: string;
      tone?: SegmentedTone;
      /** Trailing count badge, e.g. how many items the segment shows. */
      count?: number | string;
    };

export function normalizeSegmentedOptions(options: SegmentedOption[]) {
  return options.map((option) =>
    typeof option === 'string'
      ? { value: option, label: option, tone: 'accent' as SegmentedTone, count: undefined }
      : {
          value: option.value,
          label: option.label,
          tone: option.tone ?? 'accent',
          count: option.count,
        },
  );
}
