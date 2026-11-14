// Reads a mutable workspace while rendering, so React Compiler must not
// cache it (see src/lib/state/compiler-opt-out.test.ts).
'use no memo';

import clsx from 'clsx';
import { memo, useMemo } from 'react';
import { StatCell } from '#lib/components/ui/StatCell.tsx';
import { captureLimitProgress, formatCaptureDuration } from '#lib/models/capture.ts';
import { formatBytes } from '#lib/utils/index.ts';
import { m } from '#lib/i18n/messages.ts';
import { shallowEqual, useSelector } from '#lib/state/reactive.ts';
import type { CaptureWorkspace } from './capture-workspace';
import { chartSampleWindow } from './view/capture-view';
import styles from './CaptureMetrics.module.css';

interface Props {
  cap: CaptureWorkspace;
}

/** The strip shows the newest 20 counter samples as bars. */
const BAR_SAMPLES = 20;

/** `formatBytes` returns "34.2 MB"; the strip shows the unit separately. */
function splitValue(text: string): { value: string; unit: string } {
  const index = text.lastIndexOf(' ');
  return index > 0
    ? { value: text.slice(0, index), unit: text.slice(index + 1) }
    : { value: text, unit: '' };
}

export const CaptureMetrics = memo(function CaptureMetrics({ cap }: Props) {
  const s = useSelector(
    cap,
    (c) => ({
      samples: c.samples,
      packets: c.packets,
      bytes: c.bytes,
      appName: c.appName,
      filteredPackets: c.filteredPackets,
      elapsedSeconds: c.elapsedSeconds,
      droppedPackets: c.droppedPackets,
      maxSeconds: c.configuration.maxSeconds,
      maxBytes: c.configuration.maxBytes,
    }),
    shallowEqual,
  );

  const { packetBars, byteBars } = useMemo(() => {
    const recent = chartSampleWindow(s.samples).slice(-BAR_SAMPLES);
    return {
      packetBars: recent.map((sample) => sample.packetDelta),
      byteBars: recent.map((sample) => sample.bytesPerSecond),
    };
  }, [s.samples]);
  const latestSample = s.samples.at(-1);
  const size = splitValue(formatBytes(s.bytes));
  const limitProgress = captureLimitProgress(s.elapsedSeconds, s.bytes, s.maxSeconds, s.maxBytes);

  return (
    <section className={clsx(styles.metrics, 'panel')} aria-label={m.capture_stats_aria()}>
      <StatCell
        label={m.capture_metric_packets()}
        value={s.packets.toLocaleString()}
        color="var(--acc)"
        bars={packetBars}
        barSlots={BAR_SAMPLES}
        barsLabel={m.capture_bars_packets_aria()}
        caption={
          s.appName
            ? m.capture_app_filtered({ count: s.filteredPackets.toLocaleString() })
            : m.capture_metric_packets_sample({ count: latestSample?.packetDelta ?? 0 })
        }
      />
      <StatCell
        label={m.capture_metric_pcap_size()}
        value={size.value}
        unit={size.unit}
        color="var(--acc-sub)"
        bars={byteBars}
        barSlots={BAR_SAMPLES}
        barsLabel={m.capture_bars_bytes_aria()}
        caption={`${formatBytes(latestSample?.bytesPerSecond ?? 0)}/s`}
      />
      <StatCell
        label={m.capture_metric_elapsed()}
        value={formatCaptureDuration(s.elapsedSeconds)}
        color="var(--t2)"
        caption={m.capture_metric_limit_pct({ pct: limitProgress.toFixed(0) })}
      />
      <StatCell
        label={m.capture_metric_dropped()}
        value={s.droppedPackets.toLocaleString()}
        color="var(--bad)"
        valueColor={s.droppedPackets > 0 ? 'var(--bad)' : 'var(--t1)'}
        caption={
          <span className={clsx(s.droppedPackets > 0 && styles.warn)}>
            {s.droppedPackets
              ? m.capture_metric_dropped_pressure()
              : m.capture_metric_dropped_none()}
          </span>
        }
      />
    </section>
  );
});

export default CaptureMetrics;
