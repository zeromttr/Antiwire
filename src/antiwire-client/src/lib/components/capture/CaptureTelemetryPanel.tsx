// Reads a mutable workspace while rendering, so React Compiler must not
// cache it (see src/lib/state/compiler-opt-out.test.ts).
'use no memo';

import clsx from 'clsx';
import { Activity } from 'lucide-react';
import { memo, useCallback, useMemo } from 'react';
import { BarSpark } from '#lib/components/ui/BarSpark.tsx';
import { SegmentedControl } from '#lib/components/ui/SegmentedControl.tsx';
import { VirtualScrollList } from '#lib/components/ui/VirtualScrollList.tsx';
import type { CapturedPacketDto } from '#lib/api/daemon.ts';
import { recentCapturedPackets } from '#lib/models/capture.ts';
import { formatBytes } from '#lib/utils/index.ts';
import { m } from '#lib/i18n/messages.ts';
import { getLocale } from '#lib/paraglide/runtime.js';
import { shallowEqual, useSelector } from '#lib/state/reactive.ts';
import { formatPacketEndpoint } from './inspector/packet-inspector';
import {
  PACKET_ROW_HEIGHT,
  capturePacketKey,
  chartSampleWindow,
  formatCaptureClock,
  formatPacketClock,
  recentSampleWindow,
} from './view/capture-view';
import type { CaptureTelemetryView, CaptureWorkspace } from './capture-workspace';
import styles from './CaptureTelemetryPanel.module.css';

interface Props {
  cap: CaptureWorkspace;
}

/** Matches the 48-sample window the chart describes. */
const CHART_SLOTS = 48;

interface PacketRowProps {
  packet: CapturedPacketDto;
  onInspect: (packet: CapturedPacketDto) => void;
}

/** Packets are immutable once received, so a row renders once per packet. */
const PacketRow = memo(function PacketRow({ packet, onInspect }: PacketRowProps) {
  const dash = m.common_em_dash();
  const source = formatPacketEndpoint(packet.source, packet.sourcePort, dash);
  const destination = formatPacketEndpoint(packet.destination, packet.destinationPort, dash);
  return (
    <button
      type="button"
      className={styles['packet-row']}
      onClick={() => onInspect(packet)}
      title={m.capture_packet_open_inspector_title()}
    >
      <span className={clsx('mono', styles.dim)}>{packet.sequence}</span>
      <span className={clsx('mono', styles.dim)}>
        {formatPacketClock(packet.timestampUs, getLocale())}
      </span>
      <span className={styles.protocol}>
        {packet.protocol || m.capture_inspector_other_protocol()}
      </span>
      <span className="mono" title={source}>
        {source}
      </span>
      <span className="mono" title={destination}>
        {destination}
      </span>
      <span className={clsx('mono', styles.dim, styles.num)}>
        {packet.capturedLength.toLocaleString()} B
      </span>
      <span title={packet.info}>{packet.info || dash}</span>
    </button>
  );
});

export const CaptureTelemetryPanel = memo(function CaptureTelemetryPanel({ cap }: Props) {
  const { samples, capturedPackets, telemetryView } = useSelector(
    cap,
    (c) => ({
      samples: c.samples,
      capturedPackets: c.capturedPackets,
      telemetryView: c.telemetryView,
    }),
    shallowEqual,
  );

  const chartSamples = useMemo(() => chartSampleWindow(samples), [samples]);
  const rateBars = useMemo(
    () => chartSamples.map((sample) => sample.bytesPerSecond),
    [chartSamples],
  );
  const recentPackets = useMemo(() => recentCapturedPackets(capturedPackets), [capturedPackets]);
  const recentSamples = recentSampleWindow(samples);
  const latestSample = samples.at(-1);
  const locale = getLocale();

  const packetCount = capturedPackets.length;
  const sampleCount = samples.length;
  const viewOptions = useMemo(
    () => [
      {
        value: 'packets',
        label: m.capture_view_packets(),
        count: packetCount.toLocaleString(),
      },
      {
        value: 'samples',
        label: m.capture_view_samples(),
        count: sampleCount.toLocaleString(),
      },
    ],
    [packetCount, sampleCount],
  );
  const onViewChange = useCallback(
    (view: string) => cap.setTelemetryView(view as CaptureTelemetryView),
    [cap],
  );
  const renderPacket = useCallback(
    ({ item }: { item: CapturedPacketDto }) => (
      <PacketRow packet={item} onInspect={cap.inspectPacket} />
    ),
    [cap],
  );

  return (
    <main className={styles.telemetry}>
      <section className={clsx(styles['chart-panel'], 'panel')}>
        <div className={styles['panel-heading']}>
          <h2>{m.capture_telemetry_title()}</h2>
          <span className={styles.meta}>{m.capture_sample_window()}</span>
          <strong className={styles.reading}>
            {formatBytes(latestSample?.bytesPerSecond ?? 0)}/s
          </strong>
        </div>
        <div className={styles.chart}>
          {rateBars.length > 1 ? (
            <BarSpark
              values={rateBars}
              color="var(--acc)"
              width="100%"
              height={88}
              gap={3}
              slots={CHART_SLOTS}
            />
          ) : (
            <div className={styles['chart-empty']}>
              <Activity size={18} />
              <strong>{m.capture_chart_empty_title()}</strong>
              <span>{m.capture_chart_empty_body()}</span>
            </div>
          )}
        </div>
        <div className={styles['chart-axis']}>
          <span>
            {chartSamples[0]
              ? formatCaptureClock(chartSamples[0].timestampMs, locale)
              : m.common_em_dash()}
          </span>
          <span>{m.capture_chart_now()}</span>
        </div>
      </section>

      <section className={clsx(styles['activity-panel'], 'panel')}>
        <div className={styles['panel-heading']}>
          <h2>
            {telemetryView === 'packets'
              ? m.capture_explorer_packets_title()
              : m.capture_explorer_samples_title()}
          </h2>
          <div className={styles['view-switch']}>
            <SegmentedControl
              options={viewOptions}
              value={telemetryView}
              ariaLabel={m.capture_telemetry_view_aria()}
              onChange={onViewChange}
            />
          </div>
        </div>
        {telemetryView === 'packets' ? (
          <>
            <div className={styles['packet-head']}>
              <span>{m.capture_packet_col_no()}</span>
              <span>{m.capture_packet_col_time()}</span>
              <span>{m.capture_packet_col_proto()}</span>
              <span>{m.capture_packet_col_source()}</span>
              <span>{m.capture_packet_col_destination()}</span>
              <span>{m.capture_packet_col_length()}</span>
              <span>{m.capture_packet_col_info()}</span>
            </div>
            <div className={styles['packet-list']}>
              <VirtualScrollList
                items={recentPackets}
                estimateSize={PACKET_ROW_HEIGHT}
                getItemKey={capturePacketKey}
                row={renderPacket}
                empty={<div className={styles['sample-empty']}>{m.capture_packet_empty()}</div>}
              />
            </div>
          </>
        ) : (
          <>
            <div className={styles['sample-head']}>
              <span>{m.capture_sample_col_time()}</span>
              <span>{m.capture_sample_col_packets()}</span>
              <span>{m.capture_sample_col_delta()}</span>
              <span>{m.capture_sample_col_pcap_size()}</span>
              <span>{m.capture_sample_col_rate()}</span>
            </div>
            <div className={styles['sample-list']}>
              {recentSamples.length ? (
                recentSamples.map((sample) => (
                  <div key={sample.timestampMs} className={styles['sample-row']}>
                    <span>{formatCaptureClock(sample.timestampMs, locale)}</span>
                    <span>{sample.packets.toLocaleString()}</span>
                    <span className={clsx(sample.packetDelta > 0 && styles.positive)}>
                      +{sample.packetDelta.toLocaleString()}
                    </span>
                    <span>{formatBytes(sample.bytes)}</span>
                    <span>{formatBytes(sample.bytesPerSecond)}/s</span>
                  </div>
                ))
              ) : (
                <div className={styles['sample-empty']}>{m.capture_sample_empty()}</div>
              )}
            </div>
          </>
        )}
      </section>
    </main>
  );
});

export default CaptureTelemetryPanel;
