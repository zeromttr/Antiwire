import clsx from 'clsx';
import { useEffect, useMemo, useState } from 'react';
import { api, type CapturedPacketDto } from '#lib/api/daemon.ts';
import { isNative, listen } from '#lib/bridge.ts';
import {
  formatHexDump,
  formatPacketEndpoint,
  formatPacketTimestamp,
  normalizeInspectorPacket,
} from '#lib/components/capture/inspector/packet-inspector.ts';
import { m } from '#lib/i18n/messages.ts';
import { browserPreviewMode } from '#lib/preview/runtime.ts';
import styles from './InspectorPage.module.css';

function closeInspector() {
  void api.closeWindow();
}

/**
 * The packet inspector window. Packet bytes are untrusted, so every value is
 * rendered as text (React escapes it); nothing is ever parsed as HTML.
 */
export default function InspectorPage() {
  const [packet, setPacket] = useState<CapturedPacketDto | null>(null);

  useEffect(() => {
    // Invalid payloads are ignored and keep the current packet.
    const applyPacket = (value: unknown) => {
      const next = normalizeInspectorPacket(value);
      if (next) setPacket(next);
    };
    if (browserPreviewMode === 'sample') {
      void api.getPacketInspectorPacket().then(applyPacket);
      return;
    }
    if (!isNative()) return;
    void api
      .getPacketInspectorPacket()
      .then(applyPacket)
      .catch(() => {});
    return listen('packet-inspector://packet', applyPacket);
  }, []);

  useEffect(() => {
    const onKeydown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') closeInspector();
    };
    window.addEventListener('keydown', onKeydown);
    return () => window.removeEventListener('keydown', onKeydown);
  }, []);

  // A full-size packet is a 64 KiB hex dump; format it once per packet.
  const hexDump = useMemo(() => (packet ? formatHexDump(packet.data) : ''), [packet]);

  if (!packet) {
    return (
      <div className={styles.inspector} data-page-motion="inspector">
        <div className={styles.empty}>
          <p className={styles.kicker}>{m.inspector_header()}</p>
          <p className={styles.waiting}>{m.inspector_waiting()}</p>
        </div>
      </div>
    );
  }

  const dash = m.common_em_dash();
  const protocol = packet.protocol || m.capture_inspector_unknown_protocol();
  const source = formatPacketEndpoint(packet.source, packet.sourcePort, dash);
  const destination = formatPacketEndpoint(packet.destination, packet.destinationPort, dash);
  const previewBytes =
    packet.data.length < packet.capturedLength
      ? m.capture_inspector_preview_bytes_partial({
          value: packet.data.length,
          count: packet.data.length,
        })
      : m.capture_inspector_preview_bytes({ value: packet.data.length });

  return (
    <div className={styles.inspector} data-page-motion="inspector">
      <header className={styles.headline}>
        <div className={styles['title-row']}>
          <h1>{m.capture_inspector_packet({ sequence: packet.sequence })}</h1>
          <span className={clsx(styles.protocol, 'mono')}>{protocol}</span>
        </div>
      </header>

      <ul className={clsx(styles.details, 'mono')}>
        <li>
          {m.capture_inspector_timestamp({ value: formatPacketTimestamp(packet.timestampUs) })}
        </li>
        <li>{m.capture_inspector_protocol({ value: protocol })}</li>
        <li>{m.capture_inspector_source({ value: source })}</li>
        <li>{m.capture_inspector_destination({ value: destination })}</li>
        <li>{m.capture_inspector_captured_length({ value: packet.capturedLength })}</li>
        <li>{m.capture_inspector_original_length({ value: packet.originalLength })}</li>
        <li>{previewBytes}</li>
        <li>{m.capture_inspector_link_layer({ value: packet.linkLayer })}</li>
        <li>{m.capture_inspector_info({ value: packet.info || dash })}</li>
      </ul>

      <section className={styles['hex-panel']} aria-label={m.capture_inspector_hex_heading()}>
        <h2 className="mono">{m.capture_inspector_hex_heading()}</h2>
        <pre className={clsx(styles.hex, 'mono')}>{hexDump || dash}</pre>
      </section>
    </div>
  );
}
