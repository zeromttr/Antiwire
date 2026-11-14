import { describe, expect, it } from 'bun:test';
import {
  formatHexDump,
  formatPacketEndpoint,
  formatPacketTimestamp,
  hexDumpGlyph,
  normalizeInspectorPacket,
} from './packet-inspector';

describe('formatHexDump', () => {
  it('returns an empty string for no bytes', () => {
    expect(formatHexDump([])).toBe('');
  });

  it('formats a short line with ascii and padding', () => {
    const dump = formatHexDump([0x45, 0x00, 0x0a, 0x41]);
    expect(dump.startsWith('0000  45 00 0a 41')).toBe(true);
    expect(dump.endsWith('E..A')).toBe(true);
  });

  it('wraps at sixteen bytes and continues the offset', () => {
    const data = Array.from({ length: 17 }, (_, index) => index);
    const [first, second] = formatHexDump(data).split('\n');
    expect(first.startsWith('0000  00 01 02 03')).toBe(true);
    expect(second.startsWith('0010  10')).toBe(true);
    expect(second.endsWith('.')).toBe(true);
  });
});

describe('hexDumpGlyph', () => {
  it('keeps printable ascii and replaces the rest', () => {
    expect(hexDumpGlyph(0x41)).toBe('A');
    expect(hexDumpGlyph(0x0a)).toBe('.');
    expect(hexDumpGlyph(0x7f)).toBe('.');
  });
});

describe('formatPacketEndpoint', () => {
  it('formats ipv4, ipv6, and missing values', () => {
    expect(formatPacketEndpoint('10.0.0.2', 443)).toBe('10.0.0.2:443');
    expect(formatPacketEndpoint('fe80::1', 80)).toBe('[fe80::1]:80');
    expect(formatPacketEndpoint('10.0.0.2', 0)).toBe('10.0.0.2');
    expect(formatPacketEndpoint('', 80, '—')).toBe('—');
  });
});

describe('formatPacketTimestamp', () => {
  it('formats microseconds as iso-8601', () => {
    const timestampUs = Date.parse('2024-09-05T16:00:00.000Z') * 1000;
    expect(formatPacketTimestamp(timestampUs)).toBe('2024-09-05T16:00:00.000Z');
  });
});

describe('normalizeInspectorPacket', () => {
  it('returns null for empty payloads', () => {
    expect(normalizeInspectorPacket(null)).toBeNull();
    expect(normalizeInspectorPacket({})).toBeNull();
  });

  it('accepts camelCase and snake_case fields', () => {
    expect(
      normalizeInspectorPacket({
        capture_id: 'cap-1',
        sequence: 9,
        timestamp_us: 1000,
        captured_length: 64,
        original_length: 128,
        link_layer: 1,
        protocol: 'TCP',
        source: '10.0.0.1',
        destination: '10.0.0.2',
        source_port: 443,
        destination_port: 80,
        info: 'syn',
        data: [69, 0],
      }),
    ).toMatchObject({
      captureId: 'cap-1',
      sequence: 9,
      timestampUs: 1000,
      capturedLength: 64,
      originalLength: 128,
      linkLayer: 1,
      protocol: 'TCP',
      sourcePort: 443,
      destinationPort: 80,
      data: [69, 0],
    });
  });
});
