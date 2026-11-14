import { describe, expect, it } from 'bun:test';
import { recordProtocolLabel, wellKnownPortName } from './well-known-ports';

describe('wellKnownPortName', () => {
  it('names common ports that apply to both transports', () => {
    expect(wellKnownPortName(443, 'TCP')).toBe('HTTPS');
    expect(wellKnownPortName(443, 'UDP')).toBe('HTTPS');
    expect(wellKnownPortName(53, 'udp')).toBe('DNS');
  });

  it('only names transport-specific ports for that protocol', () => {
    expect(wellKnownPortName(5353, 'UDP')).toBe('MDNS');
    expect(wellKnownPortName(5353, 'TCP')).toBeUndefined();
    expect(wellKnownPortName(22, 'TCP')).toBe('SSH');
    expect(wellKnownPortName(22, 'UDP')).toBeUndefined();
  });

  it('ignores unknown or invalid ports', () => {
    expect(wellKnownPortName(49152, 'TCP')).toBeUndefined();
    expect(wellKnownPortName(0, 'TCP')).toBeUndefined();
    expect(wellKnownPortName(443.5, 'TCP')).toBeUndefined();
  });
});

describe('recordProtocolLabel', () => {
  it('prefers the service name and falls back to the transport', () => {
    expect(recordProtocolLabel('UDP', 5353)).toBe('MDNS');
    expect(recordProtocolLabel('TCP', 443)).toBe('HTTPS');
    expect(recordProtocolLabel('TCP', 9)).toBe('TCP');
    expect(recordProtocolLabel('UDP', 5353)).not.toBe('UDP');
  });
});
