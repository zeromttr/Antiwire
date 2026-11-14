import { describe, expect, it } from 'bun:test';
import { ApprovedPaths } from './approved-paths';

describe('ApprovedPaths', () => {
  it('is single-use and bounded', () => {
    const paths = new ApprovedPaths();
    expect(paths.take('picked.pcap')).toBe(false);

    paths.approve('picked.pcap');
    expect(paths.take('other.pcap')).toBe(false);
    expect(paths.take('picked.pcap')).toBe(true);
    expect(paths.take('picked.pcap')).toBe(false);

    for (let i = 0; i < 20; i++) paths.approve(`${i}.pcap`);
    expect(paths.take('0.pcap')).toBe(false);
    expect(paths.take('19.pcap')).toBe(true);
  });

  it('refuses a destination no dialog produced', () => {
    expect(() => new ApprovedPaths().require('x.csv')).toThrow(
      'the destination was not chosen in a save dialog',
    );
  });
});
