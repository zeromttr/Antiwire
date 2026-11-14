import { describe, expect, it } from 'bun:test';
import {
  counterRatePerSecond,
  niceThroughputAxisMax,
  throughputAxisDomain,
  throughputAxisTicks,
} from './throughput';

const KB = 1024;
const MB = 1024 * 1024;

describe('throughput rate', () => {
  it('normalizes counter deltas to bytes per second', () => {
    expect(counterRatePerSecond(16_000, 1_000, 15_000)).toBe(1_000);
    expect(counterRatePerSecond(3_000, 1_000, 500)).toBe(4_000);
  });

  it('treats reset counters and invalid intervals as zero', () => {
    expect(counterRatePerSecond(500, 1_000, 1_000)).toBe(0);
    expect(counterRatePerSecond(1_000, 500, 0)).toBe(0);
    expect(counterRatePerSecond(Number.NaN, 500, 1_000)).toBe(0);
  });
});

describe('throughput axis scale', () => {
  it('rounds a 55 KB peak up to 60 KB instead of 55 or 55.5', () => {
    expect(niceThroughputAxisMax(55 * KB)).toBe(60 * KB);
    expect(niceThroughputAxisMax(55.5 * KB)).toBe(60 * KB);
  });

  it('keeps the axis floor at 0 bytes for any peak', () => {
    expect(throughputAxisDomain(0)[0]).toBe(0);
    expect(throughputAxisDomain(55 * KB)[0]).toBe(0);
    expect(throughputAxisDomain(2 * MB)[0]).toBe(0);
  });

  it('raises the ceiling when upload grows past the current nice step', () => {
    expect(throughputAxisDomain(40 * KB)[1]).toBe(40 * KB);
    expect(throughputAxisDomain(55 * KB)[1]).toBe(60 * KB);
    expect(throughputAxisDomain(61 * KB)[1]).toBe(70 * KB);
  });

  it('uses whole-unit tick values that include 0 and the nice ceiling', () => {
    expect(throughputAxisTicks(60 * KB)).toEqual([0, 10, 20, 30, 40, 50, 60].map((kb) => kb * KB));
    expect(throughputAxisTicks(70 * KB)).toEqual(
      [0, 10, 20, 30, 40, 50, 60, 70].map((kb) => kb * KB),
    );
  });
});
