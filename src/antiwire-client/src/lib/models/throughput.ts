const BYTES_PER_KB = 1024;
const BYTES_PER_MB = 1024 * 1024;
const BYTES_PER_GB = 1024 * 1024 * 1024;
const IDLE_AXIS_MAX_BYTES = BYTES_PER_KB;

/** Convert a cumulative byte-counter delta into bytes per second. */
export function counterRatePerSecond(
  current: number,
  previous: number,
  elapsedMilliseconds: number,
): number {
  if (
    !Number.isFinite(current) ||
    !Number.isFinite(previous) ||
    !Number.isFinite(elapsedMilliseconds) ||
    elapsedMilliseconds <= 0
  ) {
    return 0;
  }

  return (Math.max(0, current - previous) * 1000) / elapsedMilliseconds;
}

function throughputDisplayUnit(bytes: number): number {
  if (bytes < BYTES_PER_KB) return 1;
  if (bytes < BYTES_PER_MB) return BYTES_PER_KB;
  if (bytes < BYTES_PER_GB) return BYTES_PER_MB;
  return BYTES_PER_GB;
}

/** Round a peak rate up to a whole 1 / 10 / 100 step in B, KB, MB, or GB. */
export function niceThroughputAxisMax(peakBytesPerSec: number): number {
  if (!Number.isFinite(peakBytesPerSec) || peakBytesPerSec <= 0) {
    return IDLE_AXIS_MAX_BYTES;
  }

  const unit = throughputDisplayUnit(peakBytesPerSec);
  const value = peakBytesPerSec / unit;
  const magnitude = 10 ** Math.floor(Math.log10(value));
  const nice = Math.ceil(value / magnitude - Number.EPSILON) * magnitude;
  return nice * unit;
}

export function throughputAxisDomain(peakBytesPerSec: number): [number, number] {
  return [0, niceThroughputAxisMax(peakBytesPerSec)];
}

export function throughputAxisTicks(maxBytes: number): number[] {
  const ceiling = niceThroughputAxisMax(maxBytes);
  const unit = throughputDisplayUnit(ceiling);
  const maxValue = ceiling / unit;
  if (maxValue <= 0) return [0];

  const magnitude = 10 ** Math.floor(Math.log10(maxValue));
  let step = magnitude;
  if (maxValue / step > 8) step = magnitude * 2;
  if (maxValue / step > 8) step = magnitude * 5;

  const ticks: number[] = [];
  for (let value = 0; value <= maxValue + 1e-9; value += step) {
    ticks.push(value * unit);
  }
  if (ticks[ticks.length - 1] !== ceiling) ticks.push(ceiling);
  return ticks;
}
