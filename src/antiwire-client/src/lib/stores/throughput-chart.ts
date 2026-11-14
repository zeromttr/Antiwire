import { Reactive } from '#lib/state/reactive.ts';

export const MAX_THROUGHPUT_SAMPLES = 80;

export type ThroughputSample = { t: number; download: number; upload: number };

function createEmptySamples(count: number): ThroughputSample[] {
  return Array.from({ length: count }, (_, t) => ({ t, download: 0, upload: 0 }));
}

function rollSamples(
  previous: ThroughputSample[],
  download: number,
  upload: number,
): ThroughputSample[] {
  return [...previous.slice(1), { t: MAX_THROUGHPUT_SAMPLES - 1, download, upload }].map(
    (sample, t) => ({
      ...sample,
      t,
    }),
  );
}

/** The dashboard's rolling download/upload history. `samples` is replaced on every change. */
class ThroughputChartStore extends Reactive {
  #samples = createEmptySamples(MAX_THROUGHPUT_SAMPLES);

  get samples(): ThroughputSample[] {
    return this.#samples;
  }

  readonly record = (download: number, upload: number) => {
    this.#samples = rollSamples(this.#samples, Math.max(0, download), Math.max(0, upload));
    this.changed();
  };

  readonly reset = () => {
    this.#samples = createEmptySamples(MAX_THROUGHPUT_SAMPLES);
    this.changed();
  };
}

export const throughputChart = new ThroughputChartStore();
