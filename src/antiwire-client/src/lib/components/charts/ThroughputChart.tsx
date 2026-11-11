import { curveMonotoneX } from '@visx/curve';
import { LinearGradient } from '@visx/gradient';
import { Area, LinePath } from '@visx/shape';
import {
  memo,
  useCallback,
  useId,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
  type PointerEvent,
} from 'react';
import { m } from '#lib/i18n/messages.ts';
import { prefersReducedMotion } from '#lib/motion.ts';
import { throughputAxisDomain, throughputAxisTicks } from '#lib/models/throughput.ts';
import { useSelector } from '#lib/state/reactive.ts';
import { client } from '#lib/stores/client.ts';
import {
  MAX_THROUGHPUT_SAMPLES,
  throughputChart,
  type ThroughputSample,
} from '#lib/stores/throughput-chart.ts';
import { formatThroughput, formatThroughputAxisTick } from '#lib/utils/index.ts';
import styles from './ThroughputChart.module.css';

interface Props {
  downloadRate: number;
  uploadRate: number;
}

const MAX_SAMPLES = MAX_THROUGHPUT_SAMPLES;
/** `right` leaves room for the live dots and their pulse at the newest sample. */
const PADDING = { top: 22, bottom: 8, left: 46, right: 12 } as const;
/** Tooltip offset from the hovered sample (x) and the pointer (y). */
const TIP_OFFSET_X = 14;
const TIP_OFFSET_Y = -12;
const DEFAULT_HEIGHT = 220;
/** The glide between samples lasts as long as the gap between them, within these bounds. */
const GLIDE_MIN_MS = 250;
const GLIDE_MAX_MS = 1500;

/** A sample positioned on the x axis; `t` is -1 for the one that just scrolled off. */
type Point = ThroughputSample;

/**
 * A linear map from `domain` to `range`. Local rather than @visx/scale, whose
 * generic scale factory bundles d3-time and every colour interpolator.
 */
function linearScale(
  [d0, d1]: readonly [number, number],
  [r0, r1]: readonly [number, number],
): (value: number) => number {
  const k = d1 === d0 ? 0 : (r1 - r0) / (d1 - d0);
  return (value) => r0 + (value - d0) * k;
}

/**
 * The dashboard's rolling download/upload chart, drawn with visx.
 *
 * - Download is a filled area and upload a bare line, so the two series differ
 *   in form, not only in colour: several accent pairs are too close in hue to
 *   be told apart reliably by colour alone.
 * - The rates overlap from the baseline; they are independent, so never stacked.
 * - Each new sample glides in from the right over the interval since the last
 *   one, instead of the whole chart jumping a step. The sample that scrolled off
 *   is kept one step left of the plot so the left edge never shows a gap.
 * - Pointer scrubbing never re-renders: the crosshair, the hover dots and the
 *   tooltip are written straight to the DOM.
 */
export const ThroughputChart = memo(function ThroughputChart({ downloadRate, uploadRate }: Props) {
  const samples = useSelector(throughputChart, (store) => store.samples);
  const chartColors = useSelector(client, (store) => store.chartColors);
  const downloadColor = chartColors.download;
  const uploadColor = chartColors.upload;
  const id = useId().replace(/:/g, '');

  const containerRef = useRef<HTMLDivElement | null>(null);
  const slideRef = useRef<SVGGElement | null>(null);
  const crosshairRef = useRef<SVGLineElement | null>(null);
  const hoverDownRef = useRef<SVGCircleElement | null>(null);
  const hoverUpRef = useRef<SVGCircleElement | null>(null);
  const tipRef = useRef<HTMLDivElement | null>(null);
  const tipDownRef = useRef<HTMLSpanElement | null>(null);
  const tipUpRef = useRef<HTMLSpanElement | null>(null);

  const [size, setSize] = useState({ width: 0, height: DEFAULT_HEIGHT });
  const cachedRect = useRef<DOMRect | null>(null);
  /** Scrub state: the hovered sample index and the pointer y within the container. */
  const scrub = useRef<{ index: number; pointerY: number } | null>(null);

  useLayoutEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    const measure = () => {
      cachedRect.current = null;
      const width = el.clientWidth;
      const height = el.clientHeight || DEFAULT_HEIGHT;
      setSize((prev) =>
        prev.width === width && prev.height === height ? prev : { width, height },
      );
    };
    measure();
    const observer = new ResizeObserver(measure);
    observer.observe(el);
    const invalidate = () => {
      cachedRect.current = null;
    };
    window.addEventListener('resize', invalidate);
    window.addEventListener('scroll', invalidate, true);
    return () => {
      observer.disconnect();
      window.removeEventListener('resize', invalidate);
      window.removeEventListener('scroll', invalidate, true);
    };
  }, []);

  const plotWidth = Math.max(0, size.width - PADDING.left - PADDING.right);
  const plotHeight = Math.max(0, size.height - PADDING.top - PADDING.bottom);
  /** Distance between samples: how far the data moves per new sample. */
  const step = plotWidth / (MAX_SAMPLES - 1);

  // The sample that just scrolled off, drawn at t = -1 while the rest glides left.
  const [track, setTrack] = useState<{
    samples: readonly ThroughputSample[];
    departed: Point | null;
  }>({ samples, departed: null });
  if (track.samples !== samples) {
    const first = track.samples[0];
    setTrack({ samples, departed: first ? { ...first, t: -1 } : null });
  }
  const departed = track.departed;
  const points = useMemo<Point[]>(
    () => (departed ? [departed, ...samples] : [...samples]),
    [departed, samples],
  );

  const valueDomain = useMemo(() => {
    let peak = 0;
    for (const sample of samples) {
      if (sample.download > peak) peak = sample.download;
      if (sample.upload > peak) peak = sample.upload;
    }
    peak = Math.max(peak, Math.max(0, downloadRate), Math.max(0, uploadRate));
    return throughputAxisDomain(peak);
  }, [samples, downloadRate, uploadRate]);
  const valueTicks = useMemo(() => throughputAxisTicks(valueDomain[1]), [valueDomain]);

  const xScale = useMemo(() => linearScale([0, MAX_SAMPLES - 1], [0, plotWidth]), [plotWidth]);
  const yScale = useMemo(
    () => linearScale([0, valueDomain[1] > 0 ? valueDomain[1] : 1], [plotHeight, 0]),
    [valueDomain, plotHeight],
  );
  const xOf = useCallback((point: Point) => xScale(point.t), [xScale]);
  const yDownload = useCallback((point: Point) => yScale(point.download), [yScale]);
  const yUpload = useCallback((point: Point) => yScale(point.upload), [yScale]);

  const latest = samples[samples.length - 1];

  // Latest values for the imperative painters, without re-binding handlers.
  const live = useRef({ samples, plotWidth, plotHeight, yScale, step });
  useLayoutEffect(() => {
    live.current = { samples, plotWidth, plotHeight, yScale, step };
  });

  // Glide: start one step to the right (where the data sat before this sample)
  // and slide to rest. A sample arriving mid-glide continues from where the
  // previous glide had got to, so the motion never jumps.
  const glide = useRef<{ animation: Animation | null; from: number; lastAt: number }>({
    animation: null,
    from: 0,
    lastAt: 0,
  });
  useLayoutEffect(() => {
    const el = slideRef.current;
    const { step: distance } = live.current;
    const now = performance.now();
    const lastAt = glide.current.lastAt;
    glide.current.lastAt = now;
    const running = glide.current.animation;
    // Nothing to glide from on the first paint. A hidden window does not advance
    // animations, so gliding there would only pile up offset to replay on show.
    if (
      !lastAt ||
      !el ||
      distance <= 0 ||
      scrub.current ||
      document.hidden ||
      prefersReducedMotion()
    ) {
      running?.finish();
      return;
    }
    let carried = 0;
    if (running?.playState === 'running') {
      const progress = Number(running.effect?.getComputedTiming().progress ?? 1);
      carried = (1 - progress) * glide.current.from;
      running.cancel();
    }
    // At most one step behind: a burst of samples snaps forward rather than
    // gliding further and further from the data.
    const from = distance + Math.min(carried, distance);
    glide.current.from = from;
    glide.current.animation = el.animate(
      [{ transform: `translateX(${from}px)` }, { transform: 'translateX(0)' }],
      {
        duration: Math.min(GLIDE_MAX_MS, Math.max(GLIDE_MIN_MS, now - lastAt)),
        easing: 'linear',
      },
    );
  }, [samples]);

  const hideScrub = useCallback(() => {
    scrub.current = null;
    containerRef.current?.classList.remove(styles.scrubbing);
    tipRef.current?.classList.remove(styles.tipVisible);
  }, []);

  const paintScrub = useCallback(() => {
    const state = scrub.current;
    const container = containerRef.current;
    const tip = tipRef.current;
    const crosshair = crosshairRef.current;
    const hoverDown = hoverDownRef.current;
    const hoverUp = hoverUpRef.current;
    if (!state || !container || !tip || !crosshair || !hoverDown || !hoverUp) return;
    const { samples: current, plotWidth: width, yScale: y } = live.current;
    const sample = current[state.index];
    if (!sample) {
      hideScrub();
      return;
    }
    // The glide would slide the data out from under the crosshair; settle it.
    glide.current.animation?.finish();

    const dataX = (width * state.index) / (MAX_SAMPLES - 1);
    crosshair.setAttribute('x1', String(dataX));
    crosshair.setAttribute('x2', String(dataX));
    hoverDown.setAttribute('cx', String(dataX));
    hoverDown.setAttribute('cy', String(y(sample.download)));
    hoverUp.setAttribute('cx', String(dataX));
    hoverUp.setAttribute('cy', String(y(sample.upload)));
    container.classList.add(styles.scrubbing);

    if (tipDownRef.current)
      tipDownRef.current.textContent = formatThroughput(sample.download).label;
    if (tipUpRef.current) tipUpRef.current.textContent = formatThroughput(sample.upload).label;

    // Anchored top-left at the sample and pointer; flipped to stay inside the chart.
    const tipWidth = tip.offsetWidth;
    const tipHeight = tip.offsetHeight;
    const containerWidth = container.clientWidth;
    const containerHeight = container.clientHeight;
    const anchorX = PADDING.left + dataX;
    let left = anchorX + TIP_OFFSET_X;
    if (left + tipWidth > containerWidth) left = anchorX - TIP_OFFSET_X - tipWidth;
    let top = state.pointerY + TIP_OFFSET_Y;
    if (top + tipHeight > containerHeight) top = containerHeight - tipHeight;
    if (top < 0) top = 0;
    tip.style.transform = `translate3d(${Math.max(0, left)}px, ${top}px, 0)`;
    tip.classList.add(styles.tipVisible);
  }, [hideScrub]);

  // A new sample (or a resize) moves the data under a resting pointer.
  useLayoutEffect(() => {
    if (scrub.current) paintScrub();
  }, [samples, plotWidth, plotHeight, yScale, paintScrub]);

  const onScrub = useCallback(
    (event: PointerEvent<HTMLDivElement>) => {
      const container = containerRef.current;
      const { plotWidth: width, plotHeight: height } = live.current;
      if (!container || width <= 0) return;
      const rect = cachedRect.current ?? container.getBoundingClientRect();
      cachedRect.current = rect;
      const pointX = event.clientX - rect.left;
      const pointY = event.clientY - rect.top;
      const plotX = pointX - PADDING.left;
      const plotY = pointY - PADDING.top;
      // A little slack past the right edge, so the newest sample is easy to hit.
      if (plotX < 0 || plotY < 0 || plotX > width + PADDING.right || plotY > height) {
        hideScrub();
        return;
      }
      const index = Math.max(
        0,
        Math.min(MAX_SAMPLES - 1, Math.round((plotX / width) * (MAX_SAMPLES - 1))),
      );
      scrub.current = { index, pointerY: pointY };
      paintScrub();
    },
    [hideScrub, paintScrub],
  );

  const onScrubEnter = useCallback(() => {
    cachedRect.current = containerRef.current?.getBoundingClientRect() ?? null;
  }, []);

  const onScrubLeave = useCallback(() => {
    cachedRect.current = null;
    hideScrub();
  }, [hideScrub]);

  const ready = size.width > 0;
  const baseline = Math.round(plotHeight) + 0.5;

  return (
    <div className={styles.throughputChart} ref={containerRef} data-testid="throughput-chart">
      {ready && (
        <svg
          className={styles.svg}
          width={size.width}
          height={size.height}
          role="img"
          aria-label={m.dashboard_throughput_title()}
        >
          <defs>
            <clipPath id={`${id}-clip`}>
              <rect x={0} y={-2} width={plotWidth} height={plotHeight + 4} />
            </clipPath>
            <LinearGradient
              id={`${id}-download`}
              from={downloadColor}
              to={downloadColor}
              fromOpacity={0.3}
              toOpacity={0}
            />
            <LinearGradient
              id={`${id}-upload`}
              from={uploadColor}
              to={uploadColor}
              fromOpacity={0.08}
              toOpacity={0}
            />
          </defs>
          <g transform={`translate(${PADDING.left},${PADDING.top})`}>
            <g>
              {valueTicks.map((tick) => {
                const y = Math.round(yScale(tick)) + 0.5;
                return (
                  <line
                    key={tick}
                    className={styles.gridLine}
                    x1={0}
                    x2={plotWidth}
                    y1={y}
                    y2={y}
                  />
                );
              })}
            </g>
            {/* Plain text rather than @visx/axis, whose label component bundles a CSS calc() parser. */}
            <g>
              {valueTicks.map((tick) => (
                <text
                  key={tick}
                  className={styles.yTick}
                  x={-8}
                  y={yScale(tick)}
                  textAnchor="end"
                  dominantBaseline="central"
                >
                  {formatThroughputAxisTick(tick)}
                </text>
              ))}
            </g>

            <g clipPath={`url(#${id}-clip)`}>
              <g ref={slideRef} className={styles.slide}>
                <Area<Point>
                  data={points}
                  x={xOf}
                  y0={plotHeight}
                  y1={yUpload}
                  curve={curveMonotoneX}
                  fill={`url(#${id}-upload)`}
                  stroke="none"
                />
                <Area<Point>
                  data={points}
                  x={xOf}
                  y0={plotHeight}
                  y1={yDownload}
                  curve={curveMonotoneX}
                  fill={`url(#${id}-download)`}
                  stroke="none"
                />
                <LinePath<Point>
                  className={styles.line}
                  data={points}
                  x={xOf}
                  y={yUpload}
                  curve={curveMonotoneX}
                  stroke={uploadColor}
                />
                <LinePath<Point>
                  className={styles.line}
                  data={points}
                  x={xOf}
                  y={yDownload}
                  curve={curveMonotoneX}
                  stroke={downloadColor}
                />
              </g>
            </g>

            <line className={styles.ruleLine} x1={0} x2={plotWidth} y1={baseline} y2={baseline} />

            {latest && (
              <g className={styles.liveDots} aria-hidden="true">
                {(
                  [
                    ['upload', uploadColor, latest.upload],
                    ['download', downloadColor, latest.download],
                  ] as const
                ).map(([key, color, value]) => (
                  <g
                    key={key}
                    className={styles.liveDot}
                    style={{ transform: `translate(${plotWidth}px, ${yScale(value)}px)` }}
                  >
                    <circle className={styles.pulse} r={4} fill={color} />
                    <circle className={styles.dot} r={4} fill={color} />
                  </g>
                ))}
              </g>
            )}

            <g className={styles.hover} aria-hidden="true">
              <line ref={crosshairRef} className={styles.crosshair} y1={0} y2={plotHeight} />
              <circle ref={hoverUpRef} className={styles.dot} r={4} fill={uploadColor} />
              <circle ref={hoverDownRef} className={styles.dot} r={4} fill={downloadColor} />
            </g>
          </g>
        </svg>
      )}

      <div className={styles.chartTip} ref={tipRef} aria-hidden="true">
        <div className={styles.chartTipBody}>
          <div className={styles.chartTipRow}>
            <span className={styles.chartTipKey} style={{ background: downloadColor }}></span>
            <span className={styles.chartTipLabel}>{m.dashboard_legend_down()}</span>
            <span className={styles.chartTipValue} ref={tipDownRef}></span>
          </div>
          <div className={styles.chartTipRow}>
            <span className={styles.chartTipKey} style={{ background: uploadColor }}></span>
            <span className={styles.chartTipLabel}>{m.dashboard_legend_up()}</span>
            <span className={styles.chartTipValue} ref={tipUpRef}></span>
          </div>
        </div>
      </div>

      <div
        className={styles.scrubLayer}
        aria-hidden="true"
        onPointerEnter={onScrubEnter}
        onPointerMove={onScrub}
        onPointerDown={onScrub}
        onPointerLeave={onScrubLeave}
      ></div>
    </div>
  );
});

export default ThroughputChart;
