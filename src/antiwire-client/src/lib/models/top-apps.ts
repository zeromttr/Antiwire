import type { AppSummary } from '#lib/types/index.ts';

/** Rolling window for the Dashboard's top applications. */
export const TOP_APPS_WINDOW_SECONDS = 24 * 60 * 60;
export const TOP_APPS_LIMIT = 10;
/** Rows visible before the list scrolls; matches Active now so the panels line up. */
export const TOP_APPS_VISIBLE_ROWS = 5;

export interface TopApp {
  name: string;
  path: string;
  totalBytes: number;
  bytesReceived: number;
  bytesSent: number;
  /** 0..1 of the busiest application's total, for the bar. */
  scale: number;
  /** 0..1 of all applications' combined total. */
  share: number;
}

/** The busiest applications by data, largest first. Applications that moved no data are left out. */
export function topApplications(
  summaries: readonly AppSummary[],
  limit: number = TOP_APPS_LIMIT,
): TopApp[] {
  const busy = summaries
    .filter((summary) => summary.totalBytes > 0)
    .sort(
      (a, b) => b.totalBytes - a.totalBytes || a.applicationName.localeCompare(b.applicationName),
    );
  const max = busy[0]?.totalBytes ?? 0;
  const total = busy.reduce((sum, summary) => sum + summary.totalBytes, 0);
  return busy.slice(0, limit).map((summary) => ({
    name: summary.applicationName,
    path: summary.applicationPath,
    totalBytes: summary.totalBytes,
    bytesReceived: summary.bytesReceived,
    bytesSent: summary.bytesSent,
    scale: max > 0 ? summary.totalBytes / max : 0,
    share: total > 0 ? summary.totalBytes / total : 0,
  }));
}
