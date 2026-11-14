/** Applications with live connections right now, from the daemon's flow tracker. */
export interface ActiveApp {
  name: string;
  path: string;
  connections: number;
  /** Bytes per second. */
  downloadRate: number;
  uploadRate: number;
  /** Busiest destinations first, at most three. */
  destinations: string[];
  destinationCount: number;
  /** Unix seconds when the newest live connection opened; 0 when unknown. */
  newestOpenedAt: number;
}

export interface ActiveAppsPage {
  applications: ActiveApp[];
  /** False when the daemon cannot attribute connections, so empty is not "nothing connected". */
  available: boolean;
}

/** Rows visible before the list scrolls; matches Top applications so the panels line up. */
export const ACTIVE_APPS_VISIBLE_ROWS = 5;
/** How often the Dashboard refreshes the list; also the daemon's rate window. */
export const ACTIVE_APPS_POLL_MS = 2_000;
/** Poll pace while the window is unfocused. */
export const ACTIVE_APPS_BACKGROUND_POLL_MS = 6_000;
/** A connection opened this recently marks its application as new. */
export const NEW_CONNECTION_WINDOW_SECONDS = 60;

function num(value: unknown): number {
  const n = Number(value);
  return Number.isFinite(n) && n > 0 ? n : 0;
}

export function normalizeActiveApps(raw: unknown): ActiveAppsPage {
  const page = (raw ?? {}) as Record<string, unknown>;
  const rows = Array.isArray(page.applications) ? page.applications : [];
  return {
    available: page.available === true,
    applications: rows.map((value) => {
      const row = (value ?? {}) as Record<string, unknown>;
      const destinations = Array.isArray(row.topDestinations)
        ? row.topDestinations.map(String).filter(Boolean)
        : [];
      return {
        name: String(row.appName ?? ''),
        path: String(row.appPath ?? ''),
        connections: num(row.connectionCount),
        downloadRate: num(row.downloadRate),
        uploadRate: num(row.uploadRate),
        destinations,
        destinationCount: Math.max(num(row.destinationCount), destinations.length),
        newestOpenedAt: num(row.newestOpenedAt),
      };
    }),
  };
}

/**
 * Busiest right now first, then most connections, then name. The daemon
 * already sends this order; ranking here keeps the panel right for any source.
 */
export function rankActiveApps(
  apps: readonly ActiveApp[],
  limit: number = Number.POSITIVE_INFINITY,
): ActiveApp[] {
  return [...apps]
    .sort(
      (a, b) =>
        b.downloadRate + b.uploadRate - (a.downloadRate + a.uploadRate) ||
        b.connections - a.connections ||
        a.name.localeCompare(b.name),
    )
    .slice(0, limit);
}

/** The busiest destination plus how many others there are, e.g. `api.example.com` +3. */
export function destinationSummary(app: ActiveApp): { primary: string; more: number } {
  const primary = app.destinations[0] ?? '';
  return { primary, more: primary ? Math.max(0, app.destinationCount - 1) : 0 };
}

/** True when the application opened a connection within the last minute. */
export function isNewlyActive(app: ActiveApp, nowMs: number = Date.now()): boolean {
  if (app.newestOpenedAt <= 0) return false;
  const age = nowMs / 1000 - app.newestOpenedAt;
  return age >= 0 && age < NEW_CONNECTION_WINDOW_SECONDS;
}
