import { api } from '#lib/api/daemon.ts';
import {
  ACTIVE_APPS_BACKGROUND_POLL_MS,
  ACTIVE_APPS_POLL_MS,
  type ActiveAppsPage,
} from '#lib/models/active-apps.ts';
import { Reactive } from '#lib/state/reactive.ts';
import { daemon } from '#lib/stores/daemon.ts';
import { livePace, windowActivity } from '#lib/stores/window-activity.ts';
import { debugError } from '#lib/utils/index.ts';

/**
 * Applications with live connections, shared by every view that shows them
 * (Dashboard "Active now", the Records applications panel). One poll runs
 * while at least one view holds it (`retain`); it slows while the window is
 * in the background, pauses while it is hidden or the daemon is disconnected,
 * and refreshes at once when the window comes back.
 *
 * `retain` keeps the polling alive; `subscribe` belongs to `Reactive`
 * (change listeners). A view does both:
 * `useEffect(() => activeApps.retain(), [])` and
 * `useSelector(activeApps, (a) => a.page)`.
 */
class ActiveAppsStore extends Reactive {
  #page: ActiveAppsPage | null = null;
  #fetchedAt = 0;
  #holders = 0;
  #timer: ReturnType<typeof setInterval> | null = null;
  #stopForeground: (() => void) | null = null;
  #inFlight = false;
  #lastLoad = 0;

  get page(): ActiveAppsPage | null {
    return this.#page;
  }

  /** When `page` was last refreshed (ms), for "new in the last minute" checks. */
  get fetchedAt(): number {
    return this.#fetchedAt;
  }

  #load = async () => {
    if (this.#inFlight || document.hidden || !daemon.state.connected) return;
    this.#inFlight = true;
    this.#lastLoad = Date.now();
    try {
      const next = await api.getActiveApplications();
      if (this.#holders > 0) {
        this.#page = next;
        this.#fetchedAt = Date.now();
        this.changed();
      }
    } catch (error) {
      debugError('active-apps', 'load-failed', error);
    } finally {
      this.#inFlight = false;
    }
  };

  #onVisible = () => {
    if (!document.hidden) void this.#load();
  };

  /** Ticks at the foreground pace; a background window skips ticks until its own pace is due. */
  #tick = () => {
    const pace = livePace(ACTIVE_APPS_POLL_MS, ACTIVE_APPS_BACKGROUND_POLL_MS);
    if (Date.now() - this.#lastLoad < pace - ACTIVE_APPS_POLL_MS / 2) return;
    void this.#load();
  };

  #start() {
    void this.#load();
    this.#timer = setInterval(this.#tick, ACTIVE_APPS_POLL_MS);
    document.addEventListener('visibilitychange', this.#onVisible);
    this.#stopForeground = windowActivity.onForeground(() => void this.#load());
  }

  #stop() {
    if (this.#timer) clearInterval(this.#timer);
    this.#timer = null;
    document.removeEventListener('visibilitychange', this.#onVisible);
    this.#stopForeground?.();
    this.#stopForeground = null;
  }

  /** Starts polling for the caller; the returned function releases it. */
  readonly retain = (): (() => void) => {
    this.#holders += 1;
    if (this.#holders === 1) this.#start();
    else void this.#load();
    let released = false;
    return () => {
      if (released) return;
      released = true;
      this.#holders -= 1;
      if (this.#holders === 0) this.#stop();
    };
  };

  /** Fetch now, e.g. right after the daemon reconnects. */
  readonly refresh = () => this.#load();
}

export const activeApps = new ActiveAppsStore();
