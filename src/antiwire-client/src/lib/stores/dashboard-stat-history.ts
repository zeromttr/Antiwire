import { Reactive } from '#lib/state/reactive.ts';

export const DASHBOARD_STAT_HISTORY_MAX = 80;

function roll(previous: number[], value: number): number[] {
  const next = [...previous, value];
  if (next.length <= DASHBOARD_STAT_HISTORY_MAX) return next;
  return next.slice(next.length - DASHBOARD_STAT_HISTORY_MAX);
}

/** Sparkline history for the dashboard stat tiles. Both arrays are replaced on every change. */
class DashboardStatHistoryStore extends Reactive {
  #sockets: number[] = [];
  #blocked: number[] = [];

  get sockets(): number[] {
    return this.#sockets;
  }

  get blocked(): number[] {
    return this.#blocked;
  }

  readonly record = (activeConnections: number, blockedConnections: number) => {
    this.#sockets = roll(this.#sockets, Math.max(0, activeConnections));
    this.#blocked = roll(this.#blocked, Math.max(0, blockedConnections));
    this.changed();
  };

  readonly reset = () => {
    if (this.#sockets.length === 0 && this.#blocked.length === 0) return;
    this.#sockets = [];
    this.#blocked = [];
    this.changed();
  };
}

export const dashboardStatHistory = new DashboardStatHistoryStore();
