import type { AiDecisionsPage, AiVerdictFilter, api } from '#lib/api/daemon.ts';
import { m } from '#lib/i18n/messages.ts';
import type { AiDecision } from '#lib/types/index.ts';
import { formatErrorMessage } from '#lib/utils/error.ts';
import { TrackedReactive } from '#lib/state/tracked.ts';

export type AiDecisionsApiClient = Pick<
  typeof api,
  'getAiDecisions' | 'deleteAiDecision' | 'refreshAiDecision' | 'advancedAiDecision'
>;

export type AiDecisionsHost = {
  readonly connected: boolean;
  toast(title: string, body: string, color: string): void;
};

export const AI_DECISIONS_PAGE_SIZE = 100;
export const AI_DECISIONS_SEARCH_DEBOUNCE_MS = 250;

/**
 * AI decision history state. The page owns connect/mount effects; this class
 * owns filtering, paging, and discarding responses a newer request superseded.
 */
export class AiDecisionsWorkspace extends TrackedReactive {
  decisions: AiDecision[] = [];
  totalCount = 0;
  blockCount = 0;
  recordCount = 0;
  cleanCount = 0;
  verdictFilter: AiVerdictFilter = 'all';
  searchQuery = '';
  /** The decision shown in the detail panel. */
  selectedDomain: string | null = null;
  loading = false;
  loadingMore = false;
  ready = false;
  deletingDomain: string | null = null;
  refreshingDomain: string | null = null;
  checkingDomain: string | null = null;

  private mounted = false;
  private generation = 0;
  private searchTimer: ReturnType<typeof setTimeout> | null = null;

  constructor(
    private readonly client: AiDecisionsApiClient,
    private readonly host: AiDecisionsHost,
  ) {
    super();
    this.track(
      'decisions',
      'totalCount',
      'blockCount',
      'recordCount',
      'cleanCount',
      'verdictFilter',
      'searchQuery',
      'selectedDomain',
      'loading',
      'loadingMore',
      'ready',
      'deletingDomain',
      'refreshingDomain',
      'checkingDomain',
    );
  }

  get connected() {
    return this.host.connected;
  }

  get hasMore() {
    return this.decisions.length < this.totalCount;
  }

  /** True when the daemon has classified nothing at all, as opposed to nothing matching. */
  get isEmptyHistory() {
    return this.blockCount + this.recordCount + this.cleanCount === 0 && !this.searchQuery.trim();
  }

  mount = () => {
    this.mounted = true;
  };

  unmount = () => {
    this.mounted = false;
    this.generation++;
    this.clearSearchTimer();
  };

  /** Same as `unmount`: drops in-flight requests and the search debounce. */
  dispose = () => {
    this.unmount();
  };

  onConnectionChange = () => {
    if (!this.connected) {
      this.generation++;
      this.loading = false;
      this.loadingMore = false;
      return;
    }
    queueMicrotask(() => {
      if (this.mounted) void this.reload();
    });
  };

  setVerdictFilter = (value: AiVerdictFilter) => {
    if (value === this.verdictFilter) return;
    this.verdictFilter = value;
    void this.reload();
  };

  setSearchQuery = (value: string) => {
    this.searchQuery = value;
    this.clearSearchTimer();
    this.searchTimer = setTimeout(() => {
      this.searchTimer = null;
      void this.reload();
    }, AI_DECISIONS_SEARCH_DEBOUNCE_MS);
  };

  select = (domain: string) => {
    this.selectedDomain = domain;
  };

  get selected(): AiDecision | null {
    return this.decisions.find((row) => row.domain === this.selectedDomain) ?? null;
  }

  /**
   * Removes one saved decision. Any reload still in flight is discarded so a
   * response that left the daemon before the delete cannot put the row back.
   */
  /**
   * Classifies one saved domain again and replaces that row. A verdict that
   * no longer matches the active filter leaves the list. An in-flight reload
   * is discarded so it cannot restore the previous scores.
   */
  refreshDecision = async (domain: string): Promise<boolean> => {
    if (
      !this.mounted ||
      !this.connected ||
      this.deletingDomain ||
      this.refreshingDomain ||
      this.checkingDomain
    ) {
      return false;
    }
    this.refreshingDomain = domain;
    try {
      const updated = await this.client.refreshAiDecision(domain);
      if (!this.mounted) return false;
      this.generation++;
      this.loading = false;
      this.loadingMore = false;
      this.replace(domain, updated);
      return true;
    } catch (error) {
      if (this.mounted) {
        this.host.toast(
          m.ai_decisions_refresh_failed_title(),
          formatErrorMessage(error),
          'var(--bad)',
        );
      }
      return false;
    } finally {
      if (this.refreshingDomain === domain) this.refreshingDomain = null;
    }
  };

  advancedCheck = async (domain: string): Promise<boolean> => {
    if (
      !this.mounted ||
      !this.connected ||
      this.deletingDomain ||
      this.refreshingDomain ||
      this.checkingDomain
    ) {
      return false;
    }
    this.checkingDomain = domain;
    try {
      const updated = await this.client.advancedAiDecision(domain);
      if (!this.mounted) return false;
      this.generation++;
      this.loading = false;
      this.loadingMore = false;
      this.replace(domain, updated);
      return true;
    } catch (error) {
      if (this.mounted) {
        this.host.toast(
          m.ai_decisions_advanced_failed_title(),
          formatErrorMessage(error),
          'var(--bad)',
        );
      }
      return false;
    } finally {
      if (this.checkingDomain === domain) this.checkingDomain = null;
    }
  };

  deleteDecision = async (domain: string): Promise<boolean> => {
    if (
      !this.mounted ||
      !this.connected ||
      this.deletingDomain ||
      this.refreshingDomain ||
      this.checkingDomain
    ) {
      return false;
    }
    this.deletingDomain = domain;
    try {
      await this.client.deleteAiDecision(domain);
      if (!this.mounted) return false;
      this.generation++;
      this.loading = false;
      this.loadingMore = false;
      this.forget(domain);
      return true;
    } catch (error) {
      if (this.mounted) {
        this.host.toast(
          m.ai_decisions_delete_failed_title(),
          formatErrorMessage(error),
          'var(--bad)',
        );
      }
      return false;
    } finally {
      if (this.deletingDomain === domain) this.deletingDomain = null;
    }
  };

  reload = async () => {
    this.clearSearchTimer();
    const page = await this.fetch(0, () => (this.loading = true));
    if (!page) return;
    this.decisions = page.decisions;
    // Keep the selection when it survived the reload; otherwise show the first row.
    if (!page.decisions.some((row) => row.domain === this.selectedDomain)) {
      this.selectedDomain = page.decisions[0]?.domain ?? null;
    }
  };

  loadMore = async () => {
    if (this.loading || this.loadingMore || !this.hasMore) return;
    const page = await this.fetch(this.decisions.length, () => (this.loadingMore = true));
    if (!page) return;
    // Rows can shift between pages when new classifications land; keep the first copy.
    const seen = new Set(this.decisions.map((row) => row.domain));
    this.decisions = [...this.decisions, ...page.decisions.filter((row) => !seen.has(row.domain))];
  };

  /** Resolves `null` when the request failed or a newer request superseded it. */
  private async fetch(offset: number, markBusy: () => void): Promise<AiDecisionsPage | null> {
    if (!this.mounted || !this.connected) return null;
    const generation = ++this.generation;
    markBusy();
    const current = () => this.mounted && this.connected && generation === this.generation;
    try {
      const page = await this.client.getAiDecisions({
        limit: AI_DECISIONS_PAGE_SIZE,
        offset,
        verdictFilter: this.verdictFilter,
        searchQuery: this.searchQuery.trim(),
      });
      if (!current()) return null;
      this.totalCount = page.totalCount;
      this.blockCount = page.blockCount;
      this.recordCount = page.recordCount;
      this.cleanCount = page.cleanCount;
      this.ready = true;
      return page;
    } catch (error) {
      if (!current()) return null;
      this.ready = true;
      this.host.toast(m.ai_decisions_load_failed_title(), formatErrorMessage(error), 'var(--bad)');
      return null;
    } finally {
      if (generation === this.generation) {
        this.loading = false;
        this.loadingMore = false;
      }
    }
  }

  private replace(domain: string, updated: AiDecision) {
    const index = this.decisions.findIndex((item) => item.domain === domain);
    if (index < 0) return;
    const previous = this.decisions[index];
    this.shiftCount(previous.verdict, -1);
    this.shiftCount(updated.verdict, 1);
    const visible =
      this.verdictFilter === 'all' || this.verdictFilter === (updated.verdict || 'clean');
    if (!visible) {
      this.removeRow(domain);
      this.totalCount = Math.max(0, this.totalCount - 1);
      return;
    }
    const next = this.decisions.slice();
    next[index] = { ...updated, domain };
    this.decisions = next;
  }

  private shiftCount(verdict: AiDecision['verdict'], delta: number) {
    if (verdict === 'block') this.blockCount = Math.max(0, this.blockCount + delta);
    else if (verdict === 'record') this.recordCount = Math.max(0, this.recordCount + delta);
    else this.cleanCount = Math.max(0, this.cleanCount + delta);
  }

  /** Drops a row; a selected row hands the selection to its neighbour. */
  private removeRow(domain: string) {
    const index = this.decisions.findIndex((item) => item.domain === domain);
    if (index < 0) return;
    this.decisions = this.decisions.filter((item) => item.domain !== domain);
    if (this.selectedDomain === domain) {
      const neighbour = this.decisions[index] ?? this.decisions[index - 1] ?? null;
      this.selectedDomain = neighbour?.domain ?? null;
    }
  }

  private forget(domain: string) {
    const row = this.decisions.find((item) => item.domain === domain);
    if (!row) return;
    this.removeRow(domain);
    this.totalCount = Math.max(0, this.totalCount - 1);
    if (row.verdict === 'block') this.blockCount = Math.max(0, this.blockCount - 1);
    else if (row.verdict === 'record') this.recordCount = Math.max(0, this.recordCount - 1);
    else this.cleanCount = Math.max(0, this.cleanCount - 1);
  }

  private clearSearchTimer() {
    if (this.searchTimer) clearTimeout(this.searchTimer);
    this.searchTimer = null;
  }
}
