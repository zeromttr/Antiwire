// Reads a mutable workspace while rendering, so React Compiler must not
// cache it (see src/lib/state/compiler-opt-out.test.ts).
'use no memo';

import clsx from 'clsx';
import { RefreshCw, Sparkles, Trash2 } from 'lucide-react';
import {
  memo,
  useCallback,
  useEffect,
  useLayoutEffect,
  useRef,
  useState,
  type KeyboardEvent,
} from 'react';
import { api } from '#lib/api/daemon.ts';
import { AdvancedCheckDialog } from '#lib/components/ai/AdvancedCheckDialog.tsx';
import { AiDecisionsWorkspace } from '#lib/components/ai/ai-decisions-workspace.ts';
import { DeleteDecisionDialog } from '#lib/components/ai/DeleteDecisionDialog.tsx';
import { Button } from '#lib/components/ui/Button.tsx';
import { EmptyState } from '#lib/components/ui/EmptyState.tsx';
import DaemonOffline from '#lib/components/shell/DaemonOffline.tsx';
import { SearchBox } from '#lib/components/ui/SearchBox.tsx';
import { Status } from '#lib/components/ui/Status.tsx';
import { UnderlineTabs } from '#lib/components/ui/UnderlineTabs.tsx';
import { m } from '#lib/i18n/messages.ts';
import {
  aiCategoryLabel,
  aiVerdictDescription,
  aiVerdictLabel,
  aiVerdictTabs,
  aiVerdictTone,
  formatAiScore,
  isAiVerdictFilter,
  sortedAiRatings,
} from '#lib/models/ai-decisions.ts';
import { playMotion, stepIn } from '#lib/motion.ts';
import { useReactive, useSelector } from '#lib/state/reactive.ts';
import { daemon } from '#lib/stores/daemon.ts';
import type { AiDecision } from '#lib/types/index.ts';
import { formatDateTime, formatTimeAgo } from '#lib/utils/format.ts';
import { displayText } from '#lib/utils/index.ts';
import styles from './AiPage.module.css';

interface RowProps {
  decision: AiDecision;
  selected: boolean;
  onSelect: (domain: string) => void;
}

const DecisionRow = memo(function DecisionRow({ decision, selected, onSelect }: RowProps) {
  const tone = aiVerdictTone(decision.verdict);
  return (
    <div
      id={`ai-row-${decision.domain}`}
      className={clsx(styles.row, selected && styles.selected)}
      role="option"
      tabIndex={-1}
      aria-selected={selected}
      data-domain={decision.domain}
      onClick={() => onSelect(decision.domain)}
      onKeyDown={(event) => {
        if (event.key === 'Enter' || event.key === ' ') onSelect(decision.domain);
      }}
    >
      <span className={clsx(styles.domain, 'mono')} title={displayText(decision.domain)}>
        {displayText(decision.domain)}
      </span>
      <span className={styles.verdictCell}>
        <Status tone={tone}>{aiVerdictLabel(decision.verdict)}</Status>
      </span>
      <span className={styles.reason}>
        {decision.topCategory ? (
          <>
            <span className={styles.reasonLabel}>{aiCategoryLabel(decision.topCategory)}</span>
            <span className={styles.confidence} aria-hidden="true">
              <span
                className={styles.confidenceFill}
                style={{
                  width: formatAiScore(decision.topScore),
                  background: `var(--${tone === 'ok' ? 't3' : tone})`,
                }}
              ></span>
            </span>
            <span className={styles.score}>{formatAiScore(decision.topScore)}</span>
          </>
        ) : (
          <span className={styles.muted}>{m.ai_decisions_no_category()}</span>
        )}
      </span>
      <span className={clsx(styles.time, styles.right)} title={formatDateTime(decision.updatedAt)}>
        {formatTimeAgo(decision.updatedAt)}
      </span>
    </div>
  );
});

export default function AiPage() {
  const [ai] = useState(
    () =>
      new AiDecisionsWorkspace(api, {
        get connected() {
          return daemon.state.connected;
        },
        toast: (title, body, color) => daemon.addToast(title, body, color),
      }),
  );
  useReactive(ai);
  const connected = useSelector(daemon, (d) => d.state.connected);

  // `unmount` only cancels in-flight work, so StrictMode's remount picks up again.
  useEffect(() => {
    ai.mount();
    return () => ai.unmount();
  }, [ai]);

  useEffect(() => {
    ai.onConnectionChange();
  }, [ai, connected]);

  const tabs = aiVerdictTabs({
    blockCount: ai.blockCount,
    recordCount: ai.recordCount,
    cleanCount: ai.cleanCount,
  });
  const selected = ai.selected;
  const busy =
    ai.checkingDomain !== null || ai.refreshingDomain !== null || ai.deletingDomain !== null;
  const [direction, setDirection] = useState(1);
  const listEl = useRef<HTMLDivElement | null>(null);
  const detailEl = useRef<HTMLDivElement | null>(null);
  const [pendingDelete, setPendingDelete] = useState<string | null>(null);
  const [pendingAdvanced, setPendingAdvanced] = useState<string | null>(null);

  const selectedKey = selected?.domain ?? null;
  const shownKey = useRef<string | null>(null);
  useLayoutEffect(() => {
    const previous = shownKey.current;
    shownKey.current = selectedKey;
    if (!previous || !selectedKey || previous === selectedKey || !detailEl.current) return;
    const animation = playMotion(detailEl.current, stepIn({ direction }));
    return () => animation?.cancel();
  }, [selectedKey, direction]);

  const select = useCallback(
    (domain: string) => {
      if (domain === ai.selectedDomain) return;
      const from = ai.decisions.findIndex((row) => row.domain === ai.selectedDomain);
      const to = ai.decisions.findIndex((row) => row.domain === domain);
      setDirection(to >= from ? 1 : -1);
      ai.select(domain);
    },
    [ai],
  );

  function onListKeydown(event: KeyboardEvent<HTMLDivElement>) {
    const keys = ['ArrowDown', 'ArrowUp', 'Home', 'End'];
    if (!keys.includes(event.key) || ai.decisions.length === 0) return;
    event.preventDefault();
    const last = ai.decisions.length - 1;
    const index = ai.decisions.findIndex((row) => row.domain === ai.selectedDomain);
    const next =
      event.key === 'Home'
        ? 0
        : event.key === 'End'
          ? last
          : Math.min(last, Math.max(0, index + (event.key === 'ArrowDown' ? 1 : -1)));
    const domain = ai.decisions[next].domain;
    select(domain);
    listEl.current
      ?.querySelector<HTMLElement>(`[data-domain="${CSS.escape(domain)}"]`)
      ?.scrollIntoView({ block: 'nearest' });
  }

  async function confirmAdvanced() {
    if (!pendingAdvanced) return;
    const checked = await ai.advancedCheck(pendingAdvanced);
    if (checked) setPendingAdvanced(null);
  }

  async function confirmDelete() {
    if (!pendingDelete) return;
    const removed = await ai.deleteDecision(pendingDelete);
    if (removed) setPendingDelete(null);
  }

  const selectedTone = selected ? aiVerdictTone(selected.verdict) : 'ok';

  return (
    <>
      <div className={styles.page} data-testid="page-ai" data-page-motion="ai">
        <header className={styles.pageHead}>
          <h1>{m.nav_ai()}</h1>
          {connected && ai.ready && (
            <p className={styles.sub}>{m.ai_decisions_page_sub({ count: ai.totalCount })}</p>
          )}
          <div className={styles.headActions}>
            <SearchBox
              className={styles.search}
              value={ai.searchQuery}
              placeholder={m.ai_decisions_search_placeholder()}
              onChange={ai.setSearchQuery}
            />
            <Button
              variant="ghost"
              iconOnly
              disabled={!connected || ai.loading}
              aria-label={m.ai_decisions_refresh()}
              title={m.ai_decisions_refresh()}
              onClick={() => void ai.reload()}
            >
              <RefreshCw size={14} strokeWidth={1.8} className={ai.loading ? 'spinning' : ''} />
            </Button>
          </div>
        </header>

        <div className={styles.tabs} data-motion-stage="1">
          <UnderlineTabs
            tabs={tabs}
            value={ai.verdictFilter}
            ariaLabel={m.ai_decisions_filter_aria()}
            onChange={(value) => {
              if (isAiVerdictFilter(value)) ai.setVerdictFilter(value);
            }}
          />
        </div>

        {!connected ? (
          <div className={styles.empty} data-motion-stage="2">
            <DaemonOffline text={m.ai_decisions_empty_disconnected()} />
          </div>
        ) : !ai.ready ? (
          <div className={styles.empty} data-motion-stage="2">
            <EmptyState text={m.ai_decisions_loading()} panel />
          </div>
        ) : ai.decisions.length === 0 ? (
          <div className={styles.empty} data-motion-stage="2">
            {ai.isEmptyHistory ? (
              <EmptyState
                text={m.ai_decisions_empty_none()}
                detail={m.ai_decisions_empty_none_detail()}
                panel
              />
            ) : (
              <EmptyState text={m.ai_decisions_empty_no_match()} panel />
            )}
          </div>
        ) : (
          <div className={styles.workspace} data-motion-stage="2">
            <div className={clsx(styles.table, 'panel', ai.loading && styles.busy)}>
              <div className={styles.head} aria-hidden="true">
                <span>{m.ai_decisions_col_domain()}</span>
                <span>{m.ai_decisions_col_verdict()}</span>
                <span>{m.ai_decisions_col_reason()}</span>
                <span className={styles.right}>{m.ai_decisions_col_updated()}</span>
              </div>
              <div
                className={clsx(styles.rows, 'scroll')}
                role="listbox"
                tabIndex={0}
                aria-label={m.ai_decisions_list_aria()}
                aria-activedescendant={
                  ai.selectedDomain ? `ai-row-${ai.selectedDomain}` : undefined
                }
                ref={listEl}
                onKeyDown={onListKeydown}
              >
                {ai.decisions.map((decision) => (
                  <DecisionRow
                    key={decision.domain}
                    decision={decision}
                    selected={decision.domain === ai.selectedDomain}
                    onSelect={select}
                  />
                ))}
                {ai.hasMore && (
                  <div className={styles.more}>
                    <Button
                      variant="ghost"
                      size="sm"
                      disabled={ai.loadingMore}
                      onClick={() => void ai.loadMore()}
                    >
                      {ai.loadingMore ? m.ai_decisions_loading() : m.ai_decisions_load_more()}
                    </Button>
                  </div>
                )}
              </div>
            </div>

            <aside className={clsx(styles.detail, 'panel')}>
              {selected && (
                <div className={styles.detailInner} ref={detailEl}>
                  <div className={styles.detailHead}>
                    <Status tone={selectedTone}>{aiVerdictLabel(selected.verdict)}</Status>
                    <h2 className={clsx(styles.detailDomain, 'mono')}>
                      {displayText(selected.domain)}
                    </h2>
                    <p className={styles.detailDesc}>{aiVerdictDescription(selected.verdict)}</p>
                  </div>

                  <section className={styles.detailSection}>
                    <h3>{m.ai_decisions_ratings_label()}</h3>
                    <ul className={styles.ratings}>
                      {sortedAiRatings(selected).map((rating) => {
                        const driver = rating.category === selected.topCategory;
                        return (
                          <li
                            key={rating.category}
                            className={clsx(styles.rating, driver && styles.driver)}
                          >
                            <span className={styles.ratingLabel}>{rating.label}</span>
                            <span className={styles.bar} aria-hidden="true">
                              <span
                                className={styles.fill}
                                style={{
                                  width: formatAiScore(rating.score),
                                  background:
                                    driver && selectedTone !== 'ok'
                                      ? `var(--${selectedTone})`
                                      : 'color-mix(in oklab, var(--t1) 26%, transparent)',
                                }}
                              ></span>
                            </span>
                            <span className={styles.ratingScore}>
                              {formatAiScore(rating.score)}
                            </span>
                          </li>
                        );
                      })}
                    </ul>
                  </section>

                  <section className={styles.detailSection}>
                    <dl className={styles.facts}>
                      <div>
                        <dt>{m.ai_decisions_model()}</dt>
                        <dd>{selected.model || m.common_em_dash()}</dd>
                      </div>
                      <div>
                        <dt>{m.ai_decisions_scan_tier()}</dt>
                        <dd>{selected.scanTier || m.common_em_dash()}</dd>
                      </div>
                      <div>
                        <dt>{m.ai_decisions_first_seen()}</dt>
                        <dd>{formatDateTime(selected.firstSeen) || m.common_em_dash()}</dd>
                      </div>
                      <div>
                        <dt>{m.ai_decisions_updated()}</dt>
                        <dd>{formatDateTime(selected.updatedAt) || m.common_em_dash()}</dd>
                      </div>
                    </dl>
                  </section>

                  {selected.scanTier === 'advanced' && (
                    <section className={styles.detailSection}>
                      <h3>{m.ai_decisions_signals_label()}</h3>
                      <dl className={styles.facts}>
                        <div>
                          <dt>{m.ai_decisions_signal_newly_registered()}</dt>
                          <dd>{formatAiScore(selected.signals.newlyRegistered)}</dd>
                        </div>
                        <div>
                          <dt>{m.ai_decisions_signal_registry_hold()}</dt>
                          <dd>{formatAiScore(selected.signals.registryHold)}</dd>
                        </div>
                        <div>
                          <dt>{m.ai_decisions_signal_hidden_registrant()}</dt>
                          <dd>{formatAiScore(selected.signals.hiddenRegistrant)}</dd>
                        </div>
                        <div>
                          <dt>{m.ai_decisions_signal_abusive_registrar()}</dt>
                          <dd>{formatAiScore(selected.signals.abusiveRegistrar)}</dd>
                        </div>
                      </dl>
                    </section>
                  )}

                  <div className={styles.detailActions}>
                    <Button
                      variant="secondary"
                      size="sm"
                      disabled={busy}
                      aria-label={m.ai_decisions_refresh_one_aria({
                        domain: displayText(selected.domain),
                      })}
                      onClick={() => void ai.refreshDecision(selected.domain)}
                    >
                      <RefreshCw
                        size={13}
                        strokeWidth={1.8}
                        aria-hidden="true"
                        className={ai.refreshingDomain === selected.domain ? 'spinning' : ''}
                      />
                      {ai.refreshingDomain === selected.domain
                        ? m.ai_decisions_refreshing()
                        : m.ai_decisions_refresh_one()}
                    </Button>
                    <Button
                      variant="secondary"
                      size="sm"
                      disabled={busy}
                      aria-label={m.ai_decisions_advanced_aria({
                        domain: displayText(selected.domain),
                      })}
                      onClick={() => setPendingAdvanced(selected.domain)}
                    >
                      <Sparkles
                        size={13}
                        strokeWidth={1.8}
                        aria-hidden="true"
                        className={ai.checkingDomain === selected.domain ? 'spinning' : ''}
                      />
                      {ai.checkingDomain === selected.domain
                        ? m.ai_decisions_advanced_running()
                        : m.ai_decisions_advanced()}
                    </Button>
                    <Button
                      variant="ghost"
                      size="sm"
                      iconOnly
                      disabled={busy}
                      aria-label={m.ai_decisions_delete_aria({
                        domain: displayText(selected.domain),
                      })}
                      title={m.ai_decisions_delete()}
                      onClick={() => setPendingDelete(selected.domain)}
                    >
                      <Trash2 size={14} strokeWidth={1.8} aria-hidden="true" />
                    </Button>
                  </div>
                </div>
              )}
            </aside>
          </div>
        )}
      </div>

      <AdvancedCheckDialog
        open={pendingAdvanced !== null}
        domain={pendingAdvanced ?? ''}
        submitting={ai.checkingDomain !== null}
        onConfirm={confirmAdvanced}
        onCancel={() => setPendingAdvanced(null)}
      />

      <DeleteDecisionDialog
        open={pendingDelete !== null}
        domain={pendingDelete ?? ''}
        submitting={ai.deletingDomain !== null}
        onConfirm={confirmDelete}
        onCancel={() => setPendingDelete(null)}
      />
    </>
  );
}
