import clsx from 'clsx';
import { Check, Flag, Plug, Server, X } from 'lucide-react';
import { useEffect, useMemo, useRef, useState, type CSSProperties } from 'react';
import { api } from '#lib/api/daemon.ts';
import SearchBox from '#lib/components/ui/SearchBox.tsx';
import SegmentedControl from '#lib/components/ui/SegmentedControl.tsx';
import { popoverIn, popoverOut } from '#lib/motion.ts';
import { usePresence } from '#lib/use-presence.ts';
import type { ConnectionLog } from '#lib/types/index.ts';
import { m } from '#lib/i18n/messages.ts';
import { displayText } from '#lib/utils/index.ts';
import type { RecordFacets } from '../list/records-list';
import {
  buildFacetOptions,
  countryLabel,
  facetWindowStart,
  loadFacetRows,
  rowsInFacetWindow,
  serviceLabel,
  type FacetOption,
  type FacetWindow,
} from './records-quick-filters';
import styles from './RecordsSearchFilters.module.css';

type FacetKind = keyof RecordFacets;

interface Props {
  value?: string;
  logs: readonly ConnectionLog[];
  facets: RecordFacets;
  /** Milliseconds; the range is measured back from this instant. */
  now?: number;
  connected?: boolean;
  /** Set when one application is selected; omitted for every application. */
  applicationName?: string;
  applicationId?: number;
  /** Called with the new text on every edit (was `bind:value` plus `onFilterChange`). */
  onFilterChange: (value: string) => void;
  onFacet: <K extends FacetKind>(kind: K, value: RecordFacets[K] | undefined) => void;
}

const ICONS = { port: Plug, country: Flag, host: Server } as const;
// Removal order for Backspace: the most specific filter first.
const ORDER: FacetKind[] = ['port', 'country', 'host'];

function catalogKey(range: FacetWindow, name?: string, id?: number): string {
  return `${range}|${name ?? ''}|${id ?? ''}`;
}

export function RecordsSearchFilters({
  value = '',
  logs,
  facets,
  now,
  connected = false,
  applicationName,
  applicationId,
  onFilterChange,
  onFacet,
}: Props) {
  const [open, setOpen] = useState(false);
  const [facetWindow, setFacetWindow] = useState<FacetWindow>('week');
  /** Rows loaded for the open range, with the range they belong to. Null until that request succeeds. */
  const [catalog, setCatalog] = useState<{
    rows: readonly ConnectionLog[];
    key: string;
  } | null>(null);
  const root = useRef<HTMLDivElement>(null);
  const facetRequest = useRef(0);
  const { present: menuPresent, ref: menuRef } = usePresence<HTMLDivElement>(
    open,
    popoverIn(),
    popoverOut(),
  );
  const [mountedAt] = useState(() => Date.now());

  const windowOptions = [
    { value: 'day', label: m.records_quick_window_day() },
    { value: 'week', label: m.records_quick_window_week() },
    { value: 'month', label: m.records_quick_window_month() },
  ];

  const sourceKey = catalogKey(facetWindow, applicationName, applicationId);
  // The loaded page fills in until the range's own query returns.
  const source = connected && catalog !== null && catalog.key === sourceKey ? catalog.rows : logs;
  const options = useMemo(
    () => buildFacetOptions(rowsInFacetWindow(source, facetWindow, now ?? mountedAt)),
    [source, facetWindow, now, mountedAt],
  );

  function onWindow(next: string) {
    if (next === 'day' || next === 'week' || next === 'month') setFacetWindow(next);
  }

  const groups = [
    { kind: 'port' as const, label: m.records_quick_services(), items: options.services },
    { kind: 'country' as const, label: m.records_quick_countries(), items: options.countries },
    { kind: 'host' as const, label: m.records_quick_destinations(), items: options.destinations },
  ];

  function chipLabel(kind: FacetKind, active: string | number): string {
    if (kind === 'port') {
      const port = Number(active);
      const row = logs.find((candidate) => candidate.port === port);
      const service = serviceLabel(port, row?.protocol ?? '');
      return service.detail ? `${service.label} · ${service.detail}` : service.label;
    }
    if (kind === 'country') return countryLabel(String(active));
    return String(active);
  }

  /** Active filters, labelled even when that value is outside the current range. */
  const chips = ORDER.flatMap((kind) => {
    const active = facets[kind];
    if (active === undefined) return [];
    return [{ kind, label: chipLabel(kind, active) }];
  });

  function isActive(kind: FacetKind, option: FacetOption<string | number>): boolean {
    return facets[kind] === option.value;
  }

  function toggle(kind: FacetKind, option: FacetOption<string | number>) {
    onFacet(kind, (isActive(kind, option) ? undefined : option.value) as never);
  }

  function removeLast() {
    const last = [...ORDER].reverse().find((kind) => facets[kind] !== undefined);
    if (last) onFacet(last, undefined);
  }

  function clearAll() {
    for (const kind of ORDER) if (facets[kind] !== undefined) onFacet(kind, undefined);
  }

  useEffect(() => {
    if (!open) return;
    const closeOutside = (event: PointerEvent) => {
      if (!root.current?.contains(event.target as Node)) setOpen(false);
    };
    window.addEventListener('pointerdown', closeOutside);
    return () => window.removeEventListener('pointerdown', closeOutside);
  }, [open]);

  // The table page is a slice. While the menu is open, load every connection
  // in the selected range (for the selected application) so the lists are complete.
  useEffect(() => {
    if (!open || !connected) return;
    const token = ++facetRequest.current;
    const since = facetWindowStart(facetWindow);
    const until = Math.floor(Date.now() / 1000) + 60;
    const key = catalogKey(facetWindow, applicationName, applicationId);
    const apply = (rows: readonly ConnectionLog[]) => {
      if (token !== facetRequest.current) return;
      setCatalog({ rows, key });
    };
    void loadFacetRows(
      (offset, limit) =>
        api.getConnectionLogs({
          offset,
          limit,
          timeWindowStart: since,
          timeWindowEnd: until,
          orderBy: 'last_seen',
          sortDescending: true,
          applicationName,
          applicationId,
        }),
      { onPage: apply },
    )
      .then(apply)
      .catch(() => {
        // Keep a page that already arrived; only the empty failure falls back.
        if (token === facetRequest.current) {
          setCatalog((prev) => (prev?.key === key ? prev : null));
        }
      });
  }, [open, connected, facetWindow, applicationName, applicationId]);

  const chipList = chips.map((chip) => {
    const Icon = ICONS[chip.kind];
    return (
      <span key={chip.kind} className={styles.chip}>
        <Icon size={12} strokeWidth={2} aria-hidden="true" />
        <span className={styles.chipLabel}>{displayText(chip.label)}</span>
        <button
          type="button"
          className={styles.chipRemove}
          aria-label={m.records_filter_remove_aria({ filter: displayText(chip.label) })}
          onClick={() => onFacet(chip.kind, undefined)}
        >
          <X size={11} strokeWidth={2.2} />
        </button>
      </span>
    );
  });

  return (
    <div className={clsx(styles.recordsSearch, chips.length > 0 && styles.hasChips)} ref={root}>
      <SearchBox
        className={styles.searchBox}
        value={value}
        placeholder={m.records_filter_placeholder()}
        ariaLabel={m.records_filter_aria()}
        onChange={onFilterChange}
        menuOpen={open}
        menuControls="records-quick-filter-menu"
        onMenuToggle={() => setOpen((v) => !v)}
        prefix={chips.length ? chipList : undefined}
        onBackspaceEmpty={removeLast}
      />
      {menuPresent && (
        <div
          ref={menuRef}
          id="records-quick-filter-menu"
          className={styles.quickMenu}
          role="dialog"
          tabIndex={-1}
          aria-label={m.records_quick_filters_title()}
          onKeyDown={(event) => {
            if (event.key === 'Escape') setOpen(false);
          }}
        >
          <div className={styles.menuHead}>
            <div>
              <strong>{m.records_quick_filters_title()}</strong>
              <span>{m.records_quick_filters_desc()}</span>
            </div>
            {chips.length > 0 && (
              <button type="button" className={styles.clearAll} onClick={clearAll}>
                {m.records_filters_clear()}
              </button>
            )}
          </div>
          <div className={styles.window}>
            <SegmentedControl
              options={windowOptions}
              value={facetWindow}
              ariaLabel={m.records_quick_window_aria()}
              onChange={onWindow}
            />
          </div>
          <div className={styles.groups}>
            {groups.map((group) => (
              <section key={group.kind} className={styles.group} aria-label={group.label}>
                <h3>{group.label}</h3>
                {group.items.length ? (
                  <div className={styles.options}>
                    {(group.items as FacetOption<string | number>[]).map((option) => {
                      const active = isActive(group.kind, option);
                      return (
                        <button
                          key={option.value}
                          type="button"
                          className={clsx(styles.option, active && styles.active)}
                          aria-pressed={active}
                          onClick={() => toggle(group.kind, option)}
                        >
                          <span className={styles.optionLine}>
                            <span className={styles.optionLabel}>
                              {displayText(option.label)}
                              {option.detail && (
                                <span className={clsx(styles.detail, 'mono')}>{option.detail}</span>
                              )}
                            </span>
                            {active ? (
                              <Check size={13} strokeWidth={2.4} className={styles.optionCheck} />
                            ) : (
                              <span className={clsx(styles.count, 'mono')}>{option.count}</span>
                            )}
                          </span>
                          <span className={styles.share} aria-hidden="true">
                            <span style={{ '--share': option.share } as CSSProperties}></span>
                          </span>
                        </button>
                      );
                    })}
                  </div>
                ) : (
                  <span className={styles.empty}>{m.records_quick_no_data()}</span>
                )}
              </section>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

export default RecordsSearchFilters;
