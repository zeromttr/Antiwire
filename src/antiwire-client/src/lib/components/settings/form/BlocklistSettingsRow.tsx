import clsx from 'clsx';
import { ListChecks, RefreshCw } from 'lucide-react';
import { useEffect, useState } from 'react';
import { api } from '#lib/api/daemon.ts';
import { BlocklistSelectionDialog } from '#lib/components/settings/dialogs/BlocklistSelectionDialog.tsx';
import { Button } from '#lib/components/ui/Button.tsx';
import { Dropdown } from '#lib/components/ui/Dropdown.tsx';
import { m } from '#lib/i18n/messages.ts';
import {
  HAGEZI_ABUSED_TLDS_LIST_ID,
  blocklistFrequencyOptions,
  blocklistLastSyncedAt,
  blocklistOptions,
  normalizeBlocklistFrequency,
  parseBlocklistSelection,
  selectedBlocklistOptions,
  setSelectedBlocklist,
} from '#lib/models/blocklists.ts';
import { daemon } from '#lib/stores/daemon.ts';
import { displayText, formatDateTime, formatTimeAgo } from '#lib/utils/index.ts';
import { CustomBlocklistUrlsEditor } from './CustomBlocklistUrlsEditor.tsx';
import { SettingsToggleRow } from './SettingsToggleRow.tsx';
import styles from './BlocklistSettingsRow.module.css';

interface Props {
  enabled: boolean;
  selectedLists: string;
  customUrls: string;
  /** Saved automatic sync interval, e.g. `24hours` or `manual`. */
  updateFrequency: string;
  /** RFC 3339 time of the last successful sync; the Unix epoch until the first. */
  lastUpdated: string;
  onEnabledChange: (enabled: boolean) => void;
  onUpdateFrequencyChange: (frequency: string) => void;
  onSelectedListsChange: (selection: string) => void;
  onCustomUrlsChange: (urls: string) => void;
  onSettingsRefresh?: () => void | Promise<void>;
}

/** Chips shown before the rest collapse into "+N more". */
const CHIP_LIMIT = 3;

export function BlocklistSettingsRow({
  enabled,
  selectedLists,
  customUrls,
  updateFrequency,
  lastUpdated,
  onEnabledChange,
  onUpdateFrequencyChange,
  onSelectedListsChange,
  onCustomUrlsChange,
  onSettingsRefresh,
}: Props) {
  const [dialogOpen, setDialogOpen] = useState(false);
  const [syncing, setSyncing] = useState(false);
  const activeLists = selectedBlocklistOptions(blocklistOptions(), selectedLists);
  const frequency = normalizeBlocklistFrequency(updateFrequency);
  const lastSyncedAt = blocklistLastSyncedAt(lastUpdated);

  // "Synced 3m ago" keeps counting while the page stays open.
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 30_000);
    return () => clearInterval(timer);
  }, []);

  const abusedTldsEnabled =
    enabled && parseBlocklistSelection(selectedLists).has(HAGEZI_ABUSED_TLDS_LIST_ID);

  function onAbusedTldsChange(next: boolean) {
    if (next && !enabled) {
      onEnabledChange(true);
    }
    onSelectedListsChange(setSelectedBlocklist(selectedLists, HAGEZI_ABUSED_TLDS_LIST_ID, next));
  }

  async function syncBlocklists() {
    if (syncing) return;
    setSyncing(true);
    try {
      await api.syncHostsBlocklist();
      daemon.addToast(
        m.settings_blocklists_toast_sync_title(),
        m.settings_blocklists_toast_sync_body(),
        'var(--acc)',
      );
      await onSettingsRefresh?.();
    } catch (e) {
      daemon.addToast(
        m.settings_blocklists_toast_sync_failed_title(),
        e instanceof Error ? e.message : String(e),
        'var(--bad)',
      );
    } finally {
      setSyncing(false);
    }
  }

  return (
    <>
      <SettingsToggleRow
        label={m.settings_blocklists_label()}
        description={m.settings_blocklists_desc()}
        checked={enabled}
        onCheckedChange={onEnabledChange}
      />

      {/*
        While blocklists are on, what they use and how they stay current read as
        ordinary rows: what it is on the left, its control on the right.
      */}
      {enabled && (
        <>
          <div className="resolver-row">
            <div className="resolver-text">
              <div className="resolver-label" id="blocklist-lists-label">
                {m.settings_blocklists_lists_label()}
              </div>
              <div className={clsx('resolver-desc', styles.lists)}>
                {activeLists.length ? (
                  <ul className={styles.chips} aria-labelledby="blocklist-lists-label">
                    {activeLists.slice(0, CHIP_LIMIT).map((list) => (
                      <li key={list.id} className={styles.chip}>
                        {displayText(list.name)}
                      </li>
                    ))}
                    {activeLists.length > CHIP_LIMIT && (
                      <li className={clsx(styles.chip, styles.more)}>
                        {m.settings_blocklists_more({ count: activeLists.length - CHIP_LIMIT })}
                      </li>
                    )}
                  </ul>
                ) : (
                  <span className={styles.none}>{m.settings_blocklists_none_selected()}</span>
                )}
              </div>
            </div>
            <div className="resolver-controls">
              <Button variant="secondary" size="sm" onClick={() => setDialogOpen(true)}>
                <ListChecks size={14} strokeWidth={2} />
                {m.settings_blocklists_choose()}
              </Button>
            </div>
          </div>

          <div className="resolver-row">
            <div className="resolver-text">
              <label className="resolver-label" htmlFor="blocklist-frequency">
                {m.settings_blocklists_frequency_label()}
              </label>
              <div
                className={clsx('resolver-desc', !lastSyncedAt && styles.never)}
                aria-live="polite"
              >
                {lastSyncedAt ? (
                  <>
                    <time dateTime={new Date(lastSyncedAt).toISOString()}>
                      {m.settings_blocklists_last_synced({
                        age: formatTimeAgo(lastSyncedAt, now),
                      })}
                    </time>
                    <span className={styles.srOnly}>({formatDateTime(lastSyncedAt)})</span>
                  </>
                ) : (
                  m.settings_blocklists_never_synced()
                )}
              </div>
            </div>
            <div className="resolver-controls">
              {/* Custom URLs sync too, so this stays available with no catalog list chosen. */}
              <Button
                variant="ghost"
                size="sm"
                disabled={syncing}
                onClick={() => void syncBlocklists()}
              >
                <RefreshCw size={14} strokeWidth={2} className={syncing ? 'spinning' : ''} />
                {syncing ? m.settings_blocklists_syncing() : m.settings_blocklists_sync_title()}
              </Button>
              <div className={styles.frequency}>
                <Dropdown
                  id="blocklist-frequency"
                  options={blocklistFrequencyOptions(updateFrequency)}
                  value={frequency}
                  onChange={onUpdateFrequencyChange}
                />
              </div>
            </div>
          </div>
        </>
      )}

      <SettingsToggleRow
        label={m.settings_abused_tlds_label()}
        description={m.settings_abused_tlds_desc()}
        checked={abusedTldsEnabled}
        onCheckedChange={onAbusedTldsChange}
      />

      {enabled && (
        <div className={clsx('field', styles.customField)}>
          <CustomBlocklistUrlsEditor value={customUrls} onchange={onCustomUrlsChange} />
        </div>
      )}

      <BlocklistSelectionDialog
        open={dialogOpen}
        onOpenChange={setDialogOpen}
        initialSelection={selectedLists}
        onsave={onSelectedListsChange}
      />
    </>
  );
}

export default BlocklistSettingsRow;
