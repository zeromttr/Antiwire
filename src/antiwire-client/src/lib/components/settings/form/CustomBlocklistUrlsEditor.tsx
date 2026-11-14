import clsx from 'clsx';
import { Plus, X } from 'lucide-react';
import { useState, type KeyboardEvent } from 'react';
import { Button } from '#lib/components/ui/Button.tsx';
import { SettingsFieldLabel } from '#lib/components/ui/SettingsFieldLabel.tsx';
import { SettingsInput } from '#lib/components/ui/SettingsInput.tsx';
import { m } from '#lib/i18n/messages.ts';
import {
  isValidBlocklistUrl,
  parseCustomBlocklistUrls,
  serializeCustomBlocklistUrls,
} from '#lib/models/blocklists.ts';
import styles from './CustomBlocklistUrlsEditor.module.css';

interface Props {
  value: string;
  onchange?: (value: string) => void;
}

function parseSaved(value: string): string[] {
  return parseCustomBlocklistUrls(value).filter((url) => url.trim().length > 0);
}

export function CustomBlocklistUrlsEditor({ value, onchange }: Props) {
  // The list re-parses only when `value` changes from outside (load,
  // discard); our own emits already hold the matching list.
  const [synced, setSynced] = useState(() => ({ value, urls: parseSaved(value) }));
  const [draft, setDraft] = useState('');
  let savedUrls = synced.urls;
  if (value !== synced.value) {
    savedUrls = parseSaved(value);
    setSynced({ value, urls: savedUrls });
  }

  function emit(nextUrls: string[]) {
    const serialized = serializeCustomBlocklistUrls(nextUrls);
    setSynced({ value: serialized, urls: nextUrls });
    onchange?.(serialized);
  }

  function addUrl() {
    const trimmed = draft.trim();
    if (!trimmed || !isValidBlocklistUrl(trimmed)) return;
    emit([...savedUrls, trimmed]);
    setDraft('');
  }

  function removeUrl(index: number) {
    emit(savedUrls.filter((_, i) => i !== index));
  }

  function onDraftKeyDown(event: KeyboardEvent<HTMLInputElement>) {
    if (event.key === 'Enter') {
      event.preventDefault();
      addUrl();
    }
  }

  return (
    <div className={styles.customUrls}>
      <SettingsFieldLabel label={m.settings_custom_blocklist_urls_label()} />

      {savedUrls.length > 0 && (
        <div className={styles.savedList}>
          {savedUrls.map((url, index) => (
            <div key={`${index}:${url}`} className={styles.savedRow}>
              <span className={clsx(styles.savedUrl, 'mono')} title={url}>
                {url}
              </span>
              <Button
                variant="ghost"
                size="sm"
                iconOnly
                aria-label={m.settings_custom_blocklist_remove_aria({ index: index + 1 })}
                onClick={() => removeUrl(index)}
              >
                <X size={14} strokeWidth={1.75} />
              </Button>
            </div>
          ))}
        </div>
      )}

      <div className={styles.entry}>
        <SettingsInput
          invalid={draft.trim().length > 0 && !isValidBlocklistUrl(draft)}
          placeholder={m.settings_custom_blocklist_url_placeholder()}
          aria-label={m.settings_custom_blocklist_url_aria()}
          value={draft}
          onValueChange={(next) => setDraft(String(next ?? ''))}
          onKeyDown={onDraftKeyDown}
        />
        <div className={styles.addRow}>
          <Button variant="secondary" size="sm" onClick={addUrl}>
            <Plus size={13} strokeWidth={2} />
            {m.settings_custom_blocklist_add()}
          </Button>
        </div>
      </div>
    </div>
  );
}

export default CustomBlocklistUrlsEditor;
