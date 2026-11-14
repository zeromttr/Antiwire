import clsx from 'clsx';
import { useId, type CSSProperties } from 'react';
import { Button } from '#lib/components/ui/Button.tsx';
import { Checkbox } from '#lib/components/ui/Checkbox.tsx';
import { m } from '#lib/i18n/messages.ts';
import {
  BLOCKLIST_GROUPS,
  BLOCKLIST_MAX_STRENGTH,
  RECOMMENDED_BLOCKLIST_IDS,
  blocklistOptions,
  blocklistsInGroup,
  shortBlocklistName,
  type BlocklistGroup,
} from '#lib/models/blocklists.ts';
import { displayText } from '#lib/utils/index.ts';
import styles from './BlocklistPicker.module.css';

/**
 * The blocklist catalog as a grouped, multi-select list. Every place that
 * picks blocklists (Settings, first-run setup) renders this, so a list added
 * to the catalog in `models/blocklists.ts` appears in all of them.
 */
interface Props {
  /** Selected list ids; ids not in the catalog are kept but not shown. */
  selected: ReadonlySet<string>;
  onchange: (next: Set<string>) => void;
  /** Scroll the lists inside a capped height, with the count row fixed above. */
  scrollable?: boolean;
}

function groupTitle(group: BlocklistGroup): string {
  if (group === 'hagezi') return m.settings_blocklist_group_hagezi();
  if (group === 'security') return m.settings_blocklist_group_security();
  return m.settings_blocklist_group_community();
}

const LEVELS = Array.from({ length: BLOCKLIST_MAX_STRENGTH }, (_, level) => level);

export function BlocklistPicker({ selected, onchange, scrollable = false }: Props) {
  const idPrefix = useId();
  const options = blocklistOptions();
  const catalog = new Set(options.map((option) => option.id));
  const selectedCount = options.filter((option) => selected.has(option.id)).length;
  const isRecommended =
    selectedCount === RECOMMENDED_BLOCKLIST_IDS.length &&
    RECOMMENDED_BLOCKLIST_IDS.every((id) => selected.has(id));

  /** Keeps ids outside the catalog (retired lists) exactly as they were. */
  function withCatalog(ids: Iterable<string>): Set<string> {
    return new Set([...[...selected].filter((id) => !catalog.has(id)), ...ids]);
  }

  function toggle(id: string) {
    const next = new Set(selected);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    onchange(next);
  }

  return (
    <div className={clsx(styles.picker, scrollable && styles.scrollable)}>
      <div className={styles.head}>
        <span
          className={clsx(styles.count, selectedCount > 0 && styles.hasSelection)}
          aria-live="polite"
        >
          {m.settings_blocklist_dialog_selected_of({ count: selectedCount, total: options.length })}
        </span>
        <span className={styles.headActions}>
          {!isRecommended && (
            <Button
              variant="ghost"
              size="sm"
              onClick={() => onchange(withCatalog(RECOMMENDED_BLOCKLIST_IDS))}
            >
              {m.settings_blocklist_use_recommended()}
            </Button>
          )}
          {selectedCount > 0 && (
            <Button variant="ghost" size="sm" onClick={() => onchange(withCatalog([]))}>
              {m.settings_blocklist_dialog_clear()}
            </Button>
          )}
        </span>
      </div>

      <div className={styles.groups}>
        {BLOCKLIST_GROUPS.map((group) => {
          const headingId = `${idPrefix}-${group}`;
          return (
            <section key={group} className={styles.group} aria-labelledby={headingId}>
              <div className={styles.groupHead}>
                <h3 id={headingId}>{groupTitle(group)}</h3>
                {group === 'hagezi' && (
                  <span className={styles.groupHint}>
                    {m.settings_blocklist_group_hagezi_hint()}
                  </span>
                )}
              </div>
              <ul className={styles.list} role="group" aria-labelledby={headingId}>
                {blocklistsInGroup(options, group).map((option) => {
                  const isSelected = selected.has(option.id);
                  return (
                    <li key={option.id}>
                      <button
                        type="button"
                        role="checkbox"
                        aria-checked={isSelected}
                        className={clsx(styles.item, isSelected && styles.selected)}
                        onClick={() => toggle(option.id)}
                      >
                        <span className={styles.mark}>
                          <Checkbox decorative checked={isSelected} />
                        </span>
                        <span className={styles.itemText}>
                          <span className={styles.itemName}>
                            {displayText(
                              group === 'hagezi' ? shortBlocklistName(option.name) : option.name,
                            )}
                            {option.recommended && (
                              <span className={styles.tag}>{m.onboarding_recommended()}</span>
                            )}
                          </span>
                          <span className={styles.itemDesc}>{displayText(option.description)}</span>
                        </span>
                        {option.strength ? (
                          <span
                            className={styles.strength}
                            role="img"
                            aria-label={m.settings_blocklist_strength_aria({
                              level: option.strength,
                              max: BLOCKLIST_MAX_STRENGTH,
                            })}
                          >
                            {LEVELS.map((level) => (
                              <span
                                key={level}
                                className={clsx(
                                  styles.bar,
                                  level < (option.strength ?? 0) && styles.on,
                                )}
                                style={
                                  {
                                    '--level': (level + 1) / BLOCKLIST_MAX_STRENGTH,
                                  } as CSSProperties
                                }
                              ></span>
                            ))}
                          </span>
                        ) : null}
                      </button>
                    </li>
                  );
                })}
              </ul>
            </section>
          );
        })}
      </div>
    </div>
  );
}

export default BlocklistPicker;
