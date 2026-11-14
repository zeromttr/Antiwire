import clsx from 'clsx';
import { ChevronDown, Search, X } from 'lucide-react';
import type { ChangeEvent, KeyboardEvent, ReactNode } from 'react';
import { m } from '#lib/i18n/messages.ts';
import styles from './SearchBox.module.css';

type SearchBoxVariant = 'field' | 'panel-header';

interface Props {
  /** Controlled text; update it from `onValueChange` (was `bind:value`). */
  value?: string;
  placeholder?: string;
  ariaLabel?: string;
  variant?: SearchBoxVariant;
  className?: string;
  /** `bind:value`: every edit and the clear button. */
  onValueChange?: (value: string) => void;
  /** Raw input event, for callers that need it. */
  onInput?: (event: ChangeEvent<HTMLInputElement>) => void;
  /** Called with the new text on every edit and on clear (same as `onValueChange`). */
  onChange?: (value: string) => void;
  menuOpen?: boolean;
  menuControls?: string;
  /** Shows the quick-filter disclosure button when set. */
  onMenuToggle?: () => void;
  /** Rendered between the glyph and the text, e.g. active filter chips. */
  prefix?: ReactNode;
  /** Backspace in an empty field: lets the caller remove its last chip. */
  onBackspaceEmpty?: () => void;
  /** Rendered at the end of the field, after the clear button, e.g. an inline `Dropdown`. */
  suffix?: ReactNode;
}

export function SearchBox({
  value = '',
  placeholder = m.common_search(),
  ariaLabel,
  variant = 'field',
  className = '',
  onValueChange,
  onInput,
  onChange,
  menuOpen = false,
  menuControls,
  onMenuToggle,
  prefix,
  onBackspaceEmpty,
  suffix,
}: Props) {
  const hasPrefix = prefix != null && prefix !== false;
  const iconSize = variant === 'panel-header' ? 15 : 14;

  function handleKeyDown(event: KeyboardEvent<HTMLInputElement>) {
    if (event.key !== 'Backspace' || !onBackspaceEmpty) return;
    const input = event.currentTarget;
    if (input.value === '' || (input.selectionStart === 0 && input.selectionEnd === 0)) {
      onBackspaceEmpty();
    }
  }

  function handleChange(event: ChangeEvent<HTMLInputElement>) {
    const next = event.currentTarget.value;
    onValueChange?.(next);
    onInput?.(event);
    onChange?.(next);
  }

  function clear() {
    onValueChange?.('');
    onChange?.('');
  }

  return (
    <div
      className={clsx(styles.searchBox, styles[variant], className, hasPrefix && styles.hasPrefix)}
    >
      <Search className="search-glyph" size={iconSize} strokeWidth={1.75} aria-hidden="true" />
      {hasPrefix && prefix}
      <input
        className={styles.searchInput}
        placeholder={placeholder}
        aria-label={ariaLabel ?? placeholder}
        value={value}
        onChange={handleChange}
        onKeyDown={handleKeyDown}
      />
      {value.trim() && (
        <button
          type="button"
          className={styles.clear}
          aria-label={m.common_clear_search_aria()}
          onClick={clear}
        >
          <X size={12} strokeWidth={2} />
        </button>
      )}
      {suffix != null && suffix !== false && <div className={styles.suffix}>{suffix}</div>}
      {onMenuToggle && (
        <button
          type="button"
          className={clsx(styles.disclosure, menuOpen && styles.open)}
          aria-label={m.records_quick_filters_open_aria()}
          aria-expanded={menuOpen}
          aria-controls={menuControls}
          onClick={() => onMenuToggle()}
        >
          <ChevronDown size={14} strokeWidth={2} />
        </button>
      )}
    </div>
  );
}

export default SearchBox;
