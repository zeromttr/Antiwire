import clsx from 'clsx';
import { Check, ChevronDown } from 'lucide-react';
import { memo, useEffect, useLayoutEffect, useRef, useState, type KeyboardEvent } from 'react';
import { m } from '#lib/i18n/messages.ts';
import { popoverIn, popoverOut } from '#lib/motion.ts';
import { usePresence } from '#lib/use-presence.ts';
import { fireUiAction } from '#lib/utils/ui-action.ts';
import { moveActiveIndex } from './listbox-nav';
import styles from './Dropdown.module.css';

export interface DropdownOption {
  value: string;
  label: string;
  /** Shown dimmed at the end of the option's row, e.g. a count. */
  detail?: string;
}

interface Props {
  options: DropdownOption[];
  /** Selected value; the parent owns it and updates it from `onChange`. */
  value: string;
  /** Called with the picked value (only when it differs); may be async. */
  onChange?: (value: string) => unknown;
  onError?: (message: string, error: unknown) => void;
  id?: string;
  /** Trigger text while nothing is selected. */
  hint?: string;
  disabled?: boolean;
  menuTitle?: string;
  /**
   * `inline` is a borderless trigger as wide as its text, for use inside another field
   * (see `SearchBox`'s `suffix`); its menu hangs from the trigger's right edge.
   */
  variant?: 'field' | 'inline';
  /** Names the control when no visible label does; read out ahead of the value. */
  ariaLabel?: string;
}

export const Dropdown = memo(function Dropdown({
  options,
  value,
  onChange,
  onError,
  id,
  hint = m.common_select_ellipsis(),
  disabled = false,
  menuTitle,
  variant = 'field',
  ariaLabel,
}: Props) {
  const [open, setOpen] = useState(false);
  const [activeIndex, setActiveIndex] = useState(-1);
  const rootEl = useRef<HTMLDivElement | null>(null);
  const triggerEl = useRef<HTMLButtonElement | null>(null);
  /** Option to focus once the menu has rendered. */
  const pendingFocus = useRef<number | null>(null);
  const menu = usePresence<HTMLDivElement>(open, popoverIn(), popoverOut());

  const selected = options.find((o) => o.value === value);
  const selectedIndex = options.findIndex((o) => o.value === value);
  const displayLabel = selected?.label ?? hint;
  const menuId = `${id ?? 'dropdown'}-menu`;

  function focusOptionEl(index: number) {
    menu.ref.current
      ?.querySelector<HTMLButtonElement>(`[data-index="${index}"]`)
      ?.focus({ preventScroll: true });
  }

  useLayoutEffect(() => {
    if (!open || pendingFocus.current === null) return;
    const index = pendingFocus.current;
    pendingFocus.current = null;
    menu.ref.current
      ?.querySelector<HTMLButtonElement>(`[data-index="${index}"]`)
      ?.focus({ preventScroll: true });
  }, [open, menu.ref]);

  function openMenu(focusIndex?: number) {
    if (disabled) return;
    const index = focusIndex ?? (selectedIndex >= 0 ? selectedIndex : 0);
    setOpen(true);
    setActiveIndex(index);
    pendingFocus.current = index;
  }

  function closeMenu(returnFocus = false) {
    setOpen(false);
    setActiveIndex(-1);
    pendingFocus.current = null;
    if (returnFocus) triggerEl.current?.focus();
  }

  function toggle() {
    if (disabled) return;
    if (open) closeMenu();
    else openMenu();
  }

  function select(index: number) {
    const option = options[index];
    if (!option || disabled) return;
    // DOM focus lives on the option buttons, so only return focus to the
    // trigger when the selection came from keyboard navigation.
    const hadFocus = menu.ref.current?.contains(document.activeElement) ?? false;
    closeMenu();
    if (option.value !== value) {
      fireUiAction(() => onChange?.(option.value), { onError });
    }
    if (hadFocus) triggerEl.current?.focus();
  }

  function focusOption(index: number) {
    if (index < 0 || index >= options.length) return;
    setActiveIndex(index);
    focusOptionEl(index);
  }

  function onMenuKeyDown(e: KeyboardEvent<HTMLDivElement>) {
    if (!open) return;
    switch (e.key) {
      case 'ArrowDown':
        e.preventDefault();
        focusOption(moveActiveIndex(activeIndex, options.length, 'ArrowDown', 'vertical'));
        break;
      case 'ArrowUp':
        e.preventDefault();
        focusOption(moveActiveIndex(activeIndex, options.length, 'ArrowUp', 'vertical'));
        break;
      case 'Home':
        e.preventDefault();
        focusOption(moveActiveIndex(activeIndex, options.length, 'Home'));
        break;
      case 'End':
        e.preventDefault();
        focusOption(moveActiveIndex(activeIndex, options.length, 'End'));
        break;
      case 'Enter':
      case ' ':
        e.preventDefault();
        select(activeIndex);
        break;
      case 'Escape':
        e.preventDefault();
        closeMenu(true);
        break;
      case 'Tab':
        closeMenu();
        break;
    }
  }

  function onTriggerKeyDown(e: KeyboardEvent<HTMLButtonElement>) {
    if (disabled) return;
    if (e.key === 'Enter' || e.key === ' ' || e.key === 'ArrowDown') {
      e.preventDefault();
      openMenu(e.key === 'ArrowDown' ? undefined : selectedIndex >= 0 ? selectedIndex : 0);
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      openMenu(options.length - 1);
    } else if (e.key === 'Escape' && open) {
      e.preventDefault();
      closeMenu();
    }
  }

  useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => {
      const target = e.target as Node;
      if (rootEl.current && !rootEl.current.contains(target)) {
        setOpen(false);
        setActiveIndex(-1);
      }
    };
    const onKey = (e: globalThis.KeyboardEvent) => {
      if (e.key === 'Escape') {
        setOpen(false);
        setActiveIndex(-1);
        triggerEl.current?.focus();
      }
    };
    document.addEventListener('mousedown', onDoc);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('mousedown', onDoc);
      document.removeEventListener('keydown', onKey);
    };
  }, [open]);

  return (
    <div
      className={clsx(
        styles.dropdown,
        variant === 'inline' && styles.inline,
        open && styles.open,
        disabled && styles.disabled,
      )}
      ref={rootEl}
    >
      <button
        type="button"
        className={styles.trigger}
        ref={triggerEl}
        id={id}
        disabled={disabled}
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-controls={menuId}
        aria-label={ariaLabel ? `${ariaLabel}: ${displayLabel}` : undefined}
        onClick={toggle}
        onKeyDown={onTriggerKeyDown}
      >
        <span className={clsx(styles.value, !selected && styles.placeholder)}>{displayLabel}</span>
        <ChevronDown size={15} strokeWidth={2} className={clsx('chevron', open && 'rotated')} />
      </button>

      {menu.present && (
        <div
          className={styles.menu}
          ref={menu.ref}
          role="listbox"
          id={menuId}
          aria-labelledby={id}
          tabIndex={-1}
          onKeyDown={onMenuKeyDown}
        >
          {menuTitle && <div className={styles.menuTitle}>{menuTitle}</div>}
          <ul className={styles.menuList}>
            {options.length === 0 ? (
              <li className={styles.empty}>{m.common_no_options()}</li>
            ) : (
              options.map((option, index) => {
                const isSelected = option.value === value;
                const isActive = index === activeIndex;
                return (
                  <li key={option.value} role="presentation">
                    <button
                      type="button"
                      role="option"
                      id={`${menuId}-option-${index}`}
                      data-index={index}
                      aria-selected={isSelected}
                      className={clsx(
                        styles.menuItem,
                        isSelected && styles.selected,
                        isActive && styles.active,
                      )}
                      tabIndex={-1}
                      onMouseEnter={() => setActiveIndex(index)}
                      onFocus={() => setActiveIndex(index)}
                      onClick={() => select(index)}
                    >
                      <span className={styles.itemLabel}>{option.label}</span>
                      {option.detail !== undefined && (
                        <span className={styles.itemDetail}>{option.detail}</span>
                      )}
                      {isSelected && <Check size={14} strokeWidth={2.5} className="check" />}
                    </button>
                  </li>
                );
              })
            )}
          </ul>
        </div>
      )}
    </div>
  );
});

export default Dropdown;
