import * as Dialog from '@radix-ui/react-dialog';
import clsx from 'clsx';
import { X } from 'lucide-react';
import type { ComponentType, KeyboardEvent, ReactNode } from 'react';
import { m } from '#lib/i18n/messages.ts';
import styles from './DialogModal.module.css';

export interface DialogApi {
  /** Closes the dialog unless it is submitting; runs `onClose`. */
  close: () => void;
}

type Slot = ReactNode | ((api: DialogApi) => ReactNode);

export type DialogIcon = ComponentType<{ size?: number; strokeWidth?: number; className?: string }>;

interface Props {
  /** Controlled open state (was `bind:open`). */
  open?: boolean;
  /** Called with `false` when the user dismisses the dialog (never while `submitting`). */
  onOpenChange?: (open: boolean) => void;
  title?: string;
  kicker?: string;
  /** Lucide icon shown in a tinted tile before the title. */
  icon?: DialogIcon;
  iconVariant?: 'accent' | 'warn' | 'bad';
  /** Id of the element describing the dialog; omit when there is none. */
  describedBy?: string;
  maxWidth?: string;
  /** While true, Escape, outside clicks and the close button do nothing. */
  submitting?: boolean;
  onKeyDown?: (event: KeyboardEvent<HTMLDivElement>) => void;
  /** Runs after every dismissal, alongside `onOpenChange(false)`. */
  onClose?: () => void;
  /** Body. A function receives `{ close }` (was the `children` snippet argument). */
  children?: Slot;
  /** Footer row; a function receives `{ close }`. */
  footer?: Slot;
  /** Replaces the icon tile, e.g. an app avatar. */
  leading?: ReactNode;
  className?: string;
}

function renderSlot(slot: Slot, api: DialogApi): ReactNode {
  return typeof slot === 'function' ? slot(api) : slot;
}

/** The app's modal dialog on Radix Dialog: focus trap, Escape, outside click, portal. */
export function DialogModal({
  open = false,
  onOpenChange,
  title = '',
  kicker = '',
  icon: IconComponent,
  iconVariant = 'accent',
  describedBy,
  maxWidth = '480px',
  submitting = false,
  onKeyDown,
  onClose,
  children,
  footer,
  leading,
  className = '',
}: Props) {
  function close() {
    if (submitting) return;
    onOpenChange?.(false);
    onClose?.();
  }

  function handleOpenChange(next: boolean) {
    if (!next && submitting) return;
    onOpenChange?.(next);
    if (!next) onClose?.();
  }

  const api: DialogApi = { close };
  const hasLeading = leading != null && leading !== false;
  const hasFooter = footer != null && footer !== false;

  return (
    <Dialog.Root open={open} onOpenChange={handleOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className={clsx('dialog-overlay', styles.overlay)} />
        <Dialog.Content
          aria-describedby={describedBy}
          onCloseAutoFocus={(e) => e.preventDefault()}
          style={{ maxWidth: `min(${maxWidth}, calc(100vw - 32px))` }}
          onKeyDown={onKeyDown}
          className={clsx('dialog-content', 'panel', styles.content, className)}
        >
          {kicker && <div className={styles.kicker}>{kicker}</div>}
          <header className={styles.dialogHead}>
            {hasLeading ? (
              <div className={styles.headLeading}>{leading}</div>
            ) : IconComponent ? (
              <div
                className={clsx(
                  styles.headIcon,
                  iconVariant === 'warn' && styles.warn,
                  iconVariant === 'bad' && styles.bad,
                )}
              >
                <IconComponent size={18} strokeWidth={1.75} />
              </div>
            ) : null}
            {title && <Dialog.Title className="dialog-title">{title}</Dialog.Title>}
            <button
              type="button"
              className={styles.closeBtn}
              aria-label={m.common_close_aria()}
              disabled={submitting}
              onClick={close}
            >
              <X size={18} strokeWidth={1.75} />
            </button>
          </header>

          <div className={styles.dialogBody}>{renderSlot(children, api)}</div>

          {hasFooter && <footer className={styles.dialogFoot}>{renderSlot(footer, api)}</footer>}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

export default DialogModal;
