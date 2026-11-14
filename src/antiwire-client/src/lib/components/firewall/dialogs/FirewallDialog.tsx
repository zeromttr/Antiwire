import type { KeyboardEvent, ReactNode } from 'react';
import DialogModal, { type DialogApi } from '#lib/components/ui/DialogModal.tsx';

interface Props {
  /** Controlled open state (was `bind:open`). */
  open?: boolean;
  onOpenChange?: (open: boolean) => void;
  title?: string;
  kicker?: string;
  describedBy?: string;
  onKeyDown?: (event: KeyboardEvent<HTMLDivElement>) => void;
  children?: (api: DialogApi) => ReactNode;
}

export function FirewallDialog({
  open = false,
  onOpenChange,
  title = '',
  kicker = '',
  describedBy,
  onKeyDown,
  children,
}: Props) {
  return (
    <DialogModal
      open={open}
      onOpenChange={onOpenChange}
      title={title}
      kicker={kicker}
      describedBy={describedBy}
      onKeyDown={onKeyDown}
    >
      {children}
    </DialogModal>
  );
}

export default FirewallDialog;
