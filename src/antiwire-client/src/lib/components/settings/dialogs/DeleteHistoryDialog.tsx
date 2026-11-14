import { Trash2 } from 'lucide-react';
import { Button } from '#lib/components/ui/Button.tsx';
import { DialogModal } from '#lib/components/ui/DialogModal.tsx';
import { m } from '#lib/i18n/messages.ts';
import type { HistoryDeletionRange } from '#lib/utils/history-deletion.ts';
import { formatDateTime } from '#lib/utils/index.ts';
import styles from './DeleteHistoryDialog.module.css';

interface Props {
  open?: boolean;
  onOpenChange?: (open: boolean) => void;
  /** What the confirm button deletes; fixed when the dialog opens. */
  range: HistoryDeletionRange;
  submitting?: boolean;
  onconfirm?: () => void | Promise<void>;
}

export function DeleteHistoryDialog({
  open = false,
  onOpenChange,
  range,
  submitting = false,
  onconfirm,
}: Props) {
  function close() {
    if (submitting) return;
    onOpenChange?.(false);
  }

  return (
    <DialogModal
      open={open}
      onOpenChange={onOpenChange}
      title={
        range.all ? m.settings_delete_all_dialog_title() : m.settings_delete_recent_dialog_title()
      }
      kicker={m.settings_delete_history_dialog_kicker()}
      icon={Trash2}
      iconVariant="bad"
      describedBy="delete-history-dialog-desc"
      maxWidth="440px"
      submitting={submitting}
      footer={
        <>
          <Button variant="secondary" disabled={submitting} onClick={close}>
            {m.common_cancel()}
          </Button>
          <Button variant="destructive" disabled={submitting} onClick={() => void onconfirm?.()}>
            {submitting
              ? m.settings_delete_history_deleting()
              : m.settings_delete_history_confirm()}
          </Button>
        </>
      }
    >
      <div id="delete-history-dialog-desc" className={styles.body}>
        <p>
          {range.all
            ? m.settings_delete_all_dialog_body()
            : m.settings_delete_recent_dialog_body({ start: formatDateTime(range.since) })}
        </p>
        <p className={styles.kept}>{m.settings_delete_history_dialog_kept()}</p>
      </div>
    </DialogModal>
  );
}

export default DeleteHistoryDialog;
