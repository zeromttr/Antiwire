import { Trash2 } from 'lucide-react';
import { Button } from '#lib/components/ui/Button.tsx';
import { DialogModal } from '#lib/components/ui/DialogModal.tsx';
import { m } from '#lib/i18n/messages.ts';
import { displayText } from '#lib/utils/index.ts';
import styles from './DeleteDecisionDialog.module.css';

interface Props {
  open?: boolean;
  domain?: string;
  submitting?: boolean;
  onConfirm?: () => void | Promise<void>;
  /** Every dismissal: Cancel, Escape, the close button, an outside click. */
  onCancel?: () => void;
}

export function DeleteDecisionDialog({
  open = false,
  domain = '',
  submitting = false,
  onConfirm,
  onCancel,
}: Props) {
  function close() {
    if (submitting) return;
    onCancel?.();
  }

  return (
    <DialogModal
      open={open}
      title={m.ai_decisions_delete_title()}
      kicker={m.ai_decisions_delete_kicker()}
      icon={Trash2}
      iconVariant="bad"
      describedBy="delete-decision-dialog-desc"
      maxWidth="440px"
      submitting={submitting}
      onClose={onCancel}
      footer={
        <>
          <Button variant="secondary" disabled={submitting} onClick={close}>
            {m.common_cancel()}
          </Button>
          <Button
            variant="destructive"
            disabled={submitting || !domain}
            onClick={() => void onConfirm?.()}
          >
            {submitting ? m.ai_decisions_delete_deleting() : m.ai_decisions_delete_confirm()}
          </Button>
        </>
      }
    >
      <p id="delete-decision-dialog-desc" className={styles.body}>
        {m.ai_decisions_delete_body({ domain: displayText(domain) })}
      </p>
      <p className={`${styles.domain} mono`}>{displayText(domain)}</p>
    </DialogModal>
  );
}

export default DeleteDecisionDialog;
