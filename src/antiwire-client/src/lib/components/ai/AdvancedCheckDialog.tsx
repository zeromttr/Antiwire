import { Sparkles } from 'lucide-react';
import { Button } from '#lib/components/ui/Button.tsx';
import { DialogModal } from '#lib/components/ui/DialogModal.tsx';
import { m } from '#lib/i18n/messages.ts';
import { displayText } from '#lib/utils/index.ts';
import styles from './AdvancedCheckDialog.module.css';

interface Props {
  open?: boolean;
  domain?: string;
  submitting?: boolean;
  onConfirm?: () => void | Promise<void>;
  /** Every dismissal: Cancel, Escape, the close button, an outside click. */
  onCancel?: () => void;
}

export function AdvancedCheckDialog({
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
      title={m.ai_decisions_advanced_title()}
      kicker={m.ai_decisions_advanced_kicker()}
      icon={Sparkles}
      describedBy="advanced-check-dialog-desc"
      maxWidth="440px"
      submitting={submitting}
      onClose={onCancel}
      footer={
        <>
          <Button variant="secondary" disabled={submitting} onClick={close}>
            {m.common_cancel()}
          </Button>
          <Button
            variant="primary"
            disabled={submitting || !domain}
            onClick={() => void onConfirm?.()}
          >
            {submitting ? m.ai_decisions_advanced_running() : m.ai_decisions_advanced_confirm()}
          </Button>
        </>
      }
    >
      <p id="advanced-check-dialog-desc" className={styles.body}>
        {m.ai_decisions_advanced_body({ domain: displayText(domain) })}
      </p>
      <p className={`${styles.domain} mono`}>{displayText(domain)}</p>
    </DialogModal>
  );
}

export default AdvancedCheckDialog;
