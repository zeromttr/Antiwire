import { AlertTriangle } from 'lucide-react';
import { Button } from '#lib/components/ui/Button.tsx';
import { DialogModal } from '#lib/components/ui/DialogModal.tsx';
import { m } from '#lib/i18n/messages.ts';
import styles from './PowerUserWarningDialog.module.css';

interface Props {
  open?: boolean;
  onOpenChange?: (open: boolean) => void;
  onconfirm?: () => void;
  oncancel?: () => void;
}

export function PowerUserWarningDialog({ open = false, onOpenChange, onconfirm, oncancel }: Props) {
  function close() {
    onOpenChange?.(false);
    oncancel?.();
  }

  function confirm() {
    onOpenChange?.(false);
    onconfirm?.();
  }

  return (
    <DialogModal
      open={open}
      onOpenChange={onOpenChange}
      title={m.settings_power_user_dialog_title()}
      kicker={m.settings_power_user_dialog_kicker()}
      icon={AlertTriangle}
      iconVariant="warn"
      describedBy="power-user-dialog-desc"
      maxWidth="440px"
      onClose={oncancel}
      footer={
        <>
          <Button variant="secondary" onClick={close}>
            {m.common_cancel()}
          </Button>
          <Button variant="primary" onClick={confirm}>
            {m.settings_power_user_dialog_confirm()}
          </Button>
        </>
      }
    >
      <div className={styles.body}>
        <p id="power-user-dialog-desc" className={styles.intro}>
          {m.settings_power_user_dialog_intro()}
        </p>

        <div className={styles.callout}>
          <AlertTriangle size={18} strokeWidth={1.75} className={styles.calloutIcon} />
          <p className={styles.calloutText}>{m.settings_power_user_dialog_callout()}</p>
        </div>

        <p className={styles.footnote}>{m.settings_power_user_dialog_footnote()}</p>
      </div>
    </DialogModal>
  );
}

export default PowerUserWarningDialog;
