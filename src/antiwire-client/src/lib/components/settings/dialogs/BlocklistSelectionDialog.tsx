import { Check, Shield } from 'lucide-react';
import { useState } from 'react';
import { BlocklistPicker } from '#lib/components/blocklists/BlocklistPicker.tsx';
import { Button } from '#lib/components/ui/Button.tsx';
import { DialogModal } from '#lib/components/ui/DialogModal.tsx';
import { m } from '#lib/i18n/messages.ts';
import { parseBlocklistSelection, serializeBlocklistSelection } from '#lib/models/blocklists.ts';
import styles from './BlocklistSelectionDialog.module.css';

interface Props {
  open?: boolean;
  onOpenChange?: (open: boolean) => void;
  initialSelection?: string;
  onsave?: (selection: string) => void;
}

export function BlocklistSelectionDialog({
  open = false,
  onOpenChange,
  initialSelection = '',
  onsave,
}: Props) {
  const [selected, setSelected] = useState(() => parseBlocklistSelection(initialSelection));
  // Each opening starts from the saved selection.
  const [wasOpen, setWasOpen] = useState(open);
  if (open !== wasOpen) {
    setWasOpen(open);
    if (open) setSelected(parseBlocklistSelection(initialSelection));
  }

  function close() {
    onOpenChange?.(false);
  }

  function save() {
    onsave?.(serializeBlocklistSelection(selected));
    onOpenChange?.(false);
  }

  return (
    <DialogModal
      open={open}
      onOpenChange={onOpenChange}
      title={m.settings_blocklist_dialog_title()}
      icon={Shield}
      describedBy="blocklist-dialog-desc"
      maxWidth="540px"
      footer={
        <>
          <Button variant="secondary" onClick={close}>
            {m.common_cancel()}
          </Button>
          <Button variant="primary" onClick={save}>
            <Check size={14} strokeWidth={2.5} />
            {m.settings_blocklist_dialog_save()}
          </Button>
        </>
      }
    >
      <div className={styles.body}>
        <p id="blocklist-dialog-desc" className={styles.intro}>
          {m.settings_blocklist_dialog_intro()}
        </p>
        <BlocklistPicker selected={selected} onchange={setSelected} scrollable />
      </div>
    </DialogModal>
  );
}

export default BlocklistSelectionDialog;
